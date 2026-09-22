'use strict';

const crypto = require('crypto');

/**
 * backend/src/services/sanitizer.js
 *
 * Pre-flight sanitization middleware — Section 06, Patch 1.
 *
 * Masks sensitive substrings in a code snippet before it is ever sent to
 * the external NVIDIA LLM API, and reversibly restores them afterward —
 * purely for internal storage/UI purposes. The LLM itself only ever sees
 * placeholder tokens; it never sees real emails, IPs, API keys, internal
 * hostnames, or other high-entropy secrets (cert blobs, connection
 * strings, etc).
 *
 * This is defense-in-depth, not a substitute for vendor trust: it mirrors
 * the same "mask before egress" pattern used by AWS Comprehend PII
 * redaction and Azure OpenAI's customer-data handling — the guarantee
 * holds regardless of the vendor's own data policy, and survives a
 * vendor-side breach.
 */

// Ordered MOST-SPECIFIC -> LEAST-SPECIFIC. A string that is simultaneously
// high-entropy AND an API key / internal hostname must be caught by the
// more specific tag first — HIGHENTROPY is a catch-all and runs last so
// it only mops up secrets nothing else recognized.
const PATTERNS = [
  { tag: 'EMAIL', re: /[\w.+-]+@[\w-]+\.[\w.-]+/g },
  { tag: 'IP', re: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g },
  // Hyphen/underscore aware — catches sk-proj-xxxx style keys (current
  // OpenAI issuance format) as well as legacy sk_xxxx / pk_xxxx / api_xxxx.
  { tag: 'APIKEY', re: /\b(?:sk|pk|api)[-_][A-Za-z0-9_-]{16,}\b/gi },
  { tag: 'INTERNAL_HOST', re: /\b[\w-]+\.(?:ntro|internal|corp)\.[a-z]{2,}\b/gi },
  // Catch-all: long base64-ish runs not already claimed above (cert
  // blobs, raw tokens, connection-string secrets, etc).
  { tag: 'HIGHENTROPY', re: /\b[A-Za-z0-9+/]{32,}={0,2}\b/g },
];

const MASK_KEY_PREFIX = 'mask:';
const MASK_TTL_SECONDS = 300; // 5 minutes, per spec — not configurable at call time
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Replace every sensitive substring in `snippet` with a random,
 * non-guessable placeholder token, and persist the token -> original-value
 * map in Redis (5-minute TTL) so it can be reversed later via `unmask`.
 *
 * @param {string} snippet      Raw code/text about to be sent to an LLM.
 * @param {string} projectId    Tenant scope, stored alongside the map for
 *                              audit purposes. Not part of the Redis key —
 *                              mapId (a fresh UUID) is already unique and
 *                              unguessable on its own.
 * @param {object} redisClient  Any client exposing `.set(key, value, 'EX', ttl)`
 *                              and `.get(key)` (ioredis-compatible).
 * @returns {Promise<{masked: string, mapId: string}>}
 */
async function sanitize(snippet, projectId, redisClient) {
  if (typeof snippet !== 'string') {
    throw new TypeError('sanitize(): snippet must be a string');
  }
  if (!redisClient || typeof redisClient.set !== 'function') {
    throw new TypeError('sanitize(): redisClient must expose a Redis-compatible set()');
  }

  let masked = snippet;
  const mapId = crypto.randomUUID();
  const reverseMap = {};

  for (const { tag, re } of PATTERNS) {
    masked = masked.replace(re, (match) => {
      // A prior pass already replaced this exact substring with a token —
      // don't re-mask a token we just inserted. Shouldn't occur given the
      // __TAG_hex__ shape never matches these patterns, but cheap to guard.
      if (Object.prototype.hasOwnProperty.call(reverseMap, match)) {
        return match;
      }

      const token = `__${tag}_${crypto.randomBytes(4).toString('hex')}__`;
      reverseMap[token] = match;
      return token;
    });
  }

  await redisClient.set(
    `${MASK_KEY_PREFIX}${mapId}`,
    JSON.stringify({ projectId, reverseMap, createdAt: Date.now() }),
    'EX',
    MASK_TTL_SECONDS
  );

  return { masked, mapId };
}

/**
 * Re-hydrate real values into `text` (typically an LLM's response) using
 * the reverse map `sanitize()` stored under `mapId`. For internal
 * storage/UI rendering only — the unmasked result must never be sent back
 * out to the LLM or any other external party.
 *
 * Fails open to the *masked* text (never throws) if the map has expired,
 * never existed, or is malformed — an unmask miss should degrade the
 * output, not crash the request.
 *
 * @param {string} text
 * @param {string} mapId
 * @param {object} redisClient  Any client exposing `.get(key)`.
 * @returns {Promise<string>}
 */
async function unmask(text, mapId, redisClient) {
  if (typeof mapId !== 'string' || !UUID_RE.test(mapId)) {
    // Malformed mapId — refuse to build a Redis key from unvalidated
    // caller input rather than trusting it verbatim.
    return text;
  }
  if (!redisClient || typeof redisClient.get !== 'function') {
    throw new TypeError('unmask(): redisClient must expose a Redis-compatible get()');
  }

  const raw = await redisClient.get(`${MASK_KEY_PREFIX}${mapId}`);
  if (!raw) return text; // TTL expired or mapId never existed

  let stored;
  try {
    stored = JSON.parse(raw);
  } catch {
    return text; // corrupted entry — never throw on the unmask path
  }

  let result = text;
  for (const [token, original] of Object.entries(stored.reverseMap || {})) {
    result = result.split(token).join(original);
  }
  return result;
}

module.exports = { sanitize, unmask };
