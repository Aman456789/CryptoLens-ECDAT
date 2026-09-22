'use strict';

/**
 * classicalTriageEngine.js
 *
 * Independent classical-vulnerability triage — TRD v2.2 REQ-FUNC-17,
 * "the Dual-Risk Engine."
 *
 * This is deliberately NOT part of Mosca's Algorithm (moscaAlgorithm.js).
 * A finding can be classically urgent (e.g. a live SWEET32-exploitable
 * cipher on a long-lived session) without being quantum-urgent under
 * D+T>Q, and vice versa — a quantum-critical RSA-2048 finding has no
 * classical collision weakness at all. The two risk models are computed,
 * stored, and surfaced separately:
 *
 *   - This module NEVER reads moscaScore or riskTag.
 *   - This module NEVER writes moscaScore or riskTag.
 *   - Its output (an array, persisted verbatim as Asset.classicalRiskFlags)
 *     is never averaged, weighted, or blended into the Mosca score by any
 *     caller. If a future change makes that true, it is a regression of
 *     this requirement, not a refactor.
 *
 * The caller (queues/verificationQueue.js) is responsible for combining
 * "isCritical = moscaResult.riskTag === 'Critical' || classicalFlags.length > 0"
 * for the purpose of *deciding whether to request a fix* — that OR-based
 * trigger is a business rule that lives with the caller, not a blending of
 * the two scores themselves.
 */

// SWEET32-class 64-bit block ciphers: vulnerable to birthday-bound
// collision attacks under sustained use (long-lived TLS/VPN sessions).
// Matched case-insensitively against algorithm-name substrings so common
// spellings/aliases collapse to the same flag:
//   "Blowfish"                 -> blowfish
//   "3DES", "3-DES", "DES3"    -> tripleDes / desVariant
//   "DESede" (Java/JCE name)   -> desede
//   "Triple DES", "TripleDES"  -> tripleDes
//   "RC4"                      -> rc4
//   "DES" (plain, single)      -> des
//
// NOTE: `\bdes\b` intentionally does NOT match inside "3DES" or "DESede"
// (no word boundary between a digit/letter and "des" in those strings),
// which is why those forms each have their own explicit pattern below
// rather than relying on the plain-DES pattern to catch everything.
const SWEET32_PATTERNS = [
  /blowfish/i,
  /\b3[\s-]?des\b/i,
  /des[\s-]?3\b/i,
  /desede/i,
  /triple[\s-]?des/i,
  /\brc4\b/i,
  /\bdes\b/i,
];

// Broken/deprecated hash functions with practical, publicly-demonstrated
// collision attacks. Not exhaustive by design — this module flags the two
// TRD-mandated minimums; extending the list is additive and safe.
const WEAK_HASH_PATTERNS = [/\bmd5\b/i, /\bsha-?1\b/i];

/**
 * @param {string} algorithm  Raw algorithm string from the finding, e.g.
 *   "Blowfish", "3DES-CBC", "MD5", "RSA-1024". Case-insensitive; substring
 *   matched, so "AES-256-CBC-with-MD5-HMAC" correctly still flags WEAK_HASH.
 * @returns {Array<'SWEET32'|'WEAK_HASH'>} Zero, one, or both flags. Never
 *   throws — a missing or malformed `algorithm` value fails safe to `[]`
 *   rather than crashing the verification job that calls it.
 */
function computeClassicalTriage(algorithm) {
  if (typeof algorithm !== 'string' || algorithm.trim() === '') {
    return [];
  }

  const flags = [];

  if (SWEET32_PATTERNS.some((pattern) => pattern.test(algorithm))) {
    flags.push('SWEET32');
  }

  if (WEAK_HASH_PATTERNS.some((pattern) => pattern.test(algorithm))) {
    flags.push('WEAK_HASH');
  }

  return flags;
}

module.exports = { computeClassicalTriage };
