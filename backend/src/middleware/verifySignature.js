const crypto = require('crypto');

/**
 * verifySignature.js
 *
 * Protects the ingestion endpoint from two distinct attack classes:
 *
 *   1. Payload spoofing — without this, anyone who obtains a projectId
 *      could POST fabricated findings directly to the ingest endpoint.
 *      GitHub-hosted CI runner IPs are not a stable, allowlist-able
 *      range, so IP-based trust would provide no real protection.
 *
 *   2. Timing attacks — a naive `sig === expected` string comparison
 *      returns as soon as the first mismatched byte is found, so an
 *      attacker can measure response latency to brute-force the correct
 *      signature one byte at a time. This is a textbook side-channel
 *      and is closed here with crypto.timingSafeEqual, which always
 *      takes the same amount of time regardless of where a mismatch
 *      occurs.
 *
 * Precondition: this middleware MUST run after a raw-body-capturing
 * body parser (e.g. `express.json({ verify: (req, _res, buf) => {
 * req.rawBody = buf; } })`) and after authenticateProject (which sets
 * req.projectSecret). Re-serializing req.body and signing THAT instead
 * of the raw bytes will not match a payload signed by a Python client —
 * json.dumps() inserts a space after every ':' and ',' that
 * JSON.stringify() does not, so recomputing from the parsed object
 * produces a different byte sequence and rejects every legitimate
 * request. Only the exact bytes that were signed can ever verify
 * correctly.
 */
function verifySignature(req, res, next) {
  const signatureHeader = req.headers['x-ecdat-signature'];

  if (!signatureHeader || typeof signatureHeader !== 'string') {
    return res.status(401).json({ error: 'missing X-ECDAT-Signature header' });
  }

  if (!req.rawBody || !Buffer.isBuffer(req.rawBody)) {
    // Fail closed: if the raw body was never captured upstream, there is
    // nothing trustworthy to verify against — never fall back to
    // re-serializing req.body here.
    return res.status(401).json({ error: 'raw request body unavailable for verification' });
  }

  if (!req.projectSecret) {
    // authenticateProject must run first and attach the verified
    // per-project secret; without it there is no key to HMAC with.
    return res.status(401).json({ error: 'project not authenticated' });
  }

  const expected =
    'sha256=' +
    crypto
      .createHmac('sha256', req.projectSecret)
      .update(req.rawBody)
      .digest('hex');

  const provided = Buffer.from(signatureHeader);
  const expectedBuf = Buffer.from(expected);

  // Buffers of different lengths would make timingSafeEqual throw, and
  // the length mismatch itself is already a definitive "invalid" —
  // check it first, outside the constant-time comparison.
  if (provided.length !== expectedBuf.length) {
    return res.status(401).json({ error: 'invalid signature' });
  }

  // Constant-time comparison — never a plain `===` or Buffer.equals()
  // shortcut here, both of which are timing-observable.
  const signaturesMatch = crypto.timingSafeEqual(provided, expectedBuf);

  if (!signaturesMatch) {
    return res.status(401).json({ error: 'invalid signature' });
  }

  return next();
}

module.exports = verifySignature;
