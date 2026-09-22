const bcrypt = require('bcrypt');
const Project = require('../models/Project');

/**
 * authenticateProject.js
 *
 * Prevents Insecure Direct Object Reference (IDOR) / cross-tenant
 * poisoning. Authentication proves *who* is calling; it does not by
 * itself prove *which* project they may act on. If projectId were ever
 * read from the request body, any authenticated caller could overwrite
 * or poison a different tenant's data simply by changing that field.
 *
 * The fix: projectId is resolved exclusively from a verified,
 * server-issued token — the request body's own projectId/PROJECT_ID
 * field, if present, is never consulted for this purpose.
 *
 * Token shape:   ecdat_<projectId>.<rawSecret>
 * Header:        X-ECDAT-Token
 */
async function authenticateProject(req, res, next) {
  try {
    const token = req.headers['x-ecdat-token'];

    if (!token || typeof token !== 'string') {
      return res.status(401).json({ error: 'missing X-ECDAT-Token header' });
    }

    // Strip the "ecdat_" prefix, then split on the FIRST dot only —
    // a secret is not guaranteed to be dot-free, so a naive split('.')
    // without limiting could silently truncate it.
    const withoutPrefix = token.startsWith('ecdat_') ? token.slice(6) : token;
    const separatorIndex = withoutPrefix.indexOf('.');

    if (separatorIndex === -1) {
      return res.status(401).json({ error: 'malformed token' });
    }

    const projectId = withoutPrefix.slice(0, separatorIndex);
    const rawSecret = withoutPrefix.slice(separatorIndex + 1);

    if (!projectId || !rawSecret) {
      return res.status(401).json({ error: 'malformed token' });
    }

    // tokenHash has `select: false` on the schema, so it must be
    // explicitly requested here. IMPORTANT: don't list any other field
    // name alongside `+tokenHash` (e.g. previously `'+tokenHash status'`) —
    // mixing a plain field name into a select() call switches Mongoose
    // into inclusion-only mode, silently dropping every other field
    // (name, expectedDomains, createdAt) from the returned document.
    // `+tokenHash` alone keeps the default "all fields" projection and
    // additionally includes the one field that's excluded by default.
    const project = await Project.findById(projectId).select('+tokenHash');

    // Deliberately generic error for both "not found" and "wrong secret" —
    // distinguishing them would let an attacker enumerate valid project IDs.
    if (!project || project.status !== 'active') {
      return res.status(403).json({ error: 'invalid token' });
    }

    const isValid = await bcrypt.compare(rawSecret, project.tokenHash);
    if (!isValid) {
      return res.status(403).json({ error: 'invalid token' });
    }

    // Resolved, trusted identifiers — everything downstream must use
    // these, never anything read from req.body.
    req.projectId = project._id;
    req.projectSecret = rawSecret; // needed by verifySignature.js for HMAC
    req.project = project; // full doc — e.g. scanController.js reads expectedDomains off this

    return next();
  } catch (err) {
    // Malformed ObjectId strings, DB errors, etc. all collapse to a
    // generic 403 for the same reason as above — no information leakage
    // about *why* the token failed.
    return res.status(403).json({ error: 'invalid token' });
  }
}

module.exports = authenticateProject;
