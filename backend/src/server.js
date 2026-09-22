const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');

const authenticateProject = require('./middleware/authenticateProject');
const verifySignature = require('./middleware/verifySignature');
const { handleBatch } = require('./controllers/ingestController');
const { triggerNetworkScan } = require('./controllers/scanController');
const {
  getDashboardSummary,
  listAssets,
  regenerateFix,
} = require('./controllers/dashboardController');
const { createProject } = require('./controllers/projectController');
const exportController = require('./controllers/exportController');

/**
 * server.js
 *
 * Ties together the Express gateway: CORS, auth, signature verification,
 * and route mounting. This is the ONLY publicly reachable service in the
 * stack (see docker-compose.yml) — every other container has no ports
 * exposed to the host.
 */

const app = express();

// --- CORS ------------------------------------------------------------------
// A single allowed origin, sourced from an env var so the identical line
// runs unchanged from localhost in development through to the real NTRO
// domain in production. `origin: '*'` combined with credentialed requests
// is an OWASP-flagged misconfiguration and must never be used here.
app.use(
  cors({
    origin: process.env.FRONTEND_URL,
    credentials: true,
    methods: ['GET', 'POST'],
    allowedHeaders: [
      'Content-Type',
      'x-ecdat-token',
      'x-ecdat-signature',
    ],
  })
);

// --- Body parsing ------------------------------------------------------------
// A generic JSON parser for most routes...
app.use((req, res, next) => {
  if (req.path === '/api/ingest/batch') return next();
  express.json({ limit: '1mb' })(req, res, next);
});

// ...but /api/ingest/batch needs the EXACT raw bytes the scanner signed,
// captured before any parsing touches them, so it gets its own parser
// instance with a `verify` hook. Re-serializing req.body and signing
// THAT would not match a Python-signed payload (json.dumps vs
// JSON.stringify use different whitespace), so this raw capture is
// mandatory, not a style choice.
const rawBodyJsonParser = express.json({
  limit: '2mb',
  verify: (req, _res, buf) => {
    console.log('[DEBUG] buf:', buf.toString('utf8').substring(0, 50));
    req.rawBody = buf;
  },
});

// --- Routes ------------------------------------------------------------------

app.get('/health', (_req, res) => res.status(200).json({ status: 'ok' }));

// /api/projects is the one route that must NOT require a token
app.post('/api/projects', express.json({ limit: '10kb' }), createProject);

// Path A — automated CI ingestion. Order matters: authenticateProject
// resolves req.projectId + req.projectSecret first; verifySignature then
// HMACs req.rawBody using that secret. Reordering these reopens a real
// vulnerability (see authenticateProject.js / verifySignature.js).
app.post(
  '/api/ingest/batch',
  rawBodyJsonParser,
  authenticateProject,
  verifySignature,
  handleBatch
);

// Path B — manual, browser-triggered network scan. Token-authenticated,
// but does not carry an HMAC-signed body (it's a same-origin, credentialed
// browser request under the CORS policy above, not an unattended CI job).
app.post('/api/scan/network', authenticateProject, triggerNetworkScan);

// Dashboard read path — token-authenticated, scoped to the caller's project.
app.get('/api/dashboard', authenticateProject, getDashboardSummary);

// Raw finding list — powers CBOMGraph.js and MigrationPlanner.js, which
// need per-finding fields the aggregate summary above doesn't carry.
app.get('/api/assets', authenticateProject, listAssets);

// Re-request a PQC fix for an already-ingested finding (e.g. it landed in
// fix_pending because the LLM was rate-limited or degraded on first try).
app.post('/api/assets/:contentHash/fix', authenticateProject, regenerateFix);

// CycloneDX Export
app.get('/api/export/cyclonedx', authenticateProject, exportController.toCycloneDx);

// --- Startup -----------------------------------------------------------------
async function start() {
  await mongoose.connect(process.env.MONGO_URI);
  const port = process.env.PORT || 5000;
  app.listen(port, () => console.log(`ECDAT gateway listening on :${port}`));
}

if (require.main === module) {
  start().catch((err) => {
    console.error('[server] failed to start:', err.message);
    process.exit(1);
  });
}

module.exports = app;
