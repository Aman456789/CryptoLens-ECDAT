'use strict';

const { Queue, Worker } = require('bullmq');
const Asset = require('../models/Asset');
const { fastApiBreaker } = require('../services/resilientClient');
const { generatePqcFix } = require('../services/nvidiaLlmService');
const { calculateMoscaRisk } = require('../services/moscaAlgorithm');
const { computeClassicalTriage } = require('../services/classicalTriageEngine'); // [NEW v3.0]
const { validateCandidate } = require('../services/patchValidator'); // [NEW v3.0, the Double-Validation Gate]

/**
 * verificationQueue.js
 *
 * Decouples AI verification/scoring/remediation from the ingestion request
 * path. The gateway enqueues one job per finding and returns 202
 * immediately — this worker calls the slow, rate-limited, sometimes
 * unavailable FastAPI, Mosca, classical-triage, LLM, and patch-validation
 * dependencies.
 *
 * v3.0 additions over v2.0:
 *  - Dual-Risk Engine: Mosca (quantum-timeline) and Classical Triage
 *    (SWEET32 / WEAK_HASH) are computed independently and NEVER blended
 *    into one score (REQ-FUNC-17) — either alone can trigger remediation.
 *  - Double-Validation Gate: every LLM candidate — cached or freshly
 *    generated — is re-scanned by patchValidator.validateCandidate() before
 *    fixStatus may become 'generated' (REQ-FUNC-14/15/16, a hard invariant).
 *
 * Concurrency remains hard-capped at 10: a GitHub Action can fire thousands
 * of findings in one burst, and an unbounded Promise.all() over that batch
 * means a single unrejected promise can crash the whole Node process
 * (Node's default unhandled-rejection behavior). BullMQ's `concurrency`
 * bounds how many jobs run in parallel at the process level, while each job
 * stays individually try/catch-isolated below.
 */

const connection = {
  host: process.env.REDIS_HOST || 'redis',
  port: Number(process.env.REDIS_PORT) || 6379,
};

const verificationQueue = new Queue('verification', {
  connection,
  defaultJobOptions: {
    attempts: 3,
    backoff: { type: 'exponential', delay: 2000 },
    removeOnComplete: 1000, // bound Redis memory growth on a busy queue
    removeOnFail: 5000,
  },
});

// [NEW v3.0] Maps a finding's algorithm to the NIST-finalized target
// standard it should migrate to (REQ-FUNC-10, amended v2.1). Kept local to
// this file — the decision needs both the algorithm name AND the classical
// triage result to disambiguate (e.g. "3DES" is both an algorithm name and
// a SWEET32-class flag), so it belongs next to where both are already
// available, not duplicated as a shared constant.
const ASYMMETRIC_FAMILIES = ['RSA', 'ECC', 'ECDSA', 'ECDH', 'DH', 'DIFFIE-HELLMAN'];

function resolveTargetStandard(algorithm, classicalRiskFlags) {
  const alg = (algorithm || '').toUpperCase();

  if (ASYMMETRIC_FAMILIES.some((family) => alg.includes(family))) {
    // Security-category tier (768 vs 1024) is a project-level config in the
    // full v3.0 design; that config isn't wired through to this worker yet,
    // so default to the more conservative 1024 rather than silently
    // picking the weaker option.
    return 'ML-KEM-1024';
  }

  if (classicalRiskFlags.includes('SWEET32') || classicalRiskFlags.includes('WEAK_HASH')) {
    return 'AES-256-GCM';
  }

  // Should be unreachable in practice — this is only called when isCritical
  // is true, and every algorithm the scanner recognizes falls into one of
  // the two branches above. Fails to the safer symmetric target rather than
  // throwing, so an unrecognized algorithm name degrades gracefully instead
  // of crashing the worker.
  return 'AES-256-GCM';
}

/**
 * Runs the false-positive filter, Dual-Risk scoring, LLM remediation, and
 * Double-Validation Gate for a single finding, and returns the fields to
 * write back onto the Asset document.
 */
async function processFinding(job) {
  const { snippet, algorithm, language, keySize, projectId, dataContext } = job.data;

  // Stage 1 — false-positive filter. Wrapped in a circuit breaker so a
  // stalled FastAPI can't block this worker slot indefinitely.
  const filterResult = await fastApiBreaker.fire(snippet);

  if (!filterResult || filterResult.status === 'degraded') {
    // FastAPI unavailable — leave the finding honestly unverified rather
    // than scoring or remediating something we don't yet know is real.
    return {
      riskTag: 'Unverified',
      moscaScore: null,
      classicalRiskFlags: [],
      fixStatus: 'none',
      fixSnippet: null,
    };
  }

  if (filterResult.verdict === 0) {
    // Confirmed false positive — excluded from both risk models and never
    // gets a remediation request.
    return { riskTag: 'Low', moscaScore: null, classicalRiskFlags: [], fixStatus: 'none', fixSnippet: null };
  }

  // Stage 2 — Dual-Risk Engine. Mosca (quantum-timeline, D+T>Q) and
  // Classical Triage (SWEET32 / WEAK_HASH) are ALWAYS both computed for a
  // confirmed finding and NEVER blended into one number (REQ-FUNC-17): a
  // finding can be classically urgent (a live SWEET32-exploitable cipher)
  // without being quantum-urgent, or vice versa, and collapsing them would
  // hide which threat is actually driving the urgency.
  const vulnerableInstanceCount = await Asset.countDocuments({
    projectId,
    algorithm,
    status: 'active',
  });

  const mosca = calculateMoscaRisk({
    algorithm,
    dataContext,
    vulnerableInstanceCount: vulnerableInstanceCount || 1,
  });

  const classicalRiskFlags = computeClassicalTriage(algorithm);

  const riskFields = {
    riskTag: mosca.riskTag,
    moscaScore: mosca.moscaScore,
    dataShelfLifeYears: mosca.dataShelfLifeYears,
    migrationTimeYears: mosca.migrationTimeYears,
    classicalRiskFlags,
  };

  // EITHER risk model flagging Critical is sufficient to trigger remediation.
  const isCritical = mosca.riskTag === 'Critical' || classicalRiskFlags.length > 0;

  if (!isCritical) {
    // Genuine vulnerability, but neither risk model calls it urgent yet —
    // still visible on the dashboard, just not queued against the LLM.
    return { ...riskFields, fixStatus: 'none', fixSnippet: null };
  }

  // Stage 3 — target standard + LLM dispatch. generatePqcFix owns masking,
  // rate-limiting, its own circuit breaker, and the cache-aside internally —
  // call it directly, never re-wrap it in a second breaker here.
  const targetStandard = resolveTargetStandard(algorithm, classicalRiskFlags);
  const candidateResult = await generatePqcFix(algorithm, language, keySize, snippet, projectId, targetStandard);

  if (!candidateResult || candidateResult.status !== 'ok' || !candidateResult.fixSnippet) {
    // LLM unavailable/rate-limited/degraded — honest fix_pending, no
    // fabricated field, auto-retried per REQ-FUNC-11.
    return { ...riskFields, targetStandard, fixStatus: 'fix_pending', fixSnippet: null };
  }

  // Stage 4 — the Double-Validation Gate (REQ-FUNC-14/15/16). This MUST run
  // on every candidate before it can ever be persisted as 'generated' —
  // including a candidate served from nvidiaLlmService's cache, since that
  // cache holds a *generated* candidate, not a *validated* one. This is a
  // hard invariant, not an optimization: no code path may set
  // fixStatus:'generated' without having executed both gate steps for THIS
  // finding.
  const gateResult = await validateCandidate(candidateResult.fixSnippet, algorithm, targetStandard);

  const fixValidation = {
    sastPassed: !!gateResult?.sastPassed,
    katPassed: !!gateResult?.katPassed,
    validatedAt: new Date(),
  };

  if (fixValidation.sastPassed && fixValidation.katPassed) {
    return {
      ...riskFields,
      targetStandard,
      fixValidation,
      fixStatus: 'generated',
      fixSnippet: candidateResult.fixSnippet,
    };
  }

  // Failed either gate step — retried by the identical repeatable sweep as
  // a rate-limited generation (REQ-FUNC-16), never a distinct terminal
  // status, and the unvalidated snippet is never persisted or surfaced.
  return {
    ...riskFields,
    targetStandard,
    fixValidation,
    fixStatus: 'fix_pending',
    fixSnippet: null,
  };
}

const worker = new Worker(
  'verification',
  async (job) => {
    const { contentHash, projectId } = job.data;

    try {
      const update = await processFinding(job);

      // Filter on { projectId, contentHash } together, matching the unique
      // index on Asset — contentHash alone is only unique WITHIN a project.
      await Asset.updateOne(
        { projectId, contentHash },
        { $set: { ...update, updatedAt: new Date() } }
      );
    } catch (err) {
      // Every HANDLED outcome above (false positive, low risk, degraded
      // LLM, failed gate) already returns a normal update object and gets
      // persisted — it never throws. What reaches this catch is a genuine
      // infrastructure error (Mongo unreachable, an unexpected exception
      // inside one of the risk engines, etc.). Rethrow so BullMQ's
      // configured attempts/backoff retries the job: swallowing it here
      // would silently drop a failed verification, and NOT rethrowing risks
      // the exact unhandled-rejection crash class this queue exists to
      // prevent.
      console.error(
        `[verificationQueue] job ${job.id} failed (contentHash=${contentHash}):`,
        err.message
      );
      throw err;
    }
  },
  {
    connection,
    concurrency: 10, // hard cap — do not raise without re-tuning the breakers/limiters it protects
  }
);

worker.on('failed', (job, err) => {
  console.error(
    `[verificationQueue] job ${job?.id} exhausted retries after ${job?.attemptsMade} attempts:`,
    err.message
  );
});

worker.on('error', (err) => {
  // Worker-level errors (e.g. lost Redis connection) — distinct from
  // per-job failures above.
  console.error('[verificationQueue] worker error:', err.message);
});

module.exports = { verificationQueue, worker };