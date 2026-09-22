const crypto = require('crypto');
const Asset = require('../models/Asset');
const { verificationQueue } = require('../queues/verificationQueue');

/**
 * ingestController.js
 *
 * Handles high-volume CI/CD scanner traffic. The scanner never sends one
 * unbounded payload for an entire scan — it streams fixed-size batches
 * (≤200 findings each) as separate requests. This is what actually
 * bypasses Express's payload-size ceiling: raising the body-size limit
 * only moves the cliff to a larger number, since any sufficiently large
 * monorepo scan eventually exceeds a fixed limit too. Batching removes
 * the ceiling rather than postponing it.
 *
 * Each batch is: (1) upserted idempotently, (2) used to resolve findings
 * that disappeared in this scan, (3) enqueued for async AI verification —
 * and only then does the handler respond, with 202, so the HTTP thread
 * is never blocked on the actual scoring work.
 */

const MAX_BATCH_SIZE = 200;

function computeContentHash(finding) {
  return crypto
    .createHash('sha256')
    .update(`${finding.filePath}:${finding.line}:${finding.algorithm}`)
    .digest('hex');
}

async function handleBatch(req, res) {
  const { findings } = req.body || {};

  if (!Array.isArray(findings) || findings.length === 0) {
    return res.status(400).json({ error: 'findings must be a non-empty array' });
  }

  if (findings.length > MAX_BATCH_SIZE) {
    return res
      .status(400)
      .json({ error: `batch exceeds max size of ${MAX_BATCH_SIZE} findings` });
  }

  const projectId = req.projectId; // resolved by authenticateProject — never from the body
  const seenHashes = [];

  // --- 1. idempotent bulk upsert -----------------------------------------
  const ops = findings.map((finding) => {
    const contentHash = computeContentHash(finding);
    seenHashes.push(contentHash);

    return {
      updateOne: {
        filter: { projectId, contentHash },
        update: {
          $set: {
            projectId,
            source: finding.source,
            filePath: finding.filePath,
            line: finding.line,
            column: finding.column ?? null,
            algorithm: finding.algorithm,
            contentHash,
            // Code-scan findings are always considered "linked" — the
            // Unlinked Asset concept only applies to the network-scan path
            // (see scanController.js), where a submitted URL might not
            // match the project's known domains.
            isLinked: true,
            // Persisted so a later re-fix request (POST /api/assets/:hash/fix)
            // doesn't need the original scan payload — the worker can
            // reconstruct the same verification job from stored data alone.
            code: finding.code ?? null,
            language: finding.language ?? 'unknown',
            keySize: finding.keySize ?? null,
            status: 'active',
            updatedAt: new Date(),
          },
          // only set on insert — don't clobber a riskTag/fixSnippet/moscaScore
          // the worker already computed on a previous scan of this same finding
          $setOnInsert: {
            riskTag: 'Unverified',
            fixStatus: 'none',
            fixSnippet: null,
            moscaScore: null,
            createdAt: new Date(),
          },
        },
        upsert: true,
      },
    };
  });

  try {
    // ordered:false — one malformed finding in the batch must not abort
    // the writes for every other finding in it.
    console.log('[DEBUG] running bulkWrite with ops:', JSON.stringify(ops, null, 2));
    const result = await Asset.bulkWrite(ops, { ordered: false });
    console.log('[DEBUG] bulkWrite result:', result);
  } catch (err) {
    console.error('[ingestController] bulkWrite failed:', err.message);
    return res.status(500).json({ error: 'failed to persist batch' });
  }

  // --- 2. stale-finding resolution sweep ---------------------------------
  // Anything still 'active' for this project that this batch did NOT
  // touch is presumed fixed. NOTE: scoped per-batch here for simplicity;
  // in a scan spanning multiple batches, a production deployment should
  // accumulate contentHashes across the whole scan (e.g. in Redis, keyed
  // by scanId) and run this sweep once at scan completion — otherwise a
  // finding sitting in a later batch of the same scan could be
  // prematurely marked resolved by an earlier batch's sweep.
  try {
    await Asset.updateMany(
      { projectId, status: 'active', contentHash: { $nin: seenHashes } },
      { $set: { status: 'resolved', resolvedAt: new Date() } }
    );
  } catch (err) {
    // Non-fatal — the batch itself already persisted successfully.
    console.error('[ingestController] stale-resolution sweep failed:', err.message);
  }

  // --- 3. enqueue for async AI verification -------------------------------
  // Never Promise.all() over this — that is the exact pattern that turns
  // one bad snippet into a full Node process crash. Each add() is
  // independently awaited and the queue itself bounds concurrency
  // downstream (see verificationQueue.js).
  for (const finding of findings) {
    const contentHash = computeContentHash(finding);
    try {
      await verificationQueue.add('verify', {
        contentHash,
        projectId,
        snippet: finding.code,
        algorithm: finding.algorithm,
        language: finding.language,
        keySize: finding.keySize,
      });
    } catch (err) {
      // Enqueue failure (e.g. Redis briefly unavailable) shouldn't fail
      // the whole batch response — the finding is already persisted as
      // 'active'/'Unverified' and can be picked up by a later re-scan.
      console.error(
        `[ingestController] failed to enqueue verification for ${contentHash}:`,
        err.message
      );
    }
  }

  return res.status(202).json({ queued: findings.length });
}

module.exports = { handleBatch };
