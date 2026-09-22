const mongoose = require('mongoose');
const Asset = require('../models/Asset');
const { verificationQueue } = require('../queues/verificationQueue');

const ASSET_LIST_FIELDS =
  'contentHash source filePath line column algorithm riskTag moscaScore ' +
  'fixStatus fixSnippet isLinked status resolvedAt createdAt updatedAt';

/**
 * dashboardController.js
 *
 * Every aggregation below filters strictly on { status: 'active' } —
 * resolved findings must never influence the dashboard's headline
 * numbers, or a project that has actually fixed its vulnerabilities
 * would still show them as outstanding risk.
 *
 * NOTE on the Quantum Risk Score: it's computed as the proportion of
 * active findings tagged 'Critical', not an average of stored moscaScore
 * values. Asset.js does persist a per-finding `moscaScore` now (populated
 * by the verification worker — see queues/verificationQueue.js), so a
 * future revision could blend that in; left as a critical-ratio score for
 * now since that's what the Dashboard's risk dial was designed against.
 */

async function getQuantumRiskScore(projectId) {
  const [result] = await Asset.aggregate([
    { $match: { projectId: new mongoose.Types.ObjectId(projectId), status: 'active' } },
    {
      $group: {
        _id: null,
        total: { $sum: 1 },
        critical: {
          $sum: { $cond: [{ $eq: ['$riskTag', 'Critical'] }, 1, 0] },
        },
      },
    },
  ]);

  if (!result || result.total === 0) {
    return { score: 0, totalActive: 0, criticalActive: 0 };
  }

  const score = Math.round((result.critical / result.total) * 100);

  return { score, totalActive: result.total, criticalActive: result.critical };
}

async function getVulnerableVsSafeCounts(projectId) {
  const rows = await Asset.aggregate([
    { $match: { projectId: new mongoose.Types.ObjectId(projectId), status: 'active' } },
    {
      $group: {
        _id: '$riskTag',
        count: { $sum: 1 },
      },
    },
  ]);

  const counts = { Critical: 0, Low: 0, Unverified: 0 };
  for (const row of rows) {
    if (row._id in counts) counts[row._id] = row.count;
  }

  return {
    vulnerable: counts.Critical,
    safe: counts.Low,
    unverified: counts.Unverified,
  };
}

async function getDashboardSummary(req, res) {
  const projectId = req.projectId; // resolved by authenticateProject

  try {
    const [riskScore, pieCounts] = await Promise.all([
      getQuantumRiskScore(projectId),
      getVulnerableVsSafeCounts(projectId),
    ]);

    return res.status(200).json({
      quantumRiskScore: riskScore,
      distribution: pieCounts,
    });
  } catch (err) {
    console.error('[dashboardController] aggregation failed:', err.message);
    return res.status(500).json({ error: 'failed to compute dashboard summary' });
  }
}

/**
 * GET /api/assets — the raw finding list. Dashboard.js only needs
 * aggregates (served by getDashboardSummary above), but CBOMGraph.js and
 * MigrationPlanner.js both need the actual per-finding documents
 * (contentHash, algorithm, riskTag, moscaScore, fixSnippet, isLinked,
 * etc.) to render the asset graph and migration timeline — neither of
 * which the aggregate summary endpoint can provide.
 */
async function listAssets(req, res) {
  const projectId = req.projectId; // resolved by authenticateProject
  const status = ['active', 'resolved'].includes(req.query.status)
    ? req.query.status
    : 'active';

  try {
    const assets = await Asset.find({ projectId, status })
      .select(ASSET_LIST_FIELDS)
      .sort({ moscaScore: -1, createdAt: -1 })
      .lean();

    return res.status(200).json({ assets });
  } catch (err) {
    console.error('[dashboardController] listAssets failed:', err.message);
    return res.status(500).json({ error: 'failed to list assets' });
  }
}

/**
 * POST /api/assets/:contentHash/fix — re-request a PQC fix for a finding
 * that's already been ingested (e.g. the first attempt landed in
 * fix_pending because the LLM was rate-limited or degraded). Rebuilds the
 * verification job entirely from what's already stored on the Asset
 * document — the original scan payload is never needed again, since
 * ingestController.js now persists `code`/`language`/`keySize` on ingest.
 */
async function regenerateFix(req, res) {
  const projectId = req.projectId; // resolved by authenticateProject
  const { contentHash } = req.params;

  let asset;
  try {
    asset = await Asset.findOne({ projectId, contentHash });
  } catch (err) {
    console.error('[dashboardController] regenerateFix lookup failed:', err.message);
    return res.status(500).json({ error: 'failed to look up finding' });
  }

  if (!asset) {
    return res.status(404).json({ error: 'finding not found for this project' });
  }

  try {
    await verificationQueue.add('verify', {
      contentHash: asset.contentHash,
      projectId,
      snippet: asset.code,
      algorithm: asset.algorithm,
      language: asset.language,
      keySize: asset.keySize,
    });
  } catch (err) {
    console.error(`[dashboardController] failed to re-enqueue fix for ${contentHash}:`, err.message);
    return res.status(502).json({ error: 'failed to enqueue fix request' });
  }

  return res.status(202).json({ contentHash, status: 'queued' });
}

module.exports = {
  getDashboardSummary,
  getQuantumRiskScore,
  getVulnerableVsSafeCounts,
  listAssets,
  regenerateFix,
};
