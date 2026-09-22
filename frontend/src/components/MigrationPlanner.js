// frontend/src/components/MigrationPlanner.js
//
// A Mosca-ordered remediation timeline. The crucial UI contract: a finding
// that is genuinely still being generated (fixStatus: 'fix_pending') must
// show an honest "queued" badge — never a blank code block that reads as a
// bug or a silently-dropped fix.

import React, { useEffect, useMemo, useState } from 'react';
import { fetchAssets } from '../services/api';

const RISK_ORDER = { Critical: 0, Unverified: 1, Low: 2 };

export default function MigrationPlanner() {
  const [assets, setAssets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    let cancelled = false;
    fetchAssets({ status: 'active' })
      .then((data) => {
        if (cancelled) return;
        setAssets(Array.isArray(data) ? data : data.assets || []);
      })
      .catch((err) => {
        if (!cancelled) setError(err);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  // Highest urgency first: Critical before Unverified before Low, then by
  // Mosca's raw D+T score within the same tier.
  const ordered = useMemo(() => {
    return [...assets].sort((a, b) => {
      const riskDiff = (RISK_ORDER[a.riskTag] ?? 3) - (RISK_ORDER[b.riskTag] ?? 3);
      if (riskDiff !== 0) return riskDiff;
      return (b.moscaScore ?? 0) - (a.moscaScore ?? 0);
    });
  }, [assets]);

  return (
    <div className="glass-panel migration-planner">
      <h3>Migration Planner</h3>
      <p className="muted">Prioritized by Mosca's Algorithm — D + T &gt; Q.</p>

      {loading && <p className="muted">Loading migration timeline…</p>}
      {error && <p className="error-text">Could not load findings.</p>}

      {!loading && !error && (
        <ol className="planner-timeline">
          {ordered.map((asset) => (
            <li
              key={asset.contentHash}
              className={`planner-item risk-${(asset.riskTag || 'unverified').toLowerCase()}`}
            >
              <div className="planner-item-head">
                <span className={`badge badge-${(asset.riskTag || 'unverified').toLowerCase()}`}>
                  {asset.riskTag || 'Unverified'}
                </span>
                <span className="planner-location">
                  {asset.filePath ? `${asset.filePath}:${asset.line}` : 'Network endpoint'}
                </span>
              </div>
              <div className="planner-algo">{asset.algorithm}</div>
              <FixDisplay asset={asset} />
            </li>
          ))}

          {ordered.length === 0 && <p className="muted">No active findings — nothing queued for migration.</p>}
        </ol>
      )}
    </div>
  );
}

function FixDisplay({ asset }) {
  if (asset.fixStatus === 'fix_pending') {
    return <span className="badge badge-pending">Generation Delayed — Queued</span>;
  }
  if (asset.fixStatus === 'generated' && asset.fixSnippet) {
    return (
      <pre className="fix-snippet">
        <code>{asset.fixSnippet}</code>
      </pre>
    );
  }
  return <span className="badge badge-muted">Awaiting Analysis</span>;
}
