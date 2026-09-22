// frontend/src/components/Dashboard.js
//
// Headline view: the Quantum Risk Score dial and the Vulnerable-vs-Safe
// split. Both are computed strictly over status: 'active' assets — resolved
// findings are historical evidence for the Migration Planner's audit trail,
// not part of the live risk picture, so they are excluded here on purpose,
// both via the server-side filter and a defensive client-side re-filter.

import React, { useEffect, useMemo, useState } from 'react';
import { fetchAssets } from '../services/api';

export default function Dashboard() {
  const [assets, setAssets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    let cancelled = false;
    fetchAssets({ status: 'active' })
      .then((data) => {
        if (cancelled) return;
        const list = Array.isArray(data) ? data : data.assets || [];
        setAssets(list);
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

  // Defensive re-filter: never trust upstream filtering alone. A resolved
  // finding must never influence the live dial or pie chart.
  const active = useMemo(() => assets.filter((a) => a.status === 'active'), [assets]);

  const critical = useMemo(() => active.filter((a) => a.riskTag === 'Critical'), [active]);
  const safe = useMemo(() => active.filter((a) => a.riskTag === 'Low'), [active]);
  const vulnerable = active.length - safe.length; // Critical + Unverified, pending clearance

  const riskScore = active.length === 0 ? 0 : Math.round((critical.length / active.length) * 100);

  if (loading) {
    return (
      <div className="glass-panel dashboard">
        <p className="muted">Loading quantum risk posture…</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="glass-panel dashboard">
        <p className="error-text">Could not load the dashboard. Check the gateway connection and try again.</p>
      </div>
    );
  }

  return (
    <div className="dashboard-grid">
      <div className="glass-panel dashboard-card">
        <h3>Quantum Risk Score</h3>
        <p className="muted">Share of active findings tagged Critical by Mosca's Algorithm.</p>
        <RiskDial score={riskScore} />
      </div>

      <div className="glass-panel dashboard-card">
        <h3>Vulnerable vs. Safe</h3>
        <p className="muted">Active assets only — resolved findings are excluded from this view.</p>
        <SplitPie vulnerable={vulnerable} safe={safe.length} />
      </div>
    </div>
  );
}

function RiskDial({ score }) {
  const clamped = Math.max(0, Math.min(100, score));
  const color = clamped >= 70 ? 'var(--crimson)' : clamped >= 40 ? 'var(--amber)' : 'var(--emerald)';
  const ringStyle = {
    background: `conic-gradient(${color} ${clamped * 3.6}deg, rgba(255,255,255,0.08) 0deg)`,
  };

  return (
    <div className="risk-dial-wrap">
      <div className="risk-dial-ring" style={ringStyle}>
        <div className="risk-dial-inner">
          <span className="risk-dial-value" style={{ color }}>
            {clamped}
          </span>
          <span className="risk-dial-label">/ 100</span>
        </div>
      </div>
    </div>
  );
}

function SplitPie({ vulnerable, safe }) {
  const total = vulnerable + safe;
  const vulnPct = total === 0 ? 0 : (vulnerable / total) * 100;
  const pieStyle = {
    background:
      total === 0
        ? 'rgba(255,255,255,0.08)'
        : `conic-gradient(var(--crimson) 0% ${vulnPct}%, var(--emerald) ${vulnPct}% 100%)`,
  };

  return (
    <div className="split-pie-wrap">
      <div className="split-pie" style={pieStyle} />
      <ul className="pie-legend">
        <li>
          <span className="legend-dot" style={{ background: 'var(--crimson)' }} />
          Vulnerable — {vulnerable}
        </li>
        <li>
          <span className="legend-dot" style={{ background: 'var(--emerald)' }} />
          Safe — {safe}
        </li>
      </ul>
    </div>
  );
}
