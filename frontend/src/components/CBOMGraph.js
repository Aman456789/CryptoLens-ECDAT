// frontend/src/components/CBOMGraph.js
//
// Node-and-edge visualization tracing a weak algorithm from its source-code
// location (Semgrep) to a live network endpoint (Nmap), when the platform
// has actually verified the two are related.
//
// Crucial edge case: any asset with isLinked === false is a mismatch
// between the scanned source and the submitted network URL (see the
// "Unlinked Asset" safeguard). It is rendered as its own disconnected
// island — never force-merged into the main cluster and never dropped.

import React, { useEffect, useMemo, useState } from 'react';
import { fetchAssets } from '../services/api';

const CANVAS_W = 900;
const CANVAS_H = 480;
const HUB = { x: CANVAS_W / 2, y: 210 };

const RISK_COLOR = {
  Critical: 'var(--crimson)',
  Unverified: 'var(--amber)',
  Low: 'var(--emerald)',
};

export default function CBOMGraph({ assets: assetsProp }) {
  const [assets, setAssets] = useState(assetsProp || []);
  const [loading, setLoading] = useState(!assetsProp);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (assetsProp) return undefined;
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
  }, [assetsProp]);

  const { codeNodes, networkNodes, islands } = useMemo(() => layoutGraph(assets), [assets]);

  return (
    <div className="glass-panel cbom-graph">
      <h3>Cryptographic Asset Graph</h3>
      <p className="muted">
        Linked findings trace source code to the network endpoint they expose. Unlinked findings are
        shown as disconnected islands — never guessed into a false chain.
      </p>

      {loading && <p className="muted">Loading graph…</p>}
      {error && <p className="error-text">Could not load the asset graph.</p>}

      {!loading && !error && (
        <svg viewBox={`0 0 ${CANVAS_W} ${CANVAS_H}`} className="graph-canvas" role="img" aria-label="Cryptographic asset graph">
          {/* hub */}
          <circle cx={HUB.x} cy={HUB.y} r={16} className="hub-node" />
          <text x={HUB.x} y={HUB.y + 34} textAnchor="middle" className="graph-label hub-label">
            Project
          </text>

          {/* linked cluster: code findings -> hub -> network findings */}
          {codeNodes.map((n) => (
            <g key={n.id}>
              <line x1={n.x} y1={n.y} x2={HUB.x} y2={HUB.y} className="graph-edge" />
              <circle cx={n.x} cy={n.y} r={8} fill={RISK_COLOR[n.riskTag] || RISK_COLOR.Unverified} />
              <text x={n.x} y={n.y - 12} textAnchor="middle" className="graph-label">
                {n.algorithm}
              </text>
            </g>
          ))}
          {networkNodes.map((n) => (
            <g key={n.id}>
              <line x1={HUB.x} y1={HUB.y} x2={n.x} y2={n.y} className="graph-edge" />
              <circle cx={n.x} cy={n.y} r={8} fill={RISK_COLOR[n.riskTag] || RISK_COLOR.Unverified} />
              <text x={n.x} y={n.y - 12} textAnchor="middle" className="graph-label">
                {n.algorithm}
              </text>
            </g>
          ))}

          {/* disconnected islands — deliberately no edge to the hub */}
          {islands.map((island) => (
            <g key={island.id}>
              <rect
                x={island.x - 70}
                y={island.y - 46}
                width={140}
                height={92}
                rx={12}
                className="island-boundary"
              />
              <text x={island.x} y={island.y - 54} textAnchor="middle" className="graph-label island-title">
                Unlinked Asset
              </text>
              {island.nodes.map((n, i) => (
                <g key={n.id}>
                  <circle
                    cx={island.x - 30 + i * 30}
                    cy={island.y}
                    r={7}
                    fill={RISK_COLOR[n.riskTag] || RISK_COLOR.Unverified}
                  />
                  <text x={island.x - 30 + i * 30} y={island.y + 24} textAnchor="middle" className="graph-label small">
                    {n.algorithm}
                  </text>
                </g>
              ))}
            </g>
          ))}
        </svg>
      )}

      <Legend />
    </div>
  );
}

function Legend() {
  return (
    <ul className="graph-legend">
      <li>
        <span className="legend-dot" style={{ background: 'var(--crimson)' }} /> Critical
      </li>
      <li>
        <span className="legend-dot" style={{ background: 'var(--amber)' }} /> Unverified
      </li>
      <li>
        <span className="legend-dot" style={{ background: 'var(--emerald)' }} /> Low
      </li>
    </ul>
  );
}

/**
 * Splits assets into the linked cluster (code findings arced to the left of
 * the hub, network findings arced to the right) and unlinked islands
 * (grouped in small clusters of up to 3, positioned outside the main
 * cluster with no connecting edge).
 */
function layoutGraph(assets) {
  const linked = assets.filter((a) => a.isLinked !== false);
  const unlinked = assets.filter((a) => a.isLinked === false);

  const code = linked.filter((a) => a.source === 'semgrep');
  const network = linked.filter((a) => a.source === 'nmap');

  const codeNodes = arcPositions(code, HUB.x - 260, HUB.y, 160, -70, 70);
  const networkNodes = arcPositions(network, HUB.x + 260, HUB.y, 160, 110, 250);

  const islandGroups = chunk(unlinked, 3);
  const islands = islandGroups.map((group, idx) => ({
    id: `island-${idx}`,
    x: 120 + idx * 180,
    y: CANVAS_H - 70,
    nodes: group,
  }));

  return { codeNodes, networkNodes, islands };
}

function arcPositions(items, cx, cy, radius, angleStartDeg, angleEndDeg) {
  if (items.length === 0) return [];
  const step = items.length === 1 ? 0 : (angleEndDeg - angleStartDeg) / (items.length - 1);
  return items.map((item, i) => {
    const angle = ((angleStartDeg + step * i) * Math.PI) / 180;
    return {
      ...item,
      id: item.contentHash || `${item.algorithm}-${i}`,
      x: cx + radius * Math.cos(angle),
      y: cy + radius * Math.sin(angle),
    };
  });
}

function chunk(arr, size) {
  const out = [];
  for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size));
  return out;
}
