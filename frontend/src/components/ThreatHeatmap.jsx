import { useMemo, memo } from 'react';
import { PanelHeader } from './PanelHeader.jsx';

/**
 * Real-time animated SVG threat heatmap.
 * X-axis: time buckets (last 60 minutes, 1-min resolution)
 * Y-axis: unique endpoints observed in traffic
 * Cell colour: risk density per time×endpoint intersection
 */

const CELL_W = 12;
const CELL_H = 28;
const PAD_LEFT = 140;
const PAD_TOP = 24;
const PAD_BOTTOM = 40;

function riskToColor(intensity) {
  if (intensity <= 0) return 'rgba(30,30,34,0.6)';
  if (intensity <= 20) return 'rgba(74,225,118,0.25)';
  if (intensity <= 40) return 'rgba(74,225,118,0.55)';
  if (intensity <= 55) return 'rgba(255,185,95,0.50)';
  if (intensity <= 70) return 'rgba(255,185,95,0.80)';
  if (intensity <= 85) return 'rgba(255,180,171,0.70)';
  return 'rgba(255,180,171,1.0)';
}

function ThreatHeatmap({ alerts }) {
  const { matrix, endpoints, bucketLabels, maxRisk, stats } = useMemo(() => {
    if (!alerts || alerts.length === 0) {
      return { matrix: {}, endpoints: [], bucketLabels: [], maxRisk: 0, stats: {} };
    }

    const now = Date.now();
    const NUM_BUCKETS = 60;
    const BUCKET_MS = 60 * 1000;

    const epSet = new Set();
    const grid = {};

    alerts.forEach((a) => {
      const path = a.path || a.method_path || '';
      if (!path) return;
      const short = path.length > 28 ? path.slice(0, 27) + '…' : path;
      epSet.add(short);

      const ts = a.ts || new Date(a.timestamp).getTime();
      const age = now - ts;
      const bucketIdx = Math.min(NUM_BUCKETS - 1, Math.max(0, NUM_BUCKETS - 1 - Math.floor(age / BUCKET_MS)));
      const key = `${short}|${bucketIdx}`;

      if (!grid[key]) grid[key] = { sum: 0, count: 0, blocked: 0 };
      grid[key].sum += a.risk_score || 0;
      grid[key].count += 1;
      if (a.decision === 'block') grid[key].blocked += 1;
    });

    const eps = [...epSet].sort();

    // Build bucket time labels
    const labels = [];
    for (let i = 0; i < NUM_BUCKETS; i++) {
      const minsAgo = NUM_BUCKETS - 1 - i;
      if (minsAgo % 10 === 0) {
        labels.push({ idx: i, label: minsAgo === 0 ? 'now' : `-${minsAgo}m` });
      }
    }

    // Find max for normalization
    let max = 0;
    Object.values(grid).forEach((cell) => {
      const avg = cell.sum / Math.max(cell.count, 1);
      if (avg > max) max = avg;
    });

    // Stats
    const totalCells = eps.length * NUM_BUCKETS;
    const activeCells = Object.keys(grid).length;
    const hotCells = Object.values(grid).filter(
      (c) => c.sum / Math.max(c.count, 1) > 60
    ).length;

    return {
      matrix: grid,
      endpoints: eps,
      bucketLabels: labels,
      maxRisk: max,
      stats: { totalCells, activeCells, hotCells, endpoints: eps.length },
    };
  }, [alerts]);

  const width = PAD_LEFT + 60 * CELL_W + 20;
  const height = PAD_TOP + endpoints.length * CELL_H + PAD_BOTTOM;

  if (endpoints.length === 0) {
    return (
      <div className="glass-panel rounded-lg p-6 text-center">
        <span className="material-symbols-outlined text-3xl text-ink-faint mb-2">thermostat</span>
        <p className="font-mono text-xs text-ink-faint">No threat data — run the attack simulator to populate the heatmap.</p>
      </div>
    );
  }

  return (
    <div className="glass-panel overflow-hidden rounded-lg">
      <div className="flex items-center justify-between border-b border-canvas-line px-4 py-3">
        <div className="flex items-center gap-2">
          <span className="material-symbols-outlined text-accent text-[18px]">thermostat</span>
          <h3 className="font-display text-sm font-bold uppercase tracking-wider text-accent">
            Threat Heatmap
          </h3>
        </div>
        <div className="flex items-center gap-4 font-mono text-[10px] text-ink-faint">
          <span>{stats.endpoints} endpoints</span>
          <span>{stats.activeCells} active cells</span>
          <span className="text-risk-danger">{stats.hotCells} hot zones</span>
        </div>
      </div>

      <div className="overflow-x-auto p-4">
        <svg
          width={width}
          height={Math.max(height, 140)}
          viewBox={`0 0 ${width} ${Math.max(height, 140)}`}
          className="block"
        >
          {/* Y-axis: endpoint labels */}
          {endpoints.map((ep, row) => (
            <text
              key={ep}
              x={PAD_LEFT - 8}
              y={PAD_TOP + row * CELL_H + CELL_H / 2 + 4}
              textAnchor="end"
              fill="#8c909f"
              fontSize="10"
              fontFamily="'JetBrains Mono', monospace"
            >
              {ep}
            </text>
          ))}

          {/* X-axis: time labels */}
          {bucketLabels.map((bl) => (
            <text
              key={bl.idx}
              x={PAD_LEFT + bl.idx * CELL_W + CELL_W / 2}
              y={PAD_TOP + endpoints.length * CELL_H + 18}
              textAnchor="middle"
              fill="#8c909f"
              fontSize="9"
              fontFamily="'JetBrains Mono', monospace"
            >
              {bl.label}
            </text>
          ))}

          {/* Heatmap cells */}
          {endpoints.map((ep, row) =>
            Array.from({ length: 60 }, (_, col) => {
              const key = `${ep}|${col}`;
              const cell = matrix[key];
              const intensity = cell ? cell.sum / Math.max(cell.count, 1) : 0;
              return (
                <rect
                  key={key}
                  x={PAD_LEFT + col * CELL_W}
                  y={PAD_TOP + row * CELL_H}
                  width={CELL_W - 1}
                  height={CELL_H - 2}
                  rx={2}
                  fill={riskToColor(intensity)}
                  className="transition-all duration-300"
                >
                  {cell && (
                    <title>{`${ep} · ${60 - col}m ago\nAvg risk: ${Math.round(intensity)}\nEvents: ${cell.count}\nBlocked: ${cell.blocked}`}</title>
                  )}
                </rect>
              );
            })
          )}

          {/* Color legend */}
          {[
            { label: '0', color: 'rgba(30,30,34,0.6)' },
            { label: '20', color: 'rgba(74,225,118,0.35)' },
            { label: '40', color: 'rgba(255,185,95,0.50)' },
            { label: '60', color: 'rgba(255,185,95,0.80)' },
            { label: '80', color: 'rgba(255,180,171,0.70)' },
            { label: '100', color: 'rgba(255,180,171,1.0)' },
          ].map((item, i) => (
            <g key={item.label}>
              <rect
                x={PAD_LEFT + i * 40}
                y={PAD_TOP + endpoints.length * CELL_H + 28}
                width={30}
                height={8}
                rx={2}
                fill={item.color}
              />
              <text
                x={PAD_LEFT + i * 40 + 15}
                y={PAD_TOP + endpoints.length * CELL_H + 46}
                textAnchor="middle"
                fill="#6b655c"
                fontSize="8"
                fontFamily="'JetBrains Mono', monospace"
              >
                {item.label}
              </text>
            </g>
          ))}
        </svg>
      </div>
    </div>
  );
}

export default memo(ThreatHeatmap);
