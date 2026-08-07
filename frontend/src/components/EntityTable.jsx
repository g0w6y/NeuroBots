import { memo, useMemo, useState } from 'react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';

const STATUS_STYLES = {
  active: { rule: 'border-l-risk-safe', text: 'text-risk-safe' },
  flagged: { rule: 'border-l-risk-caution', text: 'text-risk-caution' },
  blocked: { rule: 'border-l-risk-danger', text: 'text-risk-danger' }
};

const RISK_FILL = { safe: '#5fa86f', caution: '#c98a3c', danger: '#c85c4a' };

const tooltipStyle = {
  background: '#1a1917',
  border: '1px solid #2c2925',
  borderRadius: 4,
  fontFamily: "'IBM Plex Mono', monospace",
  fontSize: 12,
  color: '#ede9e4'
};

function riskBand(score) {
  if (score > 60) return 'danger';
  if (score > 30) return 'caution';
  return 'safe';
}

function riskTextColor(score) {
  return `text-risk-${riskBand(score)}`;
}

function pad(score) {
  return String(Math.round(score)).padStart(3, '0');
}

function EntityTable({ entities }) {
  const [filter, setFilter] = useState('');

  const filtered = useMemo(() => {
    const f = filter.trim().toLowerCase();
    const rows = f ? entities.filter((e) => e.subject.toLowerCase().includes(f)) : entities;
    return [...rows].sort((a, b) => b.risk_score - a.risk_score);
  }, [entities, filter]);

  // Requests per entity, top 8 by risk. This replaces a per-row three-bar
  // "trend" sparkline whose middle point was literally `request_count * 0.7` —
  // an invented dip, identical in shape on every row, with no time dimension
  // behind it. Fabricated data has no place in a security console; it also
  // mounted one ResponsiveContainer per row, so 50 entities meant 50 chart
  // instances re-measuring every 2 seconds.
  const chartData = useMemo(
    () => filtered.slice(0, 8).map((e) => ({
      subject: e.subject.length > 16 ? `${e.subject.slice(0, 15)}…` : e.subject,
      requests: e.request_count,
      band: riskBand(e.risk_score)
    })),
    [filtered]
  );

  return (
    <div className="glass-panel rounded-lg p-4">
      <div className="mb-3 flex items-center justify-between gap-3">
        <h3 className="font-display text-sm font-semibold text-ink">Entities by risk</h3>
        <label className="sr-only" htmlFor="entity-filter">Filter entities by subject</label>
        <input
          id="entity-filter"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="filter subject"
          aria-label="Filter entities by subject"
          className="w-40 rounded border border-canvas-line bg-canvas px-2 py-2 font-mono text-xs text-ink placeholder:text-ink-faint focus:border-accent focus:outline-none"
        />
      </div>

      {chartData.length > 0 && (
        <div className="mb-4">
          <div className="mb-1 font-mono text-[10px] uppercase tracking-wide text-ink-faint">
            Requests per entity — top {chartData.length} by risk
          </div>
          <ResponsiveContainer width="100%" height={Math.max(80, chartData.length * 22)}>
            <BarChart data={chartData} layout="vertical" margin={{ left: 4, right: 8, top: 4, bottom: 4 }}>
              <XAxis type="number" stroke="#6b655c" fontSize={10} tickLine={false} axisLine={false} />
              <YAxis
                type="category"
                dataKey="subject"
                stroke="#6b655c"
                fontSize={10}
                tickLine={false}
                axisLine={false}
                width={96}
              />
              <Tooltip contentStyle={tooltipStyle} cursor={{ fill: '#211f1c' }} />
              <Bar dataKey="requests" radius={2}>
                {chartData.map((d) => (
                  <Cell key={d.subject} fill={RISK_FILL[d.band]} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}

      <div className="overflow-x-auto">
        <table className="w-full min-w-[640px] text-left font-mono text-xs">
          <thead>
            <tr className="border-b border-canvas-line text-[10px] uppercase tracking-wide text-ink-faint">
              <th className="py-2 pl-3 pr-3 font-semibold">Subject</th>
              <th className="py-2 pr-3 font-semibold">Roles</th>
              <th className="py-2 pr-3 font-semibold">Requests</th>
              <th className="py-2 pr-3 font-semibold">Endpoints</th>
              <th className="py-2 pr-3 font-semibold">Objects</th>
              <th className="py-2 pr-3 font-semibold">Risk</th>
              <th className="py-2 pr-3 font-semibold">Status</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((e) => {
              const s = STATUS_STYLES[e.status] || STATUS_STYLES.active;
              return (
                <tr key={e.subject} className="border-b border-canvas-line/60 hover:bg-canvas-raised/60">
                  <td className={`border-l-[3px] ${s.rule} py-2 pl-3 pr-3 text-ink`}>{e.subject}</td>
                  <td className="py-2 pr-3 text-ink-faint">{e.roles?.length ? e.roles.join(', ') : '—'}</td>
                  <td className="py-2 pr-3 text-ink-muted">{e.request_count}</td>
                  <td className="py-2 pr-3 text-ink-muted">{e.endpoints}</td>
                  <td className="py-2 pr-3 text-ink-muted">{e.objects}</td>
                  <td className={`py-2 pr-3 font-semibold ${riskTextColor(e.risk_score)}`}>{pad(e.risk_score)}</td>
                  <td className={`py-2 pr-3 font-medium uppercase ${s.text}`}>{e.status}</td>
                </tr>
              );
            })}
            {filtered.length === 0 && (
              <tr>
                <td colSpan={7} className="py-6 text-center text-ink-faint">
                  {entities.length === 0 ? 'no entities seen yet' : `no entities match "${filter}"`}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default memo(EntityTable);
