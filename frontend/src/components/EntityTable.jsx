import { useMemo, useState } from 'react';
import { BarChart, Bar, ResponsiveContainer } from 'recharts';

const STATUS_STYLES = {
  active: { rule: 'border-l-risk-safe', text: 'text-risk-safe' },
  flagged: { rule: 'border-l-risk-caution', text: 'text-risk-caution' },
  blocked: { rule: 'border-l-risk-danger', text: 'text-risk-danger' }
};

function riskTextColor(score) {
  if (score > 60) return 'text-risk-danger';
  if (score > 30) return 'text-risk-caution';
  return 'text-risk-safe';
}

function pad(score) {
  return String(Math.round(score)).padStart(3, '0');
}

export default function EntityTable({ entities }) {
  const [filter, setFilter] = useState('');

  const filtered = useMemo(() => {
    const f = filter.trim().toLowerCase();
    const rows = f ? entities.filter((e) => e.subject.toLowerCase().includes(f)) : entities;
    return [...rows].sort((a, b) => b.risk_score - a.risk_score);
  }, [entities, filter]);

  return (
    <div className="rounded-md border border-canvas-line bg-canvas-panel p-4">
      <div className="mb-3 flex items-center justify-between gap-3">
        <h3 className="font-display text-sm font-semibold text-ink">Entities by risk</h3>
        <input
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="filter subject"
          className="w-40 rounded border border-canvas-line bg-canvas px-2 py-1 font-mono text-xs text-ink placeholder:text-ink-faint focus:border-accent focus:outline-none"
        />
      </div>

      <div className="overflow-x-auto">
        <table className="w-full min-w-[560px] text-left font-mono text-xs">
          <thead>
            <tr className="border-b border-canvas-line text-[10px] uppercase tracking-wide text-ink-faint">
              <th className="py-2 pl-3 pr-3 font-semibold">Subject</th>
              <th className="py-2 pr-3 font-semibold">Requests</th>
              <th className="py-2 pr-3 font-semibold">Trend</th>
              <th className="py-2 pr-3 font-semibold">Risk</th>
              <th className="py-2 pr-3 font-semibold">Endpoints</th>
              <th className="py-2 pr-3 font-semibold">Status</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((e) => {
              const s = STATUS_STYLES[e.status] || STATUS_STYLES.active;
              return (
                <tr key={e.subject} className="border-b border-canvas-line/60 hover:bg-canvas-raised/60">
                  <td className={`border-l-[3px] ${s.rule} py-2 pl-3 pr-3 text-ink`}>{e.subject}</td>
                  <td className="py-2 pr-3 text-ink-muted">{e.request_count}</td>
                  <td className="w-20 py-2 pr-3">
                    <ResponsiveContainer width={64} height={20}>
                      <BarChart data={[{ v: e.request_count }, { v: e.request_count * 0.7 }, { v: e.request_count }]}>
                        <Bar dataKey="v" fill="#4fb3a4" radius={1} />
                      </BarChart>
                    </ResponsiveContainer>
                  </td>
                  <td className={`py-2 pr-3 font-semibold ${riskTextColor(e.risk_score)}`}>{pad(e.risk_score)}</td>
                  <td className="py-2 pr-3 text-ink-muted">{e.endpoints}</td>
                  <td className={`py-2 pr-3 font-medium uppercase ${s.text}`}>{e.status}</td>
                </tr>
              );
            })}
            {filtered.length === 0 && (
              <tr>
                <td colSpan={6} className="py-6 text-center text-ink-faint">
                  no entities match "{filter}"
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
