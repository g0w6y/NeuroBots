import { useMemo, useState } from 'react';

// The full audit log, filterable. The Overview feed shows the newest 50 with no
// way to search; this is the same data with the whole window available, query
// filters, and CSV export for taking evidence out of the console.
//
// Every row here is a real gateway decision read from /admin/alerts. Nothing is
// synthesised, and the "showing N of M" count always names the true window size
// so a filter can never make the log look emptier than it is without saying so.

const DECISIONS = ['all', 'allow', 'observe', 'challenge', 'block'];

const DECISION_STYLES = {
  allow: 'text-risk-safe',
  observe: 'text-ink-muted',
  challenge: 'text-risk-caution',
  block: 'text-risk-danger'
};

function riskTextColor(score) {
  if (score > 60) return 'text-risk-danger';
  if (score > 30) return 'text-risk-caution';
  return 'text-risk-safe';
}

function toCsv(rows) {
  const header = [
    'timestamp', 'decision', 'risk', 'subject', 'ip', 'method', 'path',
    'status_code', 'latency_ms', 'signals', 'explanation'
  ];
  // RFC-4180 quoting: double every embedded quote and wrap. Explanations and
  // narratives contain commas as a matter of course, so naive join(',') here
  // produces a file that silently shifts every later column.
  const esc = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`;
  const lines = rows.map((a) =>
    [
      a.timestamp, a.decision, a.risk_score, a.subject, a.ip, a.method, a.path,
      a.status_code ?? '', a.latency_ms ?? '',
      (a.signals || []).map((s) => s.signal).join(' '),
      a.explanation
    ].map(esc).join(',')
  );
  return [header.join(','), ...lines].join('\n');
}

function download(filename, text) {
  const blob = new Blob([text], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  // Revoking frees the blob; without it the whole CSV stays resident for the
  // lifetime of the page, and this log can be thousands of rows.
  URL.revokeObjectURL(url);
}

function LogRow({ alert }) {
  const [open, setOpen] = useState(false);
  const hasDetail = Boolean(alert.narrative || alert.explanation || alert.signals?.length);

  return (
    <>
      <tr
        className={`border-b border-canvas-line hover:bg-canvas-raised/50 ${hasDetail ? 'cursor-pointer' : ''}`}
        onClick={() => hasDetail && setOpen((v) => !v)}
      >
        <td className="px-3 py-2 font-mono text-[11px] text-ink-faint">
          {new Date(alert.timestamp).toLocaleTimeString()}
        </td>
        <td className={`px-3 py-2 font-mono text-[11px] font-semibold uppercase ${DECISION_STYLES[alert.decision] || ''}`}>
          {alert.decision}
        </td>
        <td className={`px-3 py-2 text-right font-mono text-[11px] tabular-nums ${riskTextColor(alert.risk_score)}`}>
          {String(Math.round(alert.risk_score)).padStart(3, '0')}
        </td>
        <td className="max-w-[140px] truncate px-3 py-2 font-mono text-[11px] text-ink-muted">{alert.subject}</td>
        <td className="px-3 py-2 font-mono text-[11px] text-ink-faint">{alert.ip}</td>
        <td className="px-3 py-2 font-mono text-[11px] text-ink-muted">{alert.method}</td>
        <td className="max-w-[260px] truncate px-3 py-2 font-mono text-[11px] text-ink">{alert.path}</td>
        <td className="px-3 py-2 text-right font-mono text-[11px] tabular-nums text-ink-faint">
          {alert.status_code ?? '—'}
        </td>
        <td className="px-3 py-2 text-right font-mono text-[11px] tabular-nums text-ink-faint">
          {typeof alert.latency_ms === 'number' ? alert.latency_ms.toFixed(2) : '—'}
        </td>
        <td className="px-2 py-2 font-mono text-[11px] text-ink-faint">{hasDetail ? (open ? '▾' : '▸') : ''}</td>
      </tr>
      {open && hasDetail && (
        <tr className="border-b border-canvas-line bg-canvas/60">
          <td colSpan={10} className="px-4 py-3 font-mono text-[11px] leading-relaxed">
            {alert.narrative && <p className="mb-2 text-ink">{alert.narrative}</p>}
            {alert.signals?.map((s) => (
              <div key={s.signal} className="mb-1.5 border-l-2 border-canvas-line-strong pl-2">
                <div className="text-ink-muted">
                  <span className={DECISION_STYLES[alert.decision]}>{s.signal}</span>
                  {s.hard ? ' · confirmed' : ' · heuristic'}
                </div>
                <div className="text-ink-faint">{s.evidence}</div>
                <div className="text-ink-faint">{s.owaspFull || s.owasp} · {s.mitreFull || s.mitre}</div>
              </div>
            ))}
            {alert.explanation && <p className="mt-2 whitespace-pre-wrap text-ink-faint">{alert.explanation}</p>}
          </td>
        </tr>
      )}
    </>
  );
}

export default function LogsView({ alerts }) {
  const [query, setQuery] = useState('');
  const [decision, setDecision] = useState('all');
  const [minRisk, setMinRisk] = useState(0);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return alerts.filter((a) => {
      if (decision !== 'all' && a.decision !== decision) return false;
      if (a.risk_score < minRisk) return false;
      if (!q) return true;
      // Search across every field an operator would plausibly pivot on,
      // including signal names - "show me everything tagged bola_cross_user" is
      // the single most useful query on this page.
      return (
        a.subject?.toLowerCase().includes(q) ||
        a.path?.toLowerCase().includes(q) ||
        a.ip?.toLowerCase().includes(q) ||
        a.method?.toLowerCase().includes(q) ||
        a.decision?.toLowerCase().includes(q) ||
        (a.signals || []).some((s) => s.signal?.toLowerCase().includes(q)) ||
        a.explanation?.toLowerCase().includes(q)
      );
    });
  }, [alerts, query, decision, minRisk]);

  return (
    <div className="glass-panel flex h-full flex-col overflow-hidden rounded-lg">
      <div className="flex flex-wrap items-center gap-3 border-b border-canvas-line px-4 py-3">
        <h2 className="font-display text-sm font-semibold text-ink">Audit log</h2>

        <input
          type="search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="search subject, path, ip, signal…"
          className="min-w-[220px] flex-1 rounded border border-canvas-line bg-canvas-sunken px-3 py-1.5 font-mono text-[11px] text-ink placeholder:text-ink-faint/60 focus:border-accent focus:outline-none"
        />

        <div className="flex items-center gap-1">
          {DECISIONS.map((d) => (
            <button
              key={d}
              onClick={() => setDecision(d)}
              className={`rounded px-2 py-1 font-mono text-[10px] uppercase tracking-caps transition-colors ${
                decision === d
                  ? 'bg-accent/15 text-accent'
                  : 'text-ink-faint hover:bg-canvas-raised hover:text-ink-muted'
              }`}
            >
              {d}
            </button>
          ))}
        </div>

        <label className="flex items-center gap-2 font-mono text-[10px] uppercase tracking-caps text-ink-faint">
          risk ≥ {String(minRisk).padStart(3, '0')}
          <input
            type="range"
            min="0"
            max="100"
            step="5"
            value={minRisk}
            onChange={(e) => setMinRisk(Number(e.target.value))}
            className="w-24 accent-accent"
          />
        </label>

        <button
          onClick={() => download(`project0-log-${Date.now()}.csv`, toCsv(filtered))}
          disabled={filtered.length === 0}
          className="rounded border border-canvas-line px-2.5 py-1 font-mono text-[10px] uppercase tracking-caps text-ink-muted transition-colors hover:border-accent hover:text-accent disabled:cursor-not-allowed disabled:opacity-40"
        >
          export csv
        </button>

        <span className="font-mono text-[10px] text-ink-faint">
          {filtered.length === alerts.length
            ? `${alerts.length} entries`
            : `${filtered.length} of ${alerts.length}`}
        </span>
      </div>

      <div className="flex-1 overflow-auto">
        <table className="w-full border-collapse">
          <thead className="sticky top-0 z-10 bg-canvas-sunken">
            <tr className="border-b border-canvas-line text-left font-mono text-[10px] uppercase tracking-caps text-ink-faint">
              <th className="px-3 py-2 font-semibold">Time</th>
              <th className="px-3 py-2 font-semibold">Decision</th>
              <th className="px-3 py-2 text-right font-semibold">Risk</th>
              <th className="px-3 py-2 font-semibold">Subject</th>
              <th className="px-3 py-2 font-semibold">IP</th>
              <th className="px-3 py-2 font-semibold">Method</th>
              <th className="px-3 py-2 font-semibold">Path</th>
              <th className="px-3 py-2 text-right font-semibold">Status</th>
              <th className="px-3 py-2 text-right font-semibold">ms</th>
              <th className="px-2 py-2" />
            </tr>
          </thead>
          <tbody>
            {filtered.map((a) => (
              <LogRow key={a.id} alert={a} />
            ))}
          </tbody>
        </table>

        {filtered.length === 0 && (
          <div className="p-8 text-center font-mono text-xs text-ink-faint">
            {alerts.length === 0
              ? 'No requests logged yet — run the attack simulator to generate traffic.'
              : 'No entries match these filters.'}
          </div>
        )}
      </div>
    </div>
  );
}
