import { getExecutiveReport } from '../api/gateway.js';
import { useResource } from '../hooks/useResource.js';
import { Icon, PanelHeader } from './PanelHeader.jsx';

// Executive Report: backend/executive_report.py's deterministic summary,
// rendered here instead of only being reachable via curl. Deliberately a
// template over already-decided facts, not a live LLM call - the narrative
// text below is generated the same way the rest of this console treats any
// verdict: computed once by the gateway, never invented in the browser.

function Stat({ label, value, tone = 'default' }) {
  const toneText = { default: 'text-ink', danger: 'text-risk-danger', caution: 'text-risk-caution', safe: 'text-risk-safe' }[tone];
  return (
    <div className="rounded-lg border border-canvas-line bg-canvas-raised/60 px-4 py-3">
      <div className={`font-display text-2xl font-bold tabular-nums ${toneText}`}>{value}</div>
      <div className="label-caps mt-1 text-ink-faint">{label}</div>
    </div>
  );
}

function BreakdownList({ title, counts, icon }) {
  const entries = Object.entries(counts || {}).sort((a, b) => b[1] - a[1]);
  const max = entries.length ? entries[0][1] : 0;
  return (
    <div className="glass-panel rounded-lg">
      <PanelHeader icon={icon}>{title}</PanelHeader>
      <div className="space-y-2 p-4">
        {entries.length === 0 ? (
          <p className="font-mono text-xs text-ink-faint">No signals recorded in this period.</p>
        ) : (
          entries.map(([key, count]) => (
            <div key={key} className="flex items-center gap-3">
              <span className="w-20 shrink-0 font-mono text-[11px] text-ink-muted">{key}</span>
              <div className="h-2 flex-1 rounded bg-canvas-line/60">
                <div
                  className="h-2 rounded bg-accent/70"
                  style={{ width: `${max ? Math.max(6, (count / max) * 100) : 0}%` }}
                />
              </div>
              <span className="w-8 shrink-0 text-right font-mono text-[11px] tabular-nums text-ink-faint">{count}</span>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

function EntityTable({ title, icon, rows, columns }) {
  return (
    <div className="glass-panel rounded-lg">
      <PanelHeader icon={icon}>{title}</PanelHeader>
      {rows.length === 0 ? (
        <p className="p-4 font-mono text-xs text-ink-faint">Nothing to show for this period.</p>
      ) : (
        <table className="w-full font-mono text-[11px]">
          <thead>
            <tr className="border-b border-white/5 text-ink-faint">
              {columns.map((c) => (
                <th key={c.key} className="px-4 py-2 text-left label-caps font-normal">
                  {c.label}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((row, i) => (
              <tr key={i} className="border-b border-white/5 last:border-0">
                {columns.map((c) => (
                  <td key={c.key} className="px-4 py-2 text-ink-muted">
                    {row[c.key]}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

export default function ExecutiveReport() {
  const { data: report, state, error, refresh } = useResource(getExecutiveReport, { auto: false });

  if (state === 'idle') {
    return (
      <div className="glass-panel flex flex-col items-center gap-3 rounded-lg p-10 text-center">
        <Icon name="summarize" className="text-3xl text-ink-faint" />
        <p className="font-mono text-xs text-ink-faint">
          Generated on demand from real audit data. Nothing is pre-computed until you ask for it.
        </p>
        <button
          onClick={refresh}
          className="mt-2 rounded border border-accent/50 bg-accent/10 px-4 py-2 font-mono text-[11px] uppercase tracking-caps text-accent hover:bg-accent/20"
        >
          Generate report
        </button>
      </div>
    );
  }

  if (state === 'loading') {
    return <div className="glass-panel rounded-lg p-8 text-center font-mono text-xs text-ink-faint">Generating report…</div>;
  }

  if (state === 'error' || !report) {
    return (
      <div className="glass-panel rounded-lg p-8 text-center font-mono text-xs">
        <p className="text-risk-danger">Could not generate the report.</p>
        <p className="mt-2 text-ink-faint">{error}</p>
        <button
          onClick={refresh}
          className="mt-4 rounded border border-canvas-line px-3 py-1 font-mono text-[10px] uppercase tracking-caps text-ink-muted hover:border-accent hover:text-accent"
        >
          retry
        </button>
      </div>
    );
  }

  const { summary, period_requests_reviewed, owasp_breakdown, mitre_breakdown, top_risky_entities, most_blocked_entities, autonomous_mitigation_events, narrative, generated_at } = report;

  return (
    <div className="space-y-4">
      <div className="glass-panel rounded-lg">
        <PanelHeader
          icon="summarize"
          right={
            <button
              onClick={refresh}
              className="rounded border border-canvas-line px-2.5 py-1 font-mono text-[10px] uppercase tracking-caps text-ink-faint hover:border-accent hover:text-accent"
            >
              regenerate
            </button>
          }
        >
          Executive Summary · generated {new Date(generated_at).toLocaleString()}
        </PanelHeader>
        <p className="p-4 font-mono text-[13px] leading-relaxed text-ink">{narrative}</p>
      </div>

      <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
        <Stat label="Requests Reviewed" value={period_requests_reviewed} />
        <Stat label="Blocked" value={summary.blocked} tone="danger" />
        <Stat label="Challenged" value={summary.challenged} tone="caution" />
        <Stat label="Allowed" value={summary.allowed} tone="safe" />
        <Stat label="Block Rate" value={`${summary.block_rate_pct}%`} />
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <BreakdownList title="OWASP API Top 10 Breakdown" icon="shield" counts={owasp_breakdown} />
        <BreakdownList title="MITRE ATT&CK Breakdown" icon="hub" counts={mitre_breakdown} />
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <EntityTable
          title="Top Risky Entities"
          icon="warning"
          rows={top_risky_entities}
          columns={[
            { key: 'subject', label: 'Subject' },
            { key: 'peak_risk', label: 'Peak Risk' }
          ]}
        />
        <EntityTable
          title="Most Blocked Entities"
          icon="block"
          rows={most_blocked_entities}
          columns={[
            { key: 'subject', label: 'Subject' },
            { key: 'block_count', label: 'Blocks' }
          ]}
        />
      </div>

      <div className="glass-panel rounded-lg p-4 font-mono text-xs text-ink-muted">
        <span className="text-accent">{autonomous_mitigation_events}</span> autonomous mitigation event(s) in this period.
        Repeat offenders were automatically contained without human intervention.
      </div>
    </div>
  );
}
