import { memo, useState } from 'react';

const DECISION_STYLES = {
  allow: { rule: 'border-l-risk-safe', text: 'text-risk-safe', label: 'Allowed' },
  // The gateway forwards an "observe" request upstream exactly like an allow —
  // it means "scored, nothing hard fired". Without an entry here it fell through
  // to the allow style but with the wrong label.
  observe: { rule: 'border-l-risk-safe', text: 'text-ink-muted', label: 'Observed' },
  challenge: { rule: 'border-l-risk-caution', text: 'text-risk-caution', label: 'Challenged' },
  block: { rule: 'border-l-risk-danger', text: 'text-risk-danger', label: 'Blocked' }
};

function riskTextColor(score) {
  if (score > 60) return 'text-risk-danger';
  if (score > 30) return 'text-risk-caution';
  return 'text-risk-safe';
}

function pad(score) {
  return String(Math.round(score)).padStart(3, '0');
}

function timeAgo(ts) {
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(ts).getTime()) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  return `${Math.floor(seconds / 60)}m ago`;
}

function Row({ alert }) {
  const style = DECISION_STYLES[alert.decision] || DECISION_STYLES.allow;
  const [open, setOpen] = useState(false);
  const hasDetail = Boolean(alert.narrative || alert.explanation || alert.signals?.length);

  return (
    <div className={`border-b border-b-canvas-line border-l-[3px] ${style.rule}`}>
    <div
      role={hasDetail ? 'button' : undefined}
      tabIndex={hasDetail ? 0 : undefined}
      aria-expanded={hasDetail ? open : undefined}
      onClick={() => hasDetail && setOpen((v) => !v)}
      onKeyDown={(e) => {
        if (hasDetail && (e.key === 'Enter' || e.key === ' ')) {
          e.preventDefault();
          setOpen((v) => !v);
        }
      }}
      className={`animate-flash-in grid grid-cols-[90px_60px_1fr_140px_120px_90px] items-center gap-3 px-4 py-3 text-sm transition-colors hover:bg-canvas-raised/60 max-md:grid-cols-1 max-md:gap-1 ${hasDetail ? 'cursor-pointer' : ''}`}
    >
      <span className={`font-mono text-[11px] font-semibold uppercase tracking-wide ${style.text}`}>
        {style.label}
      </span>

      <span className={`font-mono text-base font-semibold tabular-nums ${riskTextColor(alert.risk_score)}`}>
        {pad(alert.risk_score)}
      </span>

      <div className="min-w-0">
        <div className="truncate font-mono text-xs text-ink">
          <span className="text-ink-muted">{alert.method}</span> {alert.path}
        </div>
        <div className="mt-1 flex flex-wrap gap-1">
          {alert.signals?.map((s) => (
            <span
              key={s.signal}
              className="rounded bg-canvas-raised px-1.5 py-0.5 font-mono text-[10px] text-ink-muted"
            >
              {s.signal} · {s.owasp} · {s.mitre}
            </span>
          ))}
        </div>
      </div>

      <span className="truncate font-mono text-xs text-ink-muted">{alert.subject}</span>
      <span className="truncate font-mono text-xs text-ink-muted">{alert.ip}</span>
      <span className="font-mono text-[11px] text-ink-faint">
        {timeAgo(alert.timestamp)}
        {hasDetail && <span className="ml-1 text-ink-faint">{open ? '▾' : '▸'}</span>}
      </span>
    </div>

    {/* Explainability is the product's central claim — every block mapped to a
        reason, an OWASP category and a MITRE technique. All of it was already on
        the client and none of it was on screen: `explanation` appeared only as a
        title= tooltip, and `narrative` was normalized and then never rendered at
        all. A judge asking "why was that blocked?" should not have to hover. */}
    {open && hasDetail && (
      <div className="border-t border-canvas-line bg-canvas/60 px-4 py-3 font-mono text-[11px] leading-relaxed">
        {alert.narrative && (
          <p className="mb-2 text-ink">{alert.narrative}</p>
        )}
        {alert.signals?.map((s) => (
          <div key={s.signal} className="mb-1.5 border-l-2 border-canvas-line-strong pl-2">
            <div className="text-ink-muted">
              <span className={style.text}>{s.signal}</span>
              {s.hard ? ' · confirmed' : ' · heuristic'}
            </div>
            <div className="text-ink-faint">{s.evidence}</div>
            <div className="text-ink-faint">{s.owaspFull || s.owasp} · {s.mitreFull || s.mitre}</div>
          </div>
        ))}
        {alert.explanation && (
          <p className="mt-2 whitespace-pre-wrap text-ink-faint">{alert.explanation}</p>
        )}
      </div>
    )}
    </div>
  );
}

function ThreatFeed({ alerts }) {
  return (
    <div className="glass-panel flex h-full flex-col overflow-hidden rounded-lg">
      <div className="flex items-center justify-between border-b border-canvas-line px-4 py-3">
        <h2 className="font-display text-sm font-semibold text-ink">
          Request log <span className="font-mono text-[10px] font-normal text-ink-faint">· click a row for the full reasoning</span>
        </h2>
        <span className="h-1.5 w-1.5 rounded-full bg-accent animate-breathe" aria-label="auto-updating" />
      </div>
      <div className="hidden grid-cols-[90px_60px_1fr_140px_120px_90px] gap-3 border-b border-canvas-line px-4 py-2 font-mono text-[10px] font-semibold uppercase tracking-wide text-ink-faint md:grid">
        <span>Decision</span>
        <span>Risk</span>
        <span>Request</span>
        <span>Subject</span>
        <span>IP</span>
        <span>When</span>
      </div>
      <div className="flex-1 overflow-y-auto">
        {alerts.length === 0 && (
          <div className="p-8 text-center font-mono text-xs text-ink-faint">Awaiting first request…</div>
        )}
        {alerts.slice(0, 50).map((alert) => (
          <Row key={alert.id} alert={alert} />
        ))}
      </div>
    </div>
  );
}

export default memo(ThreatFeed);
