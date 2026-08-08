// Surfaces the gateway's autonomous mitigation events (GET /admin/incidents) -
// real backend data that previously had no UI at all. An incident is logged
// whenever the gateway escalates a repeat-offender identity or source IP to a
// self-expiring cooldown without waiting for a human. This is deterministic,
// not an LLM decision - see backend/agents.py generate_narrative.

function timeAgo(ts) {
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(ts).getTime()) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  return `${Math.floor(seconds / 60)}m ago`;
}

export default function IncidentFeed({ incidents }) {
  return (
    // flex-1/min-h-0 only do anything once the parent column has a definite
    // height to distribute, which is only true at lg+ (the tactical grid
    // stretches the column to match Threat Feed's clamp() height). Below lg
    // the Overview grid stacks to a single column and this panel's height is
    // just its own content - so flex-1 alone would render every incident
    // with no cap. max-h-64 lg:max-h-none on the list below carries the old
    // fixed cap at every width below lg, and only lets go of it once the
    // grid is actually giving this column real height to fill.
    <div className="glass-panel flex min-h-0 flex-1 flex-col rounded-lg p-4">
      <div className="mb-3 flex items-center justify-between">
        <h3 className="font-display text-sm font-semibold text-ink">Autonomous mitigation</h3>
        <span className="font-mono text-[10px] uppercase tracking-wide text-ink-faint">
          {incidents.length} event{incidents.length === 1 ? '' : 's'}
        </span>
      </div>

      {incidents.length === 0 && (
        <div className="py-6 text-center font-mono text-xs text-ink-faint">
          No escalations yet - no identity or source has crossed the repeat-violation threshold.
        </div>
      )}

      <div className="flex max-h-64 flex-1 flex-col gap-2 overflow-y-auto lg:max-h-none">
        {incidents.slice(0, 20).map((i) => (
          <div
            key={i.id}
            className="border-l-[3px] border-l-risk-danger bg-canvas-raised px-3 py-2"
          >
            <div className="flex items-center justify-between gap-2">
              <span className="truncate font-mono text-xs font-semibold text-ink">{i.target}</span>
              <span className="shrink-0 font-mono text-[10px] uppercase tracking-wide text-ink-faint">
                {i.targetType === 'source_ip' ? 'IP' : 'identity'} · #{i.escalationCount}
              </span>
            </div>
            <div className="mt-1 font-mono text-[11px] text-ink-muted">{i.reason}</div>
            <div className="mt-1 flex items-center justify-between font-mono text-[10px] text-ink-faint">
              <span>cooldown {i.cooldownSec}s</span>
              <span>{timeAgo(i.time)}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
