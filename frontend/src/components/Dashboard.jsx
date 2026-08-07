import { useLiveData } from '../hooks/useLiveData.js';
import RiskGauge from './RiskGauge.jsx';
import ThreatFeed from './ThreatFeed.jsx';
import RiskChart from './RiskChart.jsx';
import MitreMatrix from './MitreMatrix.jsx';
import EntityTable from './EntityTable.jsx';
import IncidentFeed from './IncidentFeed.jsx';
import { GATEWAY_URL } from '../api/gateway.js';

function StatBox({ label, value }) {
  return (
    <div className="rounded-md border border-canvas-line bg-canvas-panel px-4 py-3">
      <div className="font-mono text-[10px] font-medium uppercase tracking-wide text-ink-faint">{label}</div>
      <div className="mt-1 font-mono text-xl font-semibold tabular-nums text-ink">{value}</div>
    </div>
  );
}

export default function Dashboard() {
  const { alerts, metrics, entities, incidents, connectionState, lastError } = useLiveData();

  return (
    <div className="min-h-screen px-4 py-6 md:px-8">
      {/* header */}
      <header className="mb-6 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="font-display text-xl font-bold tracking-tight text-ink">
            NEUROBOTS <span className="text-accent">· THREAT CONSOLE</span>
          </h1>
          <p className="mt-0.5 font-mono text-xs text-ink-faint">{GATEWAY_URL}</p>
        </div>
        <ConnectionBadge state={connectionState} />
      </header>

      {connectionState === 'error' && (
        <div className="mb-4 rounded border border-risk-danger/30 bg-risk-danger-dim/40 px-3 py-2 font-mono text-xs text-risk-danger">
          gateway unreachable at {GATEWAY_URL}{lastError ? ` — ${lastError}` : ''}. Retrying every{' '}
          {(Number(import.meta.env.VITE_POLL_INTERVAL) || 2000) / 1000}s. Showing last known data, not sample data.
        </div>
      )}

      {/* hero row: gauge + stats */}
      <div className="mb-6 flex flex-col gap-4 rounded-md border border-canvas-line bg-canvas-panel p-6 lg:flex-row lg:items-center">
        <RiskGauge score={metrics?.overall_risk ?? 0} />
        <div className="grid flex-1 grid-cols-2 gap-2 sm:grid-cols-4">
          <StatBox label="Total requests" value={metrics?.total_requests ?? 0} />
          <StatBox label="Block rate" value={`${metrics?.block_rate ?? 0}%`} />
          <StatBox label="Avg latency" value={`${(metrics?.avg_latency_ms ?? 0).toFixed(1)}ms`} />
          <StatBox label="Entities" value={metrics?.entities_count ?? 0} />
        </div>
      </div>

      <div className="mb-6">
        <RiskChart metrics={metrics} />
      </div>

      <div className="mb-6 grid grid-cols-1 gap-4 xl:grid-cols-[1.3fr_1fr]">
        <div className="h-[520px]">
          <ThreatFeed alerts={alerts} />
        </div>
        <div className="flex flex-col gap-4">
          <MitreMatrix counts={metrics?.mitre_counts} />
          <IncidentFeed incidents={incidents} />
        </div>
      </div>

      <EntityTable entities={entities} />
    </div>
  );
}

function ConnectionBadge({ state }) {
  const map = {
    connecting: { color: 'bg-ink-faint', label: 'Connecting', pulse: false },
    live: { color: 'bg-accent', label: 'Live', pulse: true },
    error: { color: 'bg-risk-danger', label: 'Gateway unreachable', pulse: false }
  };
  const s = map[state] || map.connecting;
  return (
    <span className="flex items-center gap-2 rounded-full border border-canvas-line bg-canvas-panel px-3 py-1.5 font-mono text-[11px] text-ink-muted">
      <span className={`h-2 w-2 rounded-full ${s.color} ${s.pulse ? 'animate-breathe' : ''}`} />
      {s.label}
    </span>
  );
}
