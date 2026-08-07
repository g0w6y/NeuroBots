import { useLiveData } from '../hooks/useLiveData.js';
import RiskGauge from './RiskGauge.jsx';
import ThreatFeed from './ThreatFeed.jsx';
import RiskChart from './RiskChart.jsx';
import MitreMatrix from './MitreMatrix.jsx';
import EntityTable from './EntityTable.jsx';
import IncidentFeed from './IncidentFeed.jsx';
import { GATEWAY_URL } from '../api/gateway.js';

function Icon({ name, className = '' }) {
  return (
    <span className={`material-symbols-outlined ${className}`} aria-hidden="true">
      {name}
    </span>
  );
}

// Only Overview is backed by real gateway endpoints. The other sections exist in
// the ProjectZero design but have no data behind them in this gateway, so they
// render as explicitly unavailable rather than as links to an empty page or, worse,
// a page of invented numbers. The whole point of this console is that everything on
// it came from the gateway.
const NAV = [
  { icon: 'dashboard', label: 'Overview', active: true },
  { icon: 'radar', label: 'Threat Hunt' },
  { icon: 'api', label: 'API Inventory' },
  { icon: 'lock_person', label: 'Access Control' },
  { icon: 'terminal', label: 'Logs' }
];

function SideNav({ connectionState }) {
  return (
    <nav className="fixed left-0 top-0 z-40 hidden h-full w-60 flex-col border-r border-white/10 bg-canvas-sunken py-6 md:flex">
      <div className="mb-8 px-4">
        <h1 className="font-display text-xl font-bold uppercase tracking-widest text-accent">ProjectZero</h1>
        <p className="mt-1 font-mono text-[10px] text-ink-faint">NeuroBots Gateway · Terminal 01-A</p>
      </div>

      <div className="flex flex-1 flex-col gap-1 px-2">
        {NAV.map((item) =>
          item.active ? (
            <span
              key={item.label}
              aria-current="page"
              className="flex items-center gap-3 rounded border-r-2 border-accent bg-accent/10 px-4 py-2 font-mono text-[13px] text-accent"
            >
              <Icon name={item.icon} className="text-[18px]" />
              {item.label}
            </span>
          ) : (
            <span
              key={item.label}
              title="No gateway data source — not built"
              className="flex cursor-not-allowed items-center gap-3 rounded px-4 py-2 font-mono text-[13px] text-ink-faint/50"
            >
              <Icon name={item.icon} className="text-[18px]" />
              {item.label}
              <span className="ml-auto font-mono text-[9px] uppercase tracking-caps text-ink-faint/40">n/a</span>
            </span>
          )
        )}
      </div>

      <div className="mt-auto space-y-3 border-t border-white/10 px-4 pt-4">
        <div>
          <div className="label-caps mb-1 text-ink-faint">Gateway</div>
          <div className="break-all font-mono text-[11px] text-ink-muted">{GATEWAY_URL}</div>
        </div>
        <ConnectionBadge state={connectionState} />
      </div>
    </nav>
  );
}

function StatCard({ label, value, icon, tone = 'default', foot, alert }) {
  const toneText = {
    default: 'text-ink',
    danger: 'text-risk-danger text-glow-danger',
    caution: 'text-risk-caution',
    accent: 'text-accent'
  }[tone];

  return (
    <div
      className={`glass-panel flex flex-col justify-between rounded-lg p-4 ${
        alert ? 'animate-pulse-alert border-risk-danger/30' : ''
      }`}
    >
      <div className="mb-2 flex items-start justify-between">
        <span className="label-caps text-ink-faint">{label}</span>
        <Icon name={icon} className={`text-[16px] ${tone === 'default' ? 'text-ink-faint' : toneText}`} />
      </div>
      <div className={`font-display text-4xl font-bold tabular-nums tracking-tight ${toneText}`}>{value}</div>
      {foot ? <div className="mt-2">{foot}</div> : null}
    </div>
  );
}

export default function Dashboard() {
  const { alerts, metrics, entities, incidents, connectionState, lastError } = useLiveData();

  const blockRate = metrics?.block_rate ?? 0;
  const risk = metrics?.overall_risk ?? 0;

  return (
    <div className="min-h-screen tactical-grid">
      <SideNav connectionState={connectionState} />

      <header className="fixed top-0 z-30 flex h-16 w-full items-center justify-between border-b border-white/10 bg-canvas/80 px-4 backdrop-blur-md md:pl-[256px] md:pr-8">
        <div>
          <h2 className="font-display text-lg font-semibold tracking-tight text-ink">Threat Console</h2>
          <p className="font-mono text-[10px] text-ink-faint">
            Live gateway state · polling every {(Number(import.meta.env.VITE_POLL_INTERVAL) || 2000) / 1000}s
          </p>
        </div>
        <div className="md:hidden">
          <ConnectionBadge state={connectionState} />
        </div>
      </header>

      <main className="px-4 pb-10 pt-20 md:pl-[256px] md:pr-8">
        {(connectionState === 'error' || connectionState === 'degraded') && (
          <div
            className={`mb-4 rounded border px-3 py-2 font-mono text-xs ${
              connectionState === 'error'
                ? 'border-risk-danger/30 bg-risk-danger-dim/40 text-risk-danger'
                : 'border-risk-caution/30 bg-risk-caution-dim/40 text-risk-caution'
            }`}
          >
            {connectionState === 'error'
              ? `no response from ${GATEWAY_URL}`
              : `partial response from ${GATEWAY_URL} — some panels are holding their last values`}
            {lastError ? ` — ${lastError}` : ''}. Retrying every{' '}
            {(Number(import.meta.env.VITE_POLL_INTERVAL) || 2000) / 1000}s. Showing last known data, not sample data.
          </div>
        )}

        {/* telemetry row */}
        <section className="mb-4 grid grid-cols-1 gap-3 md:grid-cols-2 lg:grid-cols-4">
          <StatCard
            label="Total requests"
            value={metrics?.total_requests ?? 0}
            icon="database"
            foot={
              <span className="font-mono text-[10px] text-ink-faint">
                {metrics?.entities_count ?? 0} entities seen
              </span>
            }
          />
          <StatCard
            label="Block rate"
            value={`${blockRate}%`}
            icon="warning"
            tone={blockRate > 0 ? 'danger' : 'default'}
            alert={blockRate > 0}
            foot={
              <div className="h-1 w-full overflow-hidden rounded-full bg-canvas-raised">
                <div
                  className="h-full bg-risk-danger transition-all duration-500"
                  style={{ width: `${Math.min(100, blockRate)}%` }}
                />
              </div>
            }
          />
          <StatCard
            label="Avg latency"
            value={`${(metrics?.avg_latency_ms ?? 0).toFixed(2)}ms`}
            icon="speed"
            tone="accent"
            foot={
              <span className="rounded bg-canvas-raised px-1.5 py-0.5 font-mono text-[10px] text-ink-muted">
                budget 15ms
              </span>
            }
          />
          <StatCard
            label="Active entities"
            value={metrics?.entities_count ?? 0}
            icon="hub"
            foot={
              <span className="font-mono text-[10px] text-ink-faint">
                {incidents?.length ?? 0} autonomous incidents
              </span>
            }
          />
        </section>

        {/* tactical grid: posture / live stream / investigation */}
        <section className="mb-4 grid grid-cols-1 gap-3 lg:grid-cols-12">
          <div className="glass-panel flex flex-col overflow-hidden rounded-lg lg:col-span-3">
            <PanelHeader icon="shield" tone="accent">Security Posture</PanelHeader>
            <div className="flex flex-1 flex-col items-center justify-center gap-6 p-4">
              <RiskGauge score={risk} />
              <div className="w-full">
                <div className="label-caps mb-2 text-ink-faint">Decision Breakdown</div>
                <DecisionBar metrics={metrics} />
              </div>
            </div>
          </div>

          <div className="lg:col-span-6 h-[560px]">
            <ThreatFeed alerts={alerts} />
          </div>

          <div className="flex flex-col gap-3 lg:col-span-3">
            <MitreMatrix counts={metrics?.mitre_counts} />
            <IncidentFeed incidents={incidents} />
          </div>
        </section>

        <section className="mb-4">
          <RiskChart metrics={metrics} />
        </section>

        <EntityTable entities={entities} />
      </main>
    </div>
  );
}

export function PanelHeader({ icon, children, tone = 'default', right }) {
  const toneText = { default: 'text-ink-muted', accent: 'text-accent', danger: 'text-risk-danger' }[tone];
  return (
    <div className="flex items-center justify-between border-b border-white/5 bg-white/[0.02] px-4 py-2.5">
      <span className={`label-caps flex items-center gap-2 ${toneText}`}>
        {icon ? <Icon name={icon} className="text-[16px]" /> : null}
        {children}
      </span>
      {right}
    </div>
  );
}

function DecisionBar({ metrics }) {
  const allowed = metrics?.allowed ?? 0;
  const challenged = metrics?.challenged ?? 0;
  const blocked = metrics?.blocked ?? 0;
  const total = allowed + challenged + blocked;

  if (!total) {
    return <div className="font-mono text-[10px] text-ink-faint">no decisions recorded yet</div>;
  }

  const pct = (n) => (n / total) * 100;

  return (
    <>
      <div className="mb-2 flex h-2 w-full overflow-hidden rounded-full bg-canvas-raised">
        <div className="bg-risk-safe" style={{ width: `${pct(allowed)}%` }} />
        <div className="bg-risk-caution" style={{ width: `${pct(challenged)}%` }} />
        <div className="bg-risk-danger" style={{ width: `${pct(blocked)}%` }} />
      </div>
      <div className="flex justify-between font-mono text-[10px] tabular-nums">
        <span className="text-risk-safe">{Math.round(pct(allowed))}% allow</span>
        <span className="text-risk-caution">{Math.round(pct(challenged))}% chal</span>
        <span className="text-risk-danger">{Math.round(pct(blocked))}% block</span>
      </div>
    </>
  );
}

function ConnectionBadge({ state }) {
  const map = {
    connecting: { color: 'bg-ink-faint', label: 'Connecting', pulse: false },
    live: { color: 'bg-risk-safe', label: 'Live', pulse: true },
    degraded: { color: 'bg-risk-caution', label: 'Partial data', pulse: false },
    error: { color: 'bg-risk-danger', label: 'Gateway unreachable', pulse: false }
  };
  const s = map[state] || map.connecting;
  return (
    <span className="flex w-fit items-center gap-2 rounded-full border border-white/10 bg-canvas-panel px-3 py-1.5 font-mono text-[11px] text-ink-muted">
      <span className={`h-2 w-2 rounded-full ${s.color} ${s.pulse ? 'animate-breathe' : ''}`} />
      {s.label}
    </span>
  );
}
