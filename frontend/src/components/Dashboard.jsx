import { useMemo, useState } from 'react';
import { useLiveData } from '../hooks/useLiveData.js';
import LogsView from './LogsView.jsx';
import ApiInventory from './ApiInventory.jsx';
import AccessControl from './AccessControl.jsx';
import ThreatHunt from './ThreatHunt.jsx';
import RiskGauge from './RiskGauge.jsx';
import ThreatFeed from './ThreatFeed.jsx';
import RiskChart from './RiskChart.jsx';
import MitreMatrix from './MitreMatrix.jsx';
import EntityTable from './EntityTable.jsx';
import IncidentFeed from './IncidentFeed.jsx';
import { Icon, PanelHeader } from './PanelHeader.jsx';
import { GATEWAY_URL } from '../api/gateway.js';

// Every section is now backed by real gateway data:
//   Overview        /admin/{metrics,alerts,entities,incidents}
//   Threat Hunt     deterministic correlation over the live alert window
//   API Inventory   /admin/routes joined against observed paths
//   Access Control  /admin/ownership (GET + POST) and /admin/entities
//   Logs            /admin/alerts, full window
//
// The original rule still holds and is worth restating: nothing on this console
// is invented. Where a capability genuinely does not exist - the LangChain
// summarisation layer PRODUCT.md proposes - the page says so plainly instead of
// rendering generated prose that reads like analysis.
const NAV = [
  { id: 'overview', icon: 'dashboard', label: 'Overview' },
  { id: 'hunt', icon: 'radar', label: 'Threat Hunt' },
  { id: 'inventory', icon: 'api', label: 'API Inventory' },
  { id: 'access', icon: 'lock_person', label: 'Access Control' },
  { id: 'logs', icon: 'terminal', label: 'Logs' }
];

const VIEW_SUBTITLE = {
  overview: 'Live gateway state',
  hunt: 'Correlation over the live alert window',
  inventory: 'Enforced routes vs. observed traffic',
  access: 'Ownership grants, roles and cooldowns',
  logs: 'Full audit log'
};

function SideNav({ connectionState, transport, view, onNavigate, counts }) {
  return (
    <nav className="fixed left-0 top-0 z-40 hidden h-full w-64 flex-col border-r border-white/10 bg-canvas-sunken py-6 md:flex">
      <div className="mb-8 px-4">
        <h1 className="font-display text-xl font-bold uppercase tracking-widest text-accent">ProjectZero</h1>
        <p className="mt-1 font-mono text-[10px] text-ink-faint">NeuroBots Gateway · Terminal 01-A</p>
      </div>

      <div className="flex flex-1 flex-col gap-1 px-2">
        {NAV.map((item) => {
          const current = item.id === view;
          const badge = counts?.[item.id];
          return (
            <button
              key={item.id}
              type="button"
              onClick={() => onNavigate(item.id)}
              aria-current={current ? 'page' : undefined}
              className={`flex items-center gap-3 rounded px-4 py-2 text-left font-mono text-[13px] transition-colors ${
                current
                  ? 'border-r-2 border-accent bg-accent/10 text-accent'
                  : 'text-ink-faint hover:bg-canvas-raised/60 hover:text-ink-muted'
              }`}
            >
              <Icon name={item.icon} className="text-[18px]" />
              {item.label}
              {badge ? (
                <span
                  className={`ml-auto rounded px-1.5 py-0.5 font-mono text-[9px] tabular-nums ${
                    badge.tone === 'danger'
                      ? 'bg-risk-danger-dim/60 text-risk-danger'
                      : 'bg-canvas-raised text-ink-faint'
                  }`}
                >
                  {badge.value}
                </span>
              ) : null}
            </button>
          );
        })}
      </div>

      <div className="mt-auto space-y-3 border-t border-white/10 px-4 pt-4">
        <div>
          <div className="label-caps mb-1 text-ink-faint">Gateway</div>
          <div className="break-all font-mono text-[11px] text-ink-muted">{GATEWAY_URL}</div>
        </div>
        <ConnectionBadge state={connectionState} transport={transport} />
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
  const { alerts, allAlerts, metrics, entities, incidents, connectionState, lastError, transport } = useLiveData();
  const [view, setView] = useState('overview');

  // Both already computed once in deriveMetrics (normalize.js) - read them
  // back rather than recomputing so the stat tile, the gauge and the pie
  // below always agree on the same numbers.
  const blockRate = metrics?.block_rate ?? 0;
  const risk = metrics?.overall_risk ?? 0;

  // Sidebar badges. Only surfaced where the number is actionable - a blocked
  // count on Logs and a cooldown count on Access Control both mean "look here";
  // a route count on Inventory would just be decoration.
  const counts = useMemo(() => {
    const blocked = allAlerts.filter((a) => a.decision === 'block').length;
    const cooling = entities.filter((e) => e.status === 'blocked').length;
    return {
      logs: blocked ? { value: blocked, tone: 'danger' } : null,
      access: cooling ? { value: cooling, tone: 'danger' } : null
    };
  }, [allAlerts, entities]);

  return (
    <div className="min-h-screen tactical-grid">
      <SideNav connectionState={connectionState} transport={transport} view={view} onNavigate={setView} counts={counts} />

      <header className="fixed top-0 z-30 flex h-16 w-full items-center justify-between border-b border-white/10 bg-canvas/80 px-4 backdrop-blur-md md:pl-64 md:pr-8">
        <div className="min-w-0 flex-1">
          <h2 className="truncate font-display text-lg font-semibold tracking-tight text-ink">
            {NAV.find((n) => n.id === view)?.label || 'Threat Console'}
          </h2>
          <p className="truncate font-mono text-[10px] text-ink-faint">
            {VIEW_SUBTITLE[view]} ·{' '}
            {transport === 'websocket'
              ? 'streaming decisions over /ws/events'
              : `polling every ${(Number(import.meta.env.VITE_POLL_INTERVAL) || 2000) / 1000}s`}
          </p>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          {/* The sidebar is hidden below md, so without this the only way to
              change section on a phone would be to widen the window. */}
          <select
            value={view}
            onChange={(e) => setView(e.target.value)}
            className="rounded border border-canvas-line bg-canvas-sunken px-2 py-1 font-mono text-[11px] text-ink md:hidden"
            aria-label="Section"
          >
            {NAV.map((n) => (
              <option key={n.id} value={n.id}>{n.label}</option>
            ))}
          </select>
          <div className="md:hidden">
            <ConnectionBadge state={connectionState} transport={transport} />
          </div>
        </div>
      </header>

      <main className="px-4 pb-10 pt-20 md:pl-64 md:pr-8">
        <div className="mx-auto w-full max-w-[1680px]">
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

        {view === 'hunt' && <ThreatHunt alerts={allAlerts} entities={entities} />}
        {view === 'inventory' && <ApiInventory alerts={allAlerts} />}
        {view === 'access' && <AccessControl entities={entities} incidents={incidents} />}
        {view === 'logs' && (
          <div className="h-[calc(100vh-140px)]">
            <LogsView alerts={allAlerts} />
          </div>
        )}

        {view === 'overview' && (
        <>
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

          {/* clamp(): scales with viewport height (55vh) but never gets so
              short it's useless on a laptop or so tall it towers over the
              posture/investigation columns on an ultrawide monitor */}
          <div className="lg:col-span-6 h-[clamp(420px,55vh,620px)]">
            <ThreatFeed alerts={alerts} />
          </div>

          {/* min-h-0 lets the flex-1 child below actually shrink/grow inside
              the grid-stretched height instead of overflowing it - the row's
              real height comes from ThreatFeed's clamp() next to it. */}
          {/* IncidentFeed owns its own flex-1/min-h-0 sizing now (see
              IncidentFeed.jsx) - no wrapper div needed here. */}
          <div className="flex min-h-0 flex-col gap-3 lg:col-span-3">
            <MitreMatrix counts={metrics?.mitre_counts} />
            <IncidentFeed incidents={incidents} />
          </div>
        </section>

        <section className="mb-4">
          <RiskChart metrics={metrics} />
        </section>

        <EntityTable entities={entities} />
        </>
        )}
       </div>
      </main>
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

function ConnectionBadge({ state, transport }) {
  const map = {
    connecting: { color: 'bg-ink-faint', label: 'Connecting', pulse: false },
    live: { color: 'bg-risk-safe', label: 'Live', pulse: true },
    degraded: { color: 'bg-risk-caution', label: 'Partial data', pulse: false },
    error: { color: 'bg-risk-danger', label: 'Gateway unreachable', pulse: false }
  };
  const s = map[state] || map.connecting;
  // "Live" meant a 2-second poll for as long as this badge has existed. Naming
  // the transport keeps the claim honest in both directions: pushed means the
  // gateway's WebSocket is delivering decisions as they happen, polled means it
  // is not and the feed is up to VITE_POLL_INTERVAL behind.
  const detail = state === 'live' ? (transport === 'websocket' ? 'pushed' : 'polled') : null;
  return (
    <span className="flex w-fit items-center gap-2 rounded-full border border-white/10 bg-canvas-panel px-3 py-1.5 font-mono text-[11px] text-ink-muted">
      <span className={`h-2 w-2 rounded-full ${s.color} ${s.pulse ? 'animate-breathe' : ''}`} />
      {s.label}
      {detail && <span className="text-ink-faint">· {detail}</span>}
    </span>
  );
}
