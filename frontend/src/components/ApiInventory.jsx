import { useMemo } from 'react';
import { getRoutes } from '../api/gateway.js';
import { buildInventory } from '../api/analysis.js';
import { useResource } from '../hooks/useResource.js';

// API Inventory: what the gateway is enforcing, joined against what it has
// actually seen.
//
// The interesting output is not the route list - it is the gap. A path under a
// protected prefix that is NOT in the route table still requires a valid token,
// but gets no object-level or role-level rules, because inventing which
// parameter is the object id would be guesswork. So it runs authenticated and
// unauthorized: exactly the BOLA-shaped hole this product exists to close, and
// invisible everywhere else in the console.
//
// Matching observed paths back to route patterns has to be done here rather
// than read off the alert, because the gateway does not echo which route
// matched. Both sides of that are real data; only the join is presentation.

function CoverageBadge({ ok, label, none }) {
  if (none) {
    return (
      <span className="rounded bg-canvas-raised px-1.5 py-0.5 font-mono text-[10px] text-ink-faint">
        {label}: n/a
      </span>
    );
  }
  return (
    <span
      className={`rounded px-1.5 py-0.5 font-mono text-[10px] ${
        ok ? 'bg-risk-safe-dim/60 text-risk-safe' : 'bg-canvas-raised text-ink-faint'
      }`}
    >
      {label}: {ok ? 'yes' : 'no'}
    </span>
  );
}

export default function ApiInventory({ alerts }) {
  const { data, state, error, refresh } = useResource(getRoutes);

  const analysis = useMemo(() => buildInventory(data, alerts), [data, alerts]);

  if (state === 'loading') {
    return <div className="glass-panel rounded-lg p-8 text-center font-mono text-xs text-ink-faint">Loading route table…</div>;
  }
  if (state === 'error' || !analysis) {
    return (
      <div className="glass-panel rounded-lg p-8 text-center font-mono text-xs">
        <p className="text-risk-danger">Could not read the route table.</p>
        <p className="mt-2 text-ink-faint">{error}</p>
        <p className="mt-2 text-ink-faint">
          Needs <span className="text-ink-muted">GET /admin/routes</span> — restart the gateway if you are running an older build.
        </p>
        <button
          onClick={refresh}
          className="mt-4 rounded border border-canvas-line px-3 py-1 font-mono text-[10px] uppercase tracking-caps text-ink-muted hover:border-accent hover:text-accent"
        >
          retry
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <Stat label="Routes defined" value={analysis.routes.length} />
        <Stat label="BOLA-protected" value={`${analysis.bolaCovered}/${analysis.routes.length}`} />
        <Stat label="BFLA-protected" value={`${analysis.bflaCovered}/${analysis.routes.length}`} />
        <Stat
          label="Unlisted paths seen"
          value={analysis.unlisted.length}
          tone={analysis.unlisted.length ? 'caution' : 'safe'}
        />
      </div>

      <div className="glass-panel overflow-hidden rounded-lg">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-canvas-line px-4 py-3">
          <h2 className="font-display text-sm font-semibold text-ink">Protected routes</h2>
          <span className="font-mono text-[10px] text-ink-faint">
            source: {analysis.source} · prefixes: {analysis.prefixes.map((p) => `/${p}`).join(', ') || 'none'}
          </span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full border-collapse">
            <thead>
              <tr className="border-b border-canvas-line text-left font-mono text-[10px] uppercase tracking-caps text-ink-faint">
                <th className="px-3 py-2 font-semibold">Method</th>
                <th className="px-3 py-2 font-semibold">Pattern</th>
                <th className="px-3 py-2 font-semibold">Resource</th>
                <th className="px-3 py-2 font-semibold">Controls</th>
                <th className="px-3 py-2 font-semibold">Roles</th>
                <th className="px-3 py-2 text-right font-semibold">Traffic</th>
                <th className="px-3 py-2 text-right font-semibold">Blocked</th>
              </tr>
            </thead>
            <tbody>
              {analysis.routes.map((r) => (
                <tr key={`${r.method} ${r.pattern}`} className="border-b border-canvas-line hover:bg-canvas-raised/40">
                  <td className="px-3 py-2 font-mono text-[11px] text-ink-muted">{r.method}</td>
                  <td className="px-3 py-2 font-mono text-[11px] text-ink">{r.pattern}</td>
                  <td className="px-3 py-2 font-mono text-[11px] text-ink-muted">{r.resource || '—'}</td>
                  <td className="px-3 py-2">
                    <div className="flex flex-wrap gap-1">
                      <CoverageBadge ok={r.require_auth} label="authn" />
                      <CoverageBadge ok={r.bola_protected} label="bola" />
                      <CoverageBadge ok={r.bfla_protected} label="bfla" />
                    </div>
                  </td>
                  <td className="px-3 py-2 font-mono text-[11px] text-ink-faint">
                    {r.required_roles?.length ? r.required_roles.join(', ') : 'any'}
                  </td>
                  <td className="px-3 py-2 text-right font-mono text-[11px] tabular-nums text-ink-muted">{r.traffic}</td>
                  <td className={`px-3 py-2 text-right font-mono text-[11px] tabular-nums ${r.blocked ? 'text-risk-danger' : 'text-ink-faint'}`}>
                    {r.blocked}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="glass-panel overflow-hidden rounded-lg">
        <div className="border-b border-canvas-line px-4 py-3">
          <h2 className="font-display text-sm font-semibold text-ink">
            Coverage gaps
            <span className="ml-2 font-mono text-[10px] font-normal text-ink-faint">
              seen under a protected prefix, but not in the route table
            </span>
          </h2>
        </div>

        {analysis.unlisted.length === 0 ? (
          <div className="p-6 text-center font-mono text-xs text-ink-faint">
            No gaps. Every path observed under {analysis.prefixes.map((p) => `/${p}`).join(', ')} matches a defined route.
          </div>
        ) : (
          <>
            <p className="border-b border-canvas-line bg-risk-caution-dim/30 px-4 py-2 font-mono text-[11px] leading-relaxed text-risk-caution">
              These received traffic and were authenticated, but have no object-level or
              role-level rules — a valid token is enough to reach them. Add an entry to{' '}
              <span className="text-ink">backend/routes.json</span> and restart the gateway to close the gap.
            </p>
            <div className="overflow-x-auto">
              <table className="w-full border-collapse">
                <thead>
                  <tr className="border-b border-canvas-line text-left font-mono text-[10px] uppercase tracking-caps text-ink-faint">
                    <th className="px-3 py-2 font-semibold">Method</th>
                    <th className="px-3 py-2 font-semibold">Path</th>
                    <th className="px-3 py-2 text-right font-semibold">Requests</th>
                    <th className="px-3 py-2 text-right font-semibold">Subjects</th>
                    <th className="px-3 py-2 text-right font-semibold">Allowed</th>
                    <th className="px-3 py-2 font-semibold">Last seen</th>
                  </tr>
                </thead>
                <tbody>
                  {analysis.unlisted.map((row) => (
                    <tr key={`${row.method} ${row.path}`} className="border-b border-canvas-line hover:bg-canvas-raised/40">
                      <td className="px-3 py-2 font-mono text-[11px] text-ink-muted">{row.method}</td>
                      <td className="px-3 py-2 font-mono text-[11px] text-risk-caution">{row.path}</td>
                      <td className="px-3 py-2 text-right font-mono text-[11px] tabular-nums text-ink-muted">{row.count}</td>
                      <td className="px-3 py-2 text-right font-mono text-[11px] tabular-nums text-ink-muted">{row.subjects.size}</td>
                      <td className="px-3 py-2 text-right font-mono text-[11px] tabular-nums text-ink-muted">{row.allowed}</td>
                      <td className="px-3 py-2 font-mono text-[11px] text-ink-faint">
                        {row.lastSeen ? new Date(row.lastSeen).toLocaleTimeString() : '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

function Stat({ label, value, tone = 'default' }) {
  const toneText = {
    default: 'text-ink',
    safe: 'text-risk-safe',
    caution: 'text-risk-caution'
  }[tone];
  return (
    <div className="glass-panel rounded-lg px-4 py-3">
      <div className="label-caps mb-1 text-ink-faint">{label}</div>
      <div className={`font-mono text-2xl font-semibold tabular-nums ${toneText}`}>{value}</div>
    </div>
  );
}
