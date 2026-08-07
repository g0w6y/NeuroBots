import { useMemo, useState } from 'react';
import { getOwnership, grantOwnership, getRevocations, revokeToken } from '../api/gateway.js';
import { useResource } from '../hooks/useResource.js';

// Access Control: the authorization data itself, rather than its consequences.
//
// Everywhere else in this console you see what the gateway DECIDED. This page
// shows what it decides AGAINST - the ownership grants BOLA is checked against,
// the roles BFLA is checked against, and who is currently under an autonomous
// cooldown. Provisioning a grant here writes through POST /admin/ownership and
// takes effect on the very next request; there is no restart and no reload.
//
// fan-in is the column worth reading. It is how many distinct subjects own one
// object. Legitimate objects are owned by one subject, occasionally two for a
// joint account. A fan-in that climbs on its own is either a provisioning bug
// or an attacker who has been granted access they should not have.

export default function AccessControl({ entities, incidents }) {
  const { data, state, error, refresh } = useResource(getOwnership);
  const revocations = useResource(getRevocations);
  const [form, setForm] = useState({ resource: 'account', objectId: '', subject: '' });
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null);
  const [query, setQuery] = useState('');
  const [revokeForm, setRevokeForm] = useState({ jti: '', reason: '' });
  const [revokeBusy, setRevokeBusy] = useState(false);
  const [revokeResult, setRevokeResult] = useState(null);

  const grants = data?.grants || [];
  const revoked = revocations.data?.revocations || [];

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return grants;
    return grants.filter(
      (g) =>
        g.resource.toLowerCase().includes(q) ||
        g.object_id.toLowerCase().includes(q) ||
        g.owners.some((o) => o.toLowerCase().includes(q))
    );
  }, [grants, query]);

  const blocked = useMemo(() => entities.filter((e) => e.status === 'blocked'), [entities]);
  const flagged = useMemo(() => entities.filter((e) => e.status === 'flagged'), [entities]);

  async function submit(e) {
    e.preventDefault();
    if (!form.resource || !form.objectId || !form.subject) return;
    setBusy(true);
    setResult(null);
    try {
      const res = await grantOwnership(form);
      setResult({ ok: true, text: `granted ${res.resource}/${res.object_id} to ${res.subject}` });
      setForm((f) => ({ ...f, objectId: '', subject: '' }));
      await refresh();
    } catch (err) {
      setResult({
        ok: false,
        text:
          err?.response?.status === 401
            ? 'admin key rejected (401) — VITE_ADMIN_KEY must match the gateway ADMIN_API_KEY'
            : err?.response?.data?.detail || err?.message || 'grant failed'
      });
    } finally {
      setBusy(false);
    }
  }

  async function submitRevoke(e) {
    e.preventDefault();
    const jti = revokeForm.jti.trim();
    if (!jti) return;
    setRevokeBusy(true);
    setRevokeResult(null);
    try {
      // exp is omitted deliberately: an operator revoking by hand rarely knows
      // the token's expiry, and the gateway falls back to a 24h TTL. Erring long
      // keeps a killed credential dead; erring short resurrects it.
      const res = await revokeToken({ jti, reason: revokeForm.reason || 'revoked from console' });
      setRevokeResult({ ok: true, text: `revoked ${res.jti} — dead on its next request` });
      setRevokeForm({ jti: '', reason: '' });
      await revocations.refresh();
    } catch (err) {
      setRevokeResult({
        ok: false,
        text: err?.response?.data?.detail || err?.message || 'revoke failed'
      });
    } finally {
      setRevokeBusy(false);
    }
  }

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
        <Stat label="Ownership grants" value={grants.length} />
        <Stat label="Known identities" value={entities.length} />
        <Stat label="Flagged" value={flagged.length} tone={flagged.length ? 'caution' : 'default'} />
        <Stat label="Under cooldown" value={blocked.length} tone={blocked.length ? 'danger' : 'default'} />
        <Stat label="Revoked tokens" value={revoked.length} tone={revoked.length ? 'caution' : 'default'} />
      </div>

      <div className="grid gap-4 lg:grid-cols-[1fr_320px]">
        {/* ---------------------------------------------------------- grants */}
        <div className="glass-panel overflow-hidden rounded-lg">
          <div className="flex flex-wrap items-center gap-3 border-b border-canvas-line px-4 py-3">
            <h2 className="font-display text-sm font-semibold text-ink">Object ownership</h2>
            <input
              type="search"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="filter by object or owner…"
              className="min-w-[180px] flex-1 rounded border border-canvas-line bg-canvas-sunken px-3 py-1.5 font-mono text-[11px] text-ink placeholder:text-ink-faint/60 focus:border-accent focus:outline-none"
            />
            <span className="font-mono text-[10px] text-ink-faint">
              store: {data?.source || '—'}
            </span>
            <button
              onClick={refresh}
              className="rounded border border-canvas-line px-2.5 py-1 font-mono text-[10px] uppercase tracking-caps text-ink-muted hover:border-accent hover:text-accent"
            >
              refresh
            </button>
          </div>

          {state === 'error' && (
            <p className="border-b border-canvas-line bg-risk-danger-dim/30 px-4 py-2 font-mono text-[11px] text-risk-danger">
              {error} — needs GET /admin/ownership; restart the gateway if you are on an older build.
            </p>
          )}

          <div className="max-h-[420px] overflow-auto">
            <table className="w-full border-collapse">
              <thead className="sticky top-0 bg-canvas-sunken">
                <tr className="border-b border-canvas-line text-left font-mono text-[10px] uppercase tracking-caps text-ink-faint">
                  <th className="px-3 py-2 font-semibold">Resource</th>
                  <th className="px-3 py-2 font-semibold">Object</th>
                  <th className="px-3 py-2 font-semibold">Owners</th>
                  <th className="px-3 py-2 text-right font-semibold">Fan-in</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((g) => (
                  <tr key={`${g.resource}/${g.object_id}`} className="border-b border-canvas-line hover:bg-canvas-raised/40">
                    <td className="px-3 py-2 font-mono text-[11px] text-ink-muted">{g.resource}</td>
                    <td className="px-3 py-2 font-mono text-[11px] text-ink">{g.object_id}</td>
                    <td className="px-3 py-2">
                      <div className="flex flex-wrap gap-1">
                        {g.owners.map((o) => (
                          <span key={o} className="rounded bg-canvas-raised px-1.5 py-0.5 font-mono text-[10px] text-ink-muted">
                            {o}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className={`px-3 py-2 text-right font-mono text-[11px] tabular-nums ${g.fan_in > 2 ? 'text-risk-caution' : 'text-ink-faint'}`}>
                      {g.fan_in}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {filtered.length === 0 && state !== 'loading' && (
              <div className="p-6 text-center font-mono text-xs text-ink-faint">
                {grants.length === 0 ? 'No ownership grants provisioned.' : 'No grants match that filter.'}
              </div>
            )}
          </div>
        </div>

        {/* ------------------------------------------------------ provision */}
        <div className="glass-panel h-fit rounded-lg">
          <div className="border-b border-canvas-line px-4 py-3">
            <h2 className="font-display text-sm font-semibold text-ink">Provision a grant</h2>
          </div>
          <form onSubmit={submit} className="space-y-3 p-4">
            <Field label="Resource">
              <input
                value={form.resource}
                onChange={(e) => setForm((f) => ({ ...f, resource: e.target.value }))}
                placeholder="account"
                className="w-full rounded border border-canvas-line bg-canvas-sunken px-3 py-1.5 font-mono text-[11px] text-ink focus:border-accent focus:outline-none"
              />
            </Field>
            <Field label="Object ID">
              <input
                value={form.objectId}
                onChange={(e) => setForm((f) => ({ ...f, objectId: e.target.value }))}
                placeholder="1004"
                className="w-full rounded border border-canvas-line bg-canvas-sunken px-3 py-1.5 font-mono text-[11px] text-ink focus:border-accent focus:outline-none"
              />
            </Field>
            <Field label="Subject">
              <input
                value={form.subject}
                onChange={(e) => setForm((f) => ({ ...f, subject: e.target.value }))}
                placeholder="dave"
                className="w-full rounded border border-canvas-line bg-canvas-sunken px-3 py-1.5 font-mono text-[11px] text-ink focus:border-accent focus:outline-none"
              />
            </Field>

            <button
              type="submit"
              disabled={busy || !form.resource || !form.objectId || !form.subject}
              className="w-full rounded bg-accent/15 px-3 py-2 font-mono text-[11px] uppercase tracking-caps text-accent transition-colors hover:bg-accent/25 disabled:cursor-not-allowed disabled:opacity-40"
            >
              {busy ? 'granting…' : 'grant ownership'}
            </button>

            {result && (
              <p className={`font-mono text-[10px] leading-relaxed ${result.ok ? 'text-risk-safe' : 'text-risk-danger'}`}>
                {result.text}
              </p>
            )}

            <p className="border-t border-canvas-line pt-3 font-mono text-[10px] leading-relaxed text-ink-faint">
              Takes effect on the next request — no restart. Grants survive
              <span className="text-ink-muted"> POST /admin/reset</span> by design: wiping them
              would leave every object unowned, which makes the next BOLA test silently pass.
            </p>
          </form>
        </div>
      </div>

      {/* ------------------------------------------------------- revocation */}
      <div className="grid gap-4 lg:grid-cols-[1fr_320px]">
        <div className="glass-panel overflow-hidden rounded-lg">
          <div className="flex flex-wrap items-center gap-3 border-b border-canvas-line px-4 py-3">
            <h2 className="font-display text-sm font-semibold text-ink">
              Revoked tokens
              <span className="ml-2 font-mono text-[10px] font-normal text-ink-faint">
                checked in step 1, before anything else — entries self-expire at token expiry
              </span>
            </h2>
            <button
              onClick={revocations.refresh}
              className="ml-auto rounded border border-canvas-line px-2.5 py-1 font-mono text-[10px] uppercase tracking-caps text-ink-muted hover:border-accent hover:text-accent"
            >
              refresh
            </button>
          </div>
          <div className="max-h-[240px] overflow-auto">
            <table className="w-full border-collapse">
              <thead className="sticky top-0 bg-canvas-sunken">
                <tr className="border-b border-canvas-line text-left font-mono text-[10px] uppercase tracking-caps text-ink-faint">
                  <th className="px-3 py-2 font-semibold">Token ID (jti)</th>
                  <th className="px-3 py-2 font-semibold">Reason</th>
                  <th className="px-3 py-2 font-semibold">Revoked</th>
                  <th className="px-3 py-2 font-semibold">Expires</th>
                </tr>
              </thead>
              <tbody>
                {revoked.map((r) => (
                  <tr key={r.jti} className="border-b border-canvas-line hover:bg-canvas-raised/40">
                    <td className="px-3 py-2 font-mono text-[11px] text-risk-caution">{r.jti}</td>
                    <td className="px-3 py-2 font-mono text-[11px] text-ink-muted">{r.reason || '—'}</td>
                    <td className="px-3 py-2 font-mono text-[11px] text-ink-faint">
                      {r.revoked_at ? new Date(r.revoked_at * 1000).toLocaleTimeString() : '—'}
                    </td>
                    <td className="px-3 py-2 font-mono text-[11px] text-ink-faint">
                      {r.expires_at ? new Date(r.expires_at * 1000).toLocaleTimeString() : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {revoked.length === 0 && (
              <div className="p-6 text-center font-mono text-xs text-ink-faint">
                No tokens revoked. Revoking one kills that session on its very next request.
              </div>
            )}
          </div>
        </div>

        <div className="glass-panel h-fit rounded-lg">
          <div className="border-b border-canvas-line px-4 py-3">
            <h2 className="font-display text-sm font-semibold text-ink">Revoke a token</h2>
          </div>
          <form onSubmit={submitRevoke} className="space-y-3 p-4">
            <Field label="Token ID (jti)">
              <input
                value={revokeForm.jti}
                onChange={(e) => setRevokeForm((f) => ({ ...f, jti: e.target.value }))}
                placeholder="sess-a1b2c3d4"
                className="w-full rounded border border-canvas-line bg-canvas-sunken px-3 py-1.5 font-mono text-[11px] text-ink focus:border-accent focus:outline-none"
              />
            </Field>
            <Field label="Reason">
              <input
                value={revokeForm.reason}
                onChange={(e) => setRevokeForm((f) => ({ ...f, reason: e.target.value }))}
                placeholder="credential suspected stolen"
                className="w-full rounded border border-canvas-line bg-canvas-sunken px-3 py-1.5 font-mono text-[11px] text-ink focus:border-accent focus:outline-none"
              />
            </Field>
            <button
              type="submit"
              disabled={revokeBusy || !revokeForm.jti.trim()}
              className="w-full rounded bg-risk-danger-dim/60 px-3 py-2 font-mono text-[11px] uppercase tracking-caps text-risk-danger transition-colors hover:bg-risk-danger-dim disabled:cursor-not-allowed disabled:opacity-40"
            >
              {revokeBusy ? 'revoking…' : 'revoke token'}
            </button>
            {revokeResult && (
              <p className={`font-mono text-[10px] leading-relaxed ${revokeResult.ok ? 'text-risk-safe' : 'text-risk-danger'}`}>
                {revokeResult.text}
              </p>
            )}
            <p className="border-t border-canvas-line pt-3 font-mono text-[10px] leading-relaxed text-ink-faint">
              Revocation is checked only after the signature verifies, so a forged
              token never reaches the denylist. A revoked token scores 90 — the same
              as a forgery, because presenting one means the session was killed and
              is being replayed anyway.
            </p>
          </form>
        </div>
      </div>

      {/* ------------------------------------------------------- identities */}
      <div className="glass-panel overflow-hidden rounded-lg">
        <div className="border-b border-canvas-line px-4 py-3">
          <h2 className="font-display text-sm font-semibold text-ink">
            Identities
            <span className="ml-2 font-mono text-[10px] font-normal text-ink-faint">
              roles drive BFLA · cooldowns are applied autonomously
            </span>
          </h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full border-collapse">
            <thead>
              <tr className="border-b border-canvas-line text-left font-mono text-[10px] uppercase tracking-caps text-ink-faint">
                <th className="px-3 py-2 font-semibold">Subject</th>
                <th className="px-3 py-2 font-semibold">Roles</th>
                <th className="px-3 py-2 text-right font-semibold">Risk</th>
                <th className="px-3 py-2 text-right font-semibold">Requests</th>
                <th className="px-3 py-2 text-right font-semibold">Objects</th>
                <th className="px-3 py-2 font-semibold">Status</th>
              </tr>
            </thead>
            <tbody>
              {entities.map((e) => (
                <tr key={e.subject} className="border-b border-canvas-line hover:bg-canvas-raised/40">
                  <td className="px-3 py-2 font-mono text-[11px] text-ink">{e.subject}</td>
                  <td className="px-3 py-2">
                    {e.roles?.length ? (
                      <div className="flex flex-wrap gap-1">
                        {e.roles.map((r) => (
                          <span
                            key={r}
                            className={`rounded px-1.5 py-0.5 font-mono text-[10px] ${
                              r === 'admin' ? 'bg-accent/15 text-accent' : 'bg-canvas-raised text-ink-muted'
                            }`}
                          >
                            {r}
                          </span>
                        ))}
                      </div>
                    ) : (
                      <span className="font-mono text-[10px] text-ink-faint">anonymous</span>
                    )}
                  </td>
                  <td className={`px-3 py-2 text-right font-mono text-[11px] tabular-nums ${
                    e.risk_score > 60 ? 'text-risk-danger' : e.risk_score > 30 ? 'text-risk-caution' : 'text-risk-safe'
                  }`}>
                    {String(Math.round(e.risk_score)).padStart(3, '0')}
                  </td>
                  <td className="px-3 py-2 text-right font-mono text-[11px] tabular-nums text-ink-muted">{e.request_count}</td>
                  <td className="px-3 py-2 text-right font-mono text-[11px] tabular-nums text-ink-muted">{e.objects}</td>
                  <td className="px-3 py-2">
                    <span className={`rounded px-1.5 py-0.5 font-mono text-[10px] uppercase ${
                      e.status === 'blocked'
                        ? 'bg-risk-danger-dim/60 text-risk-danger'
                        : e.status === 'flagged'
                          ? 'bg-risk-caution-dim/60 text-risk-caution'
                          : 'bg-canvas-raised text-ink-faint'
                    }`}>
                      {e.status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {entities.length === 0 && (
            <div className="p-6 text-center font-mono text-xs text-ink-faint">No identities seen yet.</div>
          )}
        </div>
      </div>

      {incidents.length > 0 && (
        <div className="glass-panel overflow-hidden rounded-lg">
          <div className="border-b border-canvas-line px-4 py-3">
            <h2 className="font-display text-sm font-semibold text-ink">
              Autonomous cooldowns
              <span className="ml-2 font-mono text-[10px] font-normal text-ink-faint">
                applied by the gateway, self-expiring
              </span>
            </h2>
          </div>
          <div className="divide-y divide-canvas-line">
            {incidents.map((i) => (
              <div key={i.id} className="px-4 py-3 font-mono text-[11px]">
                <div className="flex flex-wrap items-baseline gap-2">
                  <span className="text-risk-danger">{i.target}</span>
                  <span className="text-ink-faint">({i.targetType})</span>
                  <span className="text-ink-muted">· {i.reason}</span>
                  <span className="ml-auto text-ink-faint">
                    escalation #{i.escalationCount} · {i.cooldownSec}s
                  </span>
                </div>
                {i.narrative && <p className="mt-1 text-ink-faint">{i.narrative}</p>}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function Field({ label, children }) {
  return (
    <label className="block">
      <span className="label-caps mb-1 block text-ink-faint">{label}</span>
      {children}
    </label>
  );
}

function Stat({ label, value, tone = 'default' }) {
  const toneText = {
    default: 'text-ink',
    caution: 'text-risk-caution',
    danger: 'text-risk-danger'
  }[tone];
  return (
    <div className="glass-panel rounded-lg px-4 py-3">
      <div className="label-caps mb-1 text-ink-faint">{label}</div>
      <div className={`font-mono text-2xl font-semibold tabular-nums ${toneText}`}>{value}</div>
    </div>
  );
}
