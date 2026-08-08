import { useMemo, useState } from 'react';
import { HUNTS, runHunts } from '../api/analysis.js';
import { getLlmThreatSummary, getLlmExecutiveReportDownloadUrl, simulateAttack } from '../api/gateway.js';
import { useResource } from '../hooks/useResource.js';

function riskColor(score) {
  if (score > 60) return 'text-risk-danger';
  if (score > 30) return 'text-risk-caution';
  return 'text-risk-safe';
}

export default function ThreatHunt({ alerts, entities }) {
  const [activeHunt, setActiveHunt] = useState('bola');
  const [selectedSubject, setSelectedSubject] = useState(null);
  const [simulating, setSimulating] = useState(false);
  const [simResult, setSimResult] = useState(null);
  const llmSummaryResource = useResource(getLlmThreatSummary);

  const results = useMemo(() => runHunts(alerts), [alerts]);

  const hunt = HUNTS.find((h) => h.id === activeHunt);
  const rows = results[activeHunt] || [];

  const timeline = useMemo(() => {
    if (!selectedSubject) return [];
    return alerts.filter((a) => a.subject === selectedSubject).sort((a, b) => a.ts - b.ts);
  }, [alerts, selectedSubject]);

  const selectedEntity = entities.find((e) => e.subject === selectedSubject);
  const downloadUrl = getLlmExecutiveReportDownloadUrl();

  return (
    <div className="space-y-4">
      <div className="glass-panel rounded-lg px-4 py-3">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-canvas-line pb-2.5">
          <div className="flex items-center gap-2">
            <span className="material-symbols-outlined text-accent text-[18px]">psychology</span>
            <h3 className="font-display text-sm font-bold uppercase tracking-wider text-accent">LangChain Threat Intelligence Narrative</h3>
          </div>
          <div className="flex items-center gap-3">
            <span className="font-mono text-[10px] text-ink-faint">
              {llmSummaryResource.data?.engine || 'LangChain v1.3.14 + PromptTemplate'}
            </span>
            <a
              href={downloadUrl}
              target="_blank"
              rel="noreferrer"
              className="flex items-center gap-1 rounded bg-accent/15 px-2.5 py-1 font-mono text-[10px] uppercase tracking-caps text-accent transition-colors hover:bg-accent/25"
            >
              <span className="material-symbols-outlined text-[14px]">download</span>
              Download Executive Report (.md)
            </a>
          </div>
        </div>

        <div className="mt-2.5 space-y-1">
          {llmSummaryResource.data?.summary_bullets ? (
            llmSummaryResource.data.summary_bullets.map((b, idx) => (
              <p key={idx} className="font-mono text-[11px] leading-relaxed text-ink-muted">
                • {b}
              </p>
            ))
          ) : (
            <p className="font-mono text-[11px] leading-relaxed text-ink-faint">
              Analyzing live threat window telemetry with LangChain prompt template...
            </p>
          )}
        </div>
      </div>

      {/* Interactive Red Team Sandbox Panel */}
      <div className="glass-panel rounded-lg px-4 py-3">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-canvas-line pb-2.5">
          <div className="flex items-center gap-2">
            <span className="material-symbols-outlined text-risk-danger text-[18px]">terminal</span>
            <h3 className="font-display text-sm font-bold uppercase tracking-wider text-risk-danger">
              Red Team Attack Simulation Sandbox
            </h3>
            <span className="rounded bg-risk-danger-dim/50 px-2 py-0.5 font-mono text-[9px] text-risk-danger">
              Live Inline Attack Generator
            </span>
          </div>
          <span className="font-mono text-[10px] text-ink-faint">
            Trigger live attacks to verify real-time blocking & graph detection
          </span>
        </div>

        <div className="mt-3 flex flex-wrap items-center gap-2">
          {[
            { id: 'bola', label: 'BOLA Attack (API1)' },
            { id: 'bfla', label: 'BFLA Admin Escalation (API5)' },
            { id: 'alg_none', label: 'JWT alg=none Bypass (API2)' },
            { id: 'missing_token', label: 'Missing Auth Header' },
            { id: 'enumeration', label: 'BOLA Object ID Probe' }
          ].map((type) => (
            <button
              key={type.id}
              disabled={simulating}
              onClick={async () => {
                setSimulating(true);
                setSimResult(null);
                try {
                  const res = await simulateAttack(type.id);
                  setSimResult(res);
                } catch (e) {
                  setSimResult({ error: e.message });
                } finally {
                  setSimulating(false);
                }
              }}
              className="rounded border border-risk-danger/30 bg-risk-danger-dim/20 px-3 py-1 font-mono text-[11px] font-semibold text-risk-danger transition-colors hover:bg-risk-danger/30 disabled:opacity-50"
            >
              ⚡ Run {type.label}
            </button>
          ))}
        </div>

        {simResult && (
          <div className="mt-3 rounded border border-white/10 bg-canvas-sunken p-3 font-mono text-xs text-ink">
            <div className="flex items-center justify-between border-b border-white/10 pb-1.5 mb-2">
              <span className="font-bold text-accent">Simulation Outcome: {simResult.simulation?.name}</span>
              <span className={`rounded px-2 py-0.5 text-[10px] font-bold ${
                simResult.result?.action === 'block' ? 'bg-risk-danger/20 text-risk-danger' : 'bg-emerald-500/20 text-emerald-400'
              }`}>
                ACTION: {simResult.result?.action?.toUpperCase() || 'UNKNOWN'}
              </span>
            </div>
            <p className="text-[11px] text-ink-muted">{simResult.simulation?.description}</p>
            {simResult.result?.signals && (
              <div className="mt-2 space-y-1">
                <span className="text-[10px] uppercase text-ink-faint">Fired Signals:</span>
                {simResult.result.signals.map((s, idx) => (
                  <div key={idx} className="rounded bg-canvas-raised px-2 py-1 text-[11px] text-risk-danger">
                    [{s.detector}] {s.owasp} — {s.evidence}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      <div className="grid gap-4 lg:grid-cols-[260px_1fr]">
        {/* ------------------------------------------------------ hunt list */}
        <div className="glass-panel h-fit overflow-hidden rounded-lg">
          <div className="border-b border-canvas-line px-4 py-3">
            <h2 className="font-display text-sm font-semibold text-ink">Saved hunts</h2>
          </div>
          <div className="divide-y divide-canvas-line">
            {HUNTS.map((h) => {
              const n = (results[h.id] || []).length;
              return (
                <button
                  key={h.id}
                  onClick={() => {
                    setActiveHunt(h.id);
                    setSelectedSubject(null);
                  }}
                  className={`flex w-full items-center gap-2 px-4 py-2.5 text-left transition-colors ${
                    activeHunt === h.id ? 'bg-accent/10' : 'hover:bg-canvas-raised/60'
                  }`}
                >
                  <span className={`font-mono text-[11px] ${activeHunt === h.id ? 'text-accent' : 'text-ink-muted'}`}>
                    {h.name}
                  </span>
                  <span
                    className={`ml-auto rounded px-1.5 py-0.5 font-mono text-[10px] tabular-nums ${
                      n > 0 ? 'bg-risk-danger-dim/60 text-risk-danger' : 'bg-canvas-raised text-ink-faint'
                    }`}
                  >
                    {n}
                  </span>
                </button>
              );
            })}
          </div>
        </div>

        {/* ---------------------------------------------------- hunt results */}
        <div className="space-y-4">
          <div className="glass-panel overflow-hidden rounded-lg">
            <div className="border-b border-canvas-line px-4 py-3">
              <h2 className="font-display text-sm font-semibold text-ink">{hunt.name}</h2>
              <p className="mt-0.5 font-mono text-[11px] text-ink-faint">
                {hunt.question}
                {hunt.technique && <span className="ml-2 text-ink-muted">{hunt.technique}</span>}
              </p>
            </div>

            {rows.length === 0 ? (
              <div className="p-8 text-center font-mono text-xs text-ink-faint">
                No identities match this hunt in the current window.
                {alerts.length === 0 && ' Run the attack simulator to generate traffic.'}
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full border-collapse">
                  <thead>
                    <tr className="border-b border-canvas-line text-left font-mono text-[10px] uppercase tracking-caps text-ink-faint">
                      <th className="px-3 py-2 font-semibold">Subject</th>
                      <th className="px-3 py-2 text-right font-semibold">Events</th>
                      <th className="px-3 py-2 text-right font-semibold">Blocked</th>
                      <th className="px-3 py-2 text-right font-semibold">Peak risk</th>
                      <th className="px-3 py-2 text-right font-semibold">Paths</th>
                      <th className="px-3 py-2 text-right font-semibold">IPs</th>
                      <th className="px-3 py-2 font-semibold">Techniques</th>
                      <th className="px-3 py-2 text-right font-semibold">Span</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map((r) => (
                      <tr
                        key={r.subject}
                        onClick={() => setSelectedSubject(r.subject === selectedSubject ? null : r.subject)}
                        className={`cursor-pointer border-b border-canvas-line transition-colors ${
                          selectedSubject === r.subject ? 'bg-accent/10' : 'hover:bg-canvas-raised/40'
                        }`}
                      >
                        <td className="px-3 py-2 font-mono text-[11px] text-ink">{r.subject}</td>
                        <td className="px-3 py-2 text-right font-mono text-[11px] tabular-nums text-ink-muted">{r.count}</td>
                        <td className={`px-3 py-2 text-right font-mono text-[11px] tabular-nums ${r.blocked ? 'text-risk-danger' : 'text-ink-faint'}`}>
                          {r.blocked}
                        </td>
                        <td className={`px-3 py-2 text-right font-mono text-[11px] tabular-nums ${riskColor(r.peakRisk)}`}>
                          {String(Math.round(r.peakRisk)).padStart(3, '0')}
                        </td>
                        <td className="px-3 py-2 text-right font-mono text-[11px] tabular-nums text-ink-muted">{r.paths}</td>
                        <td className="px-3 py-2 text-right font-mono text-[11px] tabular-nums text-ink-muted">{r.ips}</td>
                        <td className="px-3 py-2">
                          <div className="flex flex-wrap gap-1">
                            {r.techniques.map((t) => (
                              <span key={t} className="rounded bg-canvas-raised px-1.5 py-0.5 font-mono text-[10px] text-ink-muted">
                                {t}
                              </span>
                            ))}
                          </div>
                        </td>
                        <td className="px-3 py-2 text-right font-mono text-[11px] tabular-nums text-ink-faint">
                          {r.first && r.last ? `${Math.max(0, Math.round((r.last - r.first) / 1000))}s` : '—'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* ------------------------------------------------ attack chain */}
          {selectedSubject && (
            <div className="glass-panel overflow-hidden rounded-lg">
              <div className="flex flex-wrap items-center gap-3 border-b border-canvas-line px-4 py-3">
                <h2 className="font-display text-sm font-semibold text-ink">
                  Attack chain · <span className="font-mono text-accent">{selectedSubject}</span>
                </h2>
                {selectedEntity && (
                  <span className="font-mono text-[10px] text-ink-faint">
                    risk {String(Math.round(selectedEntity.risk_score)).padStart(3, '0')} ·{' '}
                    {selectedEntity.request_count} lifetime requests · {selectedEntity.status}
                  </span>
                )}
                <button
                  onClick={() => setSelectedSubject(null)}
                  className="ml-auto rounded border border-canvas-line px-2 py-0.5 font-mono text-[10px] uppercase tracking-caps text-ink-faint hover:border-accent hover:text-accent"
                >
                  close
                </button>
              </div>

              <div className="max-h-[380px] overflow-y-auto">
                {timeline.map((a, i) => {
                  const tone =
                    a.decision === 'block'
                      ? 'border-l-risk-danger'
                      : a.decision === 'challenge'
                        ? 'border-l-risk-caution'
                        : 'border-l-risk-safe';
                  return (
                    <div key={a.id} className={`border-b border-canvas-line border-l-[3px] px-4 py-2 ${tone}`}>
                      <div className="flex flex-wrap items-baseline gap-2 font-mono text-[11px]">
                        <span className="tabular-nums text-ink-faint">{String(i + 1).padStart(2, '0')}</span>
                        <span className="text-ink-faint">{new Date(a.timestamp).toLocaleTimeString()}</span>
                        <span className={riskColor(a.risk_score)}>{a.decision}</span>
                        <span className="text-ink-muted">{a.method}</span>
                        <span className="text-ink">{a.path}</span>
                        <span className="ml-auto text-ink-faint">{a.ip}</span>
                      </div>
                      {a.narrative && <p className="mt-1 font-mono text-[10px] text-ink-faint">{a.narrative}</p>}
                      {a.signals?.length > 0 && (
                        <div className="mt-1 flex flex-wrap gap-1">
                          {a.signals.map((s) => (
                            <span key={s.signal} className="rounded bg-canvas-raised px-1.5 py-0.5 font-mono text-[10px] text-ink-muted">
                              {s.signal} · {s.owasp} · {s.mitre}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  );
                })}
                {timeline.length === 0 && (
                  <div className="p-6 text-center font-mono text-xs text-ink-faint">
                    No events for this subject in the current window.
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
