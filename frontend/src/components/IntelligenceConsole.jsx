import { useMemo, useState, useCallback, memo } from 'react';
import { useResource } from '../hooks/useResource.js';
import { getKillChains, getThreatForecast, getThreatIntel, getAdaptiveTrust, getAutoHarden } from '../api/gateway.js';

/**
 * Unified Innovation Console — surfaces all 5 new intelligence modules
 * in a tabbed card layout with live gateway data.
 */

/* ── shared helpers ─────────────────────────────────────────────── */

function Badge({ tone = 'default', children }) {
  const cls = {
    critical: 'bg-risk-danger-dim/60 text-risk-danger',
    high:     'bg-risk-caution-dim/60 text-risk-caution',
    medium:   'bg-accent/15 text-accent',
    safe:     'bg-risk-safe/20 text-risk-safe',
    default:  'bg-canvas-raised text-ink-faint',
  }[tone] || 'bg-canvas-raised text-ink-faint';
  return <span className={`rounded px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-caps ${cls}`}>{children}</span>;
}

function Metric({ label, value, tone }) {
  const cls = {
    danger:  'text-risk-danger text-glow-danger',
    caution: 'text-risk-caution',
    safe:    'text-risk-safe',
    accent:  'text-accent',
  }[tone] || 'text-ink';
  return (
    <div className="flex flex-col items-center gap-0.5 px-3">
      <span className={`font-display text-2xl font-bold tabular-nums ${cls}`}>{value}</span>
      <span className="label-caps text-ink-faint">{label}</span>
    </div>
  );
}

const SEV_TONE = { critical: 'critical', high: 'high', medium: 'medium', low: 'safe' };
const HEALTH_TONE = { compromised: 'danger', degraded: 'caution', moderate: 'caution', healthy: 'safe' };

/* ── Kill Chain Panel ───────────────────────────────────────────── */

function KillChainPanel() {
  const { data, state } = useResource(getKillChains);
  if (state === 'loading') return <Loading label="Reconstructing kill chains…" />;
  if (!data) return <Empty label="No kill chain data available." />;

  const chains = data.chains || [];
  const heatmap = data.phase_heatmap || {};

  return (
    <div className="space-y-4">
      {/* Stats row */}
      <div className="flex flex-wrap items-center justify-center gap-6 py-2">
        <Metric label="Total chains" value={data.total_chains} />
        <Metric label="Critical" value={data.critical_chains} tone={data.critical_chains > 0 ? 'danger' : undefined} />
        <Metric label="High" value={data.high_chains} tone={data.high_chains > 0 ? 'caution' : undefined} />
      </div>

      {/* Phase heatmap bar */}
      <div className="glass-panel rounded-lg p-3">
        <h4 className="label-caps text-ink-faint mb-2">Kill Chain Phase Coverage</h4>
        <div className="grid grid-cols-6 gap-2">
          {(data.phase_definitions || []).map((pd) => {
            const h = heatmap[pd.phase_id] || {};
            const pct = h.percentage || 0;
            return (
              <div key={pd.phase_id} className="text-center">
                <div className="relative mx-auto mb-1 h-14 w-14 rounded-lg border border-canvas-line bg-canvas-raised flex items-center justify-center">
                  <span className="material-symbols-outlined text-[22px]" style={{ color: pct > 50 ? '#ffb4ab' : pct > 0 ? '#ffb95f' : '#8c909f' }}>
                    {pd.icon}
                  </span>
                  {pct > 0 && (
                    <span className="absolute -right-1 -top-1 rounded bg-risk-danger px-1 py-0.5 font-mono text-[8px] font-bold text-canvas">{pct}%</span>
                  )}
                </div>
                <span className="font-mono text-[9px] text-ink-muted leading-tight block">{pd.phase}</span>
                <span className="font-mono text-[8px] text-ink-faint">{pd.mitre_id}</span>
              </div>
            );
          })}
        </div>
      </div>

      {/* Chain list */}
      {chains.length === 0 ? (
        <Empty label="No attack kill chains reconstructed in the current window." />
      ) : (
        <div className="space-y-2">
          {chains.slice(0, 8).map((chain, idx) => (
            <div key={chain.subject} className="glass-panel rounded-lg p-3">
              <div className="flex items-center justify-between gap-2 mb-2">
                <div className="flex items-center gap-2 min-w-0">
                  <Badge tone={SEV_TONE[chain.severity]}>{chain.severity}</Badge>
                  <span className="font-mono text-xs text-ink truncate">{chain.subject}</span>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <span className="font-mono text-[10px] text-ink-faint">{chain.total_events} events</span>
                  {chain.mitigated && <Badge tone="safe">mitigated</Badge>}
                </div>
              </div>
              {/* Kill chain progress bar */}
              <div className="flex items-center gap-1">
                {chain.phase_progression.map((p) => (
                  <div
                    key={p.phase_id}
                    className={`flex-1 h-2 rounded-full transition-all duration-500 ${
                      p.status === 'completed' ? 'bg-risk-danger' : 'bg-canvas-raised'
                    }`}
                    title={`${p.phase} (${p.mitre_id}) — ${p.status === 'completed' ? `${p.event_count} events` : 'not observed'}`}
                  />
                ))}
                <span className="ml-2 font-mono text-xs tabular-nums text-risk-danger font-bold">{chain.completion_pct}%</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

/* ── Threat Forecast Panel ──────────────────────────────────────── */

function ForecastPanel() {
  const { data, state } = useResource(getThreatForecast);
  if (state === 'loading') return <Loading label="Computing threat forecast…" />;
  if (!data) return <Empty label="No forecast data available." />;

  const cs = data.current_state || {};
  const fc = data.forecast || {};
  const timeline = data.timeline || [];

  // Mini sparkline
  const sparkValues = timeline.map((t) => t.threats);
  const sparkMax = Math.max(...sparkValues, 1);
  const sparkWidth = 320;
  const sparkHeight = 48;
  const points = sparkValues
    .map((v, i) => `${(i / Math.max(sparkValues.length - 1, 1)) * sparkWidth},${sparkHeight - (v / sparkMax) * sparkHeight}`)
    .join(' ');

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-center gap-6 py-2">
        <Metric label="Threat Level" value={cs.threat_level || 'N/A'} tone={
          cs.threat_level === 'CRITICAL' ? 'danger' : cs.threat_level === 'HIGH' ? 'caution' : 'safe'
        } />
        <Metric label="Trend" value={cs.threat_trend || 'N/A'} />
        <Metric label="Current Rate" value={`${cs.current_rate || 0}/min`} tone="accent" />
        <Metric label="Avg Rate" value={`${cs.average_rate || 0}/min`} />
      </div>

      {/* Sparkline */}
      <div className="glass-panel rounded-lg p-4">
        <h4 className="label-caps text-ink-faint mb-3">60-Minute Threat Volume Trend</h4>
        <svg width={sparkWidth} height={sparkHeight} className="w-full" viewBox={`0 0 ${sparkWidth} ${sparkHeight}`} preserveAspectRatio="none">
          <polyline
            points={points}
            fill="none"
            stroke="#adc6ff"
            strokeWidth="1.5"
            strokeLinejoin="round"
          />
          {/* Forecast extension */}
          {fc.predicted_threats && fc.predicted_threats.length > 0 && (() => {
            const startX = sparkWidth;
            const forecastPts = fc.predicted_threats
              .map((v, i) => `${startX + ((i + 1) / fc.predicted_threats.length) * 60},${sparkHeight - (v / sparkMax) * sparkHeight}`)
              .join(' ');
            return (
              <polyline
                points={`${sparkWidth},${sparkHeight - (sparkValues[sparkValues.length - 1] / sparkMax) * sparkHeight} ${forecastPts}`}
                fill="none"
                stroke="#ffb95f"
                strokeWidth="1.5"
                strokeDasharray="4,3"
                strokeLinejoin="round"
              />
            );
          })()}
        </svg>
        <div className="flex justify-between font-mono text-[9px] text-ink-faint mt-1">
          <span>-60m</span>
          <span>now</span>
        </div>
      </div>

      {/* Diversity assessment */}
      <div className="glass-panel rounded-lg px-4 py-3">
        <div className="flex items-center gap-2 mb-1">
          <span className="material-symbols-outlined text-accent text-[16px]">analytics</span>
          <h4 className="label-caps text-ink-faint">Entropy Analysis</h4>
        </div>
        <p className="font-mono text-[11px] text-ink-muted">{cs.diversity_assessment}</p>
        <div className="mt-2 flex items-center gap-3 font-mono text-[10px]">
          <span className="text-ink-faint">Entropy: <span className="text-accent">{cs.current_entropy}</span></span>
          <span className="text-ink-faint">Forecast trend: <span className={fc.trend_per_minute > 0 ? 'text-risk-danger' : 'text-risk-safe'}>{fc.trend_per_minute > 0 ? '+' : ''}{fc.trend_per_minute}/min</span></span>
          <span className="text-ink-faint">Confidence: <span className="text-accent">±{fc.confidence_band}</span></span>
        </div>
      </div>
    </div>
  );
}

/* ── Threat Intel Panel ─────────────────────────────────────────── */

function ThreatIntelPanel() {
  const { data, state } = useResource(getThreatIntel);
  if (state === 'loading') return <Loading label="Correlating threat intelligence…" />;
  if (!data) return <Empty label="No threat intel available." />;

  const s = data.summary || {};
  const iocs = data.iocs || [];

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-center gap-6 py-2">
        <Metric label="Threat Actors" value={s.total_threat_actors || 0} />
        <Metric label="Confirmed" value={s.confirmed_threats || 0} tone={s.confirmed_threats > 0 ? 'danger' : undefined} />
        <Metric label="Bots Detected" value={s.automated_bots_detected || 0} tone={s.automated_bots_detected > 0 ? 'caution' : undefined} />
        <Metric label="Campaigns" value={s.coordinated_campaigns || 0} tone={s.coordinated_campaigns > 0 ? 'danger' : undefined} />
      </div>

      {iocs.length === 0 ? (
        <Empty label="No IOCs generated in the current window." />
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full border-collapse">
            <thead>
              <tr className="border-b border-canvas-line text-left font-mono text-[10px] uppercase tracking-caps text-ink-faint">
                <th className="px-3 py-2 font-semibold">Subject</th>
                <th className="px-3 py-2 font-semibold">Class</th>
                <th className="px-3 py-2 text-right font-semibold">Block%</th>
                <th className="px-3 py-2 font-semibold">Pattern</th>
                <th className="px-3 py-2 font-semibold">Fingerprint</th>
                <th className="px-3 py-2 text-right font-semibold">Peak</th>
              </tr>
            </thead>
            <tbody>
              {iocs.slice(0, 12).map((ioc) => (
                <tr key={ioc.subject} className="border-b border-canvas-line hover:bg-canvas-raised/40 transition-colors">
                  <td className="px-3 py-2 font-mono text-[11px] text-ink truncate max-w-[160px]">{ioc.subject}</td>
                  <td className="px-3 py-2"><Badge tone={SEV_TONE[ioc.classification === 'confirmed_threat' ? 'critical' : ioc.classification === 'probable_threat' ? 'high' : 'medium']}>{ioc.classification.replace('_', ' ')}</Badge></td>
                  <td className="px-3 py-2 text-right font-mono text-[11px] tabular-nums text-risk-danger">{ioc.block_rate}%</td>
                  <td className="px-3 py-2">
                    <Badge tone={ioc.timing_analysis?.pattern === 'automated_bot' ? 'critical' : ioc.timing_analysis?.pattern === 'scripted_tool' ? 'high' : 'default'}>
                      {ioc.timing_analysis?.pattern?.replace('_', ' ') || '—'}
                    </Badge>
                  </td>
                  <td className="px-3 py-2 font-mono text-[10px] text-ink-faint">{ioc.fingerprint}</td>
                  <td className="px-3 py-2 text-right font-mono text-[11px] tabular-nums text-risk-danger">{String(ioc.peak_risk).padStart(3, '0')}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Coordinated campaigns */}
      {(data.coordinated_campaigns || []).length > 0 && (
        <div className="glass-panel rounded-lg px-4 py-3">
          <h4 className="label-caps text-risk-danger mb-2">⚠ Coordinated Campaigns Detected</h4>
          {data.coordinated_campaigns.map((c) => (
            <div key={c.fingerprint} className="border-l-[3px] border-l-risk-danger bg-canvas-raised px-3 py-2 mb-1 rounded-r">
              <span className="font-mono text-[11px] text-ink">{c.subject_count} subjects sharing fingerprint </span>
              <span className="font-mono text-[10px] text-accent">{c.fingerprint}</span>
              <div className="font-mono text-[10px] text-ink-faint mt-0.5">{c.subjects.join(', ')}</div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

/* ── Adaptive Trust Panel ───────────────────────────────────────── */

function TrustPanel() {
  const { data, state } = useResource(getAdaptiveTrust);
  if (state === 'loading') return <Loading label="Computing trust scores…" />;
  if (!data) return <Empty label="No trust data available." />;

  const scores = data.scores || [];
  const tierDist = data.tier_distribution || {};

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-center gap-6 py-2">
        <Metric label="Health" value={data.overall_health || 'N/A'} tone={HEALTH_TONE[data.overall_health]} />
        <Metric label="Avg Trust" value={data.average_trust || 0} tone={data.average_trust >= 50 ? 'safe' : 'caution'} />
        <Metric label="Entities" value={data.total_entities || 0} />
      </div>

      {/* Tier distribution bar */}
      <div className="glass-panel rounded-lg p-3">
        <h4 className="label-caps text-ink-faint mb-2">Trust Tier Distribution</h4>
        <div className="flex h-4 w-full overflow-hidden rounded-full bg-canvas-raised">
          {(data.tier_definitions || []).map((td) => {
            const count = tierDist[td.tier] || 0;
            const pct = (count / Math.max(data.total_entities, 1)) * 100;
            if (pct === 0) return null;
            const bg = {
              safe: 'bg-risk-safe', caution: 'bg-risk-caution', danger: 'bg-risk-danger',
            }[td.color] || 'bg-ink-faint';
            return <div key={td.tier} className={`${bg} transition-all duration-500`} style={{ width: `${pct}%` }} title={`${td.tier}: ${count}`} />;
          })}
        </div>
        <div className="flex justify-between mt-1 font-mono text-[9px] text-ink-faint">
          {(data.tier_definitions || []).map((td) => (
            <span key={td.tier}>{td.tier}: {tierDist[td.tier] || 0}</span>
          ))}
        </div>
      </div>

      {/* Score table */}
      {scores.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full border-collapse">
            <thead>
              <tr className="border-b border-canvas-line text-left font-mono text-[10px] uppercase tracking-caps text-ink-faint">
                <th className="px-3 py-2 font-semibold">Subject</th>
                <th className="px-3 py-2 text-right font-semibold">Trust</th>
                <th className="px-3 py-2 font-semibold">Tier</th>
                <th className="px-3 py-2 text-right font-semibold">Clean%</th>
                <th className="px-3 py-2 text-right font-semibold">Blocked</th>
                <th className="px-3 py-2 font-semibold">Policy Effect</th>
              </tr>
            </thead>
            <tbody>
              {scores.slice(0, 15).map((s) => {
                const toneMap = { safe: 'text-risk-safe', caution: 'text-risk-caution', danger: 'text-risk-danger' };
                return (
                  <tr key={s.subject} className="border-b border-canvas-line hover:bg-canvas-raised/40 transition-colors">
                    <td className="px-3 py-2 font-mono text-[11px] text-ink truncate max-w-[160px]">{s.subject}</td>
                    <td className={`px-3 py-2 text-right font-mono text-[11px] tabular-nums font-bold ${toneMap[s.tier_color] || 'text-ink'}`}>
                      {String(Math.round(s.trust_score)).padStart(3, '0')}
                    </td>
                    <td className="px-3 py-2">
                      <div className="flex items-center gap-1">
                        <span className="material-symbols-outlined text-[14px]" style={{ color: s.tier_color === 'danger' ? '#ffb4ab' : s.tier_color === 'caution' ? '#ffb95f' : '#4ae176' }}>{s.tier_icon}</span>
                        <span className="font-mono text-[10px] text-ink-muted">{s.tier}</span>
                      </div>
                    </td>
                    <td className={`px-3 py-2 text-right font-mono text-[11px] tabular-nums ${s.clean_rate > 80 ? 'text-risk-safe' : s.clean_rate > 50 ? 'text-risk-caution' : 'text-risk-danger'}`}>{s.clean_rate}%</td>
                    <td className="px-3 py-2 text-right font-mono text-[11px] tabular-nums text-risk-danger">{s.blocked_requests}</td>
                    <td className="px-3 py-2 font-mono text-[10px] text-ink-faint truncate max-w-[200px]">{s.policy_effect}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

/* ── Auto-Harden Panel ──────────────────────────────────────────── */

function HardenPanel() {
  const { data, state } = useResource(getAutoHarden);
  if (state === 'loading') return <Loading label="Analyzing hardening opportunities…" />;
  if (!data) return <Empty label="No hardening data available." />;

  const recs = data.recommendations || [];

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-center gap-6 py-2">
        <div className="flex flex-col items-center gap-0.5 px-3">
          <div className="relative h-16 w-16">
            <svg width="64" height="64" viewBox="0 0 64 64" className="-rotate-90">
              <circle cx="32" cy="32" r="28" fill="none" stroke="#2a2a2c" strokeWidth="6" />
              <circle
                cx="32" cy="32" r="28" fill="none"
                stroke={data.hardening_score >= 70 ? '#4ae176' : data.hardening_score >= 40 ? '#ffb95f' : '#ffb4ab'}
                strokeWidth="6" strokeLinecap="round"
                strokeDasharray={`${2 * Math.PI * 28}`}
                strokeDashoffset={`${2 * Math.PI * 28 * (1 - data.hardening_score / 100)}`}
                className="transition-all duration-700"
              />
            </svg>
            <span className="absolute inset-0 flex items-center justify-center font-display text-lg font-bold text-ink">{data.hardening_score}</span>
          </div>
          <span className="label-caps text-ink-faint">Hardening Score</span>
        </div>
        <Metric label="Endpoints" value={data.total_endpoints_analyzed || 0} />
        <Metric label="Under Attack" value={data.endpoints_under_attack || 0} tone={data.endpoints_under_attack > 0 ? 'danger' : undefined} />
        <Metric label="Recommendations" value={recs.length} tone="accent" />
      </div>

      {recs.length === 0 ? (
        <Empty label="No hardening recommendations — all endpoints are clean." />
      ) : (
        <div className="space-y-2">
          {recs.slice(0, 8).map((rec, i) => (
            <div key={rec.endpoint} className="glass-panel rounded-lg p-3">
              <div className="flex items-center justify-between gap-2 mb-2">
                <div className="flex items-center gap-2 min-w-0">
                  <Badge tone={SEV_TONE[rec.severity]}>{rec.severity}</Badge>
                  <span className="font-mono text-xs text-ink truncate">{rec.endpoint}</span>
                </div>
                <span className="font-mono text-[10px] text-ink-faint shrink-0">{rec.attack_ratio}% attack ratio</span>
              </div>
              <div className="space-y-1">
                {rec.actions.map((a, ai) => (
                  <div key={ai} className="flex items-center gap-2 rounded bg-canvas-raised px-2 py-1.5">
                    <span className="material-symbols-outlined text-[14px] text-accent">build</span>
                    <span className="font-mono text-[10px] text-ink-muted flex-1">{a.description}</span>
                    {a.priority && <Badge tone={SEV_TONE[a.priority] || 'default'}>{a.priority}</Badge>}
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

/* ── Shared micro-components ────────────────────────────────────── */

function Loading({ label }) {
  return (
    <div className="flex flex-col items-center justify-center py-12 gap-3">
      <span className="material-symbols-outlined text-3xl text-accent animate-breathe">sync</span>
      <span className="font-mono text-xs text-ink-faint">{label}</span>
    </div>
  );
}

function Empty({ label }) {
  return (
    <div className="py-8 text-center font-mono text-xs text-ink-faint">{label}</div>
  );
}

/* ── Main tabbed component ──────────────────────────────────────── */

const TABS = [
  { id: 'killchain', icon: 'account_tree', label: 'Kill Chains' },
  { id: 'forecast',  icon: 'trending_up',  label: 'Forecast' },
  { id: 'intel',     icon: 'fingerprint',  label: 'Threat Intel' },
  { id: 'trust',     icon: 'verified_user', label: 'Trust Scores' },
  { id: 'harden',    icon: 'shield',       label: 'Auto-Harden' },
];

function IntelligenceConsole() {
  const [tab, setTab] = useState('killchain');

  return (
    <div className="space-y-4">
      {/* Tab bar */}
      <div className="flex flex-wrap gap-1 rounded-lg bg-canvas-sunken p-1">
        {TABS.map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`flex items-center gap-1.5 rounded px-3 py-2 font-mono text-[11px] transition-colors ${
              tab === t.id ? 'bg-accent/15 text-accent' : 'text-ink-faint hover:bg-canvas-raised/60 hover:text-ink-muted'
            }`}
          >
            <span className="material-symbols-outlined text-[16px]">{t.icon}</span>
            {t.label}
          </button>
        ))}
      </div>

      {/* Active panel */}
      {tab === 'killchain' && <KillChainPanel />}
      {tab === 'forecast' && <ForecastPanel />}
      {tab === 'intel' && <ThreatIntelPanel />}
      {tab === 'trust' && <TrustPanel />}
      {tab === 'harden' && <HardenPanel />}
    </div>
  );
}

export default memo(IntelligenceConsole);
