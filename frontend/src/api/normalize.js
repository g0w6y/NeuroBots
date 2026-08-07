// Transforms the real gateway's actual response shapes into what the dashboard
// components consume. No randomness, no synthetic data anywhere in this file -
// every value here is derived from a real backend response.
//
// Convention used throughout this file: normalizeAlert() runs first, and every
// other function here (deriveMetrics, deriveEntities, buildTimeseries) operates
// on that ALREADY-NORMALIZED alert shape, never on the raw backend shape.
//
// Backend alert shape (main.py): { time, subject, ip, method, path, decision,
//   risk, signals: [{detector, weight, owasp, mitre, evidence, hard}], explain,
//   narrative, latency_ms, status_code }
// Backend has no `id` field on an alert - one is synthesized here (time+subject+
// path is stable enough for a React key and for de-duplication across polls).
//
// Backend entity shape (main.py): { id, risk, roles, tenant, blocked, blocked_until }
// Backend metrics shape (main.py): { requests, blocked, challenged, allowed,
//   entities, incidents, policy }

function shortCode(label) {
  // "T1078 Valid Accounts" -> "T1078", "API1:2023 Broken Object Level Authorization" -> "API1"
  if (!label) return '';
  return label.split(/[\s:]/)[0];
}

export function normalizeAlert(raw) {
  return {
    id: `${raw.time}_${raw.subject}_${raw.path}`,
    timestamp: raw.time,
    subject: raw.subject,
    ip: raw.ip,
    method: raw.method,
    path: raw.path,
    decision: raw.decision,
    risk_score: raw.risk,
    signals: (raw.signals || []).map((s) => ({
      signal: s.detector,
      owasp: shortCode(s.owasp),
      mitre: shortCode(s.mitre),
      evidence: s.evidence,
      hard: s.hard
    })),
    explanation: raw.explain,
    narrative: raw.narrative,
    latency_ms: raw.latency_ms
  };
}

// input: raw backend alerts array. output: normalized alerts array.
export function normalizeAlerts(rawAlerts) {
  return (rawAlerts || []).map(normalizeAlert);
}

function percentile(sorted, p) {
  if (sorted.length === 0) return 0;
  const idx = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length));
  return sorted[idx];
}

// input: normalized alerts array
function buildTimeseries(alerts) {
  // 12 buckets of 5 minutes = last hour, matching the RiskChart panel title
  const buckets = [];
  const now = Date.now();
  for (let i = 11; i >= 0; i -= 1) {
    const bucketEnd = now - i * 5 * 60 * 1000;
    const bucketStart = bucketEnd - 5 * 60 * 1000;
    const label = new Date(bucketEnd).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    const inBucket = alerts.filter((a) => {
      const t = new Date(a.timestamp).getTime();
      return t >= bucketStart && t < bucketEnd;
    });
    buckets.push({
      time: label,
      allowed: inBucket.filter((a) => a.decision === 'allow' || a.decision === 'observe').length,
      blocked: inBucket.filter((a) => a.decision === 'block').length
    });
  }
  return buckets;
}

// rawMetrics: backend's own /admin/metrics response (authoritative lifetime
// counts, SQL-aggregated when Postgres is connected). normalizedAlerts: the
// fetched alerts window, used only for derived visualizations the backend
// doesn't compute itself (timeseries, mitre_counts, latency percentiles,
// overall_risk) - genuinely presentation-layer aggregation, not something
// that belongs baked into the gateway's own response.
export function deriveMetrics(rawMetrics, normalizedAlerts) {
  const alerts = normalizedAlerts || [];
  const latencies = alerts.map((a) => a.latency_ms).filter((n) => typeof n === 'number').sort((a, b) => a - b);
  const risks = alerts.map((a) => a.risk_score).filter((n) => typeof n === 'number');
  const windowTotal = alerts.length;
  const windowBlocked = alerts.filter((a) => a.decision === 'block').length;

  const mitreCounts = {};
  alerts.forEach((a) => {
    (a.signals || []).forEach((s) => {
      if (s.mitre) mitreCounts[s.mitre] = (mitreCounts[s.mitre] || 0) + 1;
    });
  });

  return {
    total_requests: rawMetrics?.requests ?? windowTotal,
    allowed: rawMetrics?.allowed ?? 0,
    challenged: rawMetrics?.challenged ?? 0,
    blocked: rawMetrics?.blocked ?? 0,
    incidents: rawMetrics?.incidents ?? 0,
    entities_count: rawMetrics?.entities ?? 0,
    block_rate: windowTotal ? Math.round((windowBlocked / windowTotal) * 100) : 0,
    avg_latency_ms: latencies.length ? latencies.reduce((s, v) => s + v, 0) / latencies.length : 0,
    p95_latency_ms: percentile(latencies, 95),
    overall_risk: risks.length ? Math.round(risks.reduce((s, v) => s + v, 0) / risks.length) : 0,
    mitre_counts: mitreCounts,
    timeseries: buildTimeseries(alerts),
    policy: rawMetrics?.policy ?? null
  };
}

// rawEntities: backend's /admin/entities response. normalizedAlerts: used to
// derive per-entity request_count and distinct-endpoint count, which the
// backend's entity record doesn't carry itself.
export function deriveEntities(rawEntities, normalizedAlerts) {
  const alerts = normalizedAlerts || [];
  return (rawEntities || []).map((e) => {
    const own = alerts.filter((a) => a.subject === e.id);
    const endpoints = new Set(own.map((a) => a.path)).size;
    const status = e.blocked ? 'blocked' : e.risk > 30 ? 'flagged' : 'active';
    return {
      subject: e.id,
      request_count: own.length,
      risk_score: e.risk,
      roles: e.roles,
      tenant: e.tenant,
      endpoints,
      status
    };
  });
}

export function normalizeIncidents(rawIncidents) {
  return (rawIncidents || []).map((i) => ({
    id: `${i.time}_${i.target}`,
    time: i.time,
    target: i.target,
    targetType: i.target_type,
    reason: i.reason,
    escalationCount: i.escalation_count,
    cooldownSec: i.cooldown_sec,
    blockedUntil: i.blocked_until,
    narrative: i.narrative
  }));
}
