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
    // the gateway now assigns every alert a monotonic id; the composite key is
    // only a fallback for an older gateway build (two requests by one subject to
    // one path inside the same microsecond would collide there, which a burst
    // attack reliably produces)
    id: raw.id ?? `${raw.time}_${raw.subject}_${raw.path}`,
    timestamp: raw.time,
    // parse once here rather than re-parsing this string in the sort comparator
    // and again inside every timeseries bucket on every 2s poll
    ts: Date.parse(raw.time),
    subject: raw.subject,
    ip: raw.ip,
    method: raw.method,
    path: raw.path,
    decision: raw.decision,
    risk_score: raw.risk,
    signals: (raw.signals || []).map((s) => ({
      signal: s.detector,
      // short codes for the inline pills, full labels for the expanded detail —
      // "API1 · T1078" scans at a glance, but a judge reading the reasoning wants
      // "Broken Object Level Authorization", not an acronym
      owasp: shortCode(s.owasp),
      mitre: shortCode(s.mitre),
      owaspFull: s.owasp,
      mitreFull: s.mitre,
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

// 24 buckets of 5 seconds = the last two minutes.
//
// This was 12 x 5min = one hour, which is the wrong scale for the thing being
// watched: a demo, an incident, or an attack burst all play out in seconds. At
// hour scale eleven of the twelve buckets are always empty, so the chart renders
// as a flat zero line with one spike crushed against the right edge and reads as
// broken. Two minutes gives the line an actual shape.
export const BUCKET_MS = 5000;
export const BUCKET_COUNT = 24;

// input: normalized alerts array (each carrying a numeric `ts`)
function buildTimeseries(alerts) {
  // Quantise the origin to a bucket boundary. With a raw Date.now() every one of
  // the 24 bucket edges and X labels shifted on every 2s poll, so Recharts saw a
  // brand-new label set each tick and re-animated the whole line - visible
  // jitter. Quantised, the window advances one whole bucket at a time.
  const now = Math.ceil(Date.now() / BUCKET_MS) * BUCKET_MS;
  const origin = now - BUCKET_COUNT * BUCKET_MS;

  const buckets = [];
  for (let i = 0; i < BUCKET_COUNT; i += 1) {
    const end = origin + (i + 1) * BUCKET_MS;
    buckets.push({
      time: new Date(end).toLocaleTimeString([], { minute: '2-digit', second: '2-digit' }),
      allowed: 0,
      challenged: 0,
      blocked: 0
    });
  }

  // single pass over the alerts instead of a full array scan per bucket
  alerts.forEach((a) => {
    if (!Number.isFinite(a.ts)) return;
    const idx = Math.floor((a.ts - origin) / BUCKET_MS);
    if (idx < 0 || idx >= BUCKET_COUNT) return;
    if (a.decision === 'block') buckets[idx].blocked += 1;
    else if (a.decision === 'challenge') buckets[idx].challenged += 1;
    else if (a.decision === 'allow' || a.decision === 'observe') buckets[idx].allowed += 1;
  });

  return buckets;
}

// rawMetrics: backend's own /admin/metrics response (authoritative lifetime
// counts, SQL-aggregated when Postgres is connected). normalizedAlerts: the
// fetched alerts window, used only for derived visualizations the backend
// doesn't compute itself (timeseries, mitre_counts, latency percentiles,
// overall_risk) - genuinely presentation-layer aggregation, not something
// that belongs baked into the gateway's own response.
// How far back "current threat level" looks. Long enough that the gauge does not
// flicker between polls, short enough that it visibly cools once an attack stops.
const THREAT_WINDOW_MS = 120000;

// Current system threat level, 0-100.
//
// This was the arithmetic mean of every request's risk, allowed requests scored
// 0 included. In any realistic traffic mix - say 40 legitimate requests and 10
// blocked BOLA attempts at risk 90 - that averages out to 18, so the 200px hero
// gauge rendered a calm green "018 / SAFE" directly above a threat feed full of
// red BLOCKED rows. The most prominent number on the console contradicted the
// evidence beneath it, which is worse than showing nothing.
//
// Severity does not average. What an operator needs to know is how bad the worst
// thing happening right now is, tempered by how much of current traffic is
// hostile: one blocked probe in a quiet minute is not the same emergency as half
// of all traffic being blocked. Both terms are drawn from the same recent window
// so the gauge cools on its own once the attack stops.
function computeThreatLevel(alerts, nowMs) {
  const recent = alerts.filter((a) => Number.isFinite(a.ts) && nowMs - a.ts <= THREAT_WINDOW_MS);
  if (recent.length === 0) return 0;

  const peak = recent.reduce((m, a) => Math.max(m, a.risk_score || 0), 0);
  const hostile = recent.filter((a) => a.decision === 'block' || a.decision === 'challenge').length;
  const hostileRate = hostile / recent.length;

  return Math.min(100, Math.round(0.6 * peak + 0.4 * hostileRate * 100));
}

export function deriveMetrics(rawMetrics, normalizedAlerts) {
  const alerts = normalizedAlerts || [];
  const latencies = alerts.map((a) => a.latency_ms).filter((n) => typeof n === 'number').sort((a, b) => a - b);
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
    // Block rate is computed over the same lifetime counters the decision pie
    // uses, rather than over the fetched alert window. The two sat side by side
    // on one screen describing the same quantity over different denominators,
    // so the tile could read 45% while the pie read 20%.
    block_rate: rawMetrics?.requests
      ? Math.round((rawMetrics.blocked / rawMetrics.requests) * 100)
      : (windowTotal ? Math.round((windowBlocked / windowTotal) * 100) : 0),
    avg_latency_ms: latencies.length ? latencies.reduce((s, v) => s + v, 0) / latencies.length : 0,
    p95_latency_ms: percentile(latencies, 95),
    p99_latency_ms: percentile(latencies, 99),
    overall_risk: computeThreatLevel(alerts, Date.now()),
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

  // One grouping pass instead of a full alerts.filter() per entity. The old
  // shape was O(entities x alerts): 100 entities against a 500-alert window is
  // 50,000 comparisons, redone from scratch every 2 seconds.
  const bySubject = new Map();
  alerts.forEach((a) => {
    let bucket = bySubject.get(a.subject);
    if (!bucket) {
      bucket = { count: 0, paths: new Set() };
      bySubject.set(a.subject, bucket);
    }
    bucket.count += 1;
    bucket.paths.add(a.path);
  });

  return (rawEntities || []).map((e) => {
    const windowed = bySubject.get(e.id);
    const status = e.blocked ? 'blocked' : e.risk > 30 ? 'flagged' : 'active';
    return {
      subject: e.id,
      // The gateway now tracks these per entity for the whole life of the
      // process, so prefer its figures. Deriving them from the alert window
      // meant an entity's request count silently shrank as its older traffic
      // aged out of the window - the number went *down* while the user kept
      // making requests. The window-derived values remain as a fallback for an
      // older gateway build that does not serve these fields.
      request_count: e.request_count ?? windowed?.count ?? 0,
      endpoints: e.endpoints ?? windowed?.paths.size ?? 0,
      objects: e.objects ?? 0,
      risk_score: e.risk,
      roles: e.roles || [],
      tenant: e.tenant || '',
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
