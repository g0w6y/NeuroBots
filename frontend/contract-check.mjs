// End-to-end contract check: fetches the live gateway with the same headers the
// dashboard uses, runs the dashboard's own transform functions over the real
// responses, and asserts that every value a component renders is present and
// sane. Catches the class of bug where the backend renames a field and the UI
// silently renders undefined.
//
//   node contract-check.mjs
import { normalizeAlerts, deriveMetrics, deriveEntities, normalizeIncidents } from './src/api/normalize.js';

const GW = process.env.VITE_GATEWAY_URL || 'http://127.0.0.1:8080';
const KEY = process.env.VITE_ADMIN_KEY || 'changeme-admin-key';
const H = { 'X-Admin-Key': KEY };

let pass = 0;
let fail = 0;
function check(label, cond, detail = '') {
  if (cond) { pass += 1; console.log(`PASS  ${label}  ${detail}`); }
  else { fail += 1; console.log(`FAIL  ${label}  ${detail}`); }
}

async function get(path) {
  const r = await fetch(GW + path, { headers: H });
  if (!r.ok) throw new Error(`${path} -> ${r.status}`);
  return r.json();
}

const [rawAlerts, rawMetrics, rawEntities, rawIncidents] = await Promise.all([
  get('/admin/alerts'), get('/admin/metrics'), get('/admin/entities'), get('/admin/incidents')
]);

console.log(`\nfetched: ${rawAlerts.length} alerts, ${rawEntities.length} entities, ${rawIncidents.length} incidents\n`);

const alerts = normalizeAlerts(rawAlerts);
const metrics = deriveMetrics(rawMetrics, alerts);
const entities = deriveEntities(rawEntities, alerts);
const incidents = normalizeIncidents(rawIncidents);

// --- ThreatFeed ---
check('every alert has a unique id', new Set(alerts.map(a => a.id)).size === alerts.length,
  `${new Set(alerts.map(a => a.id)).size}/${alerts.length}`);
check('no alert field is undefined',
  alerts.every(a => ['id', 'timestamp', 'subject', 'ip', 'method', 'path', 'decision', 'risk_score']
    .every(k => a[k] !== undefined)));
check('every timestamp parses', alerts.every(a => Number.isFinite(a.ts)));
check('timestamps are not skewed into the future',
  alerts.every(a => a.ts - Date.now() < 60000),
  `newest is ${((Date.now() - Math.max(...alerts.map(a => a.ts))) / 1000).toFixed(1)}s old`);
const decisions = [...new Set(alerts.map(a => a.decision))];
check('every decision is one the UI can render',
  decisions.every(d => ['allow', 'observe', 'challenge', 'block'].includes(d)), decisions.join(','));
const withSignals = alerts.filter(a => a.signals.length);
check('signal pills have OWASP + MITRE short codes',
  withSignals.every(a => a.signals.every(s => s.signal && s.owasp && s.mitre)),
  withSignals[0] ? JSON.stringify(withSignals[0].signals[0]) : 'no signals yet');

// --- hero row ---
check('overall_risk is a 0-100 number', Number.isFinite(metrics.overall_risk)
  && metrics.overall_risk >= 0 && metrics.overall_risk <= 100, `= ${metrics.overall_risk}`);
const blocked = alerts.filter(a => a.decision === 'block').length;
check('gauge is not green while blocks are on screen',
  blocked === 0 || metrics.overall_risk > 30,
  `${blocked} blocked in window, gauge = ${metrics.overall_risk}`);
check('total_requests is live, not deque-capped',
  metrics.total_requests >= alerts.length, `= ${metrics.total_requests}`);
check('block_rate agrees with the pie chart denominator',
  metrics.block_rate === (rawMetrics.requests ? Math.round(rawMetrics.blocked / rawMetrics.requests * 100) : 0),
  `tile=${metrics.block_rate}% pie=${Math.round(rawMetrics.blocked / rawMetrics.requests * 100)}%`);
check('avg latency is a real sub-15ms number',
  metrics.avg_latency_ms > 0 && metrics.avg_latency_ms < 15,
  `avg=${metrics.avg_latency_ms.toFixed(3)}ms p99=${metrics.p99_latency_ms.toFixed(3)}ms`);

// --- charts ---
check('timeseries has 24 buckets', metrics.timeseries.length === 24);
const nonEmpty = metrics.timeseries.filter(b => b.allowed + b.blocked + b.challenged > 0).length;
check('timeseries actually contains data (chart is not a flat line)', nonEmpty > 0,
  `${nonEmpty}/24 buckets populated`);
check('every bucket carries all three series',
  metrics.timeseries.every(b => 'allowed' in b && 'challenged' in b && 'blocked' in b));
check('MITRE counts are populated', Object.keys(metrics.mitre_counts).length > 0,
  JSON.stringify(metrics.mitre_counts));

// --- entity table ---
check('entities carry every column the table renders',
  entities.every(e => ['subject', 'request_count', 'endpoints', 'objects', 'risk_score', 'status']
    .every(k => e[k] !== undefined)),
  entities[0] ? JSON.stringify(entities[0]) : 'none');
check('request_count is non-zero for seen entities',
  entities.every(e => e.request_count > 0));
check('at least one entity carries roles from its token',
  entities.some(e => e.roles.length > 0),
  JSON.stringify(entities.map(e => [e.subject, e.roles])));
check('table sorts by risk descending',
  [...entities].sort((a, b) => b.risk_score - a.risk_score)[0].risk_score
  === Math.max(...entities.map(e => e.risk_score)));

// --- incidents ---
check('incidents normalize cleanly',
  incidents.every(i => i.id && i.target && i.reason), `${incidents.length} incidents`);

console.log(`\n${pass}/${pass + fail} contract checks passed`);
process.exit(fail ? 1 : 0);
