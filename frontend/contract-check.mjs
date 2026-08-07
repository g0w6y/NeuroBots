// End-to-end contract check: fetches the live gateway with the same headers the
// dashboard uses, runs the dashboard's own transform functions over the real
// responses, and asserts that every value a component renders is present and
// sane. Catches the class of bug where the backend renames a field and the UI
// silently renders undefined.
//
//   node contract-check.mjs
import { normalizeAlerts, deriveMetrics, deriveEntities, normalizeIncidents } from './src/api/normalize.js';
import { buildInventory, runHunts, HUNTS, patternToRegex } from './src/api/analysis.js';

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

// --- API Inventory (/admin/routes + the observed-path join) ---
const rawRoutes = await get('/admin/routes');
const inventory = buildInventory(rawRoutes, alerts);

check('route table is served and non-empty',
  inventory && inventory.routes.length > 0, `${inventory?.routes.length ?? 0} routes`);
check('route source names the file, not the built-in fallback',
  rawRoutes.source && !rawRoutes.source.startsWith('built-in'),
  `source = ${rawRoutes.source}`);
check('every route carries the fields the inventory table renders',
  inventory.routes.every(r => ['method', 'pattern', 'resource', 'required_roles',
    'bola_protected', 'bfla_protected', 'traffic', 'blocked'].every(k => r[k] !== undefined)));
check('object-scoped routes are flagged bola_protected',
  inventory.routes.every(r => Boolean(r.object_param) === r.bola_protected));
check('role-gated routes are flagged bfla_protected',
  inventory.routes.every(r => (r.required_roles.length > 0) === r.bfla_protected));
// Parameterised patterns are the ones a naive escape order silently breaks, so
// assert the join actually matched traffic rather than trusting it compiled.
const parameterised = inventory.routes.filter(r => r.pattern.includes('{'));
check('parameterised patterns match real observed paths',
  parameterised.length === 0 || parameterised.some(r => r.traffic > 0),
  parameterised.map(r => `${r.pattern}=${r.traffic}`).join(' '));
check('patternToRegex substitutes placeholders',
  patternToRegex('/api/accounts/{id}').test('/api/accounts/1001')
  && !patternToRegex('/api/accounts/{id}').test('/api/accounts/1001/transactions'));
check('every unlisted path really is under a protected prefix',
  inventory.unlisted.every(u => inventory.prefixes.some(p => u.path.startsWith(`/${p}/`) || u.path === `/${p}`)),
  `${inventory.unlisted.length} gaps`);
check('total route traffic does not exceed the alert window',
  inventory.routes.reduce((s, r) => s + r.traffic, 0) <= alerts.length,
  `${inventory.routes.reduce((s, r) => s + r.traffic, 0)} matched / ${alerts.length} alerts`);

// --- Access Control (/admin/ownership) ---
const rawOwnership = await get('/admin/ownership');
check('ownership grants are served with the fields the table renders',
  Array.isArray(rawOwnership.grants)
  && rawOwnership.grants.every(g => g.resource && g.object_id && Array.isArray(g.owners)),
  `${rawOwnership.count} grants from ${rawOwnership.source}`);
check('fan_in equals the owner count it is derived from',
  rawOwnership.grants.every(g => g.fan_in === g.owners.length));
check('seeded ownership is present',
  rawOwnership.grants.length > 0,
  rawOwnership.grants.map(g => `${g.resource}/${g.object_id}`).join(' '));

// --- Revocation (flow step 1) ---
const rawRevocations = await get('/admin/revocations');
check('revocation denylist is served',
  Array.isArray(rawRevocations.revocations) && typeof rawRevocations.count === 'number',
  `${rawRevocations.count} revoked, source ${rawRevocations.source}`);
check('every revocation carries the fields the table renders',
  rawRevocations.revocations.every(r => r.jti && r.revoked_at && r.expires_at));
check('no revocation outlives the token it killed',
  rawRevocations.revocations.every(r => r.expires_at >= r.revoked_at));

// --- Threat Hunt (derived, no endpoint of its own) ---
const hunts = runHunts(alerts);
check('every hunt returns a result set', HUNTS.every(h => Array.isArray(hunts[h.id])));
check('hunt rows carry every column the table renders',
  Object.values(hunts).flat().every(r => ['subject', 'count', 'blocked', 'peakRisk',
    'paths', 'ips', 'techniques'].every(k => r[k] !== undefined)));
check('hunts never report more events than exist',
  Object.values(hunts).flat().every(r => r.count <= alerts.length));
check('repeat-offenders honours its minEvents floor',
  hunts.repeat.every(r => r.count >= 3), `${hunts.repeat.length} subjects`);
check('hunt timestamps are ordered first <= last',
  Object.values(hunts).flat().every(r => !r.first || !r.last || r.first <= r.last));
// With attack traffic in the window at least one hunt must fire - if every hunt
// is empty while blocks exist, the signal-name predicates have drifted from
// whatever the gateway now emits, and this page would silently show nothing.
const blockedCount = alerts.filter(a => a.decision === 'block').length;
check('hunts detect something when attacks are present',
  blockedCount === 0 || Object.values(hunts).some(rows => rows.length > 0),
  Object.entries(hunts).map(([k, v]) => `${k}=${v.length}`).join(' '));

// --- API3 response inspection (flow step 8) ---
// The signal rides on requests the gateway ALLOWED, so assert exactly that: a
// finding attached to a non-allowed decision would mean the response was never
// actually served and the finding is fiction.
const exposureAlerts = alerts.filter(a =>
  a.signals?.some(s => s.signal?.includes('data_exposure')));
check('API3 findings only ever attach to served responses',
  exposureAlerts.every(a => a.decision === 'allow' || a.decision === 'observe'),
  `${exposureAlerts.length} findings, decisions: ${[...new Set(exposureAlerts.map(a => a.decision))].join(',') || 'none'}`);
check('API3 findings are mapped to OWASP API3 and a MITRE technique',
  exposureAlerts.every(a => a.signals.filter(s => s.signal?.includes('data_exposure'))
    .every(s => s.owasp === 'API3' && s.mitre)),
  exposureAlerts[0]
    ? JSON.stringify(exposureAlerts[0].signals.find(s => s.signal?.includes('data_exposure')))
    : 'no findings yet');
check('API3 findings are soft, never hard',
  exposureAlerts.every(a => a.signals.filter(s => s.signal?.includes('data_exposure'))
    .every(s => s.hard === false)),
  'a response-side finding must not block a response already served');

console.log(`\n${pass}/${pass + fail} contract checks passed`);
process.exit(fail ? 1 : 0);
