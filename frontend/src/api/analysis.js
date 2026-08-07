// Derived analysis for the API Inventory and Threat Hunt pages.
//
// Kept out of the components for the same reason normalize.js is: contract-check
// .mjs runs under plain node and cannot import JSX, so any logic buried in a
// .jsx file is logic that can never be verified against the live gateway. These
// are pure functions over already-normalized alerts (see normalize.js) plus raw
// /admin/routes, with no React and no DOM.
//
// Nothing here invents data. Every number is a count or a join over real gateway
// decisions; where the two sides of a join come from different endpoints, the
// join itself is the only thing computed.

// ---------------------------------------------------------------- inventory

// "/api/accounts/{id}/transactions" -> /^\/api\/accounts\/[^/]+\/transactions$/
// Escape first, THEN substitute the placeholders. Doing it the other way round
// escapes the braces you are about to look for, and every pattern with a
// parameter silently matches nothing.
export function patternToRegex(pattern) {
  const escaped = pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const withParams = escaped.replace(/\\\{[^}]+\\\}/g, '[^/]+');
  return new RegExp(`^${withParams}$`);
}

export function isUnderProtectedPrefix(path, prefixes) {
  return (prefixes || []).some((p) => path === `/${p}` || path.startsWith(`/${p}/`));
}

// routesResponse: raw /admin/routes. alerts: normalized alerts.
export function buildInventory(routesResponse, alerts) {
  if (!routesResponse?.routes) return null;

  const prefixes = routesResponse.protected_prefixes || [];
  const compiled = routesResponse.routes.map((r) => ({ ...r, re: patternToRegex(r.pattern) }));

  const observed = new Map();
  (alerts || []).forEach((a) => {
    if (!a.path) return;
    const key = `${a.method} ${a.path}`;
    let row = observed.get(key);
    if (!row) {
      row = {
        method: a.method,
        path: a.path,
        count: 0,
        allowed: 0,
        blocked: 0,
        challenged: 0,
        subjects: new Set(),
        lastSeen: 0,
        matched: false
      };
      observed.set(key, row);
    }
    row.count += 1;
    if (a.decision === 'block') row.blocked += 1;
    else if (a.decision === 'challenge') row.challenged += 1;
    else row.allowed += 1;
    if (a.subject) row.subjects.add(a.subject);
    if (a.ts > row.lastSeen) row.lastSeen = a.ts;
  });

  const routes = compiled.map((r) => {
    let traffic = 0;
    let blocked = 0;
    const subjects = new Set();
    observed.forEach((row) => {
      if (row.method === r.method && r.re.test(row.path)) {
        traffic += row.count;
        blocked += row.blocked;
        row.subjects.forEach((s) => subjects.add(s));
        row.matched = true;
      }
    });
    const { re, ...rest } = r;
    return { ...rest, traffic, blocked, subjects: subjects.size };
  });

  // A path outside every protected prefix is not gateway-governed at all, so
  // reporting it as a coverage gap would be noise rather than a finding.
  const unlisted = [...observed.values()]
    .filter((row) => !row.matched && isUnderProtectedPrefix(row.path, prefixes))
    .sort((a, b) => b.count - a.count);

  return {
    routes,
    unlisted,
    prefixes,
    source: routesResponse.source,
    bolaCovered: routes.filter((r) => r.bola_protected).length,
    bflaCovered: routes.filter((r) => r.bfla_protected).length
  };
}

// -------------------------------------------------------------------- hunts

const sig = (a, ...needles) =>
  (a.signals || []).some((s) => needles.some((n) => s.signal?.includes(n)));

export const HUNTS = [
  {
    id: 'bola',
    name: 'Cross-object access',
    question: 'Which identities reached for objects they do not own?',
    technique: 'T1078 · API1:2023',
    match: (a) => sig(a, 'bola')
  },
  {
    id: 'enum',
    name: 'Object enumeration',
    question: 'Who is walking an ID space rather than using the app?',
    technique: 'T1087 · API1:2023',
    match: (a) => sig(a, 'enum')
  },
  {
    id: 'bfla',
    name: 'Privilege probing',
    question: 'Which non-admin identities tried admin-only functions?',
    technique: 'T1548 · API5:2023',
    match: (a) => sig(a, 'bfla', 'role')
  },
  {
    id: 'token',
    name: 'Token abuse',
    question: 'Forged, expired, wrong-key or malformed credentials.',
    technique: 'T1550 · API2:2023',
    match: (a) => sig(a, 'jwt', 'token', 'alg', 'signature', 'issuer', 'audience', 'expired')
  },
  {
    id: 'rate',
    name: 'Volumetric abuse',
    question: 'Who exceeded the sustained or burst rate limit?',
    technique: 'T1499 · API4:2023',
    match: (a) => sig(a, 'rate', 'burst')
  },
  {
    // Response-side, so these ride on requests the gateway ALLOWED. That is the
    // point: authorization passed and the response still over-served. No other
    // hunt on this page can surface that, because every other one keys off a
    // request-side signal.
    id: 'exposure',
    name: 'Data exposure',
    question: 'Which allowed responses returned more than the caller should see?',
    technique: 'T1119 · API3:2023',
    match: (a) => sig(a, 'excessive_data_exposure', 'cross_tenant_data_exposure', 'bulk_data_exposure')
  },
  {
    id: 'revoked',
    name: 'Revoked credentials',
    question: 'Who is replaying a token an operator has already killed?',
    technique: 'T1078 · API2:2023',
    match: (a) => sig(a, 'jwt_revoked')
  },
  {
    id: 'missing',
    name: 'Unauthenticated reach',
    question: 'Requests to protected routes carrying no credential at all.',
    technique: 'T1078 · API2:2023',
    match: (a) => a.subject?.startsWith('anon:') || sig(a, 'missing', 'no_token')
  },
  {
    id: 'repeat',
    name: 'Repeat offenders',
    question: 'Identities blocked more than twice — escalation candidates.',
    match: (a) => a.decision === 'block',
    minEvents: 3
  },
  {
    id: 'recon',
    name: 'Recon then exploit',
    question: 'Identities that behaved normally first, then turned hostile.',
    sequence: true
  }
];

function summarize(subject, events) {
  const techniques = new Set();
  const owasp = new Set();
  events.forEach((e) =>
    (e.signals || []).forEach((s) => {
      if (s.mitre) techniques.add(s.mitre);
      if (s.owasp) owasp.add(s.owasp);
    })
  );
  const sorted = [...events].sort((a, b) => a.ts - b.ts);
  return {
    subject,
    events: sorted,
    count: events.length,
    blocked: events.filter((e) => e.decision === 'block').length,
    peakRisk: events.reduce((m, e) => Math.max(m, e.risk_score || 0), 0),
    paths: new Set(events.map((e) => e.path)).size,
    ips: new Set(events.map((e) => e.ip)).size,
    first: sorted[0]?.ts,
    last: sorted[sorted.length - 1]?.ts,
    techniques: [...techniques],
    owasp: [...owasp]
  };
}

// Returns { [huntId]: rows[] }, each row summarizing one subject's hits.
export function runHunts(alerts) {
  const out = {};
  const list = alerts || [];

  HUNTS.forEach((hunt) => {
    const bySubject = new Map();

    if (hunt.sequence) {
      // Keep only subjects whose first hostile event is preceded by at least two
      // clean ones. A subject hostile from its very first request is a plain
      // attacker; the recon pattern is the one that built a baseline first.
      const seq = new Map();
      [...list]
        .sort((a, b) => a.ts - b.ts)
        .forEach((a) => {
          if (!seq.has(a.subject)) seq.set(a.subject, []);
          seq.get(a.subject).push(a);
        });
      seq.forEach((events, subject) => {
        const firstHostile = events.findIndex(
          (e) => e.decision === 'block' || e.decision === 'challenge'
        );
        if (firstHostile >= 2) {
          bySubject.set(subject, events.slice(firstHostile - 2));
        }
      });
    } else {
      list.forEach((a) => {
        if (!hunt.match(a)) return;
        if (!bySubject.has(a.subject)) bySubject.set(a.subject, []);
        bySubject.get(a.subject).push(a);
      });
      if (hunt.minEvents) {
        [...bySubject.entries()].forEach(([subject, events]) => {
          if (events.length < hunt.minEvents) bySubject.delete(subject);
        });
      }
    }

    out[hunt.id] = [...bySubject.entries()]
      .map(([subject, events]) => summarize(subject, events))
      .sort((a, b) => b.peakRisk - a.peakRisk || b.count - a.count);
  });

  return out;
}
