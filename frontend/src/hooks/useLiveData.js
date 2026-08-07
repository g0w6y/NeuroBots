import { useEffect, useRef, useState } from 'react';
import { getAlerts, getMetrics, getEntities, getIncidents } from '../api/gateway.js';
import { normalizeAlerts, deriveMetrics, deriveEntities, normalizeIncidents } from '../api/normalize.js';

const POLL_INTERVAL_MS = Number(import.meta.env.VITE_POLL_INTERVAL) || 2000;
const MAX_ALERTS = 50;

// No simulated/demo data anywhere in this hook. connectionState is one of:
//   connecting - first poll hasn't resolved yet
//   live       - last poll succeeded, data below is real
//   degraded   - some endpoints answered and some didn't; panels backed by the
//                failed ones hold their last real values
//   error      - nothing answered; data below is whatever was last successfully
//                fetched (may be stale, never fake). Polling keeps retrying the
//                real gateway regardless of past failures - there is no fallback
//                branch to get permanently stuck in.
export function useLiveData() {
  const [alerts, setAlerts] = useState([]);
  const [metrics, setMetrics] = useState(null);
  const [entities, setEntities] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [connectionState, setConnectionState] = useState('connecting');
  const [lastError, setLastError] = useState(null);

  // latest raw responses, so a partial failure can still be combined with the
  // last good value of whatever didn't answer this time
  const lastGood = useRef({ alerts: [], metrics: null, entities: [], incidents: [] });

  useEffect(() => {
    let cancelled = false;
    let timer = null;
    let seq = 0;

    function describe(reasons) {
      const status = reasons.map((r) => r?.response?.status).find(Boolean);
      if (status === 401) {
        // Without this, a key mismatch surfaced as "gateway unreachable", which
        // sends whoever is debugging into the network stack while the actual
        // problem is one environment variable.
        return 'admin key rejected (401) — VITE_ADMIN_KEY must match the gateway ADMIN_API_KEY';
      }
      return reasons.find((r) => r?.message)?.message || 'gateway unreachable';
    }

    async function poll() {
      // Guards against out-of-order application: a slow poll N resolving after a
      // fast poll N+1 would otherwise overwrite newer state with older data.
      const mySeq = (seq += 1);

      const settled = await Promise.allSettled([
        getAlerts(),
        getMetrics(),
        getEntities(),
        getIncidents()
      ]);

      if (cancelled || mySeq !== seq) return;

      const [aRes, mRes, eRes, iRes] = settled;
      const failures = settled.filter((r) => r.status === 'rejected');

      // Promise.all rejected the whole batch on the first failure, so a single
      // flaky endpoint flipped the entire dashboard to an error banner and froze
      // the feed, charts, gauge and table - despite three of four endpoints
      // having returned perfectly good data. Each panel now degrades alone.
      const raw = lastGood.current;
      if (aRes.status === 'fulfilled' && Array.isArray(aRes.value)) raw.alerts = aRes.value;
      if (mRes.status === 'fulfilled' && mRes.value) raw.metrics = mRes.value;
      if (eRes.status === 'fulfilled' && Array.isArray(eRes.value)) raw.entities = eRes.value;
      if (iRes.status === 'fulfilled' && Array.isArray(iRes.value)) raw.incidents = iRes.value;

      const normalizedAlerts = normalizeAlerts(raw.alerts);
      const sortedAlerts = [...normalizedAlerts].sort((a, b) => b.ts - a.ts);

      setAlerts(sortedAlerts.slice(0, MAX_ALERTS));
      setMetrics(deriveMetrics(raw.metrics, normalizedAlerts));
      setEntities(deriveEntities(raw.entities, normalizedAlerts));
      setIncidents(normalizeIncidents(raw.incidents));

      if (failures.length === 0) {
        setConnectionState('live');
        setLastError(null);
      } else if (failures.length === settled.length) {
        setConnectionState('error');
        setLastError(describe(failures.map((f) => f.reason)));
      } else {
        setConnectionState('degraded');
        setLastError(describe(failures.map((f) => f.reason)));
      }
    }

    // Self-scheduling rather than setInterval. On a slow or unreachable gateway,
    // a fixed 2s interval kept firing four more requests while the previous four
    // were still in flight (axios timeout is 4s), piling up past the browser's
    // six-per-host limit and delaying recovery once the gateway came back.
    async function tick() {
      try {
        await poll();
      } finally {
        if (!cancelled) timer = setTimeout(tick, POLL_INTERVAL_MS);
      }
    }

    tick();
    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
    };
  }, []);

  return { alerts, metrics, entities, incidents, connectionState, lastError };
}
