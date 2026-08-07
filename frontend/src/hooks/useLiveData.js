import { useEffect, useRef, useState } from 'react';
import { getAlerts, getMetrics, getEntities, getIncidents } from '../api/gateway.js';
import { normalizeAlerts, deriveMetrics, deriveEntities, normalizeIncidents } from '../api/normalize.js';

const POLL_INTERVAL_MS = Number(import.meta.env.VITE_POLL_INTERVAL) || 2000;
const MAX_ALERTS = 50;

// No simulated/demo data anywhere in this hook. connectionState is one of:
//   connecting - first poll hasn't resolved yet
//   live       - last poll succeeded, data below is real
//   error      - last poll failed; data below is whatever was last successfully
//                fetched (may be stale, never fake). Polling keeps retrying the
//                real gateway on every interval regardless of past failures -
//                there is no fallback branch to get permanently stuck in.
export function useLiveData() {
  const [alerts, setAlerts] = useState([]);
  const [metrics, setMetrics] = useState(null);
  const [entities, setEntities] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [connectionState, setConnectionState] = useState('connecting');
  const [lastError, setLastError] = useState(null);

  useEffect(() => {
    let cancelled = false;

    async function poll() {
      try {
        const [rawAlerts, rawMetrics, rawEntities, rawIncidents] = await Promise.all([
          getAlerts(),
          getMetrics(),
          getEntities(),
          getIncidents()
        ]);
        if (cancelled) return;

        const normalizedAlerts = normalizeAlerts(Array.isArray(rawAlerts) ? rawAlerts : []);
        const sortedAlerts = [...normalizedAlerts].sort(
          (a, b) => new Date(b.timestamp) - new Date(a.timestamp)
        );

        setAlerts(sortedAlerts.slice(0, MAX_ALERTS));
        setMetrics(deriveMetrics(rawMetrics, normalizedAlerts));
        setEntities(deriveEntities(Array.isArray(rawEntities) ? rawEntities : [], normalizedAlerts));
        setIncidents(normalizeIncidents(Array.isArray(rawIncidents) ? rawIncidents : []));
        setConnectionState('live');
        setLastError(null);
      } catch (err) {
        if (cancelled) return;
        setConnectionState('error');
        setLastError(err?.message || 'gateway unreachable');
      }
    }

    poll();
    const interval = setInterval(poll, POLL_INTERVAL_MS);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, []);

  return { alerts, metrics, entities, incidents, connectionState, lastError };
}
