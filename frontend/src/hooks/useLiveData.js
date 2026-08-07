import { useEffect, useRef, useState } from 'react';
import { getAlerts, getMetrics, getEntities, getIncidents, openEventStream } from '../api/gateway.js';
import { normalizeAlerts, deriveMetrics, deriveEntities, normalizeIncidents } from '../api/normalize.js';

const POLL_INTERVAL_MS = Number(import.meta.env.VITE_POLL_INTERVAL) || 2000;

// With the event stream connected, polling stops being the way decisions arrive
// and becomes a slow reconciliation pass - it still corrects any event the
// socket dropped (the gateway's fan-out is deliberately best-effort and drops
// rather than applying backpressure to the request path), and it is still what
// refreshes the counters the socket doesn't carry. Ten times slower, so a live
// dashboard costs the gateway a fraction of what it used to.
const RECONCILE_INTERVAL_MS = POLL_INTERVAL_MS * 10;

// A push lands one alert; the tiles, gauge, chart and entity table are all
// derived from /admin/metrics and /admin/entities, so a refresh has to follow.
// Coalesced, because a burst attack delivers events far faster than it is worth
// re-fetching four endpoints.
const PUSH_REFRESH_DEBOUNCE_MS = 300;
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
  // The full fetched window, uncapped. The Overview feed only ever shows the
  // newest MAX_ALERTS, but Logs, API Inventory and Threat Hunt all analyse the
  // whole window - capping their input at 50 would silently narrow every
  // aggregate they compute.
  const [allAlerts, setAllAlerts] = useState([]);
  const [metrics, setMetrics] = useState(null);
  const [entities, setEntities] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [connectionState, setConnectionState] = useState('connecting');
  const [lastError, setLastError] = useState(null);
  // 'websocket' once the gateway's live stream is carrying decisions, 'polling'
  // whenever it is not. Surfaced so the header states which one is actually in
  // use rather than claiming "live" for a 2-second poll.
  const [transport, setTransport] = useState('polling');

  // latest raw responses, so a partial failure can still be combined with the
  // last good value of whatever didn't answer this time
  const lastGood = useRef({ alerts: [], metrics: null, entities: [], incidents: [] });

  useEffect(() => {
    let cancelled = false;
    let timer = null;
    let seq = 0;
    let socket = null;
    let reconnectTimer = null;
    let reconnectDelay = 1000;
    let pushRefresh = null;

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
      setAllAlerts(sortedAlerts);
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
        if (!cancelled) {
          timer = setTimeout(tick, socket && socket.readyState === WebSocket.OPEN
            ? RECONCILE_INTERVAL_MS
            : POLL_INTERVAL_MS);
        }
      }
    }

    // ------------------------------------------------------------ live stream
    //
    // The gateway has published decisions over /ws/events all along (EventHub in
    // main.py) and nothing ever connected to it, so every dashboard sat at
    // live_subscribers: 0 and a "live" console was really a 2-second poll. A
    // pushed alert now renders the moment the gateway decides, and polling drops
    // to a reconciliation cadence behind it.

    function scheduleRefresh() {
      if (pushRefresh) return;              // already coalescing a burst
      pushRefresh = setTimeout(() => {
        pushRefresh = null;
        if (!cancelled) poll();
      }, PUSH_REFRESH_DEBOUNCE_MS);
    }

    function applyPushedAlert(rawAlert) {
      // Merge into the same raw buffer the poll path uses, so the next poll
      // reconciles against a superset rather than fighting this update. Keyed by
      // the gateway's own monotonic alert id, which is what makes a pushed event
      // and its later polled copy the same row instead of a duplicate.
      const raw = lastGood.current;
      const key = (a) => a.id ?? `${a.time}_${a.subject}_${a.path}`;
      const incoming = key(rawAlert);
      if (raw.alerts.some((a) => key(a) === incoming)) return;
      raw.alerts = [rawAlert, ...raw.alerts];

      const normalized = normalizeAlerts(raw.alerts);
      const sorted = [...normalized].sort((a, b) => b.ts - a.ts);
      setAlerts(sorted.slice(0, MAX_ALERTS));
      setAllAlerts(sorted);
      // metrics/entities are recomputed from the raw responses, not invented
      // here - scheduleRefresh re-fetches them rather than guessing at counters
      scheduleRefresh();
    }

    function connectStream() {
      if (cancelled) return;
      let ws;
      try {
        ws = openEventStream();
      } catch {
        return;                              // no WebSocket support: polling covers it
      }
      socket = ws;

      ws.onopen = () => {
        if (cancelled) return;
        reconnectDelay = 1000;
        setTransport('websocket');
      };

      ws.onmessage = (event) => {
        if (cancelled) return;
        let message;
        try {
          message = JSON.parse(event.data);
        } catch {
          return;
        }
        if (message.type === 'alert' && message.data) applyPushedAlert(message.data);
        else if (message.type === 'incident' || message.type === 'revocation') scheduleRefresh();
        // /admin/reset clears the gateway's runtime state. The retained raw
        // buffer has to be dropped with it, or the next poll would merge the
        // cleared alerts straight back in - and because the socket has slowed
        // polling to RECONCILE_INTERVAL_MS, that stale view would sit there for
        // 20s instead of the 2s it used to.
        else if (message.type === 'reset') {
          lastGood.current = { alerts: [], metrics: null, entities: [], incidents: [] };
          scheduleRefresh();
        }
      };

      const drop = () => {
        if (cancelled) return;
        setTransport('polling');
        socket = null;
        // Backoff, capped. A gateway that is down or rejecting the admin key
        // would otherwise be hammered with a reconnect every time it refuses,
        // and a 4401 close is not something retrying faster will fix.
        reconnectTimer = setTimeout(connectStream, reconnectDelay);
        reconnectDelay = Math.min(reconnectDelay * 2, 30000);
      };
      ws.onclose = drop;
      ws.onerror = () => { try { ws.close(); } catch { /* onclose still fires */ } };
    }

    tick();
    connectStream();

    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
      if (pushRefresh) clearTimeout(pushRefresh);
      if (reconnectTimer) clearTimeout(reconnectTimer);
      if (socket) {
        socket.onclose = null;               // don't schedule a reconnect on unmount
        try { socket.close(); } catch { /* already closing */ }
      }
    };
  }, []);

  return { alerts, allAlerts, metrics, entities, incidents, connectionState, lastError, transport };
}
