import axios from 'axios';

// Gateway runs everything on a single port (no separate admin port exists).
// Configurable via .env -> VITE_GATEWAY_URL.
const GATEWAY_URL = import.meta.env.VITE_GATEWAY_URL || 'http://127.0.0.1:8080';
const ADMIN_KEY = import.meta.env.VITE_ADMIN_KEY || 'changeme-admin-key';
const TIMEOUT_MS = 4000;

const client = axios.create({
  baseURL: GATEWAY_URL,
  timeout: TIMEOUT_MS,
  headers: {
    'X-Admin-Key': ADMIN_KEY
  }
});

export async function getAlerts() {
  const response = await client.get('/admin/alerts');
  return response.data;
}

export async function getMetrics() {
  const response = await client.get('/admin/metrics');
  return response.data;
}

export async function getEntities() {
  const response = await client.get('/admin/entities');
  return response.data;
}

export async function getIncidents() {
  const response = await client.get('/admin/incidents');
  return response.data;
}

// The route table the gateway is actually enforcing, for API Inventory. Not
// polled with the others: it is read once at gateway startup and cannot change
// without a restart, so re-fetching it every 2s would be pure waste.
export async function getRoutes() {
  const response = await client.get('/admin/routes');
  return response.data;
}

// Object-ownership grants - the data BOLA decisions are made against.
export async function getOwnership() {
  const response = await client.get('/admin/ownership');
  return response.data;
}

export async function grantOwnership({ resource, objectId, subject }) {
  const response = await client.post('/admin/ownership', {
    resource,
    object_id: objectId,
    subject
  });
  return response.data;
}

// Token-id denylist. Entries self-expire at the revoked token's own expiry.
export async function getRevocations() {
  const response = await client.get('/admin/revocations');
  return response.data;
}

export async function revokeToken({ jti, exp, reason }) {
  const response = await client.post('/admin/revoke', { jti, exp, reason });
  return response.data;
}

export async function getMlStatus() {
  const response = await client.get('/admin/ml-status');
  return response.data;
}

// Interactive user<->endpoint<->resource access graph (Jeevan George /
// j33v4nz, merged 2026-08-08).
export async function getGraph() {
  const response = await client.get('/admin/graph');
  return response.data;
}

// Deterministic summary over already-decided facts, not a live LLM call -
// see backend/executive_report.py. Fixed at generation time, so this is a
// one-shot fetch like getRoutes/getOwnership, not part of the 2s poll loop.
export async function getExecutiveReport() {
  const response = await client.get('/admin/executive-report');
  return response.data;
}

// Innovation intelligence endpoints — predictive, forensic, and adaptive
export async function getThreatForecast() {
  const response = await client.get('/admin/threat-forecast');
  return response.data;
}

export async function getAutoHarden() {
  const response = await client.get('/admin/auto-harden');
  return response.data;
}

export async function getKillChains() {
  const response = await client.get('/admin/kill-chains');
  return response.data;
}

export async function getThreatIntel() {
  const response = await client.get('/admin/threat-intel');
  return response.data;
}

export async function getAdaptiveTrust() {
  const response = await client.get('/admin/trust-scores');
  return response.data;
}

export async function importOpenApiSpec(spec) {
  const response = await client.post('/admin/openapi/import', spec);
  return response.data;
}

// Live decision stream (gateway: EventHub + @app.websocket("/ws/events")).
//
// The key goes in the query string rather than a header because a browser
// cannot set headers on a WebSocket handshake - the gateway accepts both forms
// for exactly that reason. That does put the admin key in the URL, where it can
// reach proxy and server logs; it is the same key already sitting in this
// bundle's VITE_ADMIN_KEY, so it is not a new exposure, but it is one more
// reason the demo key must not survive into a real deployment.
export function openEventStream() {
  const base = GATEWAY_URL.replace(/^http/, 'ws').replace(/\/$/, '');
  return new WebSocket(`${base}/ws/events?key=${encodeURIComponent(ADMIN_KEY)}`);
}

export { GATEWAY_URL };
