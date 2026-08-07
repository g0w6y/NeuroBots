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

export { GATEWAY_URL };
