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

export { GATEWAY_URL };
