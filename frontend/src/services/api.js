// frontend/src/services/api.js
//
// Centralized Axios client for all communication with the ECDAT Express
// gateway. Every request is CORS-scoped (withCredentials: true) and
// automatically carries the project's X-ECDAT-Token via an interceptor —
// the frontend never sends a projectId field itself; the gateway resolves
// it exclusively from this token (see backend/src/middleware/
// authenticateProject.js), matching the same trust boundary the CI scanner
// uses.

import axios from 'axios';

// `||` would treat an intentionally-empty string as "unset" and fall back
// to localhost — which breaks the production/Caddy deployment, where the
// build is meant to set this to "" so axios makes same-origin relative
// requests (e.g. `/api/assets`) that Caddy then routes to the backend
// (see ../Dockerfile and ../../Caddyfile). `??` only falls back when the
// var is genuinely undefined, i.e. local `npm start` without CRA env config.
const BASE_URL = process.env.REACT_APP_API_BASE_URL ?? 'http://localhost:5000';
const TOKEN_STORAGE_KEY = 'ecdat_token';

/** Read the current project token (issued once at project creation). */
export function getProjectToken() {
  return localStorage.getItem(TOKEN_STORAGE_KEY) || '';
}

/** Persist a newly-issued project token — only ever called right after project creation. */
export function setProjectToken(token) {
  localStorage.setItem(TOKEN_STORAGE_KEY, token);
}

export function clearProjectToken() {
  localStorage.removeItem(TOKEN_STORAGE_KEY);
}

const api = axios.create({
  baseURL: BASE_URL,
  // Required to align with the backend's CORS policy, which pairs a single
  // allowed origin with credentials: true — never a wildcard origin
  // (backend/src/server.js, Patch 11).
  withCredentials: true,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Attach X-ECDAT-Token to every outgoing request.
api.interceptors.request.use((config) => {
  const token = getProjectToken();
  if (token) {
    config.headers['X-ECDAT-Token'] = token;
  }
  return config;
});

// Surface auth failures distinctly so the UI can prompt for a fresh token
// instead of silently retrying with a stale or invalid one.
api.interceptors.response.use(
  (response) => response,
  (error) => {
    const status = error.response?.status;
    if (status === 401 || status === 403) {
      // eslint-disable-next-line no-console
      console.warn('[ECDAT] token missing or rejected by gateway:', status);
    }
    return Promise.reject(error);
  }
);

/**
 * Fetch the raw finding list for the current project. Dashboard.js,
 * CBOMGraph.js, and MigrationPlanner.js all consume this — the aggregate
 * `/api/dashboard` endpoint only returns summary counts, not the
 * per-finding fields (contentHash, algorithm, riskTag, moscaScore,
 * fixSnippet, isLinked, ...) these views actually render.
 * @param {{status?: 'active'|'resolved', riskTag?: string}} [filters]
 * @returns {Promise<{assets: object[]}>}
 */
export async function fetchAssets(filters = {}) {
  const { data } = await api.get('/api/assets', { params: filters });
  return data;
}

/**
 * Trigger a manual Nmap/TLS scan against a live URL, within the current
 * authenticated project session. Merges into the same normalized project
 * data as the CI code-scan path (Path A), deduplicated by content hash.
 * @param {string} url
 */
export async function triggerNetworkScan(url) {
  const { data } = await api.post('/api/scan/network', { url });
  return data;
}

/**
 * Request (or re-request) PQC replacement-code generation for a specific
 * finding. A cache hit (same algorithm/language/keySize pattern) resolves
 * instantly; a rate-limited miss returns fixStatus: 'fix_pending' rather
 * than blocking this call.
 * @param {string} contentHash
 */
export async function requestPqcFix(contentHash) {
  const { data } = await api.post(`/api/assets/${contentHash}/fix`, {});
  return data;
}

/**
 * Create a new project and return its token.
 * @param {string} projectName
 * @param {string} description
 * @param {string[]} expectedDomains
 */
export async function createProject(projectName, description = '', expectedDomains = []) {
  const { data } = await api.post('/api/projects', { projectName, description, expectedDomains });
  return data;
}

export default api;
