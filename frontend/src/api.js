// ============================================================================
// frontend/src/api.js — AgroConnect Namibia (PRODUCTION-SAFE AXIOS CLIENT)
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Central Axios client for the entire frontend.
//
// RESPONSIBILITIES:
//   • Exposes a single Axios instance (`api`) used across the app
//   • Ensures baseURL ALWAYS ends with "/api" (callers must NOT prefix "/api")
//   • Attaches JWT access token automatically (Authorization: Bearer <token>)
//   • Handles refresh-token rotation with concurrency safety (request queue)
//   • Prevents duplicate retries + refresh loops
//   • Exposes token helpers + refresh helper for AuthProvider integration
//
// DESIGN NOTES:
//   • We DO NOT force "Content-Type: application/json" globally, because
//     multipart/form-data requests must allow Axios to set boundaries.
//   • Refresh calls use *global axios* (no interceptors) to avoid recursion.
// ============================================================================

import axios from "axios";

// ----------------------------------------------------------------------------
// Backend host (NO /api here)
// ----------------------------------------------------------------------------
const HOST_BASE = (
  process.env.REACT_APP_API_URL ||
  `${window.location.protocol}//${window.location.hostname}:5000`
).replace(/\/$/, "");

// Public constant: full API root (ends with /api)
export const API_ROOT = `${HOST_BASE}/api`;

// ----------------------------------------------------------------------------
// Storage keys (keep consistent everywhere)
// ----------------------------------------------------------------------------
const ACCESS_KEY = "token";
const REFRESH_KEY = "refreshToken";

// ----------------------------------------------------------------------------
// Token helpers (used by AuthProvider and interceptors)
// ----------------------------------------------------------------------------
export function getAccessToken() {
  try {
    return localStorage.getItem(ACCESS_KEY);
  } catch {
    return null;
  }
}

export function getRefreshToken() {
  try {
    return localStorage.getItem(REFRESH_KEY);
  } catch {
    return null;
  }
}

export function setTokens({ accessToken, refreshToken }) {
  try {
    if (accessToken) localStorage.setItem(ACCESS_KEY, accessToken);
    if (refreshToken) localStorage.setItem(REFRESH_KEY, refreshToken);
  } catch {
    // Ignore storage failures (private mode / blocked storage)
  }
}

export function clearTokens() {
  try {
    localStorage.removeItem(ACCESS_KEY);
    localStorage.removeItem(REFRESH_KEY);
  } catch {
    // Ignore
  }
}

// ----------------------------------------------------------------------------
// Axios instance for app requests
// ----------------------------------------------------------------------------
const api = axios.create({
  baseURL: API_ROOT,
  timeout: 12000,
  headers: {
    Accept: "application/json",
  },
});

// ----------------------------------------------------------------------------
// Utility: set Authorization header on the shared client defaults
// ----------------------------------------------------------------------------
export function setApiAuthHeader(token) {
  if (!token) {
    delete api.defaults.headers.common.Authorization;
    return;
  }
  api.defaults.headers.common.Authorization = `Bearer ${token}`;
}

// ----------------------------------------------------------------------------
// Refresh call (NO interceptors)
// IMPORTANT: exported because AuthProvider imports it.
// ----------------------------------------------------------------------------
export async function refreshAccessToken(refreshToken) {
  // Do NOT use `api` here to avoid interceptor recursion.
  const res = await axios.post(
    `${API_ROOT}/auth/refresh`,
    { refreshToken },
    { timeout: 12000, headers: { Accept: "application/json" } }
  );
  return res.data;
}

/**
 * Extract access/refresh tokens from various backend shapes.
 * Supports:
 *  • { accessToken, refreshToken }
 *  • { token, refreshToken }
 *  • { access_token, refresh_token }
 */
function normalizeTokenResponse(data) {
  const accessToken = data?.accessToken || data?.token || data?.access_token || null;
  const refreshToken = data?.refreshToken || data?.refresh_token || null;
  return { accessToken, refreshToken };
}

// ----------------------------------------------------------------------------
// Refresh token coordination (queue)
// When multiple requests hit 401 at once, only ONE refresh is performed.
// ----------------------------------------------------------------------------
let isRefreshing = false;
let queue = [];

/**
 * Enqueue a request config while refresh is in progress.
 * Returns a promise that resolves/rejects with the retried request.
 */
function enqueueRequest(originalConfig) {
  return new Promise((resolve, reject) => {
    queue.push({ originalConfig, resolve, reject });
  });
}

/**
 * Drain the queue after refresh finishes.
 * If error is provided → reject all.
 * If token is provided → retry all with token.
 */
function resolveQueue(error, token) {
  queue.forEach(({ originalConfig, resolve, reject }) => {
    if (error) {
      reject(error);
      return;
    }

    const cfg = { ...originalConfig };
    cfg.headers = cfg.headers || {};
    cfg.headers.Authorization = `Bearer ${token}`;

    api(cfg).then(resolve).catch(reject);
  });

  queue = [];
}

// ----------------------------------------------------------------------------
// Request interceptor: attach access token if present
// ----------------------------------------------------------------------------
api.interceptors.request.use(
  (config) => {
    const token = getAccessToken();

    // Respect any manually-set Authorization header (rare but useful)
    const hasAuth =
      !!config?.headers &&
      (typeof config.headers.Authorization === "string" ||
        typeof config.headers.authorization === "string");

    if (token && !hasAuth) {
      config.headers = config.headers || {};
      config.headers.Authorization = `Bearer ${token}`;
    }

    return config;
  },
  (err) => Promise.reject(err)
);

// ----------------------------------------------------------------------------
// Response interceptor: 401 handling → refresh → retry
// ----------------------------------------------------------------------------
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const original = error?.config;
    if (!original) return Promise.reject(error);

    const status = error?.response?.status;
    if (status !== 401) return Promise.reject(error);

    // Prevent refresh loops:
    //  • never refresh for the refresh endpoint itself
    //  • never retry the same request twice
    const url = String(original.url || "");
    if (url.includes("/auth/refresh") || original._retry) {
      return Promise.reject(error);
    }

    original._retry = true;

    const rt = getRefreshToken();
    if (!rt) {
      clearTokens();
      try {
        window.dispatchEvent(new CustomEvent("auth:logout"));
      } catch {
        // ignore
      }
      return Promise.reject(error);
    }

    // If refresh already in progress, queue this request
    if (isRefreshing) {
      return enqueueRequest(original);
    }

    isRefreshing = true;

    try {
      const data = await refreshAccessToken(rt);
      const { accessToken: newAccess, refreshToken: newRefresh } = normalizeTokenResponse(data);

      if (!newAccess) throw error;

      // Persist tokens (rotate refresh token if backend returns a new one)
      setTokens({ accessToken: newAccess, refreshToken: newRefresh || rt });

      // Update defaults for future requests
      setApiAuthHeader(newAccess);

      // Release queued requests
      resolveQueue(null, newAccess);

      // Retry original request
      original.headers = original.headers || {};
      original.headers.Authorization = `Bearer ${newAccess}`;
      return api(original);
    } catch (err) {
      resolveQueue(err, null);
      clearTokens();

      try {
        window.dispatchEvent(new CustomEvent("auth:logout"));
      } catch {
        // ignore
      }

      return Promise.reject(err);
    } finally {
      isRefreshing = false;
    }
  }
);

export default api;
