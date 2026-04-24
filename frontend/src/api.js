// ============================================================================
// frontend/src/api.js — AgroConnect Namibia (PRODUCTION-SAFE AXIOS CLIENT)
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Central Axios client for the entire frontend.
//   • Single shared Axios instance (`api`) used across the app
//   • Ensures baseURL ALWAYS ends with "/api" (callers must NOT prefix "/api")
//   • Attaches JWT access token automatically (Authorization: Bearer <token>)
//   • Supports PUBLIC calls via config.skipAuth = true (no Authorization header)
//   • Refresh-token rotation with concurrency safety (request queue)
//   • Prevents duplicate retries + refresh loops
//   • Exposes token helpers + refresh helper for AuthProvider integration
//
// IMPORTANT FIX (THIS UPDATE):
//   ✅ Auto-normalize URL paths to PREVENT "/api/api/...":
//      - If caller passes "/api/orders/..." while baseURL ends with "/api",
//        we strip the redundant "/api/" and keep it correct.
//      - Supports: "orders/..", "/orders/..", "api/orders/..", "/api/orders/.."
// ============================================================================

import axios from "axios";

// ----------------------------------------------------------------------------
// Runtime helpers
// ----------------------------------------------------------------------------
function hasWindow() {
  return typeof window !== "undefined" && !!window.location;
}

function getWindowOriginSafe() {
  if (hasWindow()) return window.location.origin;
  return "http://localhost:3000";
}

// ----------------------------------------------------------------------------
// URL helpers
// ----------------------------------------------------------------------------
function isAbsoluteUrl(url) {
  return /^([a-z][a-z\d+\-.]*:)?\/\//i.test(String(url || ""));
}

/**
 * Normalize request URLs so callers can safely pass:
 *   • "orders/..."        (relative)  ✅ recommended
 *   • "/orders/..."       (leading slash)
 *   • "/api/orders/..."   (legacy / explicit)
 *   • "api/orders/..."    (legacy)
 *
 * Goal:
 *   If baseURL ends with ".../api", then config.url MUST NOT start with "api"
 *   (otherwise axios may build ".../api/api/...").
 */
function normalizeApiUrlForBase(config, apiInstance) {
  try {
    let url = String(config?.url || "").trim();
    if (!url) return;
    if (isAbsoluteUrl(url)) return;

    const base = String(config?.baseURL || apiInstance?.defaults?.baseURL || "");
    const baseClean = base.replace(/\/+$/, "");
    const baseEndsWithApi = /\/api$/i.test(baseClean);

    if (!baseEndsWithApi) return;

    // Step 1) Strip leading slashes
    url = url.replace(/^\/+/, "");

    // Step 2) Remove any number of leading "api" segments
    // "api/orders" -> "orders"
    // "api/api/auth/login" -> "auth/login"
    while (/^api(?:\/|$)/i.test(url)) {
      url = url.replace(/^api\/?/i, "");
    }

    // Step 3) Put cleaned relative URL back
    config.url = url || "";
  } catch {
    // no-op
  }
}

/**
 * Normalize configured API host/base:
 * - Accepts:
 *   • "http://localhost:5000"
 *   • "http://localhost:5000/api"
 *   • "/api" (relative -> same origin)
 * - Ensures output WITHOUT trailing "/" and WITHOUT "/api".
 */
function normalizeHostBase(input) {
  const raw = String(input || "").trim();
  if (!raw) return "";

  // Relative path like "/api" -> same origin
  if (raw.startsWith("/")) {
    const u = `${getWindowOriginSafe()}${raw}`;
    return u.replace(/\/+$/, "").replace(/\/api\/?$/i, "");
  }

  // Absolute
  if (isAbsoluteUrl(raw)) {
    return raw.replace(/\/+$/, "").replace(/\/api\/?$/i, "");
  }

  // Bare host (rare)
  return raw.replace(/\/+$/, "").replace(/\/api\/?$/i, "");
}

// ----------------------------------------------------------------------------
// Backend host (NO /api here)
// ----------------------------------------------------------------------------
const defaultDevHost = hasWindow()
  ? `${window.location.protocol}//${window.location.hostname}:5000`
  : "http://localhost:5000";

const envApiUrl = typeof process !== "undefined" ? process.env.REACT_APP_API_URL : "";
const hostFromEnv = normalizeHostBase(envApiUrl || "");
const HOST_BASE = (hostFromEnv || defaultDevHost).replace(/\/+$/, "");

// Public constant: full API root (ends with /api)
export const API_ROOT = `${HOST_BASE}/api`;

// ----------------------------------------------------------------------------
// Storage keys
// ----------------------------------------------------------------------------
const ACCESS_KEY = "token";
const REFRESH_KEY = "refreshToken";

// ----------------------------------------------------------------------------
// Token helpers
// ----------------------------------------------------------------------------
export function getAccessToken() {
  try {
    if (!hasWindow()) return null;
    return window.localStorage.getItem(ACCESS_KEY);
  } catch {
    return null;
  }
}

export function getRefreshToken() {
  try {
    if (!hasWindow()) return null;
    return window.localStorage.getItem(REFRESH_KEY);
  } catch {
    return null;
  }
}

export function setTokens({ accessToken, refreshToken }) {
  try {
    if (!hasWindow()) return;
    if (accessToken) window.localStorage.setItem(ACCESS_KEY, accessToken);
    if (refreshToken) window.localStorage.setItem(REFRESH_KEY, refreshToken);
  } catch {
    // no-op
  }
}

export function clearTokens() {
  try {
    if (!hasWindow()) return;
    window.localStorage.removeItem(ACCESS_KEY);
    window.localStorage.removeItem(REFRESH_KEY);
  } catch {
    // no-op
  }
}

/**
 * Extract access/refresh tokens from various backend response shapes.
 * Exported so AuthProvider and other auth workflows can reuse one parser.
 */
export function normalizeTokenResponse(data) {
  const accessToken =
    data?.accessToken ||
    data?.token ||
    data?.access_token ||
    data?.access ||
    null;

  const refreshToken =
    data?.refreshToken ||
    data?.refresh_token ||
    data?.refresh ||
    null;

  return { accessToken, refreshToken };
}

/**
 * Backward-compatible alias.
 * Some auth-layer files may still import normalizeTokenPayload.
 */
export const normalizeTokenPayload = normalizeTokenResponse;

// ----------------------------------------------------------------------------
// Axios instance for app requests
// ----------------------------------------------------------------------------
const api = axios.create({
  baseURL: API_ROOT, // IMPORTANT: ends with /api
  timeout: 20000,
  headers: {
    Accept: "application/json",
  },
});

// ----------------------------------------------------------------------------
// Utility: set Authorization header
// ----------------------------------------------------------------------------
export function setApiAuthHeader(token) {
  if (!token) {
    delete api.defaults.headers.common.Authorization;
    return;
  }
  api.defaults.headers.common.Authorization = `Bearer ${token}`;
}

// Set default header on module load
setApiAuthHeader(getAccessToken());

// ----------------------------------------------------------------------------
// Refresh call (NO interceptors)
// ----------------------------------------------------------------------------
export async function refreshAccessToken(refreshToken) {
  const res = await axios.post(
    `${API_ROOT}/auth/refresh`,
    { refreshToken, refresh_token: refreshToken },
    { timeout: 20000, headers: { Accept: "application/json" } }
  );
  return res.data;
}

// ----------------------------------------------------------------------------
// Refresh coordination queue
// ----------------------------------------------------------------------------
let isRefreshing = false;
let queue = [];

function enqueueRequest(originalConfig) {
  return new Promise((resolve, reject) => {
    queue.push({ originalConfig, resolve, reject });
  });
}

function resolveQueue(error, token) {
  queue.forEach(({ originalConfig, resolve, reject }) => {
    if (error) return reject(error);

    const cfg = { ...originalConfig };
    cfg.headers = cfg.headers || {};
    cfg.headers.Authorization = `Bearer ${token}`;
    api(cfg).then(resolve).catch(reject);
  });

  queue = [];
}

// ----------------------------------------------------------------------------
// Request interceptor: attach token + normalize URL paths
// ----------------------------------------------------------------------------
api.interceptors.request.use(
  (config) => {
    // Prevent "/api/api/..." by stripping redundant api prefixes
    normalizeApiUrlForBase(config, api);

    const skipAuth = !!config?.skipAuth;
    if (skipAuth) {
      if (config.headers) {
        delete config.headers.Authorization;
        delete config.headers.authorization;
      }
      return config;
    }

    const token = getAccessToken();

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
// Response interceptor: refresh on 401 → retry
// ----------------------------------------------------------------------------
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const original = error?.config;
    if (!original) return Promise.reject(error);

    const status = error?.response?.status;

    if (original.skipAuth) return Promise.reject(error);
    if (status !== 401) return Promise.reject(error);

    const url = String(original.url || "");
    if (url.includes("auth/refresh") || original._retry) {
      return Promise.reject(error);
    }

    original._retry = true;

    const rt = getRefreshToken();
    if (!rt) {
      clearTokens();
      try {
        if (hasWindow()) window.dispatchEvent(new CustomEvent("auth:logout"));
      } catch {
        // no-op
      }
      return Promise.reject(error);
    }

    if (isRefreshing) {
      return enqueueRequest(original);
    }

    isRefreshing = true;

    try {
      const data = await refreshAccessToken(rt);
      const { accessToken: newAccess, refreshToken: newRefresh } = normalizeTokenResponse(data);

      if (!newAccess) throw error;

      setTokens({ accessToken: newAccess, refreshToken: newRefresh || rt });
      setApiAuthHeader(newAccess);

      resolveQueue(null, newAccess);

      original.headers = original.headers || {};
      original.headers.Authorization = `Bearer ${newAccess}`;
      return api(original);
    } catch (err) {
      resolveQueue(err, null);
      clearTokens();
      try {
        if (hasWindow()) window.dispatchEvent(new CustomEvent("auth:logout"));
      } catch {
        // no-op
      }
      return Promise.reject(err);
    } finally {
      isRefreshing = false;
    }
  }
);

export default api;