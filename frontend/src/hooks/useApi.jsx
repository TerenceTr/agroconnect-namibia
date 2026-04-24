// ============================================================================
// frontend/src/hooks/useApi.jsx — AgroConnect Namibia
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Reusable GET data-fetch hook for pages/dashboards.
//   • GET via shared Axios client (frontend/src/api.js)
//   • Consistent shape: { data, loading, error, status, refetch, usedEndpoint }
//   • Supports fallback endpoints (array): tries next on 404/405
//   • Normalizes "/api/*" endpoints when Axios baseURL already ends with "/api"
//   • Avoids stale async updates after unmount / route change (AbortController)
//   • Prevents “fetch on every render” by stabilizing:
//       - params/headers (objects)
//       - endpoints (arrays often created inline by pages)
// ============================================================================

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import api from "../api";

// ----------------------------------------------------------------------------
// Small URL helpers
// ----------------------------------------------------------------------------
function isAbsoluteUrl(url) {
  return /^([a-z][a-z\d+\-.]*:)?\/\//i.test(String(url || ""));
}

/**
 * Normalize endpoint so it plays nicely with api.js baseURL = ".../api"
 *
 * Accepts:
 *   "admin/overview"
 *   "/admin/overview"
 *   "/api/admin/overview"   -> "/admin/overview" (when baseURL ends with /api)
 *   "http://localhost:5000/api/admin/overview" (absolute, untouched)
 */
function normalizeEndpoint(endpoint) {
  if (!endpoint) return null;

  const raw = String(endpoint).trim();
  if (!raw) return null;

  // Absolute URL (http://, https://, //) → do not touch
  if (isAbsoluteUrl(raw)) return raw;

  // Ensure it starts with "/"
  const path = raw.startsWith("/") ? raw : `/${raw}`;

  // If caller passed "/api/..." but Axios baseURL already includes "/api",
  // strip the leading "/api" to avoid ".../api/api/...".
  const base = String(api?.defaults?.baseURL || "");
  const baseEndsWithApi = /\/api\/?$/.test(base);

  if (baseEndsWithApi && path.startsWith("/api/")) {
    return path.replace(/^\/api/, "");
  }

  return path;
}

// ----------------------------------------------------------------------------
// Stable stringify (sorted keys) to memoize objects safely
// ----------------------------------------------------------------------------
function stableStringify(value) {
  const seen = new WeakSet();

  const sorter = (obj) => {
    if (!obj || typeof obj !== "object") return obj;
    if (seen.has(obj)) return null;
    seen.add(obj);

    if (Array.isArray(obj)) return obj.map(sorter);

    const out = {};
    Object.keys(obj)
      .sort()
      .forEach((k) => {
        out[k] = sorter(obj[k]);
      });
    return out;
  };

  try {
    return JSON.stringify(sorter(value));
  } catch {
    // If it can't stringify, treat it as changing every time.
    // (This should be rare for params/headers/endpoints.)
    return String(Math.random());
  }
}

// ----------------------------------------------------------------------------
// Error normalization (keeps UI consistent)
// ----------------------------------------------------------------------------
function normalizeError(err) {
  const status = err?.response?.status ?? null;

  const message =
    err?.response?.data?.message ||
    err?.response?.data?.error ||
    err?.message ||
    "Request failed";

  return { message, status };
}

// ----------------------------------------------------------------------------
// Utility: treat 404/405 as "try next fallback endpoint"
// ----------------------------------------------------------------------------
function isRetryableNotFound(status) {
  return status === 404 || status === 405;
}

// ============================================================================
// Hook
// ============================================================================
/**
 * useApi(endpointOrEndpoints, options)
 *
 * @param {string|string[]|null|undefined} endpointOrEndpoints
 * @param {object} options
 * @param {boolean} [options.enabled]       - defaults to Boolean(endpoint(s))
 * @param {any}     [options.initialData]   - initial data (default: undefined)
 * @param {object}  [options.params]        - axios params
 * @param {object}  [options.headers]       - axios headers
 * @param {boolean} [options.coerceNull]    - null -> undefined (default: true)
 * @param {boolean} [options.skipAuth]      - for public endpoints (no Authorization)
 * @param {any[]}   [options.deps]          - extra deps to trigger refetch
 *
 * @returns { data, loading, error, status, refetch, usedEndpoint }
 */
export default function useApi(endpointOrEndpoints, options = {}) {
  const {
    enabled: enabledProp,
    initialData = undefined,
    params,
    headers,
    coerceNull = true,
    skipAuth = false,
    deps = [],
  } = options;

  // --------------------------------------------------------------------------
  // CRITICAL FIX:
  // Many pages pass endpoints as an array returned by a function:
  //   useApi(epOverview(farmerId), ...)
  // That array is often NEW on every render → without stabilization, it would
  // trigger fetch-on-every-render.
  //
  // We build a stable "endpointKey" from content, then derive endpoints from it.
  // --------------------------------------------------------------------------
  const endpointKey = useMemo(
    () => stableStringify(endpointOrEndpoints),
    [endpointOrEndpoints]
  );

  // Normalize into a de-duplicated array of endpoints (supports fallback)
  const endpoints = useMemo(() => {
    // NOTE: We intentionally depend on endpointKey (content), not array identity.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    const src = endpointOrEndpoints;

    const list = Array.isArray(src) ? src : [src];

    // Normalize then de-dupe (important when callers provide both "/api/x" and "/x")
    const normalized = list.map((e) => normalizeEndpoint(e)).filter(Boolean);

    const out = [];
    const seen = new Set();
    for (const u of normalized) {
      if (seen.has(u)) continue;
      seen.add(u);
      out.push(u);
    }
    return out;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [endpointKey]);

  const enabled = enabledProp ?? endpoints.length > 0;

  // Stabilize params/headers so we don't refetch every render
  const paramsKey = useMemo(() => stableStringify(params), [params]);
  const headersKey = useMemo(() => stableStringify(headers), [headers]);

  // eslint-disable-next-line react-hooks/exhaustive-deps
  const stableParams = useMemo(() => params, [paramsKey]);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const stableHeaders = useMemo(() => headers, [headersKey]);

  // Start as undefined (NOT null) so destructuring defaults work:
  //   const { data: users = [] } = useApi(...)
  const [data, setData] = useState(initialData);
  const [loading, setLoading] = useState(Boolean(enabled && endpoints.length));
  const [error, setError] = useState(null);
  const [status, setStatus] = useState(null);
  const [usedEndpoint, setUsedEndpoint] = useState(null);

  // Cancel in-flight requests safely on unmount/route change
  const abortRef = useRef(null);

  const fetchNow = useCallback(async () => {
    if (!enabled || endpoints.length === 0) {
      setLoading(false);
      setError(null);
      setStatus(null);
      setUsedEndpoint(null);
      setData(initialData);
      return;
    }

    // Abort any previous in-flight request
    if (abortRef.current) abortRef.current.abort();

    const controller = new AbortController();
    abortRef.current = controller;

    setLoading(true);
    setError(null);
    setStatus(null);

    let lastErr = null;

    // Try endpoints in order; if missing (404/405), try next
    for (const url of endpoints) {
      try {
        const res = await api.get(url, {
          params: stableParams,
          headers: stableHeaders,
          signal: controller.signal, // axios v1 supports AbortController
          // NOTE: api.js interceptor may read config.skipAuth to omit Authorization.
          skipAuth,
        });

        if (controller.signal.aborted) return;

        setUsedEndpoint(url);
        setStatus(res?.status ?? 200);

        const next = res?.data;
        setData(coerceNull && next === null ? undefined : next);

        setLoading(false);
        return; // SUCCESS
      } catch (err) {
        if (controller.signal.aborted) return;

        const e = normalizeError(err);
        lastErr = e;

        if (isRetryableNotFound(e.status)) continue; // try next fallback

        // Other errors (401/500/etc): stop immediately
        break;
      }
    }

    // All attempts failed
    setUsedEndpoint(null);
    setStatus(lastErr?.status ?? null);
    setError(lastErr?.message ?? "Request failed");
    setData(initialData);
    setLoading(false);
  }, [
    enabled,
    endpoints,
    stableParams,
    stableHeaders,
    initialData,
    coerceNull,
    skipAuth,
  ]);

  useEffect(() => {
    fetchNow();
    return () => {
      if (abortRef.current) abortRef.current.abort();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [fetchNow, ...deps]);

  return {
    data,
    loading,
    error,
    status,
    refetch: fetchNow,
    usedEndpoint,
  };
}
