// ============================================================================
// src/hooks/useApi.jsx — AgroConnect Namibia
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Reusable GET data-fetch hook for pages/dashboards.
//
// RESPONSIBILITIES:
//   • Fetch data from a GET endpoint using the shared Axios client (src/api.js)
//   • Provide consistent shape: { data, loading, error, status, refetch, usedEndpoint }
//   • Support fallback endpoints (array): tries next on 404/405
//   • Normalize "/api/*" endpoints when Axios baseURL already ends with "/api"
//   • Avoid stale async updates after unmount / route change (AbortController)
//   • Prevent “fetch on every render” by stabilizing params/headers dependencies
//
// WHY THIS MATTERS:
//   Many dashboard pages pass inline objects: { farmerId, days, q }
//   If those objects are used directly in hook dependencies, React will refetch
//   continuously. This hook now stabilizes them safely.
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
 * Accepts any of these safely:
 *   "admin/overview"
 *   "/admin/overview"
 *   "/api/admin/overview"   <-- normalized to "/admin/overview" if baseURL ends with /api
 *   "http://localhost:5000/api/admin/overview" (absolute, left untouched)
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
// Stable stringify (sorted keys) to memoize params/headers safely
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
    // Fallback: if it can't stringify, treat as changing every time
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
 * @param {boolean} [options.coerceNull]    - if true, response null -> undefined (default: true)
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
    deps = [],
  } = options;

  // Normalize into an array of endpoints (supports fallback)
  const endpoints = useMemo(() => {
    const list = Array.isArray(endpointOrEndpoints)
      ? endpointOrEndpoints
      : [endpointOrEndpoints];

    return list.map((e) => normalizeEndpoint(e)).filter(Boolean);
  }, [endpointOrEndpoints]);

  const enabled = enabledProp ?? endpoints.length > 0;

  // Stabilize params/headers so we don't refetch every render
  const paramsKey = useMemo(() => stableStringify(params), [params]);
  const headersKey = useMemo(() => stableStringify(headers), [headers]);

  const stableParams = useMemo(() => params, [paramsKey]);   // eslint-disable-line react-hooks/exhaustive-deps
  const stableHeaders = useMemo(() => headers, [headersKey]); // eslint-disable-line react-hooks/exhaustive-deps

  // CRITICAL: start as undefined (NOT null) so destructuring defaults work:
  //   const { data: users = [] } = useApi(...)
  const [data, setData] = useState(initialData);
  const [loading, setLoading] = useState(Boolean(enabled && endpoints.length));
  const [error, setError] = useState(null);
  const [status, setStatus] = useState(null);
  const [usedEndpoint, setUsedEndpoint] = useState(null);

  // Used to cancel in-flight requests safely on unmount/route change
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

    // Try endpoints in order; if first is missing (404/405), try next
    for (const url of endpoints) {
      try {
        const res = await api.get(url, {
          params: stableParams,
          headers: stableHeaders,
          signal: controller.signal, // axios v1 supports AbortController
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

        // Only fall back when endpoint is missing / method not allowed
        if (isRetryableNotFound(e.status)) continue;

        // Other errors (401/500/etc): stop immediately
        break;
      }
    }

    // If we got here, all attempts failed
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
  ]);

  // Auto-fetch on mount + when dependencies change
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
    usedEndpoint, // helpful for debugging which backend route worked
  };
}
