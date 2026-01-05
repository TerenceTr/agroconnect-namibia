// ============================================================================
// src/analytics/analyticsApi.js
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Optional server sync for analytics (if backend endpoints exist).
//   • Frontend must keep working even without these endpoints.
//   • Calls are intentionally guarded with clear errors.
// ============================================================================

const API = process.env.REACT_APP_API_URL || "";

/** Build Authorization header from stored JWT (if present). */
function authHeaders() {
  const token = localStorage.getItem("token");
  return token ? { Authorization: `Bearer ${token}` } : {};
}

/**
 * Small helper for fetch -> JSON with consistent error message.
 * NOTE: We keep it simple and do NOT crash the whole app if endpoint is missing.
 */
async function fetchJson(url) {
  const res = await fetch(url, { headers: { ...authHeaders() } });

  // Typical missing-endpoint result is 404; surface a friendly error.
  if (!res.ok) {
    const msg = `Request failed (${res.status}) for ${url}`;
    throw new Error(msg);
  }

  return res.json();
}

// Example endpoints (implement later if you want):
// GET /api/customer/analytics/summary
// GET /api/admin/analytics/summary

export function fetchCustomerAnalyticsSummary() {
  return fetchJson(`${API}/api/customer/analytics/summary`);
}

export function fetchAdminAnalyticsSummary() {
  return fetchJson(`${API}/api/admin/analytics/summary`);
}
