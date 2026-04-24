// ============================================================================
// frontend/src/components/analytics/analyticsApi.js
// ----------------------------------------------------------------------------
// FILE ROLE:
//   ⚠️ OPTIONAL Analytics API Layer (SAFE / NON-BLOCKING)
//
// PURPOSE:
//   • Fetch analytics summaries ONLY if backend endpoints exist
//   • Never break dashboards if analytics routes are missing
//
// CORE GUARANTEES:
//   • Returns `null` when endpoints are missing/disabled (404 / 501)
//   • Throws ONLY on auth errors (401 / 403)
//   • Any other errors are treated as optional failures (return null)
//
// PATH NOTE (IMPORTANT):
//   This file is under: src/components/analytics/analyticsApi.js
//   The axios instance is at: src/api.js
//   Therefore the correct relative import is: "../../api"
// ============================================================================

// ✅ Correct path: components/analytics -> (.. to components) -> (.. to src) -> api.js
import api from "../../api";

// ---------------------------------------------------------------------------
// Internal helper: optional GET request
// ---------------------------------------------------------------------------
async function optionalGet(url) {
  try {
    const res = await api.get(url);
    return res?.data ?? null;
  } catch (err) {
    const status = err?.response?.status;

    // Endpoint not implemented or disabled
    if (status === 404 || status === 501) return null;

    // Authentication/authorization must remain visible
    if (status === 401 || status === 403) throw err;

    // Network/server/timeouts treated as optional
    return null;
  }
}

// ---------------------------------------------------------------------------
// CUSTOMER ANALYTICS (OPTIONAL)
// Endpoint (if implemented):
//   GET /api/customer/analytics/summary
// ---------------------------------------------------------------------------
export function fetchCustomerAnalyticsSummary() {
  return optionalGet("/customer/analytics/summary");
}

// ---------------------------------------------------------------------------
// ADMIN ANALYTICS (OPTIONAL)
// Endpoint (if implemented):
//   GET /api/admin/analytics/summary
// ---------------------------------------------------------------------------
export function fetchAdminAnalyticsSummary() {
  return optionalGet("/admin/analytics/summary");
}

// ---------------------------------------------------------------------------
// Default export (optional convenience)
// ---------------------------------------------------------------------------
export default {
  fetchCustomerAnalyticsSummary,
  fetchAdminAnalyticsSummary,
};
