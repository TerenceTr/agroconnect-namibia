// ============================================================================
// src/analytics/analyticsApi.js
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Optional server sync for analytics (only if backend endpoints exist).
//   • Frontend works WITHOUT this file.
//   • Keep calls guarded so a missing endpoint (404/501) doesn't break the UI.
// ============================================================================

import api from "../api";

// ---------------------------------------------------------------------------
// Helper: optional GET that returns null if endpoint is not available
// ---------------------------------------------------------------------------
async function optionalGet(url) {
  try {
    const res = await api.get(url);
    return res.data ?? null;
  } catch (err) {
    const status = err?.response?.status;
    // Endpoint not implemented / disabled
    if (status === 404 || status === 501) return null;
    // Auth errors should still be visible to callers
    if (status === 401 || status === 403) throw err;
    // Anything else: treat as optional failure
    return null;
  }
}

// Example endpoints (implement later if needed):
// GET  /customer/analytics/summary
// GET  /admin/analytics/summary

export function fetchCustomerAnalyticsSummary() {
  return optionalGet("/customer/analytics/summary");
}

export function fetchAdminAnalyticsSummary() {
  return optionalGet("/admin/analytics/summary");
}
