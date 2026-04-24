// ============================================================================
// frontend/src/services/reviewAnalyticsApi.js
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Review-quality analytics service layer for Phase 4B.
//
// PHASE 4B:
//   ✅ Farmer analytics endpoint helper
//   ✅ Admin analytics endpoint helper
//   ✅ Shared filter serialization for complaint charts and filters
// ============================================================================

import api from "../api";

// ----------------------------------------------------------------------------
// Generic payload helpers
// ----------------------------------------------------------------------------
function unwrapApiDataEnvelope(raw) {
  if (raw == null) return raw;
  if (Array.isArray(raw)) return raw;
  if (typeof raw !== "object") return raw;

  if (Object.prototype.hasOwnProperty.call(raw, "data") && raw.data != null) {
    return raw.data;
  }

  return raw;
}

function extractData(response) {
  const first = response?.data ?? response;
  return unwrapApiDataEnvelope(first);
}

function normalizeError(error, fallback = "Request failed.") {
  const message =
    error?.response?.data?.message ||
    error?.response?.data?.error ||
    error?.message ||
    fallback;

  const e = new Error(message);
  e.cause = error;
  e.status = error?.response?.status ?? null;
  e.payload = error?.response?.data ?? null;
  return e;
}

// ----------------------------------------------------------------------------
// Shared analytics filter serialization
// ----------------------------------------------------------------------------
function buildAnalyticsParams(filters = {}) {
  return {
    days: filters?.days,
    bucket: filters?.bucket,
    product_id: filters?.product_id ?? filters?.productId,
    taxonomy_code: filters?.taxonomy_code ?? filters?.taxonomyCode,
    parent_group: filters?.parent_group ?? filters?.parentGroup,
    detected_by: filters?.detected_by ?? filters?.detectedBy,
    resolution_status: filters?.resolution_status ?? filters?.resolutionStatus,
    verified_only:
      typeof filters?.verified_only !== "undefined"
        ? (filters.verified_only ? 1 : 0)
        : typeof filters?.verifiedOnly !== "undefined"
          ? (filters.verifiedOnly ? 1 : 0)
          : undefined,
    only_negative:
      typeof filters?.only_negative !== "undefined"
        ? (filters.only_negative ? 1 : 0)
        : typeof filters?.onlyNegative !== "undefined"
          ? (filters.onlyNegative ? 1 : 0)
          : undefined,
    min_severity: filters?.min_severity ?? filters?.minSeverity,
    repeat_threshold: filters?.repeat_threshold ?? filters?.repeatThreshold,
  };
}

// ----------------------------------------------------------------------------
// Farmer analytics
// ----------------------------------------------------------------------------
export async function fetchFarmerReviewAnalytics(farmerId, filters = {}) {
  try {
    const response = await api.get(`/reviews/analytics/farmer/${farmerId}`, {
      params: buildAnalyticsParams(filters),
    });
    return extractData(response);
  } catch (error) {
    throw normalizeError(error, "Failed to load farmer review analytics.");
  }
}

// ----------------------------------------------------------------------------
// Admin analytics
// ----------------------------------------------------------------------------
export async function fetchAdminReviewAnalytics(filters = {}) {
  try {
    const response = await api.get("/reviews/analytics/admin/overview", {
      params: buildAnalyticsParams(filters),
    });
    return extractData(response);
  } catch (error) {
    throw normalizeError(error, "Failed to load admin review analytics.");
  }
}

// ----------------------------------------------------------------------------
// Default export for object-style imports
// ----------------------------------------------------------------------------
const reviewAnalyticsApi = {
  fetchFarmerReviewAnalytics,
  fetchAdminReviewAnalytics,
};

export default reviewAnalyticsApi;