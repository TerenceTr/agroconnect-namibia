// ============================================================================
// frontend/src/services/repeatIssueApi.js
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Repeat issue detection service layer for Phase 4C.
//
// THIS VERSION FIXES:
//   ✅ Exports fetchFarmerRepeatIssueDetection
//   ✅ Exports fetchAdminRepeatIssueDetection
//   ✅ Keeps existing fetchFarmerRepeatIssues / fetchAdminRepeatIssues names
//   ✅ Supports both direct named imports and object-style default imports
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
// Shared repeat-issue filter serialization
// ----------------------------------------------------------------------------
function buildRepeatIssueParams(filters = {}) {
  return {
    days: filters?.days,
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
    min_score: filters?.min_score ?? filters?.minScore,
    risk_band: filters?.risk_band ?? filters?.riskBand,
    scope: filters?.scope,
  };
}

// ----------------------------------------------------------------------------
// Farmer repeat issue alerts
// ----------------------------------------------------------------------------
export async function fetchFarmerRepeatIssues(farmerId, filters = {}) {
  try {
    const response = await api.get(`/reviews/analytics/farmer/${farmerId}/repeat-issues`, {
      params: buildRepeatIssueParams(filters),
    });
    return extractData(response);
  } catch (error) {
    throw normalizeError(error, "Failed to load farmer repeat issue alerts.");
  }
}

// ----------------------------------------------------------------------------
// Admin repeat issue alerts
// ----------------------------------------------------------------------------
export async function fetchAdminRepeatIssues(filters = {}) {
  try {
    const response = await api.get("/reviews/analytics/admin/repeat-issues", {
      params: buildRepeatIssueParams(filters),
    });
    return extractData(response);
  } catch (error) {
    throw normalizeError(error, "Failed to load admin repeat issue alerts.");
  }
}

// ----------------------------------------------------------------------------
// Compatibility aliases
// ----------------------------------------------------------------------------
// NOTE:
// Some pages import the "...RepeatIssueDetection" names instead of the
// shorter "...RepeatIssues" names. Export both so older/newer files compile.
export async function fetchFarmerRepeatIssueDetection(farmerId, filters = {}) {
  return fetchFarmerRepeatIssues(farmerId, filters);
}

export async function fetchAdminRepeatIssueDetection(filters = {}) {
  return fetchAdminRepeatIssues(filters);
}

// ----------------------------------------------------------------------------
// Default export for object-style imports
// ----------------------------------------------------------------------------
const repeatIssueApi = {
  fetchFarmerRepeatIssues,
  fetchAdminRepeatIssues,
  fetchFarmerRepeatIssueDetection,
  fetchAdminRepeatIssueDetection,
};

export default repeatIssueApi;