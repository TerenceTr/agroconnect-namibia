// ============================================================================
// frontend/src/services/reviewQualityApi.js
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Complaint taxonomy and review-issue-link service layer.
//
// PHASE 4A:
//   ✅ Fetch complaint taxonomy
//   ✅ Admin create/update taxonomy
//   ✅ Fetch review issue links
//   ✅ Create / replace issue links on reviews
//   ✅ Reclassify issue links as farmer/admin
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

function asArray(data) {
  const payload = unwrapApiDataEnvelope(data);
  if (Array.isArray(payload)) return payload;
  if (Array.isArray(payload?.items)) return payload.items;
  return [];
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
// Complaint taxonomy APIs
// ----------------------------------------------------------------------------
export async function fetchComplaintTaxonomy(options = {}) {
  try {
    const response = await api.get("/reviews/taxonomy", {
      params: {
        include_inactive: options?.include_inactive ? 1 : 0,
        parent_group: options?.parent_group ?? "",
      },
    });

    const payload = extractData(response);
    return {
      items: asArray(payload?.items ?? payload),
      groups: payload?.groups ?? {},
    };
  } catch (error) {
    throw normalizeError(error, "Failed to load complaint taxonomy.");
  }
}

export async function createComplaintTaxonomy(payload = {}) {
  try {
    const response = await api.post("/reviews/taxonomy", payload);
    return extractData(response);
  } catch (error) {
    throw normalizeError(error, "Failed to create complaint taxonomy item.");
  }
}

export async function updateComplaintTaxonomy(taxonomyId, payload = {}) {
  try {
    const response = await api.patch(`/reviews/taxonomy/${taxonomyId}`, payload);
    return extractData(response);
  } catch (error) {
    throw normalizeError(error, "Failed to update complaint taxonomy item.");
  }
}

// ----------------------------------------------------------------------------
// Review issue link APIs
// ----------------------------------------------------------------------------
export async function fetchReviewIssueLinks(ratingId) {
  try {
    const response = await api.get(`/reviews/${ratingId}/issues`);
    const payload = extractData(response);
    return asArray(payload?.items ?? payload);
  } catch (error) {
    throw normalizeError(error, "Failed to load review issue links.");
  }
}

export async function createReviewIssueLinks(ratingId, issues = [], options = {}) {
  try {
    const response = await api.post(`/reviews/${ratingId}/issues`, {
      issues,
      replace_existing: Boolean(options?.replace_existing),
    });

    const payload = extractData(response);
    return asArray(payload?.items ?? payload);
  } catch (error) {
    throw normalizeError(error, "Failed to save review issue links.");
  }
}

export async function updateReviewIssueLinks(ratingId, issues = []) {
  try {
    const response = await api.patch(`/reviews/${ratingId}/issues`, { issues });
    const payload = extractData(response);
    return asArray(payload?.items ?? payload);
  } catch (error) {
    throw normalizeError(error, "Failed to update review issue links.");
  }
}

// ----------------------------------------------------------------------------
// Default export for projects that prefer object-style imports
// ----------------------------------------------------------------------------
const reviewQualityApi = {
  fetchComplaintTaxonomy,
  createComplaintTaxonomy,
  updateComplaintTaxonomy,
  fetchReviewIssueLinks,
  createReviewIssueLinks,
  updateReviewIssueLinks,
};

export default reviewQualityApi;