// ============================================================================
// src/hooks/ai/aiClient.js
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Axios client dedicated to AI endpoints (forecast/recommend/sms).
//
// WHY THIS EXISTS:
//   Prevents runtime crashes like:
//     "Cannot read properties of undefined (reading 'post')"
//   which typically happens when aiClient exports don't match imports.
//
// EXPORTS:
//   - default export: API client
//   - named export: API (alias) for flexibility
// ============================================================================

import axios from "axios";

function normalizeBase(base) {
  // Allow env override; fallback to local Flask default
  const raw = base || process.env.REACT_APP_API_BASE_URL || "http://localhost:5000";
  return raw.replace(/\/+$/, "");
}

// If your backend mounts AI under /api/ai, this becomes:
//   http://localhost:5000/api/ai
// If your backend uses /ai directly, change the suffix accordingly.
const API_BASE = `${normalizeBase()}/api/ai`;

const client = axios.create({
  baseURL: API_BASE,
  withCredentials: true,
  headers: {
    "Content-Type": "application/json",
  },
});

client.interceptors.response.use(
  (res) => res,
  (err) => {
    // Provide a consistent error surface
    const msg =
      err?.response?.data?.error ||
      err?.response?.data?.message ||
      err?.message ||
      "AI request failed";
    err.normalizedMessage = msg;
    return Promise.reject(err);
  }
);

export const API = client;
export default client;
