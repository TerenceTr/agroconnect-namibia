// ============================================================================
// frontend/src/services/messagingApi.js — Buyer/Seller Messaging API Client
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Thin frontend helpers for the new conversation-based messaging endpoints.
// ============================================================================

import api from "../api";

function safeStr(value, fallback = "") {
  const text = String(value ?? "").trim();
  return text || fallback;
}

function apiPath(path) {
  const base = String(api?.defaults?.baseURL || "");
  const clean = path.startsWith("/") ? path : `/${path}`;
  return /\/api\/?$/.test(base) && clean.startsWith("/api/") ? clean.replace(/^\/api/, "") : clean;
}

function unwrapEnvelope(raw) {
  const root = raw?.data ?? raw ?? {};
  return root?.data ?? root;
}

export async function listConversations(params = {}) {
  const response = await api.get(apiPath("/api/messages/conversations"), { params });
  return unwrapEnvelope(response);
}

export async function startConversation(payload = {}) {
  const response = await api.post(apiPath("/api/messages/conversations/start"), payload);
  return unwrapEnvelope(response);
}

export async function getConversation(threadId, params = {}) {
  const id = safeStr(threadId);
  const response = await api.get(apiPath(`/api/messages/conversations/${id}`), { params });
  return unwrapEnvelope(response);
}

export async function sendMessage(threadId, body) {
  const id = safeStr(threadId);
  const response = await api.post(apiPath(`/api/messages/conversations/${id}/messages`), { body });
  return unwrapEnvelope(response);
}

export async function markConversationRead(threadId) {
  const id = safeStr(threadId);
  const response = await api.post(apiPath(`/api/messages/conversations/${id}/read`), {});
  return unwrapEnvelope(response);
}
