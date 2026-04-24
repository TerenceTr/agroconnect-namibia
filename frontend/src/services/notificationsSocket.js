// ============================================================================
// frontend/src/services/notificationsSocket.js
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Tiny Socket.IO helper for live notification bell refreshes.
//
// DESIGN:
//   • Connects only when a refresh token exists
//   • Uses the backend /notifications namespace
//   • Keeps the client simple: callers subscribe to notifications:changed
// ============================================================================

import { io } from "socket.io-client";

import { API_ROOT, getRefreshToken } from "../api";

function getSocketBaseUrl() {
  return String(API_ROOT || "").replace(/\/api\/?$/i, "");
}

export function connectNotificationsSocket() {
  const refreshToken = getRefreshToken();
  if (!refreshToken) return null;

  return io(`${getSocketBaseUrl()}/notifications`, {
    autoConnect: true,
    transports: ["websocket", "polling"],
    auth: {
      refresh_token: refreshToken,
      refreshToken,
    },
  });
}
