// ============================================================================
// frontend/src/services/notificationsSocket.js
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Optional Socket.IO helper for live notification bell refreshes.
//
// IMPORTANT DEV BEHAVIOUR:
//   Socket.IO is DISABLED by default because normal local testing uses the Flask
//   REST API server. This prevents repeated websocket/polling console noise.
//
// ENABLE REALTIME MANUALLY:
//   Create frontend/.env.local and add:
//
//     REACT_APP_ENABLE_SOCKETIO=true
//
//   Then restart the React development server.
//
// REST FALLBACK:
//   When Socket.IO is disabled, this helper returns null. Notification dropdowns
//   still load through REST endpoints such as:
//
//     GET /api/notifications/me
// ============================================================================

import { io } from "socket.io-client";

import { API_ROOT, getRefreshToken } from "../api";

/**
 * Returns true only when realtime sockets are explicitly enabled.
 */
function socketIoEnabled() {
  return String(process.env.REACT_APP_ENABLE_SOCKETIO || "")
    .trim()
    .toLowerCase() === "true";
}

/**
 * Converts the API root into the Socket.IO server origin.
 *
 * Example:
 *   http://127.0.0.1:5000/api -> http://127.0.0.1:5000
 */
function getSocketBaseUrl() {
  return String(API_ROOT || "").replace(/\/api\/?$/i, "");
}

/**
 * Connect to the notifications namespace.
 *
 * Returns:
 *   Socket instance when realtime is enabled and a refresh token exists
 *   null when realtime is disabled or the user is not authenticated
 */
export function connectNotificationsSocket() {
  if (!socketIoEnabled()) {
    return null;
  }

  const refreshToken = getRefreshToken();

  if (!refreshToken) {
    return null;
  }

  return io(`${getSocketBaseUrl()}/notifications`, {
    autoConnect: true,

    // Polling first reduces local development websocket failures.
    transports: ["polling", "websocket"],

    timeout: 8000,
    reconnectionAttempts: 3,

    auth: {
      refresh_token: refreshToken,
      refreshToken,
    },
  });
}
