// ============================================================================
// frontend/src/services/messagingSocket.js
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Optional Socket.IO helper for realtime messaging refreshes.
//
// IMPORTANT DEV BEHAVIOUR:
//   Socket.IO is DISABLED by default because the normal Flask development server
//   is mainly used for REST API testing and can produce noisy websocket errors.
//
// ENABLE REALTIME MANUALLY:
//   Create frontend/.env.local and add:
//
//     REACT_APP_ENABLE_SOCKETIO=true
//
//   Then restart the React development server.
//
// REST FALLBACK:
//   When Socket.IO is disabled, this helper returns null. Messaging pages still
//   work through normal REST API calls; they simply do not receive live push
//   refresh events.
// ============================================================================

import { io } from "socket.io-client";

import { API_ROOT, getAccessToken, getRefreshToken } from "../api";

/**
 * Returns true only when the developer explicitly enables realtime sockets.
 *
 * We intentionally default to false so local testing stays quiet and stable.
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
 * Connect to the default Socket.IO namespace for messaging events.
 *
 * Returns:
 *   Socket instance when realtime is enabled and tokens exist
 *   null when realtime is disabled or the user is not authenticated
 */
export function connectMessagingSocket() {
  if (!socketIoEnabled()) {
    return null;
  }

  const accessToken = getAccessToken();
  const refreshToken = getRefreshToken();

  if (!accessToken && !refreshToken) {
    return null;
  }

  return io(getSocketBaseUrl(), {
    autoConnect: true,

    // Polling first is more forgiving in local development.
    // WebSocket upgrade can still happen when the backend supports it.
    transports: ["polling", "websocket"],

    timeout: 8000,
    reconnectionAttempts: 3,

    auth: {
      token: accessToken || undefined,
      access_token: accessToken || undefined,
      refresh_token: refreshToken || undefined,
    },
  });
}
