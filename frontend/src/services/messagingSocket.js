import { io } from 'socket.io-client';

import { API_ROOT, getAccessToken, getRefreshToken } from '../api';

function getSocketBaseUrl() {
  return String(API_ROOT || '').replace(/\/api\/?$/i, '');
}

export function connectMessagingSocket() {
  const accessToken = getAccessToken();
  const refreshToken = getRefreshToken();

  if (!accessToken && !refreshToken) {
    return null;
  }

  return io(getSocketBaseUrl(), {
    autoConnect: true,
    transports: ['websocket', 'polling'],
    auth: {
      token: accessToken || undefined,
      access_token: accessToken || undefined,
      refresh_token: refreshToken || undefined,
    },
  });
}
