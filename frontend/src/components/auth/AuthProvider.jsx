// ============================================================================
// frontend/src/components/auth/AuthProvider.jsx — AgroConnect Namibia
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Owns authentication state (user + tokens) for the frontend.
//
// RESPONSIBILITIES:
//   • Stores user + tokens (access + refresh)
//   • Exposes login/logout helpers
//   • Keeps Axios Authorization defaults in sync (setApiAuthHeader)
//   • Optionally triggers manual refresh (attemptRefresh)
//   • Initializes Socket.IO connection using the access token
//   • Listens for "auth:logout" events fired by api.js when refresh fails
//
// DOES NOT DO:
//   ❌ No navigation / redirects (pages decide where to redirect)
// ============================================================================

import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import io from "socket.io-client";

import api, {
  API_ROOT,
  clearTokens,
  getAccessToken,
  getRefreshToken,
  refreshAccessToken,
  setApiAuthHeader,
  setTokens,
} from "../../api";

const AuthContext = createContext(null);

const STORAGE_KEYS = {
  user: "user",
};

function safeJsonParse(value) {
  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}

function normalizeAuthResponse(data) {
  return {
    accessToken: data?.accessToken || data?.token || data?.access_token || null,
    refreshToken: data?.refreshToken || data?.refresh_token || null,
    user: data?.user || null,
  };
}

// Socket host: API_ROOT is ".../api" → remove "/api"
const SOCKET_BASE = API_ROOT.replace(/\/api$/, "");

export function AuthProvider({ children }) {
  // ---------------------------------------------------------------------------
  // Bootstrap from storage
  // ---------------------------------------------------------------------------
  const [token, setToken] = useState(() => getAccessToken());
  const [refreshToken, setRefreshToken] = useState(() => getRefreshToken());
  const [user, setUser] = useState(() => safeJsonParse(localStorage.getItem(STORAGE_KEYS.user)));

  const [loading, setLoading] = useState(false);

  // Keep socket instance in a ref (prevents stale closures)
  const socketRef = useRef(null);

  // ---------------------------------------------------------------------------
  // Keep Axios defaults in sync
  // (api.js attaches token per request; this also helps for defaults)
  // ---------------------------------------------------------------------------
  useEffect(() => {
    setApiAuthHeader(token);
  }, [token]);

  // ---------------------------------------------------------------------------
  // Handle forced logout events from api.js
  // (e.g., refresh token expired)
  // ---------------------------------------------------------------------------
  useEffect(() => {
    const onLogoutEvent = () => {
      // No navigation here — just clear state.
      doLogout();
    };

    window.addEventListener("auth:logout", onLogoutEvent);
    return () => window.removeEventListener("auth:logout", onLogoutEvent);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // ---------------------------------------------------------------------------
  // Socket initializer (disconnect prior connection)
  // ---------------------------------------------------------------------------
  const initSocket = useCallback((jwt) => {
    if (!jwt) return;

    // Disconnect old socket (if any)
    if (socketRef.current) {
      try {
        socketRef.current.disconnect();
      } catch {
        // ignore
      }
    }

    socketRef.current = io(SOCKET_BASE, {
      transports: ["polling"], // safe default for many hosting environments
      upgrade: false,
      auth: { token: jwt },
    });
  }, []);

  // Boot socket when we have a token + user
  useEffect(() => {
    if (token && user) initSocket(token);

    return () => {
      if (socketRef.current) {
        try {
          socketRef.current.disconnect();
        } catch {
          // ignore
        }
      }
    };
  }, [token, user, initSocket]);

  // ---------------------------------------------------------------------------
  // Persist auth state helpers
  // ---------------------------------------------------------------------------
  const persistUser = useCallback((u) => {
    if (u) {
      localStorage.setItem(STORAGE_KEYS.user, JSON.stringify(u));
      setUser(u);
    } else {
      localStorage.removeItem(STORAGE_KEYS.user);
      setUser(null);
    }
  }, []);

  const persistTokens = useCallback(({ accessToken, refreshToken: rt }) => {
    if (accessToken || rt) {
      setTokens({ accessToken: accessToken || null, refreshToken: rt || null });
    }

    setToken(accessToken || null);
    setRefreshToken(rt || null);
  }, []);

  // ---------------------------------------------------------------------------
  // Logout (NO navigation here)
  // ---------------------------------------------------------------------------
  const doLogout = useCallback(() => {
    clearTokens();
    localStorage.removeItem(STORAGE_KEYS.user);

    setToken(null);
    setRefreshToken(null);
    setUser(null);

    if (socketRef.current) {
      try {
        socketRef.current.disconnect();
      } catch {
        // ignore
      }
      socketRef.current = null;
    }
  }, []);

  // ---------------------------------------------------------------------------
  // Login
  // ---------------------------------------------------------------------------
  const login = useCallback(
    async (credentials) => {
      setLoading(true);
      try {
        const { data } = await api.post("/auth/login", credentials);
        const normalized = normalizeAuthResponse(data);

        // Persist user + tokens
        persistUser(normalized.user);
        persistTokens({
          accessToken: normalized.accessToken,
          refreshToken: normalized.refreshToken,
        });

        // Start socket for realtime events
        if (normalized.accessToken) initSocket(normalized.accessToken);

        return normalized.user;
      } finally {
        setLoading(false);
      }
    },
    [persistUser, persistTokens, initSocket]
  );

  // ---------------------------------------------------------------------------
  // Manual refresh (optional for ProtectedRoute or other guard)
  // NOTE: api.js already refreshes automatically on 401.
  // ---------------------------------------------------------------------------
  const attemptRefresh = useCallback(async () => {
    const rt = refreshToken || getRefreshToken();
    if (!rt) throw new Error("No refresh token available");

    const data = await refreshAccessToken(rt);
    const newAccess = data?.accessToken || data?.token || data?.access_token || null;
    const newRefresh = data?.refreshToken || data?.refresh_token || rt;

    if (!newAccess) throw new Error("Refresh response missing access token");

    persistTokens({ accessToken: newAccess, refreshToken: newRefresh });

    // Keep socket auth fresh
    initSocket(newAccess);

    return newAccess;
  }, [refreshToken, persistTokens, initSocket]);

  const value = useMemo(
    () => ({
      user,
      token,
      refreshToken,
      loading,
      login,
      logout: doLogout,
      attemptRefresh,
      socket: socketRef.current,
      isAuthenticated: Boolean(token && user),
    }),
    [user, token, refreshToken, loading, login, doLogout, attemptRefresh]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export const useAuth = () => useContext(AuthContext);
