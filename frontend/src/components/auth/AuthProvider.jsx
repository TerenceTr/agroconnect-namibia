// ============================================================================
// frontend/src/components/auth/AuthProvider.jsx — AgroConnect Namibia
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Central authentication provider for the web interface.
//
// THIS VERSION IMPROVES:
//   • Restores sessions from stored tokens with a lightweight user snapshot
//   • Auto-authenticates after registration so users land directly in the
//     correct dashboard without an unnecessary extra login step
//   • Keeps password reset helpers for the shared auth dialog
//   • Handles forced logout events from the shared API layer
//   • Clears local session state immediately on logout for faster UX
//   • Prefetches role-specific dashboard bundles after auth success
// ============================================================================

import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from 'react';

import api, {
  clearTokens,
  getAccessToken,
  getRefreshToken,
  normalizeTokenResponse,
  setApiAuthHeader,
  setTokens,
} from '../../api';

const AuthContext = createContext(null);
const USER_SNAPSHOT_KEY = 'ac_user_snapshot';

function safeRoleName(userLike) {
  const roleName = String(userLike?.role_name || userLike?.roleName || '')
    .trim()
    .toLowerCase();

  if (roleName) return roleName;

  const roleNum = Number(
    userLike?.role ?? userLike?.role_id ?? userLike?.roleId ?? NaN
  );

  if (roleNum === 1) return 'admin';
  if (roleNum === 2) return 'farmer';
  if (roleNum === 3) return 'customer';
  return '';
}

function normalizeUser(userLike) {
  if (!userLike || typeof userLike !== 'object') return null;

  const user = { ...userLike };
  const roleName = safeRoleName(userLike);

  if (roleName && !user.role_name) {
    user.role_name = roleName;
  }

  return user;
}

function extractUserPayload(data) {
  return normalizeUser(
    data?.user || data?.data?.user || data?.profile || data?.data || null
  );
}

function authErrorMessage(error, fallback) {
  const status = Number(error?.response?.status || 0);

  if (status === 404) {
    return 'This auth feature is not available on the current backend yet.';
  }

  return (
    error?.response?.data?.message ||
    error?.response?.data?.error ||
    error?.message ||
    fallback
  );
}

function saveUserSnapshot(userLike) {
  try {
    if (typeof window === 'undefined') return;
    const normalized = normalizeUser(userLike);
    if (!normalized) {
      window.localStorage.removeItem(USER_SNAPSHOT_KEY);
      return;
    }
    window.localStorage.setItem(USER_SNAPSHOT_KEY, JSON.stringify(normalized));
  } catch {
    // Ignore storage problems.
  }
}

function readUserSnapshot() {
  try {
    if (typeof window === 'undefined') return null;
    const raw = window.localStorage.getItem(USER_SNAPSHOT_KEY);
    if (!raw) return null;
    return normalizeUser(JSON.parse(raw));
  } catch {
    return null;
  }
}

function clearUserSnapshot() {
  try {
    if (typeof window === 'undefined') return;
    window.localStorage.removeItem(USER_SNAPSHOT_KEY);
  } catch {
    // Ignore storage problems.
  }
}

function preloadDashboardForRole(userLike) {
  const role = safeRoleName(userLike);

  try {
    if (role === 'admin') {
      void import('../../pages/dashboards/admin/AdminDashboard');
      return;
    }

    if (role === 'farmer') {
      void import('../../pages/dashboards/farmer/FarmerDashboard');
      return;
    }

    if (role === 'customer') {
      void import('../../pages/dashboards/customer/CustomerDashboard');
    }
  } catch {
    // Prefetch is best-effort only.
  }
}

function applyAuthenticatedSession(data, setUser) {
  const tokenPayload = normalizeTokenResponse(data || {});
  const nextUser = extractUserPayload(data || {});

  if (!tokenPayload?.accessToken) {
    if (nextUser) {
      setUser(nextUser);
      saveUserSnapshot(nextUser);
      preloadDashboardForRole(nextUser);
    }
    return { user: nextUser, hasSession: false };
  }

  setTokens(tokenPayload);
  setApiAuthHeader(tokenPayload.accessToken);
  setUser(nextUser);
  saveUserSnapshot(nextUser);
  preloadDashboardForRole(nextUser);

  return { user: nextUser, hasSession: true };
}

export function AuthProvider({ children }) {
  const [user, setUser] = useState(() => readUserSnapshot());
  const [loading, setLoading] = useState(true);
  const [authBusy, setAuthBusy] = useState(false);

  const clearLocalSession = useCallback(() => {
    clearTokens();
    clearUserSnapshot();
    setApiAuthHeader(null);
    setUser(null);
  }, []);

  const hydrateCurrentUser = useCallback(async () => {
    const accessToken = getAccessToken();
    const snapshot = readUserSnapshot();

    if (!accessToken) {
      clearLocalSession();
      setLoading(false);
      return null;
    }

    if (snapshot) {
      setUser(snapshot);
      preloadDashboardForRole(snapshot);
    }

    setApiAuthHeader(accessToken);

    try {
      const response = await api.get('auth/me');
      const nextUser = extractUserPayload(response?.data);
      setUser(nextUser);
      saveUserSnapshot(nextUser);
      preloadDashboardForRole(nextUser);
      return nextUser;
    } catch {
      clearLocalSession();
      return null;
    } finally {
      setLoading(false);
    }
  }, [clearLocalSession]);

  useEffect(() => {
    void hydrateCurrentUser();
  }, [hydrateCurrentUser]);

  useEffect(() => {
    const handleForcedLogout = () => {
      clearLocalSession();
      setLoading(false);
    };

    window.addEventListener('auth:logout', handleForcedLogout);
    return () => window.removeEventListener('auth:logout', handleForcedLogout);
  }, [clearLocalSession]);

  const login = useCallback(async ({ email, password, identifier }) => {
    setAuthBusy(true);

    try {
      const payload = {
        email: String(email || '').trim().toLowerCase(),
        password: String(password || ''),
        identifier: String(identifier || '').trim(),
      };

      const response = await api.post('auth/login', payload, {
        skipAuth: true,
      });

      const data = response?.data || {};
      const { user: nextUser, hasSession } = applyAuthenticatedSession(
        data,
        setUser
      );

      if (!hasSession) {
        throw new Error('Login succeeded but no access token was returned.');
      }

      return nextUser;
    } catch (error) {
      clearLocalSession();
      throw new Error(authErrorMessage(error, 'Login failed.'));
    } finally {
      setAuthBusy(false);
    }
  }, [clearLocalSession]);

  const register = useCallback(async (payload) => {
    setAuthBusy(true);

    try {
      const body = {
        full_name: String(payload?.full_name || '').trim(),
        email: String(payload?.email || '').trim().toLowerCase(),
        phone: String(payload?.phone || '').trim(),
        location: String(payload?.location || '').trim(),
        password: String(payload?.password || ''),
        role: Number(payload?.role || 2),
      };

      const response = await api.post('auth/register', body, {
        skipAuth: true,
      });

      const data = response?.data || {};
      const directSession = applyAuthenticatedSession(data, setUser);

      if (directSession.hasSession) {
        return directSession.user;
      }

      const loginResponse = await api.post(
        'auth/login',
        {
          email: body.email,
          password: body.password,
          identifier: body.email,
        },
        { skipAuth: true }
      );

      const fallbackData = loginResponse?.data || {};
      const fallbackSession = applyAuthenticatedSession(fallbackData, setUser);

      if (!fallbackSession.hasSession) {
        throw new Error(
          'Account created, but automatic sign-in could not complete.'
        );
      }

      return fallbackSession.user;
    } catch (error) {
      clearLocalSession();
      throw new Error(authErrorMessage(error, 'Registration failed.'));
    } finally {
      setAuthBusy(false);
    }
  }, [clearLocalSession]);

  const logout = useCallback(async () => {
    const refreshToken = getRefreshToken();

    clearLocalSession();
    setLoading(false);

    if (refreshToken) {
      void api
        .post(
          'auth/logout',
          { refreshToken, refresh_token: refreshToken },
          { skipAuth: true }
        )
        .catch(() => {
          // Explicit logout should still complete locally.
        });
    }
  }, [clearLocalSession]);

  const requestPasswordReset = useCallback(async (email) => {
    setAuthBusy(true);

    try {
      const response = await api.post(
        'auth/forgot-password',
        { email: String(email || '').trim().toLowerCase() },
        { skipAuth: true }
      );
      return response?.data || {};
    } catch (error) {
      throw new Error(
        authErrorMessage(error, 'Could not start password reset.')
      );
    } finally {
      setAuthBusy(false);
    }
  }, []);

  const resetPassword = useCallback(
    async ({ token, password, confirmPassword }) => {
      setAuthBusy(true);

      try {
        const response = await api.post(
          'auth/reset-password',
          {
            token: String(token || '').trim(),
            password: String(password || ''),
            confirmPassword: String(confirmPassword || ''),
            confirm_password: String(confirmPassword || ''),
          },
          { skipAuth: true }
        );

        return response?.data || {};
      } catch (error) {
        throw new Error(authErrorMessage(error, 'Could not reset password.'));
      } finally {
        setAuthBusy(false);
      }
    },
    []
  );

  const value = useMemo(
    () => ({
      user,
      loading: loading || authBusy,
      authBootstrapping: loading,
      isAuthenticated: !!user && !!getAccessToken(),
      login,
      register,
      logout,
      requestPasswordReset,
      resetPassword,
      refreshUser: hydrateCurrentUser,
    }),
    [
      user,
      loading,
      authBusy,
      login,
      register,
      logout,
      requestPasswordReset,
      resetPassword,
      hydrateCurrentUser,
    ]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);

  if (!ctx) {
    throw new Error('useAuth must be used inside <AuthProvider>.');
  }

  return ctx;
}

export default AuthProvider;
