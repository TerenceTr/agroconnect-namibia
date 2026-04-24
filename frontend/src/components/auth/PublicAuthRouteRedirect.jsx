// ============================================================================
// frontend/src/components/auth/PublicAuthRouteRedirect.jsx
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Tiny route adapter that keeps legacy public auth URLs working while
//   redirecting the real experience back to the public marketplace.
//
// WHY THIS EXISTS:
//   • /login, /register, and /forgot-password may still be bookmarked
//   • StartScreen + AuthDialog is now the single public auth UI
//   • keeps route files short and easy to remove later
// ============================================================================

import React, { useEffect, useMemo } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';

import { useAuth } from './AuthProvider';

function normalizeRoleHint(rawRole, fallbackRole = 'customer') {
  const value = String(rawRole || fallbackRole).trim().toLowerCase();

  if (
    value === '2' ||
    value === 'farmer' ||
    value === 'seller' ||
    value === 'sell'
  ) {
    return 'farmer';
  }

  return 'customer';
}

function resolveDashboardRoute(userLike) {
  const roleName = String(userLike?.role_name || userLike?.roleName || '')
    .trim()
    .toLowerCase();
  const roleNum = Number(userLike?.role ?? userLike?.role_id ?? userLike?.roleId ?? NaN);

  if (roleName === 'admin' || roleNum === 1) return '/dashboard/admin';
  if (roleName === 'farmer' || roleNum === 2) return '/dashboard/farmer/overview';
  return '/dashboard/customer';
}

function buildMarketplaceState({ mode, location, fallbackRole }) {
  const params = new URLSearchParams(location.search || '');
  const requestedRole = normalizeRoleHint(
    location.state?.defaultRole ?? location.state?.registrationRole ?? params.get('role'),
    fallbackRole
  );

  if (mode === 'forgot') {
    return {
      authMode: 'forgot',
      from: location.state?.from || null,
    };
  }

  if (mode === 'register') {
    return {
      authMode: requestedRole === 'farmer' ? 'register-farmer' : 'register-customer',
      defaultRole: requestedRole,
      registrationRole: requestedRole,
      from: location.state?.from || null,
    };
  }

  return {
    authMode: 'login',
    from: location.state?.from || null,
  };
}

export default function PublicAuthRouteRedirect({
  mode = 'login',
  fallbackRole = 'customer',
}) {
  const location = useLocation();
  const navigate = useNavigate();
  const { loading, isAuthenticated, user } = useAuth();

  const targetState = useMemo(
    () => buildMarketplaceState({ mode, location, fallbackRole }),
    [mode, location, fallbackRole]
  );

  useEffect(() => {
    if (loading) return;

    if (isAuthenticated && user) {
      navigate(resolveDashboardRoute(user), { replace: true });
      return;
    }

    navigate('/', {
      replace: true,
      state: targetState,
    });
  }, [loading, isAuthenticated, user, navigate, targetState]);

  return (
    <div className="flex min-h-[40vh] items-center justify-center text-slate-600">
      Redirecting to AgroConnect…
    </div>
  );
}
