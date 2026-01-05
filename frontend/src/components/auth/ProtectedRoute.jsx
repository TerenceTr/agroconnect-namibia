// ============================================================================
// 🔐 ProtectedRoute.jsx — AgroConnect Namibia
// ----------------------------------------------------------------------------
// ROLE:
// • Centralized Role-Based Access Control (RBAC)
// • Guards routes BEFORE components render
//
// MSc VALUE:
// • Prevents data leakage
// • Enforces security at routing layer
// • Clean separation: routing ≠ layout ≠ UI
// ============================================================================

import React from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from './AuthProvider';

export default function ProtectedRoute({ roles = [], children }) {
  const { user, isAuthenticated } = useAuth();
  const location = useLocation();

  // --------------------------------------------------
  // Not authenticated → redirect to login
  // --------------------------------------------------
  if (!isAuthenticated || !user) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  // --------------------------------------------------
  // Normalize role
  // --------------------------------------------------
  const role = user.role_name?.toLowerCase();

  // --------------------------------------------------
  // RBAC enforcement
  // --------------------------------------------------
  if (roles.length > 0 && !roles.includes(role)) {
    return (
      <div className="flex items-center justify-center min-h-[70vh]">
        <div className="glass-card p-6 text-center border border-red-500/30">
          <h2 className="text-xl font-semibold text-red-400 mb-2">Access denied</h2>
          <p className="text-white/70">
            You do not have permission to access this resource.
          </p>
        </div>
      </div>
    );
  }

  return children;
}
