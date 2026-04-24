// ============================================================================
// frontend/src/components/auth/ProtectedRoute.jsx — AgroConnect Namibia
// ----------------------------------------------------------------------------
// ROLE:
// • Centralized Role-Based Access Control (RBAC)
// • Guards routes BEFORE components render
//
// MSc VALUE:
// • Prevents data leakage
// • Enforces security at routing layer
// • Clean separation: routing ≠ layout ≠ UI
//
// THIS UPDATE:
// • Normalizes both numeric and string roles
// • Redirects authenticated users to their correct dashboard home when a stale
//   or incompatible route is opened (prevents role-switch “Access denied” loops)
// • Sends unauthenticated traffic back to the public Start screen instead of
//   the standalone login page
// ============================================================================

import React from "react";
import { Navigate, useLocation } from "react-router-dom";
import { useAuth } from "./AuthProvider";

function normalizeRole(user) {
  const roleName = String(user?.role_name || user?.roleName || "")
    .trim()
    .toLowerCase();

  if (["admin", "farmer", "customer"].includes(roleName)) return roleName;

  const roleNum = Number(user?.role ?? user?.role_id ?? user?.roleId ?? NaN);
  if (roleNum === 1) return "admin";
  if (roleNum === 2) return "farmer";
  if (roleNum === 3) return "customer";
  return "";
}

function roleHome(role) {
  if (role === "admin") return "/dashboard/admin";
  if (role === "farmer") return "/dashboard/farmer/overview";
  if (role === "customer") return "/dashboard/customer";
  return "/";
}

export default function ProtectedRoute({ roles = [], children }) {
  const { user, isAuthenticated, loading } = useAuth();
  const location = useLocation();

  if (loading) return null;

  if (!isAuthenticated || !user) {
    return (
      <Navigate
        to="/"
        state={{ from: location, authMode: "login" }}
        replace
      />
    );
  }

  const role = normalizeRole(user);
  const normalizedRoles = Array.isArray(roles)
    ? roles.map((value) => String(value || "").trim().toLowerCase()).filter(Boolean)
    : [];

  if (normalizedRoles.length > 0 && !normalizedRoles.includes(role)) {
    return (
      <Navigate
        to={roleHome(role)}
        state={{ deniedFrom: location.pathname }}
        replace
      />
    );
  }

  return children;
}
