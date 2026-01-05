// ============================================================================
// src/App.js — AgroConnect Namibia (Routing + Chunk-Load Recovery)
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Central router configuration for the frontend.
//   • Mounts AuthProvider (state-only, router-safe)
//   • Mounts ToastProvider (global notifications)
//   • Owns RouterProvider (navigation + routing)
//
// WHY THIS UPDATE EXISTS:
//   Fixes runtime "Loading chunk ... failed (ChunkLoadError)" crashes that happen
//   when the browser cache references an older code-split chunk filename.
//
// HOW IT WORKS:
//   • Wrap React.lazy imports with a retry helper
//   • On ChunkLoadError, it performs ONE safe reload to fetch the correct chunks
//
// FARMER IA (your spec):
//   • Overview  -> /dashboard/farmer/overview
//   • Products  -> /dashboard/farmer/products
//   • Orders    -> /dashboard/farmer/orders
//   • Feedback  -> /dashboard/farmer/feedback
//   • /dashboard/farmer redirects to /dashboard/farmer/overview
// ============================================================================

import React, { Suspense } from "react";
import { createBrowserRouter, RouterProvider, Navigate } from "react-router-dom";

import { AuthProvider } from "./components/auth/AuthProvider";
import ProtectedRoute from "./components/auth/ProtectedRoute";

import ToastProvider from "./components/ui/ToastProvider";
import RouterLayout from "./components/common/RouterLayout";

// Public pages
import StartScreen from "./pages/StartScreen";
import Login from "./pages/Login";
import Register from "./pages/Register";

// ----------------------------------------------------------------------------
// Chunk-load recovery helper (prevents fatal blank screens)
// ----------------------------------------------------------------------------
function lazyWithRetry(factory, key) {
  return React.lazy(async () => {
    try {
      return await factory();
    } catch (err) {
      const msg = String(err?.message || err || "");
      const isChunkError =
        /ChunkLoadError|Loading chunk|CSS_CHUNK_LOAD_FAILED/i.test(msg);

      if (isChunkError) {
        // Prevent infinite reload loops
        const k = `ac_chunk_retry_${key}`;
        const alreadyTried = sessionStorage.getItem(k);

        if (!alreadyTried) {
          sessionStorage.setItem(k, "1");
          window.location.reload();
          // Return a never-resolving promise (page will reload)
          // eslint-disable-next-line no-new
          return new Promise(() => {});
        }

        sessionStorage.removeItem(k);
      }

      throw err;
    }
  });
}

// --------------------------------------------------------------------
// Small helper: consistent Suspense wrapper
// --------------------------------------------------------------------
function Lazy({ children }) {
  return (
    <Suspense
      fallback={
        <div className="min-h-[40vh] flex items-center justify-center text-slate-600">
          <div className="animate-spin mr-3 border-2 border-emerald-600 rounded-full w-6 h-6 border-t-transparent" />
          Loading…
        </div>
      }
    >
      {children}
    </Suspense>
  );
}

// --------------------------------------------------------------------
// Lazy pages (keeps initial bundle small)
// --------------------------------------------------------------------
const FarmerOverviewPage = lazyWithRetry(
  () => import("./pages/dashboards/farmer/FarmerDashboard"),
  "FarmerDashboard"
);
const FarmerProductsPage = lazyWithRetry(
  () => import("./pages/dashboards/farmer/FarmerProductsPage"),
  "FarmerProductsPage"
);
const FarmerOrdersPage = lazyWithRetry(
  () => import("./pages/dashboards/farmer/FarmerOrdersPage"),
  "FarmerOrdersPage"
);
const FarmerFeedbackPage = lazyWithRetry(
  () => import("./pages/dashboards/farmer/FarmerFeedbackPage"),
  "FarmerFeedbackPage"
);

const CustomerDashboard = lazyWithRetry(
  () => import("./pages/dashboards/customer/CustomerDashboard"),
  "CustomerDashboard"
);

const AdminDashboard = lazyWithRetry(
  () => import("./pages/dashboards/admin/AdminDashboard"),
  "AdminDashboard"
);
const AdminUsersPage = lazyWithRetry(
  () => import("./pages/dashboards/admin/AdminUsersPage"),
  "AdminUsersPage"
);
const AdminModerationPage = lazyWithRetry(
  () => import("./pages/dashboards/admin/AdminModerationPage"),
  "AdminModerationPage"
);
const AuditLogPage = lazyWithRetry(
  () => import("./pages/dashboards/admin/AuditLogPage"),
  "AuditLogPage"
);
const AdminAnalyticsPage = lazyWithRetry(
  () => import("./pages/dashboards/admin/AdminAnalyticsPage"),
  "AdminAnalyticsPage"
);
const AdminReportsPage = lazyWithRetry(
  () => import("./pages/dashboards/admin/AdminReportsPage"),
  "AdminReportsPage"
);
const AdminSettingsPage = lazyWithRetry(
  () => import("./pages/dashboards/admin/AdminSettingsPage"),
  "AdminSettingsPage"
);
const AdminMessagingPage = lazyWithRetry(
  () => import("./pages/dashboards/admin/AdminMessagingPage"),
  "AdminMessagingPage"
);

// --------------------------------------------------------------------
// Router
// --------------------------------------------------------------------
const router = createBrowserRouter([
  // Public
  { path: "/", element: <StartScreen /> },
  { path: "/login", element: <Login /> },
  { path: "/register", element: <Register /> },

  // Authenticated (layout route)
  {
    element: <RouterLayout />,
    children: [
      // Farmer (NEW IA)
      {
        path: "/dashboard/farmer",
        element: <Navigate to="/dashboard/farmer/overview" replace />,
      },
      {
        path: "/dashboard/farmer/overview",
        element: (
          <ProtectedRoute roles={["farmer"]}>
            <Lazy>
              <FarmerOverviewPage />
            </Lazy>
          </ProtectedRoute>
        ),
      },
      {
        path: "/dashboard/farmer/products",
        element: (
          <ProtectedRoute roles={["farmer"]}>
            <Lazy>
              <FarmerProductsPage />
            </Lazy>
          </ProtectedRoute>
        ),
      },
      {
        path: "/dashboard/farmer/orders",
        element: (
          <ProtectedRoute roles={["farmer"]}>
            <Lazy>
              <FarmerOrdersPage />
            </Lazy>
          </ProtectedRoute>
        ),
      },
      {
        path: "/dashboard/farmer/feedback",
        element: (
          <ProtectedRoute roles={["farmer"]}>
            <Lazy>
              <FarmerFeedbackPage />
            </Lazy>
          </ProtectedRoute>
        ),
      },

      // Customer
      {
        path: "/dashboard/customer",
        element: (
          <ProtectedRoute roles={["customer"]}>
            <Lazy>
              <CustomerDashboard />
            </Lazy>
          </ProtectedRoute>
        ),
      },

      // Admin
      {
        path: "/dashboard/admin",
        element: (
          <ProtectedRoute roles={["admin"]}>
            <Lazy>
              <AdminDashboard />
            </Lazy>
          </ProtectedRoute>
        ),
      },
      {
        path: "/dashboard/admin/users",
        element: (
          <ProtectedRoute roles={["admin"]}>
            <Lazy>
              <AdminUsersPage />
            </Lazy>
          </ProtectedRoute>
        ),
      },
      {
        path: "/dashboard/admin/moderation",
        element: (
          <ProtectedRoute roles={["admin"]}>
            <Lazy>
              <AdminModerationPage />
            </Lazy>
          </ProtectedRoute>
        ),
      },
      {
        path: "/dashboard/admin/audit-log",
        element: (
          <ProtectedRoute roles={["admin"]}>
            <Lazy>
              <AuditLogPage />
            </Lazy>
          </ProtectedRoute>
        ),
      },
      {
        path: "/dashboard/admin/analytics",
        element: (
          <ProtectedRoute roles={["admin"]}>
            <Lazy>
              <AdminAnalyticsPage />
            </Lazy>
          </ProtectedRoute>
        ),
      },
      {
        path: "/dashboard/admin/reports",
        element: (
          <ProtectedRoute roles={["admin"]}>
            <Lazy>
              <AdminReportsPage />
            </Lazy>
          </ProtectedRoute>
        ),
      },
      {
        path: "/dashboard/admin/messaging",
        element: (
          <ProtectedRoute roles={["admin"]}>
            <Lazy>
              <AdminMessagingPage />
            </Lazy>
          </ProtectedRoute>
        ),
      },
      {
        path: "/dashboard/admin/settings",
        element: (
          <ProtectedRoute roles={["admin"]}>
            <Lazy>
              <AdminSettingsPage />
            </Lazy>
          </ProtectedRoute>
        ),
      },
    ],
  },

  // Fallback
  { path: "*", element: <Navigate to="/" replace /> },
]);

export default function App() {
  return (
    <AuthProvider>
      <ToastProvider />
      <RouterProvider router={router} />
    </AuthProvider>
  );
}
