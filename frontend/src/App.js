// ============================================================================
// frontend/src/App.js — AgroConnect Namibia
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Central router configuration for the frontend.
//   • Mounts AuthProvider
//   • Mounts ToastProvider
//   • Owns RouterProvider
//
// THIS FIX:
//   ✅ Restores clean router-only responsibilities
//   ✅ Adds forgot-password public route
//   ✅ Adds reset-password public route
//   ✅ Keeps role-aware landing / fallback
//   ✅ Keeps protected dashboard routing
//   ✅ Keeps chunk-load retry handling
//   ✅ Adds Phase 4B farmer/admin review analytics pages
// ============================================================================

import React, { Suspense } from "react";
import { createBrowserRouter, Navigate, RouterProvider } from "react-router-dom";

import { AuthProvider, useAuth } from "./components/auth/AuthProvider";
import ProtectedRoute from "./components/auth/ProtectedRoute";

import ToastProvider from "./components/ui/ToastProvider";
import RouterLayout from "./components/common/RouterLayout";
import DashboardLayout from "./components/layout/DashboardLayout";

// ----------------------------------------------------------------------------
// Public pages
// ----------------------------------------------------------------------------
import StartScreen from "./pages/StartScreen";
import Login from "./pages/Login";
import Register from "./pages/Register";
import ForgotPassword from "./pages/ForgotPassword";
import ResetPassword from "./pages/ResetPassword";

// ----------------------------------------------------------------------------
// Chunk-load retry helper
// ----------------------------------------------------------------------------
function lazyWithRetry(factory, key) {
  return React.lazy(async () => {
    try {
      return await factory();
    } catch (err) {
      const msg = String(err?.message || err || "");
      const isChunkError = /ChunkLoadError|Loading chunk|CSS_CHUNK_LOAD_FAILED/i.test(
        msg
      );

      if (isChunkError) {
        const storageKey = `ac_chunk_retry_${key}`;
        const alreadyTried = sessionStorage.getItem(storageKey);

        if (!alreadyTried) {
          sessionStorage.setItem(storageKey, "1");
          window.location.reload();

          // The page will reload immediately.
          return new Promise(() => {});
        }

        sessionStorage.removeItem(storageKey);
      }

      throw err;
    }
  });
}

// ----------------------------------------------------------------------------
// Shared loading indicator
// ----------------------------------------------------------------------------
function Loader({ label = "Loading…" }) {
  return (
    <div className="min-h-[40vh] flex items-center justify-center text-slate-600">
      <div className="animate-spin mr-3 border-2 border-slate-400 rounded-full w-6 h-6 border-t-transparent" />
      {label}
    </div>
  );
}

// ----------------------------------------------------------------------------
// Suspense wrapper
// ----------------------------------------------------------------------------
function Lazy({ children }) {
  return <Suspense fallback={<Loader />}>{children}</Suspense>;
}

// ----------------------------------------------------------------------------
// Role-based redirect
// ----------------------------------------------------------------------------
function RoleHomeRedirect() {
  const { user, loading } = useAuth();

  if (loading) return <Loader />;

  if (!user) return <Navigate to="/" state={{ authMode: "login" }} replace />;

  const roleName = String(user?.role_name || user?.roleName || "").toLowerCase();
  const roleNum = user?.role ?? user?.role_id ?? user?.roleId ?? null;

  if (roleName === "admin" || roleNum === 1) {
    return <Navigate to="/dashboard/admin" replace />;
  }

  if (roleName === "farmer" || roleNum === 2) {
    return <Navigate to="/dashboard/farmer/overview" replace />;
  }

  if (roleName === "customer" || roleNum === 3) {
    return <Navigate to="/dashboard/customer" replace />;
  }

  return <Navigate to="/" state={{ authMode: "login" }} replace />;
}

// ----------------------------------------------------------------------------
// Lazy pages
// ----------------------------------------------------------------------------

// Farmer
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
const FarmerQualityAnalyticsPage = lazyWithRetry(
  () => import("./pages/dashboards/farmer/FarmerQualityAnalyticsPage"),
  "FarmerQualityAnalyticsPage"
);
const FarmerMessagesPage = lazyWithRetry(
  () => import("./pages/dashboards/farmer/FarmerMessagesPage"),
  "FarmerMessagesPage"
);
const FarmerAnnouncementsPage = lazyWithRetry(
  () => import("./pages/dashboards/farmer/FarmerAnnouncementsPage"),
  "FarmerAnnouncementsPage"
);
const FarmerSettingsPage = lazyWithRetry(
  () => import("./pages/dashboards/farmer/FarmerSettingsPage"),
  "FarmerSettingsPage"
);

// Customer
const CustomerDashboard = lazyWithRetry(
  () => import("./pages/dashboards/customer/CustomerDashboard"),
  "CustomerDashboard"
);
const CustomerOrdersPage = lazyWithRetry(
  () => import("./pages/dashboards/customer/CustomerOrders"),
  "CustomerOrders"
);
const CustomerMessagesPage = lazyWithRetry(
  () => import("./pages/dashboards/customer/CustomerMessagesPage"),
  "CustomerMessagesPage"
);
const CustomerAnnouncementsPage = lazyWithRetry(
  () => import("./pages/dashboards/customer/CustomerAnnouncementsPage"),
  "CustomerAnnouncementsPage"
);
const CustomerSavedSearchPage = lazyWithRetry(
  () => import("./pages/dashboards/customer/CustomerSavedSearch"),
  "CustomerSavedSearch"
);
const CustomerInsightsPage = lazyWithRetry(
  () => import("./pages/dashboards/customer/CustomerInsights"),
  "CustomerInsights"
);
const CustomerPaymentsPage = lazyWithRetry(
  () => import("./pages/dashboards/customer/CustomerPayments"),
  "CustomerPayments"
);
const CustomerSettingsPage = lazyWithRetry(
  () => import("./pages/dashboards/customer/CustomerSettings"),
  "CustomerSettings"
);

// Admin
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
const AdminReviewAnalyticsPage = lazyWithRetry(
  () => import("./pages/dashboards/admin/AdminReviewAnalyticsPage"),
  "AdminReviewAnalyticsPage"
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
const AdminOrderDetailPage = lazyWithRetry(
  () => import("./pages/dashboards/admin/AdminOrderDetailPage"),
  "AdminOrderDetailPage"
);

// AI
const AiDashboard = lazyWithRetry(
  () => import("./pages/dashboards/AiDashboard"),
  "AiDashboard"
);

// ----------------------------------------------------------------------------
// Router
// ----------------------------------------------------------------------------
const router = createBrowserRouter(
  [
    // ------------------------------------------------------------------------
    // Public routes
    // ------------------------------------------------------------------------
    { path: "/", element: <StartScreen /> },
    { path: "/login", element: <Login /> },
    { path: "/register", element: <Register /> },
    { path: "/forgot-password", element: <ForgotPassword /> },
    { path: "/reset-password", element: <ResetPassword /> },

    // ------------------------------------------------------------------------
    // Authenticated routes
    // ------------------------------------------------------------------------
    {
      element: <RouterLayout />,
      children: [
        { path: "/dashboard", element: <RoleHomeRedirect /> },

        // Farmer
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
          path: "/dashboard/farmer/messages",
          element: (
            <ProtectedRoute roles={["farmer"]}>
              <Lazy>
                <FarmerMessagesPage />
              </Lazy>
            </ProtectedRoute>
          ),
        },
        {
          path: "/dashboard/farmer/announcements",
          element: (
            <ProtectedRoute roles={["farmer"]}>
              <Lazy>
                <FarmerAnnouncementsPage />
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
        {
          path: "/dashboard/farmer/quality-analytics",
          element: (
            <ProtectedRoute roles={["farmer"]}>
              <Lazy>
                <FarmerQualityAnalyticsPage />
              </Lazy>
            </ProtectedRoute>
          ),
        },
        {
          path: "/dashboard/farmer/settings",
          element: (
            <ProtectedRoute roles={["farmer"]}>
              <Lazy>
                <FarmerSettingsPage />
              </Lazy>
            </ProtectedRoute>
          ),
        },

        // Customer
        {
          path: "/dashboard/customer/overview",
          element: <Navigate to="/dashboard/customer" replace />,
        },
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
        {
          path: "/dashboard/customer/orders",
          element: (
            <ProtectedRoute roles={["customer"]}>
              <DashboardLayout>
                <Lazy>
                  <CustomerOrdersPage />
                </Lazy>
              </DashboardLayout>
            </ProtectedRoute>
          ),
        },
        {
          path: "/dashboard/customer/messages",
          element: (
            <ProtectedRoute roles={["customer"]}>
              <DashboardLayout>
                <Lazy>
                  <CustomerMessagesPage />
                </Lazy>
              </DashboardLayout>
            </ProtectedRoute>
          ),
        },
        {
          path: "/dashboard/customer/announcements",
          element: (
            <ProtectedRoute roles={["customer"]}>
              <DashboardLayout>
                <Lazy>
                  <CustomerAnnouncementsPage />
                </Lazy>
              </DashboardLayout>
            </ProtectedRoute>
          ),
        },
        {
          path: "/dashboard/customer/saved-search",
          element: (
            <ProtectedRoute roles={["customer"]}>
              <DashboardLayout>
                <Lazy>
                  <CustomerSavedSearchPage />
                </Lazy>
              </DashboardLayout>
            </ProtectedRoute>
          ),
        },
        {
          path: "/dashboard/customer/insights",
          element: (
            <ProtectedRoute roles={["customer"]}>
              <DashboardLayout>
                <Lazy>
                  <CustomerInsightsPage />
                </Lazy>
              </DashboardLayout>
            </ProtectedRoute>
          ),
        },
        {
          path: "/dashboard/customer/payments",
          element: (
            <ProtectedRoute roles={["customer"]}>
              <DashboardLayout>
                <Lazy>
                  <CustomerPaymentsPage />
                </Lazy>
              </DashboardLayout>
            </ProtectedRoute>
          ),
        },
        {
          path: "/dashboard/customer/account",
          element: (
            <ProtectedRoute roles={["customer"]}>
              <DashboardLayout>
                <Lazy>
                  <CustomerSettingsPage />
                </Lazy>
              </DashboardLayout>
            </ProtectedRoute>
          ),
        },
        {
          path: "/dashboard/customer/settings",
          element: <Navigate to="/dashboard/customer/account" replace />,
        },

        // AI
        {
          path: "/dashboard/ai",
          element: (
            <ProtectedRoute roles={["admin", "farmer"]}>
              <Lazy>
                <AiDashboard />
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
          path: "/dashboard/admin/review-analytics",
          element: (
            <ProtectedRoute roles={["admin"]}>
              <Lazy>
                <AdminReviewAnalyticsPage />
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
        {
          path: "/dashboard/admin/orders/:orderId",
          element: (
            <ProtectedRoute roles={["admin"]}>
              <Lazy>
                <AdminOrderDetailPage />
              </Lazy>
            </ProtectedRoute>
          ),
        },
      ],
    },

    // Final fallback
    { path: "*", element: <RoleHomeRedirect /> },
  ],
  {
    future: {
      v7_startTransition: true,
    },
  }
);

export default function App() {
  return (
    <AuthProvider>
      <ToastProvider />
      <RouterProvider router={router} />
    </AuthProvider>
  );
}