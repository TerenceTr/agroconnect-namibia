// ============================================================================
// frontend/src/components/AdminLayout.jsx
// ----------------------------------------------------------------------------
// 🧱 AdminLayout — Admin Shell Layout (AgroConnect Namibia)
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Shared layout wrapper for ALL admin pages.
//   • Renders AdminSidebar + AdminTopbar
//   • Keeps the admin top bar FIXED while page content scrolls
//   • Responsive sidebar: mobile drawer + desktop collapse
//   • Owns logout navigation
//   • Fetches lightweight admin presence for the sidebar widget
//
// THIS UPDATE:
//   ✅ Freezes the admin top bar during page scroll
//   ✅ Adds top spacing so content never hides behind the fixed header
//   ✅ Keeps sidebar offset aligned with collapsed/expanded widths
//   ✅ Redirects logout to the Start screen for consistent public-entry flow
// ============================================================================

import React, { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";

import AdminSidebar from "./AdminSidebar";
import AdminTopbar from "./AdminTopbar";
import { useAuth } from "./auth/AuthProvider";
import useApi from "../hooks/useApi";

// -----------------------------------------------------------------------------
// Sidebar / topbar sizing
// Keep these values aligned with AdminSidebar desktop widths.
// -----------------------------------------------------------------------------
const SIDEBAR_WIDE_CLASS = "lg:left-[270px]";
const SIDEBAR_COLLAPSED_CLASS = "lg:left-[84px]";
const CONTENT_WIDE_PAD_CLASS = "lg:pl-[270px]";
const CONTENT_COLLAPSED_PAD_CLASS = "lg:pl-[84px]";
const TOPBAR_HEIGHT_PAD_CLASS = "pt-[84px]";

// Prefer presence endpoint; if missing, fall back to overview which may include presence.
const PRESENCE_ENDPOINTS = [
  "/admin/reports/presence",
  "/admin/presence",
  "/admin/reports/overview?period=week&span=12",
  "/admin/reports/overview",
  "/admin/overview",
];

function safeObj(v) {
  return v && typeof v === "object" ? v : null;
}

function safeArr(v) {
  return Array.isArray(v) ? v : [];
}

/**
 * Normalize multiple possible backend shapes into the Sidebar widget shape:
 *   { window_minutes, online: [], recent: [] }
 */
function normalizePresence(raw) {
  const d = safeObj(raw);
  if (!d) return null;

  // Preferred shape from /admin/reports/presence
  if ("window_minutes" in d && (Array.isArray(d.online) || Array.isArray(d.recent))) {
    return {
      window_minutes: Number(d.window_minutes) || 10,
      online: safeArr(d.online),
      recent: safeArr(d.recent),
    };
  }

  // Overview fallback may nest presence info here
  if (d.recent && typeof d.recent === "object" && d.recent.presence_admins) {
    const p = d.recent.presence_admins;
    if (p && typeof p === "object") return p;
  }

  // Older shape fallback
  if (Array.isArray(d.admins)) {
    return {
      window_minutes: Number(d.window_minutes) || 10,
      online: [],
      recent: d.admins,
    };
  }

  return null;
}

export default function AdminLayout({ children }) {
  const navigate = useNavigate();
  const { user, logout } = useAuth();

  const [drawerOpen, setDrawerOpen] = useState(false);

  // Persist collapsed desktop sidebar state
  const [collapsed, setCollapsed] = useState(() => {
    try {
      return localStorage.getItem("admin_sidebar_collapsed") === "1";
    } catch {
      return false;
    }
  });

  useEffect(() => {
    try {
      localStorage.setItem("admin_sidebar_collapsed", collapsed ? "1" : "0");
    } catch {
      // Ignore storage issues (private mode, disabled storage, etc.)
    }
  }, [collapsed]);

  // ---------------------------------------------------------------------------
  // Lightweight presence fetch (best-effort)
  // ---------------------------------------------------------------------------
  const { data: rawPresence } = useApi(PRESENCE_ENDPOINTS, { initialData: undefined });
  const presenceAdmins = useMemo(() => normalizePresence(rawPresence), [rawPresence]);

  // Auto-close drawer when switching to desktop
  useEffect(() => {
    const mq = window.matchMedia("(min-width: 1024px)");
    const onChange = () => {
      if (mq.matches) setDrawerOpen(false);
    };

    onChange();
    mq.addEventListener?.("change", onChange);
    return () => mq.removeEventListener?.("change", onChange);
  }, []);

  // ESC closes drawer + lock body scroll on mobile drawer
  useEffect(() => {
    const onKey = (e) => {
      if (e.key === "Escape") setDrawerOpen(false);
    };

    window.addEventListener("keydown", onKey);

    const prev = document.body.style.overflow;
    if (drawerOpen) document.body.style.overflow = "hidden";

    return () => {
      window.removeEventListener("keydown", onKey);
      document.body.style.overflow = prev;
    };
  }, [drawerOpen]);

  const adminName = useMemo(
    () => user?.full_name || user?.name || user?.email || "Admin",
    [user]
  );

  // ---------------------------------------------------------------------------
  // Logout is owned here; layout decides where admin lands after logout.
  // ---------------------------------------------------------------------------
  const handleLogout = () => {
    logout?.();
    navigate("/", { replace: true, state: { authMode: "login", fromLogout: true } });
  };

  // Desktop content offset must follow the current sidebar width.
  const leftPad = collapsed ? CONTENT_COLLAPSED_PAD_CLASS : CONTENT_WIDE_PAD_CLASS;

  // Fixed topbar must also shift right when the desktop sidebar changes width.
  const topbarLeft = collapsed ? SIDEBAR_COLLAPSED_CLASS : SIDEBAR_WIDE_CLASS;

  return (
    <div className="min-h-screen overflow-x-hidden bg-[#F4FBF7] text-slate-900">
      <a
        href="#admin-content"
        className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-[999] rounded-xl border border-slate-200 bg-white px-4 py-2 shadow"
      >
        Skip to content
      </a>

      {/* ---------------------------------------------------------------------
         Fixed sidebar (desktop) + drawer (mobile)
      --------------------------------------------------------------------- */}
      <AdminSidebar
        drawerOpen={drawerOpen}
        onCloseDrawer={() => setDrawerOpen(false)}
        collapsed={collapsed}
        onToggleCollapsed={() => setCollapsed((v) => !v)}
        onLogout={handleLogout}
        presenceAdmins={presenceAdmins}
      />

      {/* ---------------------------------------------------------------------
         Main shell
         • Uses desktop left padding to avoid the fixed sidebar
         • Uses top padding so content starts below the fixed topbar
      --------------------------------------------------------------------- */}
      <div className={["min-h-screen", leftPad].join(" ")}>
        {/* -------------------------------------------------------------------
           Fixed admin top bar
           This stays visible while the admin scrolls anywhere on the page.
        ------------------------------------------------------------------- */}
        <div className={["fixed inset-x-0 top-0 z-40", topbarLeft].join(" ")}>
          <AdminTopbar
            adminName={adminName}
            onOpenDrawer={() => setDrawerOpen(true)}
            onLogout={handleLogout}
          />
        </div>

        {/* -------------------------------------------------------------------
           Content area
           Top padding prevents the fixed header from overlapping the page body.
        ------------------------------------------------------------------- */}
        <main
          id="admin-content"
          className={["px-4 pb-6 md:px-6", TOPBAR_HEIGHT_PAD_CLASS].join(" ")}
        >
          <div className="mx-auto w-full max-w-[1400px]">{children}</div>
        </main>
      </div>
    </div>
  );
}