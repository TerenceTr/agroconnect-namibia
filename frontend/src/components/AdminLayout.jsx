// ============================================================================
// src/components/AdminLayout.jsx
// ----------------------------------------------------------------------------
// 🧱 AdminLayout — Admin Shell Layout (AgroConnect Namibia) [CALM GREEN BASE]
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Shared layout wrapper for ALL admin pages.
//   • Renders AdminSidebar + AdminTopbar
//   • Manages responsive sidebar (mobile drawer + desktop collapse)
//   • Owns logout navigation (AuthProvider MUST NOT navigate)
//
// DESIGN GOAL:
//   • Calm green-tinted app background (like your reference UI)
//   • Content stays on white cards → green is an accent, not a wall
// ============================================================================

import React, { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";

import AdminSidebar from "./AdminSidebar";
import AdminTopbar from "./AdminTopbar";
import { useAuth } from "./auth/AuthProvider";

export default function AdminLayout({ children }) {
  const navigate = useNavigate();
  const { user, logout } = useAuth();

  const [drawerOpen, setDrawerOpen] = useState(false);
  const [collapsed, setCollapsed] = useState(false);

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

  const handleLogout = () => {
    logout();
    navigate("/", { replace: true });
  };

  const leftPad = collapsed ? "lg:pl-[84px]" : "lg:pl-[270px]";

  return (
    <div className="min-h-screen bg-[#F4FBF7] text-slate-900">
      <a
        href="#admin-content"
        className="sr-only focus:not-sr-only focus:fixed focus:top-4 focus:left-4 focus:z-[999] bg-white px-4 py-2 rounded-xl shadow border border-slate-200"
      >
        Skip to content
      </a>

      <AdminSidebar
        drawerOpen={drawerOpen}
        onCloseDrawer={() => setDrawerOpen(false)}
        collapsed={collapsed}
        onToggleCollapsed={() => setCollapsed((v) => !v)}
        onLogout={handleLogout}
      />

      <div className={["min-h-screen", leftPad].join(" ")}>
        <AdminTopbar
          adminName={adminName}
          onOpenDrawer={() => setDrawerOpen(true)}
          onLogout={handleLogout}
        />

        <main id="admin-content" className="p-4 md:p-6">
          <div className="mx-auto w-full max-w-[1400px]">{children}</div>
        </main>
      </div>
    </div>
  );
}
