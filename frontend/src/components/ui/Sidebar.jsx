// ====================================================================
// 🧭 frontend/src/components/ui/Sidebar.jsx — Hybrid Sidebar
// --------------------------------------------------------------------
// FILE ROLE:
//   Shared hybrid sidebar for desktop + mobile navigation.
//
// KEY RESPONSIBILITIES:
//   • Role-aware navigation for admin, farmer, and customer
//   • Expand/collapse behavior on desktop
//   • Mobile drawer navigation
//   • Logout access
//
// THIS UPDATE:
//   ✅ Keeps AI Insights for Admin + Farmer only
//   ✅ Renames customer "Account" to "My Account"
//   ✅ Leaves customer AI access disabled
// ====================================================================

import React, { useState, useEffect } from "react";
import { Link, useLocation } from "react-router-dom";
import {
  Menu,
  X,
  Home,
  BarChart3,
  Users,
  ShoppingBag,
  LogOut,
  Settings,
  Truck,
  LineChart,
} from "lucide-react";

export default function Sidebar({
  pinned,
  setPinned,
  mobileOpen,
  setMobileOpen,
  onLogout,
  user,
}) {
  const [expanded, setExpanded] = useState(false);
  const location = useLocation();

  useEffect(() => {
    setExpanded(pinned);
  }, [pinned]);

  // ---------------------------------------------
  // NORMALIZED ROLE
  // ---------------------------------------------
  // Use role_name when available because it is the clearest backend-provided
  // role source for UI navigation decisions.
  const role = (user?.role_name || "").toLowerCase();

  // ---------------------------------------------
  // COMMON NAV
  // ---------------------------------------------
  // Shared public/home entry.
  const common = [{ label: "Home", to: "/", icon: <Home /> }];

  // ---------------------------------------------
  // ADMIN NAV
  // ---------------------------------------------
  const admin = [
    { label: "Dashboard", to: "/dashboard/admin", icon: <BarChart3 /> },
    { label: "Users", to: "/dashboard/admin/users", icon: <Users /> },
    { label: "Reports", to: "/dashboard/admin/reports", icon: <ShoppingBag /> },
    { label: "Settings", to: "/dashboard/admin/settings", icon: <Settings /> },
    // Admin can access AI insights.
    { label: "AI Insights", to: "/dashboard/ai", icon: <LineChart /> },
  ];

  // ---------------------------------------------
  // FARMER NAV
  // ---------------------------------------------
  const farmer = [
    { label: "Dashboard", to: "/dashboard/farmer", icon: <Truck /> },
    { label: "Products", to: "/dashboard/farmer/products", icon: <ShoppingBag /> },
    // Farmer can access AI insights.
    { label: "AI Insights", to: "/dashboard/ai", icon: <LineChart /> },
  ];

  // ---------------------------------------------
  // CUSTOMER NAV
  // ---------------------------------------------
  const customer = [
    { label: "Market", to: "/dashboard/customer", icon: <ShoppingBag /> },
    { label: "My Account", to: "/dashboard/customer/account", icon: <Users /> },
    // Customers do NOT see AI dashboard.
  ];

  // ---------------------------------------------
  // FINAL NAV ITEMS (by role)
  // ---------------------------------------------
  const items = [
    ...common,
    ...(role === "admin" ? admin : []),
    ...(role === "farmer" ? farmer : []),
    ...(role === "customer" ? customer : []),
  ];

  // ---------------------------------------------
  // DESKTOP SIDEBAR STYLE
  // ---------------------------------------------
  const desktopClass = `
    hidden md:flex flex-col fixed left-0 top-0 h-full z-40
    bg-white/6 backdrop-blur-lg border-r border-white/10
    transition-all duration-300
    ${expanded ? "w-56" : "w-20"}
  `;

  return (
    <>
      {/* DESKTOP SIDEBAR */}
      <aside
        className={desktopClass}
        onMouseEnter={() => setExpanded(true)}
        onMouseLeave={() => !pinned && setExpanded(false)}
      >
        {/* LOGO / HEADER */}
        <div className="flex items-center justify-between p-4">
          <div className="flex items-center gap-3">
            <img
              src={`${process.env.PUBLIC_URL}/assets/logo.png`}
              alt="logo"
              className="h-8 w-8"
            />
            {expanded && <span className="font-bold text-white">AgroConnect</span>}
          </div>

          <button
            className="text-white/70 hover:text-white"
            onClick={() => setPinned((s) => !s)}
          >
            {pinned ? <X /> : <Menu />}
          </button>
        </div>

        {/* NAVIGATION */}
        <nav className="mt-6 px-2 flex-1 flex flex-col gap-1">
          {items.map((it) => {
            const active = location.pathname === it.to;

            return (
              <Link
                key={it.to}
                to={it.to}
                className={`
                  flex items-center gap-3 px-3 py-3 mx-2 rounded-lg transition
                  ${active ? "bg-namibia-green text-white" : "text-white/80 hover:bg-white/10"}
                `}
              >
                <span>{it.icon}</span>
                {expanded && <span className="font-medium">{it.label}</span>}
              </Link>
            );
          })}
        </nav>

        {/* LOGOUT BUTTON */}
        <div className="p-4">
          <button
            onClick={onLogout}
            className="w-full flex items-center gap-3 px-3 py-2 rounded-lg text-red-300 hover:bg-red-500/20"
          >
            <LogOut />
            {expanded && <span>Logout</span>}
          </button>
        </div>
      </aside>

      {/* MOBILE TOPBAR */}
      <div className="md:hidden fixed top-0 left-0 right-0 z-50">
        <div className="flex items-center justify-between bg-namibia-dark text-white px-4 py-3">
          <div className="flex items-center gap-3">
            <img
              src={`${process.env.PUBLIC_URL}/assets/logo.png`}
              alt="logo"
              className="h-8 w-8"
            />
            <span className="font-semibold">AgroConnect</span>
          </div>

          <button onClick={() => setMobileOpen(true)}>
            <Menu />
          </button>
        </div>

        {/* MOBILE DRAWER */}
        {mobileOpen && (
          <div className="fixed inset-0 z-50 flex">
            <div
              className="w-64 bg-white/6 backdrop-blur-xl p-4 border-r border-white/10"
              onClick={(e) => e.stopPropagation()}
            >
              <div className="flex items-center justify-between mb-4">
                <strong>Menu</strong>
                <button onClick={() => setMobileOpen(false)}>
                  <X />
                </button>
              </div>

              <nav className="flex flex-col gap-2">
                {items.map((it) => (
                  <Link
                    key={it.to}
                    to={it.to}
                    onClick={() => setMobileOpen(false)}
                    className="flex items-center gap-3 px-3 py-3 rounded-lg text-white/80 hover:bg-white/10"
                  >
                    {it.icon}
                    <span>{it.label}</span>
                  </Link>
                ))}
              </nav>

              <div className="mt-auto pt-4">
                <button
                  onClick={() => {
                    setMobileOpen(false);
                    onLogout();
                  }}
                  className="flex items-center gap-3 text-red-300 px-3 py-2 rounded-lg hover:bg-red-500/20 w-full"
                >
                  <LogOut />
                  <span>Logout</span>
                </button>
              </div>
            </div>

            <div className="flex-1" onClick={() => setMobileOpen(false)} />
          </div>
        )}
      </div>
    </>
  );
}