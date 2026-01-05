// ============================================================================
// src/components/FarmerSidebar.jsx — Navigation Sidebar (Farmer IA) [GREEN LIGHT]
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Farmer navigation rail (mobile drawer + desktop collapse).
//
// RESPONSIBILITIES:
//   • Provide farmer IA links:
//       - Overview  -> /dashboard/farmer/overview
//       - Products  -> /dashboard/farmer/products
//       - Orders    -> /dashboard/farmer/orders
//       - Feedback  -> /dashboard/farmer/feedback
//   • Match AdminSidebar behavior (drawer + collapse)
//   • Light green sidebar surface + white nav pills (reference UI)
// ============================================================================

import React from "react";
import { NavLink } from "react-router-dom";
import {
  Home,
  LayoutDashboard,
  Package,
  ClipboardList,
  MessageSquareText,
  LogOut,
  Leaf,
  ChevronLeft,
  ChevronRight,
  X,
} from "lucide-react";

function Item({ name, icon: Icon, path, end, collapsed, onClick }) {
  return (
    <NavLink
      to={path}
      end={Boolean(end)}
      onClick={onClick}
      className={({ isActive }) =>
        [
          "group flex items-center gap-3 rounded-2xl px-3 py-2.5 transition",
          "border shadow-sm",
          isActive
            ? "bg-[#D8F3DC] text-[#1B4332] border-[#B7E4C7]"
            : "bg-white/85 text-slate-700 border-white/40 hover:bg-white hover:text-slate-900",
        ].join(" ")
      }
      title={collapsed ? name : undefined}
    >
      <div className="h-9 w-9 rounded-2xl bg-white border border-[#D8F3DC] grid place-items-center">
        <Icon className="h-5 w-5 text-current opacity-90 group-hover:opacity-100" />
      </div>
      {!collapsed && <span className="text-sm font-semibold">{name}</span>}
    </NavLink>
  );
}

export default function FarmerSidebar({
  drawerOpen,
  onCloseDrawer,
  collapsed,
  onToggleCollapsed,
  onLogout,
}) {
  const navItems = [
    { name: "Home", icon: Home, path: "/", end: true },
    { name: "Overview", icon: LayoutDashboard, path: "/dashboard/farmer/overview" },
    { name: "Products", icon: Package, path: "/dashboard/farmer/products" },
    { name: "Orders", icon: ClipboardList, path: "/dashboard/farmer/orders" },
    { name: "Feedback", icon: MessageSquareText, path: "/dashboard/farmer/feedback" },
  ];

  const widthClass = collapsed ? "w-[84px]" : "w-[270px]";
  const close = () => (typeof onCloseDrawer === "function" ? onCloseDrawer() : undefined);

  const Shell = (
    <div
      className={[
        "h-full text-slate-900",
        "bg-[#F4FBF7]",
        "border-r border-[#D8F3DC]",
        widthClass,
        "flex flex-col",
      ].join(" ")}
      aria-label="Farmer sidebar"
    >
      {/* Header / Brand */}
      <div className="px-4 py-4 flex items-center justify-between border-b border-[#D8F3DC]">
        <div className="flex items-center gap-3 min-w-0">
          <div className="h-10 w-10 rounded-2xl bg-white grid place-items-center border border-[#B7E4C7] shadow-sm">
            <Leaf className="h-5 w-5 text-[#2D6A4F]" />
          </div>

          {!collapsed && (
            <div className="min-w-0">
              <div className="font-extrabold tracking-tight truncate">AgroConnect</div>
              <div className="text-xs text-slate-500 truncate">Farmer Console</div>
            </div>
          )}
        </div>

        {/* Mobile close */}
        <button
          type="button"
          onClick={close}
          className="lg:hidden h-9 w-9 rounded-xl border border-[#D8F3DC] bg-white hover:bg-slate-50 grid place-items-center"
          aria-label="Close sidebar"
        >
          <X className="h-4 w-4 text-slate-700" />
        </button>

        {/* Collapse toggle (desktop) */}
        <button
          type="button"
          onClick={onToggleCollapsed}
          className="hidden lg:inline-flex h-9 w-9 items-center justify-center rounded-xl border border-[#D8F3DC] bg-white hover:bg-slate-50 transition"
          aria-label="Toggle sidebar"
          title={collapsed ? "Expand" : "Collapse"}
        >
          {collapsed ? <ChevronRight className="h-4 w-4" /> : <ChevronLeft className="h-4 w-4" />}
        </button>
      </div>

      {/* Nav */}
      <nav className="mt-3 px-3 space-y-2 flex-1">
        {navItems.map((n) => (
          <Item key={n.path} {...n} collapsed={collapsed} onClick={close} />
        ))}
      </nav>

      {/* Logout */}
      <div className="p-3 border-t border-[#D8F3DC]">
        <button
          type="button"
          onClick={onLogout}
          className="w-full flex items-center gap-3 rounded-2xl px-3 py-2.5 bg-white/85 border border-white/40 shadow-sm text-slate-700 hover:text-slate-900 hover:bg-white transition"
          title={collapsed ? "Logout" : undefined}
        >
          <div className="h-9 w-9 rounded-2xl bg-white border border-[#D8F3DC] grid place-items-center">
            <LogOut className="h-5 w-5" />
          </div>
          {!collapsed && <span className="text-sm font-semibold">Logout</span>}
        </button>
      </div>
    </div>
  );

  return (
    <>
      {/* Desktop */}
      <aside className="hidden lg:fixed lg:inset-y-0 lg:left-0 lg:z-40 lg:block">{Shell}</aside>

      {/* Mobile drawer */}
      {drawerOpen && (
        <div className="lg:hidden fixed inset-0 z-50">
          <button
            type="button"
            aria-label="Close drawer"
            onClick={close}
            className="absolute inset-0 bg-black/40"
          />
          <div className="absolute inset-y-0 left-0">{Shell}</div>
        </div>
      )}
    </>
  );
}
