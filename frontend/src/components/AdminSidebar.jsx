// ============================================================================
// frontend/src/components/AdminSidebar.jsx
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Left navigation rail for all Admin pages.
//
// THIS UPDATE:
//   ✅ Keeps fixed sidebar, collapse behavior, and presence widget
//   ✅ Adds a compact Reports quick-actions card
//   ✅ Gives the admin a clearer entry point to the new report workflow
//   ✅ Preserves current navigation layout and mobile drawer behavior
// ============================================================================

import React, { useCallback, useMemo } from "react";
import { NavLink } from "react-router-dom";
import {
  LayoutDashboard,
  Users,
  ShieldCheck,
  BarChart3,
  ClipboardList,
  FileText,
  Settings,
  MessageSquare,
  ChevronLeft,
  ChevronRight,
  Leaf,
  X,
} from "lucide-react";

import AdminSidebarReportQuickActions from "./admin/AdminSidebarReportQuickActions";

const nav = [
  { to: "/dashboard/admin", label: "Dashboard", icon: LayoutDashboard },
  { to: "/dashboard/admin/users", label: "Users", icon: Users },
  { to: "/dashboard/admin/moderation", label: "Moderation", icon: ShieldCheck },
  { to: "/dashboard/admin/analytics", label: "Analytics", icon: BarChart3 },
  { to: "/dashboard/admin/audit-log", label: "Audit Log", icon: ClipboardList },
  { to: "/dashboard/admin/reports", label: "Reports", icon: FileText },
  { to: "/dashboard/admin/messaging", label: "Messaging", icon: MessageSquare },
  { to: "/dashboard/admin/settings", label: "Settings", icon: Settings },
];

// ---------------------------------------------------------------------------
// Small defensive helpers
// ---------------------------------------------------------------------------
function safeArr(v) {
  return Array.isArray(v) ? v : [];
}

function safeObj(v) {
  return v && typeof v === "object" ? v : null;
}

// ---------------------------------------------------------------------------
// Nav item
// ---------------------------------------------------------------------------
function Item({ to, label, icon: Icon, collapsed, onClick }) {
  return (
    <NavLink
      to={to}
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
      title={collapsed ? label : undefined}
      aria-label={label}
    >
      <div className="grid h-9 w-9 place-items-center rounded-2xl border border-[#D8F3DC] bg-white">
        <Icon className="h-5 w-5 text-current opacity-90 group-hover:opacity-100" />
      </div>

      {!collapsed && <span className="truncate text-sm font-semibold">{label}</span>}
    </NavLink>
  );
}

// ---------------------------------------------------------------------------
// Presence widget
// ---------------------------------------------------------------------------
function PresencePanel({ presenceAdmins, collapsed }) {
  if (collapsed) return null;

  const p = safeObj(presenceAdmins);
  if (!p) return null;

  const windowMinutes = p?.window_minutes ?? 10;
  const online = safeArr(p?.online);
  const recent = safeArr(p?.recent);

  const renderName = (u) => u?.full_name || u?.name || u?.email || "Admin";

  return (
    <div className="mt-3 rounded-2xl border border-[#D8F3DC] bg-white/85 p-3 shadow-sm">
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="text-sm font-extrabold text-slate-900">Admin Presence</div>
          <div className="text-xs text-slate-500">Online window: {windowMinutes} min</div>
        </div>

        <span className="inline-flex items-center gap-1 text-xs text-slate-600">
          <span className="h-2 w-2 rounded-full bg-emerald-500" />
          Live
        </span>
      </div>

      <div className="mt-3 space-y-3">
        <div>
          <div className="text-xs font-semibold text-slate-700">Online now</div>
          {online.length === 0 ? (
            <div className="mt-1 text-xs text-slate-500">No admins online.</div>
          ) : (
            <ul className="mt-1 space-y-1">
              {online.slice(0, 3).map((u) => (
                <li
                  key={u?.id || u?.email || renderName(u)}
                  className="flex items-center justify-between gap-2"
                >
                  <span className="truncate text-xs text-slate-700">{renderName(u)}</span>
                  <span className="h-2 w-2 shrink-0 rounded-full bg-emerald-500" />
                </li>
              ))}
            </ul>
          )}
        </div>

        <div>
          <div className="text-xs font-semibold text-slate-700">Recently seen</div>
          {recent.length === 0 ? (
            <div className="mt-1 text-xs text-slate-500">No recent activity.</div>
          ) : (
            <ul className="mt-1 space-y-1">
              {recent.slice(0, 3).map((u) => (
                <li
                  key={u?.id || u?.email || renderName(u)}
                  className="flex items-center justify-between gap-2"
                >
                  <span className="truncate text-xs text-slate-700">{renderName(u)}</span>
                  <span className="h-2 w-2 shrink-0 rounded-full bg-slate-300" />
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </div>
  );
}

export default function AdminSidebar({
  drawerOpen,
  onCloseDrawer,
  collapsed,
  onToggleCollapsed,
  onLogout, // kept for compatibility with AdminLayout
  presenceAdmins,
}) {
  const widthClass = collapsed ? "w-[84px]" : "w-[270px]";

  const close = useCallback(() => {
    if (typeof onCloseDrawer === "function") onCloseDrawer();
  }, [onCloseDrawer]);

  const shell = useMemo(
    () => (
      <div
        className={[
          "flex h-screen flex-col",
          "bg-[#F4FBF7] text-slate-900",
          "border-r border-[#D8F3DC]",
          widthClass,
        ].join(" ")}
        aria-label="Admin sidebar"
      >
        {/* Brand row */}
        <div className="flex items-center justify-between border-b border-[#D8F3DC] px-4 py-4">
          <div className="flex min-w-0 items-center gap-3">
            <div className="grid h-10 w-10 place-items-center rounded-2xl border border-[#B7E4C7] bg-white shadow-sm">
              <Leaf className="h-5 w-5 text-[#2D6A4F]" />
            </div>

            {!collapsed && (
              <div className="min-w-0">
                <div className="truncate font-extrabold tracking-tight">AgroConnect</div>
                <div className="truncate text-xs text-slate-500">Admin Console</div>
              </div>
            )}
          </div>

          <button
            type="button"
            onClick={close}
            className="grid h-9 w-9 place-items-center rounded-xl border border-[#D8F3DC] bg-white hover:bg-slate-50 lg:hidden"
            aria-label="Close sidebar"
            title="Close"
          >
            <X className="h-4 w-4 text-slate-700" />
          </button>

          <button
            type="button"
            onClick={onToggleCollapsed}
            className="hidden h-9 w-9 items-center justify-center rounded-xl border border-[#D8F3DC] bg-white transition hover:bg-slate-50 lg:inline-flex"
            aria-label="Toggle sidebar"
            title={collapsed ? "Expand" : "Collapse"}
          >
            {collapsed ? (
              <ChevronRight className="h-4 w-4" />
            ) : (
              <ChevronLeft className="h-4 w-4" />
            )}
          </button>
        </div>

        {/* Nav + quick actions */}
        <div className="flex-1 overflow-y-auto px-3 py-3">
          <div className="space-y-2">
            {nav.map((n) => (
              <Item key={n.to} {...n} collapsed={collapsed} onClick={close} />
            ))}
          </div>

          {/* Report shortcuts */}
          <AdminSidebarReportQuickActions collapsed={collapsed} />
        </div>

        {/* Presence */}
        <div className="px-3 pb-4">
          <PresencePanel presenceAdmins={presenceAdmins} collapsed={collapsed} />
        </div>
      </div>
    ),
    [collapsed, onToggleCollapsed, close, presenceAdmins, widthClass]
  );

  return (
    <>
      <aside className="hidden lg:fixed lg:inset-y-0 lg:left-0 lg:z-40 lg:block">{shell}</aside>

      {drawerOpen && (
        <div className="fixed inset-0 z-50 lg:hidden">
          <button
            type="button"
            aria-label="Close drawer"
            onClick={close}
            className="absolute inset-0 bg-black/40"
          />
          <div className="absolute inset-y-0 left-0">{shell}</div>
        </div>
      )}
    </>
  );
}