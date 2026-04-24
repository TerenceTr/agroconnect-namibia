// ============================================================================
// frontend/src/components/layout/DashboardLayout.jsx — AgroConnect Namibia
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Shared dashboard shell (sidebar + topbar + responsive drawer).
//
// KEY RESPONSIBILITIES:
//   • Role-aware navigation (admin/farmer/customer)
//   • Sticky top header with profile dropdown
//   • Mobile drawer + desktop collapsible sidebar
//   • Consistent premium-neutral palette
//
// THIS UPDATE:
//   ✅ Keeps customer Payments link
//   ✅ Renames customer Account label to "My Account" in sidebar navigation
//   ✅ Renames customer Account label to "My Account" in the top-right dropdown
// ============================================================================

import React, { useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate, useLocation } from "react-router-dom";
import {
  Menu,
  X,
  LogOut,
  BarChart3,
  User,
  Tractor,
  Users,
  Shield,
  Package,
  ClipboardList,
  MessageSquareText,
  Leaf,
  ChevronLeft,
  ChevronRight,
  ChevronDown,
  Settings,
  Search,
  CreditCard,
  Bell,
} from "lucide-react";

import { useAuth } from "../auth/AuthProvider";
import { notifySuccess } from "../../utils/notify";

// -----------------------------------------------------------------------------
// Small helpers
// -----------------------------------------------------------------------------
function getInitials(name) {
  const s = String(name || "User").trim();
  const parts = s.split(/\s+/).slice(0, 2);
  return (parts.map((p) => p[0]?.toUpperCase()).join("") || "U").slice(0, 2);
}

function normalizePath(path) {
  const s = String(path || "").trim();
  if (!s) return "/";
  if (s === "/") return "/";
  return s.replace(/\/+$/, "");
}

// Paths that should only be active on exact match.
// This avoids highlighting a parent route when a deeper child route is open.
const EXACT_ONLY_ACTIVE_PATHS = new Set([
  "/dashboard/customer",
  "/dashboard/admin",
]);

function isNavActive(pathname, to) {
  const current = normalizePath(pathname);
  const target = normalizePath(to);

  if (!target) return false;

  if (EXACT_ONLY_ACTIVE_PATHS.has(target)) {
    return current === target;
  }

  return current === target || current.startsWith(`${target}/`);
}

export default function DashboardLayout({
  children,
  title,
  topbarActions = null,
}) {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  // Mobile drawer, desktop sidebar collapse, and profile menu state.
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [collapsed, setCollapsed] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const menuRef = useRef(null);

  // Resolve the authenticated user's role in a backend-tolerant way.
  const role = useMemo(() => {
    const name = user?.role_name?.toLowerCase?.();
    if (name) return name;
    if (user?.role === 1) return "admin";
    if (user?.role === 2) return "farmer";
    if (user?.role === 3) return "customer";
    return "user";
  }, [user]);

  // Best-effort display name for the avatar chip and menu.
  const displayName = useMemo(
    () => user?.full_name || user?.name || user?.email || "User",
    [user]
  );

  // Use an explicit page title when provided; otherwise build one from role.
  const pageTitle = useMemo(() => {
    if (title && String(title).trim()) return String(title).trim();
    return `${role} Dashboard`;
  }, [title, role]);

  const handleLogout = () => {
    void logout?.();
    notifySuccess?.("Logged out successfully");
    navigate("/", { replace: true, state: { authMode: "login", fromLogout: true } });
  };

  // Close drawer and profile menu whenever route changes.
  useEffect(() => {
    setDrawerOpen(false);
    setMenuOpen(false);
  }, [location.pathname]);

  // Ensure the mobile drawer is closed when switching to desktop viewport.
  useEffect(() => {
    if (typeof window === "undefined") return undefined;

    const mq = window.matchMedia("(min-width: 1024px)");
    const onChange = () => {
      if (mq.matches) setDrawerOpen(false);
    };

    onChange();
    mq.addEventListener?.("change", onChange);
    return () => mq.removeEventListener?.("change", onChange);
  }, []);

  // Handle escape key for drawer/menu dismissal and lock body scroll while
  // the mobile drawer is open.
  useEffect(() => {
    const onKey = (e) => {
      if (e.key === "Escape") {
        setDrawerOpen(false);
        setMenuOpen(false);
      }
    };

    window.addEventListener("keydown", onKey);

    const prev = document.body.style.overflow;
    if (drawerOpen) document.body.style.overflow = "hidden";

    return () => {
      window.removeEventListener("keydown", onKey);
      document.body.style.overflow = prev;
    };
  }, [drawerOpen]);

  // Close the profile dropdown when clicking outside of it.
  useEffect(() => {
    const onDoc = (e) => {
      if (!menuRef.current) return;
      if (!menuRef.current.contains(e.target)) setMenuOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, []);

  // Role-aware navigation links.
  const navLinks = useMemo(() => {
    const links = [];

    if (role === "admin") {
      links.push(
        { to: "/dashboard/admin", label: "Dashboard", icon: BarChart3 },
        { to: "/dashboard/admin/users", label: "Users", icon: Users },
        { to: "/dashboard/admin/moderation", label: "Moderation", icon: Shield }
      );
    }

    if (role === "farmer") {
      links.push(
        { to: "/dashboard/farmer/overview", label: "Overview", icon: Tractor },
        { to: "/dashboard/farmer/products", label: "Products", icon: Package },
        { to: "/dashboard/farmer/orders", label: "Orders", icon: ClipboardList },
        { to: "/dashboard/farmer/feedback", label: "Feedback", icon: MessageSquareText }
      );
    }

    if (role === "customer") {
      links.push(
        { to: "/dashboard/customer", label: "Overview", icon: User },
        { to: "/dashboard/customer/orders", label: "Orders", icon: ClipboardList },
        { to: "/dashboard/customer/messages", label: "Messages", icon: MessageSquareText },
        { to: "/dashboard/customer/announcements", label: "Announcements", icon: Bell },
        { to: "/dashboard/customer/saved-search", label: "Saved & Search", icon: Search },
        { to: "/dashboard/customer/insights", label: "Insights", icon: BarChart3 },
        { to: "/dashboard/customer/payments", label: "Payments", icon: CreditCard },
        { to: "/dashboard/customer/account", label: "My Account", icon: Settings }
      );
    }

    return links;
  }, [role]);

  // Layout width classes for expanded vs collapsed desktop sidebar.
  const widthClass = collapsed ? "w-[84px]" : "w-[270px]";
  const leftPad = collapsed ? "lg:pl-[84px]" : "lg:pl-[270px]";

  // Shared sidebar navigation item renderer.
  const Item = ({ to, label, Icon }) => {
    const active = isNavActive(location.pathname, to);

    return (
      <Link
        to={to}
        className={[
          "group flex items-center gap-3 rounded-2xl px-3 py-2.5 transition",
          "border shadow-sm",
          active
            ? "bg-[#D8F3DC] text-[#1B4332] border-[#B7E4C7]"
            : "bg-white/85 text-slate-700 border-white/40 hover:bg-white hover:text-slate-900",
        ].join(" ")}
        title={collapsed ? label : undefined}
        aria-current={active ? "page" : undefined}
      >
        <div className="grid h-9 w-9 place-items-center rounded-2xl border border-[#D8F3DC] bg-white">
          <Icon className="h-5 w-5 text-current opacity-90 group-hover:opacity-100" />
        </div>
        {!collapsed && <span className="text-sm font-semibold">{label}</span>}
      </Link>
    );
  };

  // Shared sidebar shell used by both desktop and mobile drawer variants.
  const SidebarShell = (
    <aside
      className={[
        "h-full text-slate-900",
        "bg-[#F4FBF7]",
        "border-r border-[#D8F3DC]",
        widthClass,
        "flex flex-col",
      ].join(" ")}
      aria-label="Dashboard sidebar"
    >
      <div className="flex items-center justify-between border-b border-[#D8F3DC] px-4 py-4">
        <div className="min-w-0 flex items-center gap-3">
          <div className="grid h-10 w-10 place-items-center rounded-2xl border border-[#B7E4C7] bg-white shadow-sm">
            <Leaf className="h-5 w-5 text-[#2D6A4F]" />
          </div>

          {!collapsed && (
            <div className="min-w-0">
              <div className="truncate font-extrabold tracking-tight">AgroConnect</div>
              <div className="truncate text-xs capitalize text-slate-500">{role} console</div>
            </div>
          )}
        </div>

        <button
          type="button"
          aria-label="Close sidebar"
          className="grid h-9 w-9 place-items-center rounded-xl border border-[#D8F3DC] bg-white hover:bg-slate-50 lg:hidden"
          onClick={() => setDrawerOpen(false)}
        >
          <X className="h-4 w-4 text-slate-700" />
        </button>

        <button
          type="button"
          onClick={() => setCollapsed((v) => !v)}
          className="hidden h-9 w-9 items-center justify-center rounded-xl border border-[#D8F3DC] bg-white transition hover:bg-slate-50 lg:inline-flex"
          aria-label="Toggle sidebar"
          title={collapsed ? "Expand" : "Collapse"}
        >
          {collapsed ? <ChevronRight className="h-4 w-4" /> : <ChevronLeft className="h-4 w-4" />}
        </button>
      </div>

      <nav className="mt-3 flex-1 space-y-2 px-3">
        {navLinks.map((n) => (
          <Item key={n.to} to={n.to} label={n.label} Icon={n.icon} />
        ))}
      </nav>

      <div className="border-t border-[#D8F3DC] p-3">
        <button
          type="button"
          onClick={handleLogout}
          className={[
            "w-full flex items-center gap-3 rounded-2xl px-3 py-2.5",
            "bg-white/85 border border-white/40 shadow-sm",
            "text-slate-700 hover:text-slate-900 hover:bg-white transition",
          ].join(" ")}
          title={collapsed ? "Logout" : undefined}
        >
          <div className="grid h-9 w-9 place-items-center rounded-2xl border border-[#D8F3DC] bg-white">
            <LogOut className="h-5 w-5" />
          </div>
          {!collapsed && <span className="text-sm font-semibold">Logout</span>}
        </button>
      </div>
    </aside>
  );

  return (
    <div className="min-h-screen bg-[#F4FBF7] text-slate-900">
      {/* Accessibility skip link for keyboard users */}
      <a
        href="#dash-content"
        className="sr-only rounded-xl border border-slate-200 bg-white px-4 py-2 shadow focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-[999]"
      >
        Skip to content
      </a>

      {/* Desktop fixed sidebar */}
      <div className="hidden lg:fixed lg:inset-y-0 lg:left-0 lg:z-40 lg:block">{SidebarShell}</div>

      {/* Mobile drawer */}
      {drawerOpen && (
        <div className="fixed inset-0 z-50 lg:hidden">
          <button
            type="button"
            aria-label="Close drawer overlay"
            className="absolute inset-0 bg-black/40"
            onClick={() => setDrawerOpen(false)}
          />
          <div className="absolute inset-y-0 left-0">{SidebarShell}</div>
        </div>
      )}

      {/* Main content shell */}
      <div className={["min-h-screen", leftPad].join(" ")}>
        <header className="sticky top-0 z-30 border-b border-[#D8F3DC] bg-white/85 backdrop-blur">
          <div className="mx-auto flex w-full max-w-[1400px] items-center justify-between gap-3 px-4 py-3 md:px-6">
            <div className="min-w-0 flex items-center gap-3">
              <button
                type="button"
                aria-label="Open sidebar"
                className="grid h-10 w-10 place-items-center rounded-xl border border-[#D8F3DC] bg-white transition hover:bg-slate-50 lg:hidden"
                onClick={() => setDrawerOpen(true)}
              >
                <Menu className="h-5 w-5 text-slate-700" />
              </button>

              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <span className="inline-block h-6 w-1.5 rounded-full bg-[#40916C]" />
                  <div className="text-sm text-slate-500">AgroConnect Namibia</div>
                </div>
                <div className="truncate text-lg font-bold capitalize text-slate-800">
                  {pageTitle}
                </div>
              </div>
            </div>

            <div className="flex shrink-0 items-center gap-2">
              {topbarActions ? <div className="shrink-0">{topbarActions}</div> : null}

              <div className="relative" ref={menuRef}>
                <button
                  type="button"
                  onClick={() => setMenuOpen((v) => !v)}
                  className="flex items-center gap-3 rounded-2xl border border-[#D8F3DC] bg-white px-3 py-2 transition hover:bg-slate-50"
                  aria-haspopup="menu"
                  aria-expanded={menuOpen}
                >
                  <div className="grid h-9 w-9 place-items-center rounded-xl border border-[#B7E4C7] bg-[#EAF7F0] text-sm font-bold text-[#2D6A4F]">
                    {getInitials(displayName)}
                  </div>

                  <div className="hidden text-left sm:block">
                    <div className="max-w-[220px] truncate text-sm font-semibold text-slate-800">
                      {displayName}
                    </div>
                    <div className="text-xs capitalize text-slate-500">{role}</div>
                  </div>

                  <ChevronDown className="h-4 w-4 text-slate-600" />
                </button>

                {menuOpen && (
                  <div className="absolute right-0 mt-2 w-56 overflow-hidden rounded-2xl border border-[#D8F3DC] bg-white shadow-lg">
                    {role === "customer" && (
                      <Link
                        to="/dashboard/customer/account"
                        className="flex w-full items-center gap-2 px-4 py-3 text-left text-sm text-slate-700 hover:bg-slate-50"
                        onClick={() => setMenuOpen(false)}
                      >
                        <Settings className="h-4 w-4 text-slate-600" />
                        My Account
                      </Link>
                    )}

                    <button
                      type="button"
                      onClick={() => {
                        setMenuOpen(false);
                        handleLogout();
                      }}
                      className="flex w-full items-center gap-2 px-4 py-3 text-left text-sm text-slate-700 hover:bg-slate-50"
                    >
                      <LogOut className="h-4 w-4 text-slate-600" />
                      Logout
                    </button>
                  </div>
                )}
              </div>
            </div>
          </div>
        </header>

        <main id="dash-content" className="p-4 md:p-6">
          <div className="mx-auto w-full max-w-[1400px]">{children}</div>
        </main>
      </div>
    </div>
  );
}