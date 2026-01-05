// ====================================================================
// frontend/src/components/layout/DashboardLayout.jsx — AgroConnect Namibia
// ====================================================================
// FILE ROLE:
//   Shared shell for dashboards (Admin / Farmer / Customer).
//
// RESPONSIBILITIES:
//   • Sidebar navigation (role-aware UI links)
//   • Responsive shell (mobile overlay)
//   • Topbar (simple + consistent)
//   • Logout navigation (AuthProvider MUST NOT navigate)
//
// DESIGN (Reference UI):
//   ✅ Calm green-tinted base background
//   ✅ Light green sidebar surface
//   ✅ White rounded nav pills, active soft green
// ====================================================================

import React, { useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate, useLocation } from "react-router-dom";
import {
  Menu,
  X,
  Home,
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
} from "lucide-react";

import { useAuth } from "../auth/AuthProvider";
import { notifySuccess } from "../../utils/notify";

// Small helper
function getInitials(name) {
  const s = String(name || "User").trim();
  const parts = s.split(/\s+/).slice(0, 2);
  return (parts.map((p) => p[0]?.toUpperCase()).join("") || "U").slice(0, 2);
}

export default function DashboardLayout({ children }) {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  // Sidebar states
  const [drawerOpen, setDrawerOpen] = useState(false); // mobile
  const [collapsed, setCollapsed] = useState(false); // desktop collapse

  // Profile menu
  const [menuOpen, setMenuOpen] = useState(false);
  const menuRef = useRef(null);

  // Normalize role (supports either role_name or numeric role)
  const role = useMemo(() => {
    const name = user?.role_name?.toLowerCase?.();
    if (name) return name;
    if (user?.role === 1) return "admin";
    if (user?.role === 2) return "farmer";
    if (user?.role === 3) return "customer";
    return "user";
  }, [user]);

  const displayName = useMemo(
    () => user?.full_name || user?.name || user?.email || "User",
    [user]
  );

  const handleLogout = () => {
    logout();
    notifySuccess?.("Logged out successfully");
    navigate("/login", { replace: true });
  };

  // Close drawer on desktop breakpoint
  useEffect(() => {
    const mq = window.matchMedia("(min-width: 1024px)");
    const onChange = () => {
      if (mq.matches) setDrawerOpen(false);
    };
    onChange();
    mq.addEventListener?.("change", onChange);
    return () => mq.removeEventListener?.("change", onChange);
  }, []);

  // ESC closes drawer + menu + locks body scroll on mobile drawer
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

  // Click-outside closes profile menu
  useEffect(() => {
    const onDoc = (e) => {
      if (!menuRef.current) return;
      if (!menuRef.current.contains(e.target)) setMenuOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, []);

  // Role-aware nav (aligned with your NEW Farmer IA routes)
  const navLinks = useMemo(() => {
    const base = [{ to: "/", label: "Home", icon: Home }];

    if (role === "admin") {
      base.push(
        { to: "/dashboard/admin", label: "Dashboard", icon: BarChart3 },
        { to: "/dashboard/admin/users", label: "Users", icon: Users },
        { to: "/dashboard/admin/moderation", label: "Moderation", icon: Shield }
      );
    }

    if (role === "farmer") {
      base.push(
        { to: "/dashboard/farmer/overview", label: "Overview", icon: Tractor },
        { to: "/dashboard/farmer/products", label: "Products", icon: Package },
        { to: "/dashboard/farmer/orders", label: "Orders", icon: ClipboardList },
        { to: "/dashboard/farmer/feedback", label: "Feedback", icon: MessageSquareText }
      );
    }

    if (role === "customer") {
      base.push({ to: "/dashboard/customer", label: "Customer", icon: User });
    }

    return base;
  }, [role]);

  const widthClass = collapsed ? "w-[84px]" : "w-[270px]";
  const leftPad = collapsed ? "lg:pl-[84px]" : "lg:pl-[270px]";

  const Item = ({ to, label, Icon }) => {
    const active = location.pathname === to || location.pathname.startsWith(to + "/");
    return (
      <Link
        to={to}
        onClick={() => setDrawerOpen(false)}
        className={[
          "group flex items-center gap-3 rounded-2xl px-3 py-2.5 transition",
          "border shadow-sm",
          active
            ? "bg-[#D8F3DC] text-[#1B4332] border-[#B7E4C7]"
            : "bg-white/85 text-slate-700 border-white/40 hover:bg-white hover:text-slate-900",
        ].join(" ")}
        title={collapsed ? label : undefined}
      >
        <div className="h-9 w-9 rounded-2xl bg-white border border-[#D8F3DC] grid place-items-center">
          <Icon className="h-5 w-5 text-current opacity-90 group-hover:opacity-100" />
        </div>
        {!collapsed && <span className="text-sm font-semibold">{label}</span>}
      </Link>
    );
  };

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
      {/* Brand */}
      <div className="px-4 py-4 flex items-center justify-between border-b border-[#D8F3DC]">
        <div className="flex items-center gap-3 min-w-0">
          <div className="h-10 w-10 rounded-2xl bg-white grid place-items-center border border-[#B7E4C7] shadow-sm">
            <Leaf className="h-5 w-5 text-[#2D6A4F]" />
          </div>

          {!collapsed && (
            <div className="min-w-0">
              <div className="font-extrabold tracking-tight truncate">AgroConnect</div>
              <div className="text-xs text-slate-500 truncate capitalize">{role} console</div>
            </div>
          )}
        </div>

        {/* Close (mobile) */}
        <button
          type="button"
          aria-label="Close sidebar"
          className="lg:hidden h-9 w-9 rounded-xl border border-[#D8F3DC] bg-white hover:bg-slate-50 grid place-items-center"
          onClick={() => setDrawerOpen(false)}
        >
          <X className="h-4 w-4 text-slate-700" />
        </button>

        {/* Collapse toggle (desktop) */}
        <button
          type="button"
          onClick={() => setCollapsed((v) => !v)}
          className="hidden lg:inline-flex h-9 w-9 items-center justify-center rounded-xl border border-[#D8F3DC] bg-white hover:bg-slate-50 transition"
          aria-label="Toggle sidebar"
          title={collapsed ? "Expand" : "Collapse"}
        >
          {collapsed ? <ChevronRight className="h-4 w-4" /> : <ChevronLeft className="h-4 w-4" />}
        </button>
      </div>

      {/* Nav */}
      <nav className="mt-3 px-3 space-y-2 flex-1">
        {navLinks.map((n) => (
          <Item key={n.to} to={n.to} label={n.label} Icon={n.icon} />
        ))}
      </nav>

      {/* Logout */}
      <div className="p-3 border-t border-[#D8F3DC]">
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
          <div className="h-9 w-9 rounded-2xl bg-white border border-[#D8F3DC] grid place-items-center">
            <LogOut className="h-5 w-5" />
          </div>
          {!collapsed && <span className="text-sm font-semibold">Logout</span>}
        </button>
      </div>
    </aside>
  );

  return (
    <div className="min-h-screen bg-[#F4FBF7] text-slate-900">
      <a
        href="#dash-content"
        className="sr-only focus:not-sr-only focus:fixed focus:top-4 focus:left-4 focus:z-[999] bg-white px-4 py-2 rounded-xl shadow border border-slate-200"
      >
        Skip to content
      </a>

      {/* Desktop sidebar */}
      <div className="hidden lg:fixed lg:inset-y-0 lg:left-0 lg:z-40 lg:block">{SidebarShell}</div>

      {/* Mobile drawer */}
      {drawerOpen && (
        <div className="lg:hidden fixed inset-0 z-50">
          <button
            type="button"
            aria-label="Close drawer overlay"
            className="absolute inset-0 bg-black/40"
            onClick={() => setDrawerOpen(false)}
          />
          <div className="absolute inset-y-0 left-0">{SidebarShell}</div>
        </div>
      )}

      {/* Main */}
      <div className={["min-h-screen", leftPad].join(" ")}>
        {/* Top bar */}
        <header className="sticky top-0 z-30 bg-white/85 backdrop-blur border-b border-[#D8F3DC]">
          <div className="mx-auto w-full max-w-[1400px] px-4 md:px-6 py-3 flex items-center justify-between gap-3">
            <div className="flex items-center gap-3 min-w-0">
              <button
                type="button"
                aria-label="Open sidebar"
                className="lg:hidden h-10 w-10 rounded-xl border border-[#D8F3DC] bg-white hover:bg-slate-50 transition grid place-items-center"
                onClick={() => setDrawerOpen(true)}
              >
                <Menu className="h-5 w-5 text-slate-700" />
              </button>

              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <span className="inline-block w-1.5 h-6 rounded-full bg-[#40916C]" />
                  <div className="text-sm text-slate-500">AgroConnect Namibia</div>
                </div>
                <div className="text-lg font-bold text-slate-800 truncate capitalize">
                  {role} Dashboard
                </div>
              </div>
            </div>

            {/* User menu */}
            <div className="relative" ref={menuRef}>
              <button
                type="button"
                onClick={() => setMenuOpen((v) => !v)}
                className="flex items-center gap-3 px-3 py-2 rounded-2xl border border-[#D8F3DC] bg-white hover:bg-slate-50 transition"
                aria-haspopup="menu"
                aria-expanded={menuOpen}
              >
                <div className="h-9 w-9 rounded-xl bg-[#EAF7F0] border border-[#B7E4C7] grid place-items-center text-[#2D6A4F] font-bold text-sm">
                  {getInitials(displayName)}
                </div>
                <div className="hidden sm:block text-left">
                  <div className="text-sm font-semibold text-slate-800 truncate max-w-[220px]">
                    {displayName}
                  </div>
                  <div className="text-xs text-slate-500 capitalize">{role}</div>
                </div>
                <ChevronDown className="h-4 w-4 text-slate-600" />
              </button>

              {menuOpen && (
                <div className="absolute right-0 mt-2 w-56 bg-white border border-[#D8F3DC] rounded-2xl shadow-lg overflow-hidden">
                  <button
                    type="button"
                    onClick={() => {
                      setMenuOpen(false);
                      handleLogout();
                    }}
                    className="w-full px-4 py-3 text-left text-sm text-slate-700 hover:bg-slate-50 flex items-center gap-2"
                  >
                    <LogOut className="h-4 w-4 text-slate-600" />
                    Logout
                  </button>
                </div>
              )}
            </div>
          </div>
        </header>

        {/* Content */}
        <main id="dash-content" className="p-4 md:p-6">
          <div className="mx-auto w-full max-w-[1400px]">{children}</div>
        </main>
      </div>
    </div>
  );
}
