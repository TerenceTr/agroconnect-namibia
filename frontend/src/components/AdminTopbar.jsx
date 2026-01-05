// ============================================================================
// 🧩 AdminTopbar.jsx — Admin Header Bar (Green Accent)
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Top header for Admin pages.
//   • Mobile drawer trigger
//   • Page title derived from current route
//   • Admin profile pill with logout action
//
// DESIGN (Reference UI):
//   ✅ White topbar surface
//   ✅ Subtle green brand accent
//   ✅ Clean typography + spacing
//
// UX:
//   • Click-outside closes menu
//   • Escape closes menu
// ============================================================================

import React, { useEffect, useMemo, useRef, useState } from "react";
import { useLocation } from "react-router-dom";
import { Menu, ChevronDown, LogOut } from "lucide-react";

const titleMap = [
  { match: "/dashboard/admin/users", title: "Users" },
  { match: "/dashboard/admin/moderation", title: "Moderation" },
  { match: "/dashboard/admin/analytics", title: "Analytics" },
  { match: "/dashboard/admin/audit-log", title: "Audit Log" },
  { match: "/dashboard/admin/reports", title: "Reports & Analytics" },
  { match: "/dashboard/admin/messaging", title: "Messaging & Broadcasts" },
  { match: "/dashboard/admin/settings", title: "System Settings" },
  { match: "/dashboard/admin", title: "Admin Dashboard" },
];

function initials(name) {
  const s = String(name || "").trim();
  if (!s) return "AD";
  const parts = s.split(/\s+/).slice(0, 2);
  return parts.map((p) => p[0]?.toUpperCase()).join("") || "AD";
}

export default function AdminTopbar({ adminName = "Admin", onOpenDrawer, onLogout }) {
  const { pathname } = useLocation();
  const [open, setOpen] = useState(false);
  const ref = useRef(null);

  const pageTitle = useMemo(() => {
    const hit = titleMap.find((t) => pathname.startsWith(t.match));
    return hit?.title || "Admin";
  }, [pathname]);

  useEffect(() => {
    const onDoc = (e) => {
      if (!ref.current) return;
      if (!ref.current.contains(e.target)) setOpen(false);
    };
    const onKey = (e) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDoc);
      document.removeEventListener("keydown", onKey);
    };
  }, []);

  return (
    <header className="sticky top-0 z-30 bg-white/85 backdrop-blur border-b border-[#D8F3DC]">
      <div className="mx-auto w-full max-w-[1400px] px-4 md:px-6 py-3 flex items-center justify-between gap-3">
        {/* Left: drawer + titles */}
        <div className="flex items-center gap-3 min-w-0">
          <button
            type="button"
            onClick={onOpenDrawer}
            className="lg:hidden h-10 w-10 rounded-xl border border-[#D8F3DC] bg-white hover:bg-slate-50 transition grid place-items-center"
            aria-label="Open menu"
          >
            <Menu className="h-5 w-5 text-slate-700" />
          </button>

          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <span className="inline-block w-1.5 h-6 rounded-full bg-[#40916C]" />
              <div className="text-sm text-slate-500">AgroConnect Namibia</div>
            </div>
            <h1 className="text-lg md:text-xl font-bold text-slate-800 truncate">{pageTitle}</h1>
          </div>
        </div>

        {/* Right: profile pill */}
        <div className="relative" ref={ref}>
          <button
            type="button"
            onClick={() => setOpen((v) => !v)}
            className="flex items-center gap-3 px-3 py-2 rounded-2xl border border-[#D8F3DC] bg-white hover:bg-slate-50 transition"
            aria-haspopup="menu"
            aria-expanded={open}
          >
            <div className="h-9 w-9 rounded-xl bg-[#EAF7F0] border border-[#B7E4C7] grid place-items-center text-[#2D6A4F] font-bold">
              {initials(adminName)}
            </div>
            <div className="hidden sm:block text-left">
              <div className="text-sm font-semibold text-slate-800 truncate max-w-[220px]">
                {adminName}
              </div>
              <div className="text-xs text-slate-500">Administrator</div>
            </div>
            <ChevronDown className="h-4 w-4 text-slate-600" />
          </button>

          {open && (
            <div className="absolute right-0 mt-2 w-52 bg-white border border-[#D8F3DC] rounded-2xl shadow-lg overflow-hidden">
              <button
                type="button"
                onClick={() => {
                  setOpen(false);
                  onLogout?.();
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
  );
}
