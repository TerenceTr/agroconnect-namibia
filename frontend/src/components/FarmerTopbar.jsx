// ============================================================================
// src/components/FarmerTopbar.jsx — Header Bar for Farmer Console (Green Accent)
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Farmer top navigation bar.
//   • Mobile drawer trigger
//   • Brand label
//   • User dropdown with logout action
//
// DESIGN (Reference UI):
//   ✅ White topbar surface
//   ✅ Subtle green brand accent
//
// UX IMPROVEMENTS:
//   • Click-outside closes menu
//   • Escape key closes menu
// ============================================================================

import React, { useEffect, useMemo, useRef, useState } from "react";
import { Menu, User, LogOut, ChevronDown } from "lucide-react";

export default function FarmerTopbar({ farmerName = "Farmer", onOpenDrawer, onLogout }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);

  const initials = useMemo(() => {
    const parts = String(farmerName || "Farmer").trim().split(/\s+/);
    return (
      parts
        .slice(0, 2)
        .map((p) => p[0]?.toUpperCase())
        .join("") || "FR"
    );
  }, [farmerName]);

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
      <div className="h-14 px-4 md:px-6 flex items-center justify-between">
        {/* Left: brand + mobile menu */}
        <div className="flex items-center gap-3 min-w-0">
          <button
            type="button"
            onClick={onOpenDrawer}
            className="lg:hidden h-10 w-10 rounded-xl border border-[#D8F3DC] bg-white hover:bg-slate-50 transition grid place-items-center"
            aria-label="Open sidebar"
          >
            <Menu className="h-5 w-5 text-slate-700" />
          </button>

          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <span className="inline-block w-1.5 h-6 rounded-full bg-[#40916C]" />
              <h2 className="text-base md:text-lg font-semibold text-slate-800 tracking-tight truncate">
                AgroConnect Namibia
              </h2>
            </div>
          </div>
        </div>

        {/* Right: user menu */}
        <div className="relative" ref={ref}>
          <button
            type="button"
            onClick={() => setOpen((v) => !v)}
            className="flex items-center gap-3 px-2 py-1.5 rounded-2xl border border-[#D8F3DC] bg-white hover:bg-slate-50 transition"
            aria-haspopup="menu"
            aria-expanded={open}
          >
            <div className="h-9 w-9 rounded-xl bg-[#EAF7F0] border border-[#B7E4C7] flex items-center justify-center text-[#1B4332] font-semibold">
              {initials || <User className="h-5 w-5" />}
            </div>

            <div className="hidden sm:block text-left">
              <div className="text-sm font-semibold text-slate-800 truncate max-w-[220px]">
                {farmerName}
              </div>
              <div className="text-xs text-slate-500">Farmer</div>
            </div>

            <ChevronDown className="h-4 w-4 text-slate-600" />
          </button>

          {open && (
            <div className="absolute right-0 mt-2 w-48 bg-white border border-[#D8F3DC] rounded-2xl shadow-lg overflow-hidden">
              <button
                type="button"
                onClick={() => {
                  setOpen(false);
                  onLogout?.();
                }}
                className="w-full flex items-center gap-2 px-4 py-3 text-sm text-slate-700 hover:bg-slate-50"
              >
                <LogOut className="h-4 w-4 text-slate-700" />
                Logout
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
