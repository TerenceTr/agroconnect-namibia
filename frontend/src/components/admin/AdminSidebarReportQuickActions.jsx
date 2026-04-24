// ============================================================================
// frontend/src/components/admin/AdminSidebarReportQuickActions.jsx
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Small reusable sidebar card for quick admin report actions.
//
// PURPOSE:
//   Lets the admin jump directly into the new report workflow from the sidebar.
//
// THIS UPDATE:
//   ✅ Sends the admin to /dashboard/admin/reports?builder=1
//   ✅ Allows the reports page to auto-open the Report Builder drawer
// ============================================================================

import React from "react";
import { Link, useLocation } from "react-router-dom";
import {
  FileText,
  Wand2,
  ShieldCheck,
  Search,
  Clock3,
  ChevronRight,
} from "lucide-react";

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------
function cx(...parts) {
  return parts.filter(Boolean).join(" ");
}

function isReportsRoute(pathname) {
  return typeof pathname === "string" && pathname.startsWith("/dashboard/admin/reports");
}

// ----------------------------------------------------------------------------
// Component
// ----------------------------------------------------------------------------
export default function AdminSidebarReportQuickActions({ collapsed = false }) {
  const location = useLocation();
  const active = isReportsRoute(location.pathname);

  const cardClass = cx(
    "rounded-2xl border shadow-sm transition",
    active
      ? "border-emerald-300 bg-emerald-50"
      : "border-emerald-100 bg-white hover:border-emerald-200 hover:bg-emerald-50/50"
  );

  if (collapsed) {
    return (
      <div className="mt-3">
        <Link
          to="/dashboard/admin/reports?builder=1"
          title="Open Report Builder"
          className={cx(
            "group flex items-center justify-center rounded-2xl border p-3 shadow-sm transition",
            active
              ? "border-emerald-300 bg-emerald-50 text-emerald-800"
              : "border-emerald-100 bg-white text-slate-700 hover:border-emerald-200 hover:bg-emerald-50 hover:text-emerald-800"
          )}
        >
          <FileText className="h-5 w-5" />
        </Link>
      </div>
    );
  }

  return (
    <div className="mt-4">
      <div className={cardClass}>
        <div className="border-b border-emerald-100 px-4 py-3">
          <div className="flex items-center gap-2">
            <div className="rounded-xl border border-emerald-200 bg-white p-2 text-emerald-700 shadow-sm">
              <FileText className="h-4 w-4" />
            </div>
            <div className="min-w-0">
              <div className="text-sm font-black text-slate-900">Reports</div>
              <div className="text-xs font-semibold text-slate-500">
                Standard & ad hoc exports
              </div>
            </div>
          </div>
        </div>

        <div className="space-y-2 px-3 py-3">
          <Link
            to="/dashboard/admin/reports?builder=1"
            className={cx(
              "flex items-center justify-between rounded-xl px-3 py-2 text-sm font-bold transition",
              active
                ? "bg-emerald-100 text-emerald-900"
                : "text-slate-700 hover:bg-emerald-50 hover:text-emerald-900"
            )}
          >
            <span className="flex items-center gap-2">
              <Wand2 className="h-4 w-4" />
              Open Report Builder
            </span>
            <ChevronRight className="h-4 w-4" />
          </Link>

          <div className="grid grid-cols-1 gap-2">
            <div className="flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-xs font-semibold text-slate-600">
              <ShieldCheck className="h-3.5 w-3.5 text-emerald-700" />
              Auth, audit, governance
            </div>

            <div className="flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-xs font-semibold text-slate-600">
              <Search className="h-3.5 w-3.5 text-emerald-700" />
              Search statistics
            </div>

            <div className="flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-xs font-semibold text-slate-600">
              <Clock3 className="h-3.5 w-3.5 text-emerald-700" />
              Moderation SLA exports
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}