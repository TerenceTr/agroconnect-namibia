// ============================================================================
// frontend/src/components/ui/DataCard.jsx — AgroConnect Namibia
// ============================================================================
// FILE ROLE:
//   KPI tile used on dashboards (Products, Orders, Revenue, Alerts, etc).
//
// DESIGN:
//   • White surface, subtle border/shadow
//   • Left icon pill
//   • Optional small “meta” line (trend / comparison)
// ============================================================================

import React from "react";
import clsx from "clsx";

export function DataCard({
  title,
  value,
  icon,
  meta,
  metaTone = "muted", // muted | good | warn | bad
  className = "",
}) {
  const tone = {
    muted: "text-slate-500",
    good: "text-emerald-600",
    warn: "text-amber-600",
    bad: "text-rose-600",
  }[metaTone];

  return (
    <div
      className={clsx(
        "rounded-2xl bg-white border border-slate-200/70 shadow-sm px-5 py-4 flex items-center gap-4",
        className
      )}
    >
      {icon ? (
        <div className="h-11 w-11 rounded-xl bg-emerald-50 text-emerald-700 flex items-center justify-center">
          {icon}
        </div>
      ) : (
        <div className="h-11 w-11 rounded-xl bg-slate-100" />
      )}

      <div className="min-w-0 flex-1">
        <p className="text-xs font-medium text-slate-500">{title}</p>
        <div className="mt-1 text-xl font-semibold text-slate-900 truncate">{value}</div>

        {meta ? (
          <p className={clsx("mt-1 text-xs", tone)}>{meta}</p>
        ) : null}
      </div>
    </div>
  );
}

export default DataCard;
