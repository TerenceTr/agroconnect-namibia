// ============================================================================
// src/pages/dashboards/farmer/dashboard/FarmerKpiRow.jsx — Farmer KPI Row (SPEC)
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Renders the EXACT KPI set for the Farmer Overview dashboard.
//
// KPIs (REQUIRED):
//   • Product Listings (count)
//   • Orders Received (range) (count)
//   • Revenue Total (Paid only) (sum paid orders in range)
//   • Average Rating (range)
//   • Feedback Count (range)
//   • Farmer Rank (rank + score OR "—")
//   • (Optional) Low Stock (count <= threshold)
//
// DESIGN:
//   • White cards, neutral background, emerald accent only.
// ============================================================================

import React from "react";
import {
  Package,
  ClipboardList,
  Banknote,
  Star,
  MessageSquareText,
  Trophy,
  AlertTriangle,
} from "lucide-react";

function StatCard({ icon: Icon, label, value, hint, tone = "emerald" }) {
  const toneBox =
    tone === "amber"
      ? "bg-amber-50 border-amber-100"
      : "bg-emerald-50 border-emerald-100";

  const toneIcon = tone === "amber" ? "text-amber-700" : "text-emerald-700";

  return (
    <div className="rounded-2xl bg-white border border-slate-200 shadow-sm p-4">
      <div className="flex items-center gap-3">
        <div className={["h-10 w-10 rounded-2xl border grid place-items-center", toneBox].join(" ")}>
          <Icon className={["h-5 w-5", toneIcon].join(" ")} />
        </div>
        <div className="min-w-0">
          <div className="text-xs text-slate-500 font-semibold">{label}</div>
          <div className="text-xl font-extrabold text-slate-900 truncate">{value}</div>
          {hint ? <div className="text-xs text-slate-500 mt-0.5">{hint}</div> : null}
        </div>
      </div>
    </div>
  );
}

export default function FarmerKpiRow({
  loading = false,
  rangeLabel = "Last 7 days",
  productCount = 0,
  ordersReceived = 0,
  revenuePaidTotal = 0,
  avgRating = 0,
  feedbackCount = 0,
  farmerRankLabel = "—",
  lowStockCount = null, // optional
  currencyPrefix = "N$ ",
}) {
  const v = (x) => (loading ? "…" : x);

  const ratingText = loading ? "…" : `${Number(avgRating || 0).toFixed(1)} / 5`;
  const revenueText =
    loading ? "…" : `${currencyPrefix}${Number(revenuePaidTotal || 0).toFixed(2)}`;

  return (
    <div className={["grid gap-4", lowStockCount !== null ? "grid-cols-1 sm:grid-cols-2 xl:grid-cols-7" : "grid-cols-1 sm:grid-cols-2 xl:grid-cols-6"].join(" ")}>
      <StatCard icon={Package} label="Product Listings" value={v(productCount)} hint="Your active listings" />
      <StatCard icon={ClipboardList} label={`Orders Received (${rangeLabel})`} value={v(ordersReceived)} hint="Sales orders in range" />
      <StatCard icon={Banknote} label="Revenue Total (Paid only)" value={revenueText} hint={`Paid orders • ${rangeLabel}`} />
      <StatCard icon={Star} label={`Average Rating (${rangeLabel})`} value={ratingText} hint="Quality score" />
      <StatCard icon={MessageSquareText} label={`Feedback Count (${rangeLabel})`} value={v(feedbackCount)} hint="Ratings + comments" />
      <StatCard icon={Trophy} label="Farmer Rank" value={v(farmerRankLabel)} hint="Rank + score if available" />

      {lowStockCount !== null ? (
        <StatCard
          icon={AlertTriangle}
          label="Low Stock"
          value={v(lowStockCount)}
          hint="At/under threshold"
          tone="amber"
        />
      ) : null}
    </div>
  );
}
