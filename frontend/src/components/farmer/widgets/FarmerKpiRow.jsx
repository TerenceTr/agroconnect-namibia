// ============================================================================
// src/components/farmer/widgets/FarmerKpiRow.jsx — Farmer KPI Row (SPEC)
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Renders the EXACT KPI set for Farmer Overview dashboard.
//
// KPIs (REQUIRED by your instructions):
//   • Product Listings (count)
//   • Orders Received (range) (count)
//   • Revenue Total (Paid only) (sum of paid orders in range)
//   • Average Rating (range) (avg rating score)
//   • Feedback Count (range) (count of ratings/comments)
//   • Farmer Rank (rank position + score OR "—" if not available)
//   • (Optional) Low Stock (count ≤ threshold)
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

function StatCard({ icon: Icon, label, value, hint }) {
  return (
    <div className="rounded-2xl bg-white border border-slate-200 shadow-sm p-4">
      <div className="flex items-center gap-3">
        <div className="h-10 w-10 rounded-2xl bg-emerald-50 border border-emerald-100 grid place-items-center">
          <Icon className="h-5 w-5 text-emerald-700" />
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

  // Range label shown on tiles (7/30/90)
  rangeLabel = "Last 7 days",

  // Required metrics
  productCount = 0,
  ordersReceived = 0,
  revenuePaidTotal = 0,
  avgRating = 0,
  feedbackCount = 0,
  farmerRankLabel = "—",

  // Optional metric
  lowStockCount = null,

  currencyPrefix = "N$ ",
}) {
  const v = (x) => (loading ? "…" : x);

  const ratingText = loading ? "…" : `${Number(avgRating || 0).toFixed(1)} / 5`;
  const revenueText = loading
    ? "…"
    : `${currencyPrefix}${Number(revenuePaidTotal || 0).toFixed(2)}`;

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-6 gap-4">
      <StatCard
        icon={Package}
        label="Product Listings"
        value={v(productCount)}
        hint="Your active listings"
      />
      <StatCard
        icon={ClipboardList}
        label={`Orders Received (${rangeLabel})`}
        value={v(ordersReceived)}
        hint="Sales orders in range"
      />
      <StatCard
        icon={Banknote}
        label="Revenue Total (Paid only)"
        value={revenueText}
        hint={`Paid orders • ${rangeLabel}`}
      />
      <StatCard
        icon={Star}
        label={`Average Rating (${rangeLabel})`}
        value={ratingText}
        hint="Quality score"
      />
      <StatCard
        icon={MessageSquareText}
        label={`Feedback Count (${rangeLabel})`}
        value={v(feedbackCount)}
        hint="Ratings + comments"
      />
      <StatCard
        icon={Trophy}
        label="Farmer Rank"
        value={v(farmerRankLabel)}
        hint="Rank + score if available"
      />

      {lowStockCount !== null ? (
        <div className="sm:col-span-2 xl:col-span-6">
          <div className="rounded-2xl bg-white border border-slate-200 shadow-sm p-4 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="h-10 w-10 rounded-2xl bg-amber-50 border border-amber-100 grid place-items-center">
                <AlertTriangle className="h-5 w-5 text-amber-700" />
              </div>
              <div>
                <div className="text-xs text-slate-500 font-semibold">Low Stock (optional)</div>
                <div className="text-lg font-extrabold text-slate-900">{v(lowStockCount)}</div>
              </div>
            </div>
            <div className="text-sm text-slate-500">Products at/under threshold</div>
          </div>
        </div>
      ) : null}
    </div>
  );
}
