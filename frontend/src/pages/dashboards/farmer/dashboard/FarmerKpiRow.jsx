// ============================================================================
// frontend/src/pages/dashboards/farmer/dashboard/FarmerKpiRow.jsx
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Compact KPI grid for FarmerDashboard.jsx.
//
// UPDATE (Option A - Step 2):
//   • Adds “Today snapshot” KPIs (orders + revenue)
//   • Adds unit-aware “Items Sold” summary
//   • Adds moderation counters (pending/rejected) and out-of-stock
//   • Keeps backward compatibility (safe defaults)
// ============================================================================

import React from "react";
import {
  Package,
  ClipboardList,
  Banknote,
  Boxes,
  Star,
  MessageSquareText,
  Trophy,
  AlertTriangle,
} from "lucide-react";

function formatMoney(value) {
  const n = Number(value || 0);
  return `N$ ${n.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
}

function StatCard({ icon: Icon, label, value, hint, loading, onClick }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`w-full text-left rounded-xl border bg-white/5 p-4 hover:bg-white/10 transition ${
        onClick ? "cursor-pointer" : "cursor-default"
      }`}
      disabled={!onClick}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="rounded-lg border bg-white/5 p-2">
            <Icon className="h-5 w-5" />
          </div>
          <div>
            <div className="text-xs text-white/60">{label}</div>
            <div className="text-xl font-semibold leading-tight">
              {loading ? "…" : value}
            </div>
          </div>
        </div>
      </div>
      {hint ? <div className="mt-2 text-xs text-white/50">{hint}</div> : null}
    </button>
  );
}

function itemsSoldSummary(itemsSoldByUnit = []) {
  if (!Array.isArray(itemsSoldByUnit) || itemsSoldByUnit.length === 0) return "—";
  const top = itemsSoldByUnit
    .slice(0, 2)
    .map((x) => `${Number(x.quantity || 0).toLocaleString()} ${x.label || "units"}`);
  return top.join(" • ");
}

export default function FarmerKpiRow({
  loading = false,
  rangeLabel = "Last 7 days",

  // Existing KPIs
  productCount = 0,
  ordersReceived = 0,
  revenuePaidTotal = 0,
  avgRating = 0,
  feedbackCount = 0,
  farmerRankLabel = "—",
  lowStockCount = 0,

  // New (Option A - Step 2)
  pendingProductsCount = 0,
  rejectedProductsCount = 0,
  outOfStockCount = 0,
  newOrdersToday = 0,
  newOrders7d = 0,
  revenueTodayPaid = 0,
  revenueMonthPaid = 0,
  itemsSoldByUnit = [],

  onLowStockClick,
}) {
  const approvalsHint =
    pendingProductsCount || rejectedProductsCount
      ? `Pending: ${pendingProductsCount} • Rejected: ${rejectedProductsCount}`
      : "Your active listings";

  const ordersHint =
    newOrdersToday || newOrders7d ? `Today: ${newOrdersToday} • 7d: ${newOrders7d}` : rangeLabel;

  const revenueHint =
    revenueTodayPaid || revenueMonthPaid
      ? `Today: ${formatMoney(revenueTodayPaid)} • Month: ${formatMoney(revenueMonthPaid)}`
      : "Paid (in range)";

  const stockHint =
    outOfStockCount ? `Out of stock: ${outOfStockCount}` : "Watch low items";

  return (
    <div className="grid grid-cols-2 md:grid-cols-4 xl:grid-cols-6 2xl:grid-cols-10 gap-3">
      <StatCard
        icon={Package}
        label="Product listings"
        value={loading ? "…" : String(productCount)}
        hint={approvalsHint}
        loading={loading}
      />

      <StatCard
        icon={ClipboardList}
        label="Orders"
        value={loading ? "…" : String(ordersReceived)}
        hint={ordersHint}
        loading={loading}
      />

      <StatCard
        icon={Banknote}
        label="Revenue (Paid)"
        value={loading ? "…" : formatMoney(revenuePaidTotal)}
        hint={revenueHint}
        loading={loading}
      />

      <StatCard
        icon={Boxes}
        label="Items sold"
        value={loading ? "…" : itemsSoldSummary(itemsSoldByUnit)}
        hint={`Unit-aware • ${rangeLabel}`}
        loading={loading}
      />

      <StatCard
        icon={Star}
        label="Avg rating"
        value={loading ? "…" : Number(avgRating || 0).toFixed(2)}
        hint={rangeLabel}
        loading={loading}
      />

      <StatCard
        icon={MessageSquareText}
        label="Feedback count"
        value={loading ? "…" : String(feedbackCount)}
        hint={rangeLabel}
        loading={loading}
      />

      <StatCard
        icon={Trophy}
        label="Farmer rank"
        value={loading ? "…" : String(farmerRankLabel || "—")}
        hint="Based on ratings"
        loading={loading}
      />

      <StatCard
        icon={AlertTriangle}
        label="Low stock"
        value={loading ? "…" : String(lowStockCount)}
        hint={stockHint}
        loading={loading}
        onClick={onLowStockClick}
      />
    </div>
  );
}
