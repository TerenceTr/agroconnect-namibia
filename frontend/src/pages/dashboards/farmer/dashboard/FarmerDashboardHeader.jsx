// ============================================================================
// frontend/src/pages/dashboards/farmer/dashboard/FarmerDashboardHeader.jsx
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Farmer dashboard “hero” header (interactive controls + pipeline filters).
//
// RESPONSIBILITIES:
//   • Display title + welcome text
//   • Provide Search, Range, Moving Avg controls
//   • Provide clickable “Order Status” and “Payment” filter pills
//   • Provide primary actions (Refresh, Manage Products, Add Product, Logout)
// ============================================================================

import React from "react";
import { Link } from "react-router-dom";
import { ArrowRight, LogOut, Package, Plus, RefreshCw, Search } from "lucide-react";

function Pill({ active, onClick, children, tone = "emerald" }) {
  const activeCls =
    tone === "emerald"
      ? "bg-emerald-600 text-white border-emerald-600"
      : "bg-slate-900 text-white border-slate-900";

  const idleCls = "bg-white text-slate-700 border-slate-200 hover:bg-slate-50";

  return (
    <button
      type="button"
      onClick={onClick}
      className={[
        "px-3 py-1.5 rounded-full text-xs font-semibold border transition",
        active ? activeCls : idleCls,
      ].join(" ")}
    >
      {children}
    </button>
  );
}

export default function FarmerDashboardHeader({
  user,
  days,
  setDays,
  timeWindows,
  maWindow,
  setMaWindow,
  query,
  setQuery,
  pipeline,
  statusFocus,
  setStatusFocus,
  paymentFocus,
  setPaymentFocus,
  onRefresh,
  onAddProduct,
  onLogout,
}) {
  const p = pipeline || {
    total: 0,
    counts: { pending: 0, in_progress: 0, delivered: 0, cancelled: 0 },
    pays: { paid: 0, unpaid: 0, unknown: 0 },
  };

  return (
    <div className="rounded-3xl border border-slate-200 bg-gradient-to-r from-emerald-50 via-white to-white shadow-sm overflow-hidden">
      <div className="p-5 md:p-6 flex flex-col gap-4">
        {/* Top row */}
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <div className="h-10 w-10 rounded-2xl bg-emerald-600 text-white flex items-center justify-center shadow-sm">
              <Package size={18} />
            </div>
            <div>
              <h1 className="text-xl md:text-2xl font-semibold text-slate-900">Farmer Dashboard</h1>
              <p className="text-sm text-slate-600 mt-0.5">
                Welcome back{user?.full_name ? `, ${user.full_name}` : ""}. Showing last <b>{days}</b> days.
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={onRefresh}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-white text-slate-800 border border-slate-200 hover:bg-slate-50"
            >
              <RefreshCw size={16} />
              Refresh
            </button>

            <Link
              to="/dashboard/farmer/products"
              className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-white text-slate-800 border border-slate-200 hover:bg-slate-50"
            >
              Manage Products <ArrowRight size={16} />
            </Link>

            <button
              type="button"
              onClick={onAddProduct}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-emerald-600 text-white font-semibold hover:bg-emerald-700"
            >
              <Plus size={16} />
              Add Product
            </button>

            <button
              type="button"
              onClick={onLogout}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-white text-slate-800 border border-slate-200 hover:bg-slate-50"
            >
              <LogOut size={16} />
              Logout
            </button>
          </div>
        </div>

        {/* Controls */}
        <div className="flex flex-col lg:flex-row lg:items-center gap-3 lg:gap-4">
          <div className="flex-1">
            <div className="flex items-center gap-2 bg-white rounded-2xl border border-slate-200 px-3 py-2 shadow-sm">
              <Search size={18} className="text-slate-400" />
              <input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Search products, orders, customers, feedback…"
                className="w-full outline-none text-sm text-slate-700"
              />
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <span className="text-sm text-slate-600">Range:</span>
            <select
              value={days}
              onChange={(e) => setDays(Number(e.target.value))}
              className="bg-white border border-slate-200 text-slate-800 rounded-xl px-3 py-2 text-sm shadow-sm outline-none"
            >
              {timeWindows.map((w) => (
                <option key={w.value} value={w.value}>
                  {w.label}
                </option>
              ))}
            </select>

            <span className="text-sm text-slate-600 ml-2">Moving avg:</span>
            <select
              value={maWindow}
              onChange={(e) => setMaWindow(Number(e.target.value))}
              className="bg-white border border-slate-200 text-slate-800 rounded-xl px-3 py-2 text-sm shadow-sm outline-none"
            >
              {[2, 3, 5].map((n) => (
                <option key={n} value={n}>
                  {n} points
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* Filter pills */}
        <div className="flex flex-col xl:flex-row xl:items-center xl:justify-between gap-3">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs font-semibold text-slate-600 mr-1">Order status:</span>

            <Pill active={statusFocus === "all"} onClick={() => setStatusFocus("all")}>
              All ({p.total})
            </Pill>
            <Pill active={statusFocus === "pending"} onClick={() => setStatusFocus("pending")}>
              Pending ({p.counts.pending})
            </Pill>
            <Pill active={statusFocus === "in_progress"} onClick={() => setStatusFocus("in_progress")}>
              In progress ({p.counts.in_progress})
            </Pill>
            <Pill active={statusFocus === "delivered"} onClick={() => setStatusFocus("delivered")}>
              Delivered ({p.counts.delivered})
            </Pill>
            <Pill active={statusFocus === "cancelled"} onClick={() => setStatusFocus("cancelled")}>
              Cancelled ({p.counts.cancelled})
            </Pill>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs font-semibold text-slate-600 mr-1">Payment:</span>

            <Pill tone="slate" active={paymentFocus === "all"} onClick={() => setPaymentFocus("all")}>
              All
            </Pill>
            <Pill tone="slate" active={paymentFocus === "paid"} onClick={() => setPaymentFocus("paid")}>
              Paid ({p.pays.paid})
            </Pill>
            <Pill tone="slate" active={paymentFocus === "unpaid"} onClick={() => setPaymentFocus("unpaid")}>
              Unpaid ({p.pays.unpaid})
            </Pill>
            <Pill tone="slate" active={paymentFocus === "unknown"} onClick={() => setPaymentFocus("unknown")}>
              Unknown ({p.pays.unknown})
            </Pill>
          </div>
        </div>
      </div>
    </div>
  );
}
