// ============================================================================
// src/components/analytics/AdminAnalyticsCharts.jsx — Admin Analytics Charts
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Chart.js visual layer for the Admin Analytics page.
//   • Renders backend-fed summaries (defensive: never crashes on missing data)
//   • Keeps your existing chart architecture intact (Bar charts, same layout)
//   • Adds Moderation SLA trend charts (daily + monthly aggregation) using
//     summary.sla.daily_snapshot (optional) without breaking other charts.
//
// EXPECTED BACKEND PAYLOAD (defensive):
//   summary = {
//     orders_by_status: { pending: 10, delivered: 5, ... },   // snake_case (backend)
//     ordersByStatus:   { pending: 10, delivered: 5, ... },   // camelCase (legacy)
//     topProducts / top_products: [{ name, product_id, orders }, ...], optional
//     sla: {
//       target_hours: 48,
//       summary: { sla_percent, avg_review_hours, total_reviewed, breached_count },
//       daily_snapshot: [
//         { date: "2026-01-01", sla_percent: 92.4, reviewed_count: 21, breached_count: 2, avg_review_hours: 18.2 },
//         ...
//       ]
//     }
//   }
//
// NOTES:
//   • This file supports both snake_case and camelCase keys to avoid silent breakage.
//   • If SLA snapshot data is missing, SLA charts simply won't render.
// ============================================================================

import React, { useMemo } from "react";
import PropTypes from "prop-types";
import { Bar } from "react-chartjs-2";

import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  Tooltip,
  Legend,
} from "chart.js";

ChartJS.register(CategoryScale, LinearScale, BarElement, Tooltip, Legend);

// ----------------------------
// Helpers (small + defensive)
// ----------------------------
function num(v) {
  const n = Number(v);
  return Number.isFinite(n) ? n : 0;
}

function pick(obj, ...keys) {
  for (const k of keys) {
    if (obj && obj[k] !== undefined && obj[k] !== null) return obj[k];
  }
  return undefined;
}

function toISODate(d) {
  // Accepts Date, string, or anything; returns a YYYY-MM-DD-ish string
  if (!d) return "";
  if (typeof d === "string") return d.slice(0, 10);
  try {
    return new Date(d).toISOString().slice(0, 10);
  } catch {
    return String(d);
  }
}

function monthKey(isoDateStr) {
  // "2026-01-15" -> "2026-01"
  if (!isoDateStr || typeof isoDateStr !== "string") return "";
  return isoDateStr.slice(0, 7);
}

export default function AdminAnalyticsCharts({ summary }) {
  // --------------------------------------------------------------------------
  // Orders by Status
  // --------------------------------------------------------------------------
  const statusData = useMemo(() => {
    // Support both legacy camelCase + new snake_case
    const s =
      pick(summary, "ordersByStatus", "orders_by_status", "orders_by_status_window") ||
      {};

    const labels = ["pending", "confirmed", "in_transit", "delivered", "rejected"];
    const values = labels.map((k) => num(s[k]));

    return {
      labels,
      datasets: [{ label: "Orders", data: values }],
    };
  }, [summary]);

  // --------------------------------------------------------------------------
  // Top Products (by orders) — optional (safe fallback)
  // --------------------------------------------------------------------------
  const topProductsData = useMemo(() => {
    const rows =
      pick(summary, "topProducts", "top_products") && Array.isArray(pick(summary, "topProducts", "top_products"))
        ? pick(summary, "topProducts", "top_products")
        : [];

    return {
      labels: rows.map((r) => r?.name || `#${r?.product_id || "—"}`),
      datasets: [{ label: "Orders", data: rows.map((r) => num(r?.orders)) }],
    };
  }, [summary]);

  // --------------------------------------------------------------------------
  // SLA (daily snapshot) — optional (safe fallback)
  // --------------------------------------------------------------------------
  const slaDaily = useMemo(() => {
    const daily = summary?.sla?.daily_snapshot;
    if (!Array.isArray(daily) || daily.length === 0) return [];

    // Normalize + sort by date asc
    return daily
      .map((r) => ({
        date: toISODate(r?.date),
        sla_percent: Number(r?.sla_percent),
        reviewed_count: num(r?.reviewed_count),
      }))
      .filter((r) => r.date)
      .sort((a, b) => (a.date > b.date ? 1 : -1));
  }, [summary]);

  // Monthly aggregation from daily snapshot:
  // - SLA% weighted by reviewed_count (audit-friendly)
  const slaMonthly = useMemo(() => {
    if (!slaDaily.length) return [];

    const buckets = new Map(); // month -> { reviewed, withinApprox, sumWeightedPercent }
    for (const r of slaDaily) {
      const m = monthKey(r.date);
      if (!m) continue;

      const reviewed = num(r.reviewed_count);
      const pct = Number.isFinite(Number(r.sla_percent)) ? Number(r.sla_percent) : 0;

      const prev = buckets.get(m) || { reviewed: 0, weightedPctSum: 0 };
      prev.reviewed += reviewed;

      // weighted average of percent by volume
      prev.weightedPctSum += pct * reviewed;
      buckets.set(m, prev);
    }

    const out = Array.from(buckets.entries())
      .map(([month, v]) => ({
        month,
        reviewed: v.reviewed,
        sla_percent: v.reviewed > 0 ? v.weightedPctSum / v.reviewed : 0,
      }))
      .sort((a, b) => (a.month > b.month ? 1 : -1));

    return out;
  }, [slaDaily]);

  // --------------------------------------------------------------------------
  // Chart.js options (keep neutral & consistent)
  // --------------------------------------------------------------------------
  const options = useMemo(
    () => ({
      responsive: true,
      plugins: { legend: { display: true } },
    }),
    []
  );

  const slaDailyChart = useMemo(() => {
    if (!slaDaily.length) return null;
    return {
      labels: slaDaily.map((r) => r.date),
      datasets: [
        {
          label: "SLA% (daily)",
          data: slaDaily.map((r) =>
            Number.isFinite(Number(r.sla_percent)) ? Number(r.sla_percent) : 0
          ),
        },
      ],
    };
  }, [slaDaily]);

  const slaMonthlyChart = useMemo(() => {
    if (!slaMonthly.length) return null;
    return {
      labels: slaMonthly.map((r) => r.month),
      datasets: [
        {
          label: "SLA% (monthly)",
          data: slaMonthly.map((r) => Number(r.sla_percent || 0)),
        },
      ],
    };
  }, [slaMonthly]);

  // --------------------------------------------------------------------------
  // Render
  // --------------------------------------------------------------------------
  const topProductsRows = pick(summary, "topProducts", "top_products");
  const hasTopProducts = Array.isArray(topProductsRows) && topProductsRows.length > 0;

  const hasSla = Boolean(summary?.sla);
  const hasSlaDaily = Boolean(slaDailyChart);
  const hasSlaMonthly = Boolean(slaMonthlyChart);

  return (
    <div className="space-y-6">
      {/* Orders by Status */}
      <div className="glass-card p-6 rounded-2xl">
        <h3 className="font-semibold mb-3">Orders by Status</h3>
        <Bar data={statusData} options={options} />
      </div>

      {/* Top Products (by Orders) */}
      <div className="glass-card p-6 rounded-2xl">
        <h3 className="font-semibold mb-3">Top Products (by Orders)</h3>
        {hasTopProducts ? (
          <Bar data={topProductsData} options={options} />
        ) : (
          <div className="text-white/70">No top-products data yet.</div>
        )}
      </div>

      {/* Moderation SLA charts (optional) */}
      {hasSla ? (
        <>
          {hasSlaMonthly ? (
            <div className="glass-card p-6 rounded-2xl">
              <h3 className="font-semibold mb-3">Moderation SLA% (Monthly)</h3>
              <Bar data={slaMonthlyChart} options={options} />
              <div className="text-xs text-white/60 mt-2">
                Weighted by reviewed volume for audit-grade reporting.
              </div>
            </div>
          ) : null}

          {hasSlaDaily ? (
            <div className="glass-card p-6 rounded-2xl">
              <h3 className="font-semibold mb-3">Moderation SLA% (Daily)</h3>
              <Bar data={slaDailyChart} options={options} />
              <div className="text-xs text-white/60 mt-2">
                Uses backend SLA daily snapshot series (or computed series if you chose that design).
              </div>
            </div>
          ) : null}

          {!hasSlaDaily && !hasSlaMonthly ? (
            <div className="glass-card p-6 rounded-2xl">
              <h3 className="font-semibold mb-2">Moderation SLA</h3>
              <div className="text-white/70">
                SLA data is available, but no snapshot series was returned yet.
              </div>
            </div>
          ) : null}
        </>
      ) : null}
    </div>
  );
}

AdminAnalyticsCharts.propTypes = {
  summary: PropTypes.shape({
    // Support both legacy camelCase and new snake_case fields defensively
    ordersByStatus: PropTypes.object,
    orders_by_status: PropTypes.object,
    orders_by_status_window: PropTypes.object,

    topProducts: PropTypes.array,
    top_products: PropTypes.array,

    sla: PropTypes.shape({
      target_hours: PropTypes.number,
      summary: PropTypes.object,
      leaderboard: PropTypes.array,
      daily_snapshot: PropTypes.array,
    }),
  }),
};
