// ============================================================================
// frontend/src/pages/dashboards/admin/AdminAnalyticsPage.jsx
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Executive analytics and operational intelligence page for admins.
//
// DESIGN GOALS IN THIS UPDATE:
//   ✅ Uses doughnut charts for executive operational distributions
//   ✅ Keeps the analytics page clean, professional, and decision-oriented
//   ✅ Shows live and recent presence with real-time last-seen updates
//   ✅ Makes the notification watchlist useful when direct admin alerts are sparse
//   ✅ Handles sparse / partial backend payloads gracefully
// ============================================================================

import React, { useEffect, useMemo, useState } from "react";
import { Doughnut, Line } from "react-chartjs-2";
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  ArcElement,
  Tooltip,
  Legend,
  Filler,
} from "chart.js";
import {
  RefreshCw,
  ClipboardList,
  Users,
  Clock3,
  AlertTriangle,
  Activity,
} from "lucide-react";

import AdminLayout from "../../../components/AdminLayout";
import Card from "../../../components/ui/Card";
import EmptyState from "../../../components/ui/EmptyState";
import useApi from "../../../hooks/useApi";

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, ArcElement, Tooltip, Legend, Filler);

const ENDPOINTS = ["/admin/analytics/summary", "/admin/analytics", "/admin/reports/overview"];

const ORDER_STATUS_COLORS = {
  pending: "#f97316",
  completed: "#6b7280",
  delivered: "#111827",
};

const PRODUCT_STATUS_COLORS = {
  pending: "#f97316",
  available: "#10b981",
  rejected: "#ef4444",
};

// -----------------------------------------------------------------------------
// Safety helpers
// -----------------------------------------------------------------------------
function safeObj(v) {
  return v && typeof v === "object" ? v : {};
}

function safeArray(v) {
  return Array.isArray(v) ? v : [];
}

function safeNumber(v, fallback = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

function safeStr(v, fallback = "") {
  if (typeof v === "string") return v;
  if (v == null) return fallback;
  return String(v);
}

function toPct(v) {
  const n = safeNumber(v, 0);
  if (n <= 1 && n > 0) return n * 100;
  return n;
}

function fmtNAD(v) {
  const n = safeNumber(v, 0);
  try {
    return new Intl.NumberFormat(undefined, {
      style: "currency",
      currency: "NAD",
      maximumFractionDigits: 2,
    }).format(n);
  } catch {
    return `N$ ${n.toFixed(2)}`;
  }
}

function fmtDateTime(v) {
  try {
    if (!v) return "—";
    const d = new Date(v);
    if (Number.isNaN(d.getTime())) return "—";
    return d.toLocaleString();
  } catch {
    return "—";
  }
}

function parseIsoToEpochMs(value) {
  const raw = safeStr(value, "").trim();
  if (!raw) return null;
  const normalized = /(?:Z|[+-]\d{2}:\d{2})$/i.test(raw) ? raw : `${raw}Z`;
  const ms = Date.parse(normalized);
  return Number.isFinite(ms) ? ms : null;
}

function fmtRelativeFromEpoch(targetMs, nowMs = Date.now()) {
  const target = safeNumber(targetMs, 0);
  const now = safeNumber(nowMs, Date.now());
  if (!target) return "";

  const diffMins = Math.max(0, Math.round((now - target) / 60000));

  if (diffMins < 1) return "Just now";
  if (diffMins < 60) return `${diffMins} min ago`;

  const diffHours = Math.round(diffMins / 60);
  if (diffHours < 24) return `${diffHours}h ago`;

  const diffDays = Math.round(diffHours / 24);
  return `${diffDays}d ago`;
}

function titleCaseWords(v) {
  return safeStr(v)
    .replace(/[_-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/\b\w/g, (m) => m.toUpperCase());
}

function normalizeCountMap(input, preferredOrder = []) {
  const out = new Map();

  if (Array.isArray(input)) {
    input.forEach((x) => {
      const o = safeObj(x);
      const k = safeStr(o.status || o.label || o.name || "").toLowerCase();
      const v = safeNumber(o.count ?? o.value ?? o.total ?? 0);
      if (k) out.set(k, v);
    });
  } else if (input && typeof input === "object") {
    Object.entries(input).forEach(([k, v]) => out.set(safeStr(k).toLowerCase(), safeNumber(v, 0)));
  }

  const keys = [];
  preferredOrder.forEach((k) => out.has(k) && keys.push(k));
  [...out.keys()].forEach((k) => !keys.includes(k) && keys.push(k));

  return {
    labels: keys,
    values: keys.map((k) => safeNumber(out.get(k), 0)),
    total: keys.reduce((sum, k) => sum + safeNumber(out.get(k), 0), 0),
  };
}

function normalizeOrderDistribution(input) {
  const src = normalizeCountMap(input, ["pending", "completed", "delivered"]);
  if (src.labels.length > 0) return src;

  // Frontend fallback when only raw order statuses are available.
  const raw = normalizeCountMap(input, ["pending", "completed", "delivered", "cancelled"]);
  const pending = safeNumber(raw.values[raw.labels.indexOf("pending")], 0) + safeNumber(raw.values[raw.labels.indexOf("cancelled")], 0);
  const completed = safeNumber(raw.values[raw.labels.indexOf("completed")], 0);
  const delivered = safeNumber(raw.values[raw.labels.indexOf("delivered")], 0);

  return {
    labels: ["pending", "completed", "delivered"],
    values: [pending, completed, delivered],
    total: pending + completed + delivered,
  };
}

function normalizeProductDistribution(input) {
  const src = normalizeCountMap(input, ["pending", "available", "rejected"]);
  if (src.labels.length > 0) return src;

  // Frontend fallback when only raw listing states are available.
  const raw = normalizeCountMap(input, ["pending", "available", "approved", "active", "published", "rejected", "unavailable"]);
  const pending =
    safeNumber(raw.values[raw.labels.indexOf("pending")], 0) +
    safeNumber(raw.values[raw.labels.indexOf("unavailable")], 0);
  const available =
    safeNumber(raw.values[raw.labels.indexOf("available")], 0) +
    safeNumber(raw.values[raw.labels.indexOf("approved")], 0) +
    safeNumber(raw.values[raw.labels.indexOf("active")], 0) +
    safeNumber(raw.values[raw.labels.indexOf("published")], 0);
  const rejected = safeNumber(raw.values[raw.labels.indexOf("rejected")], 0);

  return {
    labels: ["pending", "available", "rejected"],
    values: [pending, available, rejected],
    total: pending + available + rejected,
  };
}

function normalizeAnalytics(raw) {
  const d = safeObj(raw);
  const root = d.data && typeof d.data === "object" ? d.data : d;

  const ordersByStatus =
    root.orders_status_distribution ||
    root.ordersStatusDistribution ||
    root.orders_operational_distribution ||
    root.ordersOperationalDistribution ||
    root.orders_by_status ||
    root.ordersByStatus ||
    safeObj(root.orders)?.by_status ||
    safeObj(root.orders)?.byStatus ||
    {};

  const productsByStatus =
    root.products_status_distribution ||
    root.productsStatusDistribution ||
    root.products_governance_distribution ||
    root.productsGovernanceDistribution ||
    root.products_by_status ||
    root.productsByStatus ||
    safeObj(root.products)?.by_status ||
    safeObj(root.products)?.byStatus ||
    {};

  const topProducts = safeArray(root.top_products || root.topProducts || []);
  const recentProducts = safeArray(root.recent_products || root.recentProducts || []);
  const demandPredictions = safeArray(root.demand_predictions || root.demandPredictions || []);
  const notifications = safeObj(root.notifications || {});
  const presence = safeObj(root.presence || {});

  const sla = safeObj(root.sla || {});
  const summary = safeObj(sla.summary || root.sla_summary || {});
  const leaderboard = safeArray(sla.leaderboard || root.sla_leaderboard || []);
  const daily = safeArray(sla.daily_snapshot || sla.daily || root.sla_daily || []);
  const monthly = safeArray(sla.monthly || sla.monthly_snapshot || root.sla_monthly || []);

  return {
    windowDays: safeNumber(root.window_days, 30),
    ordersByStatus,
    productsByStatus,
    avgRating: safeNumber(root.avg_rating, 0),
    ratingsTrend: safeArray(root.ratings_trend || []),
    topProducts,
    recentProducts,
    demandPredictions,
    notifications: {
      unreadCount: safeNumber(notifications.unread_count, 0),
      items: safeArray(notifications.items || []),
    },
    presence: {
      windowMinutes: safeNumber(presence.window_minutes, 10),
      serverNowEpochMs:
        safeNumber(presence.server_now_epoch_ms, 0) ||
        parseIsoToEpochMs(presence.server_now_utc) ||
        Date.now(),
      farmersCount: safeNumber(presence.farmers_count, 0),
      customersCount: safeNumber(presence.customers_count, 0),
      farmersOnline: safeArray(presence.farmers_online || []),
      customersOnline: safeArray(presence.customers_online || []),
      farmersRecent: safeArray(presence.farmers_recent || []),
      customersRecent: safeArray(presence.customers_recent || []),
    },
    sla: {
      targetHours: safeNumber(sla.target_hours || sla.targetHours, 48),
      windowDays: safeNumber(sla.window_days || sla.windowDays || root.window_days, 30),
      summary: {
        reviewed: safeNumber(summary.reviewed, 0),
        breached: safeNumber(summary.breached, 0),
        avgHours: safeNumber(summary.avg_hours ?? summary.avgHours, 0),
        slaPct: toPct(summary.sla_pct ?? summary.slaPct ?? 0),
      },
      daily,
      monthly,
      leaderboard,
    },
  };
}

// -----------------------------------------------------------------------------
// UI bits
// -----------------------------------------------------------------------------
function TonePill({ tone = "neutral", children }) {
  const cls =
    tone === "success"
      ? "border-emerald-200 bg-emerald-50 text-emerald-700"
      : tone === "warn"
        ? "border-amber-200 bg-amber-50 text-amber-800"
        : tone === "danger"
          ? "border-rose-200 bg-rose-50 text-rose-700"
          : "border-slate-200 bg-slate-50 text-slate-700";

  return (
    <span className={`inline-flex items-center gap-2 rounded-full border px-3 py-1.5 text-xs font-bold ${cls}`}>
      {children}
    </span>
  );
}

function KpiCard({ icon, label, value, sub }) {
  return (
    <Card className="border border-slate-200 bg-white p-5">
      <div className="flex items-start gap-4">
        <div className="grid h-11 w-11 place-items-center rounded-2xl border border-emerald-100 bg-emerald-50 text-emerald-700 shadow-sm">
          {icon}
        </div>
        <div className="min-w-0">
          <div className="text-[11px] font-bold uppercase tracking-wide text-slate-500">{label}</div>
          <div className="mt-1 text-2xl font-extrabold tracking-tight text-slate-900">{value}</div>
          {sub ? <div className="mt-1 text-xs font-semibold text-slate-500">{sub}</div> : null}
        </div>
      </div>
    </Card>
  );
}

function SectionCard({ title, subtitle, right, children }) {
  return (
    <Card className="border border-slate-200 bg-white p-5">
      <div className="mb-4 flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="text-sm font-extrabold text-slate-900">{title}</div>
          {subtitle ? <div className="mt-0.5 text-xs font-semibold text-slate-500">{subtitle}</div> : null}
        </div>
        {right ? <div className="shrink-0">{right}</div> : null}
      </div>
      {children}
    </Card>
  );
}

function MiniMetric({ label, value, tone = "slate" }) {
  const toneClass =
    tone === "emerald"
      ? "border-emerald-200 bg-emerald-50 text-emerald-700"
      : tone === "amber"
        ? "border-amber-200 bg-amber-50 text-amber-700"
        : "border-slate-200 bg-slate-50 text-slate-700";

  return (
    <div className={`rounded-2xl border p-4 ${toneClass}`}>
      <div className="text-[11px] font-bold uppercase tracking-wide opacity-80">{label}</div>
      <div className="mt-1 text-2xl font-extrabold">{value}</div>
    </div>
  );
}

function getPresenceEpochMs(row) {
  return safeNumber(row?.last_seen_epoch_ms, 0) || parseIsoToEpochMs(row?.last_seen_at) || 0;
}

function PresenceList({ title, rows, emptyMessage, nowMs, online = false }) {
  const items = safeArray(rows);

  return (
    <div>
      <div className="mb-2 text-xs font-bold uppercase tracking-wide text-slate-500">{title}</div>
      {items.length === 0 ? (
        <div className="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-5 text-sm text-slate-500">
          {emptyMessage}
        </div>
      ) : (
        <div className="space-y-2">
          {items.map((row, idx) => {
            const lastSeenMs = getPresenceEpochMs(row);
            const relative = fmtRelativeFromEpoch(lastSeenMs, nowMs);

            return (
              <div
                key={`${safeStr(row.user_id, idx)}-${idx}`}
                className="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3"
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="truncate text-sm font-bold text-slate-900">{safeStr(row.full_name, "User")}</div>
                    <div className="truncate text-xs font-semibold text-slate-500">{safeStr(row.location, "—")}</div>
                  </div>
                  <div className="shrink-0">
                    {online ? (
                      <TonePill tone="success">
                        <span className="inline-block h-2.5 w-2.5 rounded-full bg-emerald-500" />
                        Online now
                      </TonePill>
                    ) : (
                      <TonePill tone="neutral">Last active {relative || "recently"}</TonePill>
                    )}
                  </div>
                </div>

                <div className="mt-2 text-[11px] font-semibold text-slate-500">
                  Last active at {fmtDateTime(lastSeenMs || row.last_seen_at)}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

function NotificationWatchlist({ items, nowMs }) {
  const rows = safeArray(items);

  if (rows.length === 0) {
    return <EmptyState message="No admin alerts are available right now." />;
  }

  return (
    <div className="space-y-2">
      {rows.map((row, idx) => {
        const type = safeStr(row.type, "system").toLowerCase();
        const tone = type.includes("reject") ? "danger" : type.includes("product") ? "warn" : "neutral";
        const createdMs = safeNumber(row.created_epoch_ms, 0) || parseIsoToEpochMs(row.created_at) || 0;

        return (
          <div
            key={`${safeStr(row.notification_id, idx)}-${idx}`}
            className="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3"
          >
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <div className="truncate text-sm font-extrabold text-slate-900">
                  {safeStr(row.title, "Notification")}
                </div>
                <div className="mt-1 text-xs font-medium text-slate-600 line-clamp-2">
                  {safeStr(row.message, "Open the admin workspace for more detail.")}
                </div>
              </div>
              <div className="shrink-0 flex items-center gap-2">
                <TonePill tone={tone}>{titleCaseWords(type.replace(/_/g, " "))}</TonePill>
                {!row.is_read ? <TonePill tone={tone}>New</TonePill> : null}
              </div>
            </div>
            <div className="mt-2 text-[11px] font-semibold text-slate-500">
              {fmtRelativeFromEpoch(createdMs, nowMs) || fmtDateTime(createdMs || row.created_at)}
            </div>
          </div>
        );
      })}
    </div>
  );
}

function NewListingsList({ rows, nowMs }) {
  const items = safeArray(rows);

  if (items.length === 0) {
    return <EmptyState message="No recent product listing activity is available." />;
  }

  return (
    <div className="space-y-2">
      {items.map((row, idx) => {
        const status = safeStr(row.status, "pending").toLowerCase();
        const tone =
          status === "approved" || status === "available"
            ? "success"
            : status === "rejected"
              ? "danger"
              : "warn";

        const activityMs = safeNumber(row.activity_epoch_ms, 0) || parseIsoToEpochMs(row.activity_at) || 0;

        return (
          <div
            key={`${safeStr(row.product_id, idx)}-${idx}`}
            className="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3"
          >
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0">
                <div className="truncate text-sm font-extrabold text-slate-900">
                  {safeStr(row.product_name, "Product")}
                </div>
                <div className="mt-1 text-xs font-semibold text-slate-500">
                  {safeStr(row.farmer_name, "Farmer")} • {safeStr(row.category, "—")}
                </div>
              </div>
              <TonePill tone={tone}>{titleCaseWords(status)}</TonePill>
            </div>
            <div className="mt-2 flex flex-wrap items-center gap-2 text-[11px] font-semibold text-slate-500">
              <span>{fmtNAD(row.price)}</span>
              <span>•</span>
              <span>Qty {safeNumber(row.quantity, 0)}</span>
              <span>•</span>
              <span>{fmtRelativeFromEpoch(activityMs, nowMs) || fmtDateTime(activityMs || row.activity_at)}</span>
            </div>
          </div>
        );
      })}
    </div>
  );
}

function TopProductsList({ rows }) {
  const items = safeArray(rows);

  if (items.length === 0) {
    return <EmptyState message="No top-product ranking is available yet." />;
  }

  return (
    <div className="space-y-2">
      {items.map((row, idx) => (
        <div
          key={`${safeStr(row.product_id, idx)}-${idx}`}
          className="flex items-center gap-3 rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3"
        >
          <div className="grid h-8 w-8 place-items-center rounded-xl border border-slate-200 bg-white text-xs font-extrabold text-slate-700">
            {idx + 1}
          </div>
          <div className="min-w-0 flex-1">
            <div className="truncate text-sm font-extrabold text-slate-900">{safeStr(row.name, "Product")}</div>
            <div className="text-xs font-semibold text-slate-500">
              {safeStr(row.category, "—")} • {safeNumber(row.orders, 0)} orders
            </div>
          </div>
          <div className="text-right">
            <div className="text-sm font-extrabold text-slate-900">{fmtNAD(row.revenue)}</div>
            <div className="text-[11px] font-semibold text-slate-500">Revenue</div>
          </div>
        </div>
      ))}
    </div>
  );
}

function DemandPredictionsTable({ rows }) {
  const items = safeArray(rows);

  if (items.length === 0) {
    return <EmptyState message="No demand forecast output is available yet." />;
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[760px] text-sm">
        <thead className="border-b border-slate-200 text-slate-500">
          <tr>
            <th className="py-3 pr-4 text-left text-xs font-bold uppercase tracking-wide">Product</th>
            <th className="py-3 pr-4 text-left text-xs font-bold uppercase tracking-wide">Farmer</th>
            <th className="py-3 pr-4 text-left text-xs font-bold uppercase tracking-wide">Signal</th>
            <th className="py-3 pr-4 text-right text-xs font-bold uppercase tracking-wide">Predicted</th>
            <th className="py-3 pr-4 text-right text-xs font-bold uppercase tracking-wide">Actual</th>
            <th className="py-3 pr-4 text-left text-xs font-bold uppercase tracking-wide">Model</th>
            <th className="py-3 text-left text-xs font-bold uppercase tracking-wide">Updated</th>
          </tr>
        </thead>
        <tbody>
          {items.map((row, idx) => {
            const task = safeStr(row.task, "forecast").toLowerCase();
            const tone = task === "demand" ? "warn" : "success";
            const actualValue =
              row.actual_value === null || row.actual_value === undefined
                ? "—"
                : safeNumber(row.actual_value, 0).toFixed(2);
            const predictedMs = safeNumber(row.predicted_epoch_ms, 0) || parseIsoToEpochMs(row.predicted_at) || 0;

            return (
              <tr key={`${safeStr(row.product_id, idx)}-${idx}`} className="border-b border-slate-100">
                <td className="py-4 pr-4 align-top">
                  <div className="font-extrabold text-slate-900">{safeStr(row.product_name, "Unknown product")}</div>
                  <div className="mt-0.5 text-xs font-semibold text-slate-500">{safeStr(row.category, "—")}</div>
                </td>
                <td className="py-4 pr-4 align-top text-slate-700">
                  <div>{safeStr(row.farmer_name, "—")}</div>
                  <div className="mt-0.5 text-xs font-semibold text-slate-500">{safeStr(row.farmer_location, "—")}</div>
                </td>
                <td className="py-4 pr-4 align-top">
                  <TonePill tone={tone}>{titleCaseWords(task)}</TonePill>
                </td>
                <td className="py-4 pr-4 align-top text-right font-extrabold text-slate-900">
                  {safeNumber(row.predicted_value, 0).toFixed(2)}
                </td>
                <td className="py-4 pr-4 align-top text-right font-semibold text-slate-700">
                  {actualValue}
                </td>
                <td className="py-4 pr-4 align-top text-slate-700">{safeStr(row.model_version, "—")}</td>
                <td className="py-4 align-top text-slate-700">
                  <div>{fmtDateTime(predictedMs || row.predicted_at)}</div>
                  <div className="mt-0.5 text-xs font-semibold text-slate-500">
                    Horizon: {safeNumber(row.horizon_days, 30)} days
                  </div>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function buildDoughnutData(distribution, palette) {
  return {
    labels: distribution.labels,
    datasets: [
      {
        data: distribution.values,
        backgroundColor: distribution.labels.map((label) => palette[label] || "#cbd5e1"),
        borderColor: "#ffffff",
        borderWidth: 4,
        hoverOffset: 8,
      },
    ],
  };
}

function buildDoughnutOptions(total) {
  return {
    responsive: true,
    maintainAspectRatio: false,
    cutout: "68%",
    plugins: {
      legend: {
        position: "bottom",
        labels: {
          boxWidth: 12,
          boxHeight: 12,
          padding: 16,
          color: "rgba(71, 85, 105, 0.92)",
          font: { size: 11, weight: "700" },
          usePointStyle: true,
          pointStyle: "circle",
        },
      },
      tooltip: {
        callbacks: {
          label: (ctx) => {
            const value = safeNumber(ctx.raw, 0);
            const pct = total > 0 ? ((value / total) * 100).toFixed(1) : "0.0";
            return `${titleCaseWords(ctx.label)}: ${value} (${pct}%)`;
          },
        },
      },
    },
  };
}

export default function AdminAnalyticsPage() {
  const { data: raw, loading, error, refetch } = useApi(ENDPOINTS, { initialData: undefined });
  const analytics = useMemo(() => normalizeAnalytics(raw), [raw]);

  const [slaMode, setSlaMode] = useState("month");
  const [nowMs, setNowMs] = useState(Date.now());

  useEffect(() => {
    setNowMs(analytics.presence.serverNowEpochMs || Date.now());
  }, [analytics.presence.serverNowEpochMs]);

  useEffect(() => {
    const timerId = window.setInterval(() => setNowMs(Date.now()), 30000);
    return () => window.clearInterval(timerId);
  }, []);

  const orders = useMemo(() => normalizeOrderDistribution(analytics.ordersByStatus), [analytics.ordersByStatus]);
  const products = useMemo(() => normalizeProductDistribution(analytics.productsByStatus), [analytics.productsByStatus]);

  const slaSeries = useMemo(() => {
    const arr = slaMode === "month" ? safeArray(analytics.sla.monthly) : safeArray(analytics.sla.daily);
    const labels = arr.map((x) => safeStr(x.month || x.date || x.period || x.label || ""));
    const values = arr.map((x) => toPct(x.sla_pct ?? x.slaPct ?? x.value ?? 0));
    return { labels, values };
  }, [analytics.sla.daily, analytics.sla.monthly, slaMode]);

  const ordersDoughnut = useMemo(() => buildDoughnutData(orders, ORDER_STATUS_COLORS), [orders]);
  const productsDoughnut = useMemo(() => buildDoughnutData(products, PRODUCT_STATUS_COLORS), [products]);

  const doughnutOptionsOrders = useMemo(() => buildDoughnutOptions(orders.total), [orders.total]);
  const doughnutOptionsProducts = useMemo(() => buildDoughnutOptions(products.total), [products.total]);

  const slaLine = useMemo(
    () => ({
      labels: slaSeries.labels,
      datasets: [
        {
          data: slaSeries.values,
          borderWidth: 2,
          tension: 0.35,
          pointRadius: 2,
          fill: true,
          backgroundColor: "rgba(16, 185, 129, 0.08)",
          borderColor: "rgba(16, 185, 129, 0.82)",
        },
      ],
    }),
    [slaSeries]
  );

  const lineOptions = useMemo(
    () => ({
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: { intersect: false, mode: "index" },
      },
      interaction: { mode: "index", intersect: false },
      scales: {
        x: {
          grid: { color: "rgba(148, 163, 184, 0.18)" },
          ticks: { color: "rgba(71, 85, 105, 0.90)", font: { size: 11, weight: "600" } },
        },
        y: {
          beginAtZero: true,
          max: 100,
          grid: { color: "rgba(148, 163, 184, 0.18)" },
          ticks: {
            callback: (v) => `${v}%`,
            color: "rgba(71, 85, 105, 0.90)",
            font: { size: 11, weight: "600" },
          },
        },
      },
    }),
    []
  );

  const reviewed = safeNumber(analytics.sla.summary.reviewed, 0);
  const breached = safeNumber(analytics.sla.summary.breached, 0);
  const avgHours = safeNumber(analytics.sla.summary.avgHours, 0);
  const slaPct = toPct(analytics.sla.summary.slaPct);
  const unreadAlerts = safeNumber(analytics.notifications.unreadCount, 0);
  const liveUsers = safeNumber(analytics.presence.farmersCount, 0) + safeNumber(analytics.presence.customersCount, 0);

  const summaryError = !!error;

  return (
    <AdminLayout>
      <div className="space-y-6">
        <Card className="border border-slate-200 bg-white p-6">
          <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
            <div className="min-w-0">
              <div className="text-xs font-semibold text-slate-500">AgroConnect Namibia</div>
              <h1 className="text-2xl font-extrabold text-slate-900">Analytics & Governance Intelligence</h1>
              <p className="mt-1 max-w-3xl text-sm text-slate-600">
                A consolidated view of moderation performance, product activity, live user presence,
                demand signals, and administrative alerts.
              </p>

              <div className="mt-3 flex flex-wrap items-center gap-2">
                <TonePill tone="success">Live analytics window: {analytics.windowDays} days</TonePill>
                <TonePill tone="neutral">Presence window: {analytics.presence.windowMinutes} minutes</TonePill>
                <TonePill tone="warn">Unread alerts: {unreadAlerts}</TonePill>
                {summaryError ? <TonePill tone="danger">Some analytics blocks could not be loaded</TonePill> : null}
              </div>
            </div>

            <div className="flex items-center gap-2">
              <button className="btn-secondary" onClick={refetch} type="button">
                <RefreshCw className="h-4 w-4" /> Refresh
              </button>
            </div>
          </div>
        </Card>

        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
          <KpiCard
            icon={<ClipboardList className="h-5 w-5" />}
            label="Reviewed"
            value={loading ? "…" : reviewed}
            sub={`Moderation decisions in the last ${analytics.sla.windowDays || analytics.windowDays} days`}
          />
          <KpiCard
            icon={<AlertTriangle className="h-5 w-5" />}
            label="Breached"
            value={loading ? "…" : breached}
            sub={`Beyond ${analytics.sla.targetHours || 48}h service target`}
          />
          <KpiCard
            icon={<Clock3 className="h-5 w-5" />}
            label="Average turnaround"
            value={loading ? "…" : `${avgHours.toFixed(2)}h`}
            sub="Across reviewed moderation items"
          />
          <KpiCard
            icon={<Users className="h-5 w-5" />}
            label="Users online now"
            value={loading ? "…" : liveUsers}
            sub={`${analytics.presence.farmersCount} farmers • ${analytics.presence.customersCount} customers`}
          />
        </div>

        <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
          <SectionCard
            title="Live presence"
            subtitle="Heartbeat-based online status with separate recently active users for last-seen visibility."
            right={
              <TonePill tone="neutral">
                <Activity className="h-3.5 w-3.5" />
                Live signal
              </TonePill>
            }
          >
            <div className="mb-4 grid grid-cols-2 gap-3">
              <MiniMetric label="Farmers online" value={analytics.presence.farmersCount} tone="emerald" />
              <MiniMetric label="Customers online" value={analytics.presence.customersCount} tone="slate" />
            </div>
            <div className="grid grid-cols-1 gap-4">
              <PresenceList
                title="Farmers online"
                rows={analytics.presence.farmersOnline}
                emptyMessage="No farmers are currently online."
                nowMs={nowMs}
                online
              />
              <PresenceList
                title="Recently active farmers"
                rows={analytics.presence.farmersRecent}
                emptyMessage="No recent farmer activity is available."
                nowMs={nowMs}
              />
              <PresenceList
                title="Customers online"
                rows={analytics.presence.customersOnline}
                emptyMessage="No customers are currently online."
                nowMs={nowMs}
                online
              />
              <PresenceList
                title="Recently active customers"
                rows={analytics.presence.customersRecent}
                emptyMessage="No recent customer activity is available."
                nowMs={nowMs}
              />
            </div>
          </SectionCard>

          <SectionCard
            title="New product listings"
            subtitle="Latest catalogue activity requiring governance visibility and review context."
          >
            <NewListingsList rows={analytics.recentProducts} nowMs={nowMs} />
          </SectionCard>

          <SectionCard
            title="Notification watchlist"
            subtitle="Recent admin-facing alerts, including product workflow and system events."
            right={<TonePill tone={unreadAlerts > 0 ? "warn" : "neutral"}>{unreadAlerts} unread</TonePill>}
          >
            <NotificationWatchlist items={analytics.notifications.items} nowMs={nowMs} />
          </SectionCard>
        </div>

        <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
          <div className="xl:col-span-2">
            <SectionCard
              title="Future product demand prediction"
              subtitle="Latest model output from demand and forecast runs to support inventory and catalogue planning."
            >
              <DemandPredictionsTable rows={analytics.demandPredictions} />
            </SectionCard>
          </div>

          <div>
            <SectionCard
              title="Top products"
              subtitle="Products ranked by distinct order count, with revenue as a secondary signal."
            >
              <TopProductsList rows={analytics.topProducts} />
            </SectionCard>
          </div>
        </div>

        <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
          <SectionCard
            title="Orders by status"
            subtitle="Operational distribution of orders across the platform."
          >
            <div className="h-[320px]">
              {orders.labels.length === 0 || orders.total === 0 ? (
                <EmptyState message="No order-status data is available." />
              ) : (
                <Doughnut data={ordersDoughnut} options={doughnutOptionsOrders} />
              )}
            </div>
          </SectionCard>

          <SectionCard
            title="Products by status"
            subtitle="Catalogue governance distribution across product listing states."
          >
            <div className="h-[320px]">
              {products.labels.length === 0 || products.total === 0 ? (
                <EmptyState message="No product-status data is available." />
              ) : (
                <Doughnut data={productsDoughnut} options={doughnutOptionsProducts} />
              )}
            </div>
          </SectionCard>
        </div>

        <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
          <SectionCard
            title="Moderation SLA trend"
            subtitle="Compliance trajectory against the moderation service target."
            right={
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => setSlaMode("month")}
                  className={[
                    "rounded-full border px-3 py-1.5 text-xs font-bold",
                    slaMode === "month"
                      ? "border-emerald-200 bg-emerald-50 text-emerald-700"
                      : "border-slate-200 bg-white text-slate-700 hover:bg-slate-50",
                  ].join(" ")}
                >
                  Monthly
                </button>
                <button
                  type="button"
                  onClick={() => setSlaMode("day")}
                  className={[
                    "rounded-full border px-3 py-1.5 text-xs font-bold",
                    slaMode === "day"
                      ? "border-emerald-200 bg-emerald-50 text-emerald-700"
                      : "border-slate-200 bg-white text-slate-700 hover:bg-slate-50",
                  ].join(" ")}
                >
                  Daily
                </button>
              </div>
            }
          >
            <div className="mb-4 grid grid-cols-1 gap-3 sm:grid-cols-3">
              <MiniMetric label="SLA target" value={`${analytics.sla.targetHours || 48}h`} tone="slate" />
              <MiniMetric label="Compliance" value={`${slaPct.toFixed(1)}%`} tone="emerald" />
              <MiniMetric label="Average review" value={`${avgHours.toFixed(2)}h`} tone="amber" />
            </div>

            <div className="h-[280px]">
              {slaSeries.labels.length === 0 ? (
                <EmptyState message="No SLA time-series is available." />
              ) : (
                <Line data={slaLine} options={lineOptions} />
              )}
            </div>
          </SectionCard>

          <SectionCard
            title="Moderation SLA leaderboard"
            subtitle="Administrative review performance across the configured governance window."
          >
            {safeArray(analytics.sla.leaderboard).length === 0 ? (
              <EmptyState message="No SLA leaderboard entries are available." />
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full min-w-[620px] text-sm">
                  <thead className="border-b border-slate-200 text-slate-500">
                    <tr>
                      <th className="py-3 pr-4 text-left text-xs font-bold uppercase tracking-wide">Admin</th>
                      <th className="py-3 pr-4 text-right text-xs font-bold uppercase tracking-wide">Reviewed</th>
                      <th className="py-3 pr-4 text-right text-xs font-bold uppercase tracking-wide">Breached</th>
                      <th className="py-3 pr-4 text-right text-xs font-bold uppercase tracking-wide">Avg hours</th>
                      <th className="py-3 text-right text-xs font-bold uppercase tracking-wide">SLA%</th>
                    </tr>
                  </thead>
                  <tbody>
                    {safeArray(analytics.sla.leaderboard).map((row, idx) => {
                      const reviewedValue = safeNumber(row.reviewed_count ?? row.reviewed ?? 0, 0);
                      const breachedValue = safeNumber(row.breached_count ?? row.breached ?? 0, 0);
                      const avgValue = safeNumber(row.avg_review_hours ?? row.avg_hours ?? row.avgHours ?? 0, 0);
                      const pctValue = toPct(row.sla_percentage ?? row.sla_pct ?? row.slaPct ?? 0);

                      return (
                        <tr key={`${safeStr(row.admin_id, idx)}-${idx}`} className="border-b border-slate-100">
                          <td className="py-4 pr-4 align-top">
                            <div className="font-extrabold text-slate-900">{safeStr(row.admin_name || row.name || "Admin")}</div>
                            <div className="mt-0.5 text-xs font-semibold text-slate-500">
                              {safeStr(row.admin_id || "—")}
                            </div>
                          </td>
                          <td className="py-4 pr-4 text-right font-semibold text-slate-900">{reviewedValue}</td>
                          <td className="py-4 pr-4 text-right font-semibold text-slate-900">{breachedValue}</td>
                          <td className="py-4 pr-4 text-right font-semibold text-slate-900">{avgValue.toFixed(2)}</td>
                          <td className="py-4 text-right">
                            <TonePill tone={pctValue >= 95 ? "success" : pctValue >= 80 ? "warn" : "danger"}>
                              {pctValue.toFixed(1)}%
                            </TonePill>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </SectionCard>
        </div>
      </div>
    </AdminLayout>
  );
}