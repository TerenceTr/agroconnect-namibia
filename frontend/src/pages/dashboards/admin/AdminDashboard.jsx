// ============================================================================
// frontend/src/pages/dashboards/admin/AdminDashboard.jsx
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Admin governance dashboard overview.
//
// DESIGN GOALS IN THIS UPDATE:
//   ✅ Cleaner executive-style admin dashboard
//   ✅ Removes low-value technical clutter such as raw endpoint/source text
//   ✅ Uses space more effectively and reduces empty-looking panels
//   ✅ Organises content into clear decision-oriented sections:
//      1) Executive header
//      2) KPI overview
//      3) Platform activity + operational snapshot
//      4) Recent orders worklist
//      5) Trend analysis
//   ✅ Keeps the existing backend contract and defensive fallbacks
//   ✅ Maintains click-through to admin order detail
//
// DATA / RESILIENCE:
//   ✅ Supports { success:true, data:{...} } or direct payload
//   ✅ Prefers backend weekly series; falls back to bucketing daily series in UI
//   ✅ Handles empty states cleanly without noisy developer-facing messaging
// ============================================================================

import React, { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Line } from "react-chartjs-2";
import {
  Users,
  ShoppingBasket,
  Package,
  Star,
  ClipboardList,
  UserPlus,
  RefreshCw,
  BarChart3,
  LogIn,
  Activity,
  ArrowUpRight,
  ShieldCheck,
  AlertTriangle,
} from "lucide-react";

import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Tooltip,
  Legend,
  Filler,
} from "chart.js";

import useApi from "../../../hooks/useApi";
import AdminLayout from "../../../components/AdminLayout";
import Card from "../../../components/ui/Card";
import EmptyState from "../../../components/ui/EmptyState";

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Tooltip, Legend, Filler);

// ---------------------------------------------------------------------------
// Stable empties
// ---------------------------------------------------------------------------
const EMPTY_OBJ = Object.freeze({});
const EMPTY_ARR = Object.freeze([]);

// ---------------------------------------------------------------------------
// Safety helpers
// ---------------------------------------------------------------------------
function safeObj(v) {
  return v && typeof v === "object" ? v : EMPTY_OBJ;
}

function safeArray(v) {
  return Array.isArray(v) ? v : EMPTY_ARR;
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

function shortId(id) {
  const s = safeStr(id, "");
  if (!s) return "—";
  return s.length <= 10 ? s : `${s.slice(0, 6)}…${s.slice(-4)}`;
}

function fmtDateTime(iso) {
  try {
    if (!iso) return "—";
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return "—";
    return d.toLocaleString();
  } catch {
    return "—";
  }
}

function fmtNAD(amount) {
  const n = safeNumber(amount, 0);
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

function pluralize(value, one, many = `${one}s`) {
  return safeNumber(value) === 1 ? one : many;
}

function lastOf(arr) {
  const list = safeArray(arr);
  return list.length ? list[list.length - 1] : null;
}

// ---------------------------------------------------------------------------
// Overview endpoints
// ---------------------------------------------------------------------------
const OVERVIEW_ENDPOINTS = ["/admin/reports/overview", "/admin/overview"];

const DAY_RANGE_OPTIONS = [7, 14, 30, 90, 180, 365];

function titleCaseBucket(value) {
  const s = safeStr(value, "").trim().toLowerCase();
  if (!s) return "Period";
  if (s === "biweekly") return "Bi-weekly";
  return s.charAt(0).toUpperCase() + s.slice(1);
}

function pickAdaptiveSeries(source, baseKey, days) {
  const bag = safeObj(source);
  const safeDays = safeNumber(days, 90);

  const seriesByKey = {
    daily: safeArray(bag[`daily_${baseKey}`]),
    weekly: safeArray(bag[`weekly_${baseKey}`]),
    biweekly: safeArray(bag[`biweekly_${baseKey}`]),
    monthly: safeArray(bag[`monthly_${baseKey}`]),
  };

  const preferredKeys =
    safeDays <= 30
      ? ["daily", "weekly", "biweekly", "monthly"]
      : safeDays <= 90
      ? ["weekly", "daily", "biweekly", "monthly"]
      : safeDays <= 180
      ? ["biweekly", "weekly", "monthly", "daily"]
      : ["monthly", "biweekly", "weekly", "daily"];

  for (const key of preferredKeys) {
    const rows = seriesByKey[key];
    if (rows.length) return { bucket: key, rows };
  }

  return { bucket: safeDays <= 30 ? "daily" : "weekly", rows: [] };
}

// ---------------------------------------------------------------------------
// Wrapper-safe normalizer
// ---------------------------------------------------------------------------
function normalizeOverview(raw) {
  let d = raw && typeof raw === "object" ? raw : {};

  if (d && d.success === true && d.data && typeof d.data === "object") {
    d = d.data;
  }

  if (d.totals && (d.recent || d.time_series)) {
    return {
      totals: d.totals || {},
      recent: d.recent || {},
      time_series: d.time_series || {},
      top_products: safeArray(d.top_products),
      login_stats: d.login_stats || {},
      meta: d.meta || {},
    };
  }

  // Older fallback shape
  if (d.kpis || d.recent) {
    const k = d.kpis || {};
    const r = d.recent || {};
    return {
      totals: {
        total_users: k.users_total ?? 0,
        total_products: k.products_total ?? 0,
        total_orders: k.orders_total ?? 0,
        avg_rating: 0,
        total_ratings: 0,
      },
      recent: {
        recent_registrations: safeArray(r.users),
        recent_orders: safeArray(r.orders),
        recent_products: safeArray(r.products),
        recent_ratings: [],
      },
      time_series: {},
      top_products: [],
      login_stats: {},
      meta: {},
    };
  }

  return {
    totals: d.totals || {},
    recent: d.recent || {},
    time_series: d.time_series || {},
    top_products: safeArray(
      d.top_products ||
        d.topProducts ||
        safeObj(d.analytics).top_products ||
        safeObj(d.summary).top_products ||
        []
    ),
    login_stats: d.login_stats || d.loginStats || {},
    meta: d.meta || {},
  };
}

// ---------------------------------------------------------------------------
// UI atoms
// ---------------------------------------------------------------------------
function SectionHeader({ icon, title, subtitle, action = null }) {
  return (
    <div className="flex items-start justify-between gap-4">
      <div className="flex items-start gap-3 min-w-0">
        <div className="mt-0.5 grid h-10 w-10 place-items-center rounded-2xl border border-emerald-100 bg-emerald-50 text-emerald-700 shadow-sm">
          {icon}
        </div>

        <div className="min-w-0">
          <h2 className="text-lg font-extrabold tracking-tight text-slate-900">{title}</h2>
          {subtitle ? (
            <p className="mt-1 text-sm font-medium text-slate-500">{subtitle}</p>
          ) : null}
        </div>
      </div>

      {action ? <div className="shrink-0">{action}</div> : null}
    </div>
  );
}

function StatusPill({ tone = "neutral", children }) {
  const cls =
    tone === "danger"
      ? "border-rose-200 bg-rose-50 text-rose-700"
      : tone === "success"
      ? "border-emerald-200 bg-emerald-50 text-emerald-700"
      : tone === "warn"
      ? "border-amber-200 bg-amber-50 text-amber-800"
      : "border-slate-200 bg-slate-50 text-slate-700";

  return (
    <span
      className={[
        "inline-flex items-center gap-2 rounded-full border px-3 py-1.5",
        "text-xs font-bold whitespace-nowrap",
        cls,
      ].join(" ")}
    >
      {children}
    </span>
  );
}

function Badge({ children }) {
  return (
    <span className="inline-flex items-center rounded-full border border-slate-200 bg-slate-50 px-2.5 py-1 text-[11px] font-extrabold text-slate-700 whitespace-nowrap">
      {children}
    </span>
  );
}

function MetricCard({ icon, label, value, sub }) {
  return (
    <Card className="border border-slate-200 bg-white p-5">
      <div className="flex items-start gap-4">
        <div className="grid h-11 w-11 place-items-center rounded-2xl border border-slate-200 bg-slate-50 text-emerald-700 shadow-sm">
          {icon}
        </div>

        <div className="min-w-0">
          <div className="text-xs font-bold uppercase tracking-wide text-slate-500">{label}</div>
          <div className="mt-1 text-2xl font-extrabold tracking-tight text-slate-900">{value}</div>
          {sub ? <div className="mt-1 text-xs font-semibold text-slate-500">{sub}</div> : null}
        </div>
      </div>
    </Card>
  );
}

function MicroStat({ label, value, sub }) {
  return (
    <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
      <div className="text-[11px] font-bold uppercase tracking-wide text-slate-500">{label}</div>
      <div className="mt-1 text-2xl font-extrabold tracking-tight text-slate-900">{value}</div>
      {sub ? <div className="mt-1 text-xs font-semibold text-slate-500">{sub}</div> : null}
    </div>
  );
}

function InsightRow({ label, value, emphasis = false }) {
  return (
    <div className="flex items-start justify-between gap-3 rounded-2xl border border-slate-200 bg-white px-4 py-3">
      <div className="min-w-0 text-sm font-semibold text-slate-600">{label}</div>
      <div
        className={[
          "text-right text-sm font-extrabold",
          emphasis ? "text-slate-900" : "text-slate-700",
        ].join(" ")}
      >
        {value}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------
export default function AdminDashboard() {
  const navigate = useNavigate();
  const [selectedDays, setSelectedDays] = useState(90);

  const overviewParams = useMemo(
    () => ({
      days: selectedDays,
      ttl: 300,
    }),
    [selectedDays]
  );

  const { data: rawOverview, loading, error, status, refetch } = useApi(OVERVIEW_ENDPOINTS, {
    initialData: undefined,
    params: overviewParams,
    deps: [selectedDays],
  });

  const overview = useMemo(() => normalizeOverview(rawOverview), [rawOverview]);

  const totals = useMemo(() => safeObj(overview?.totals), [overview?.totals]);
  const recent = useMemo(() => safeObj(overview?.recent), [overview?.recent]);
  const ts = useMemo(() => safeObj(overview?.time_series), [overview?.time_series]);
  const meta = useMemo(() => safeObj(overview?.meta), [overview?.meta]);
  const topProducts = useMemo(() => safeArray(overview?.top_products), [overview?.top_products]);
  const loginStats = useMemo(() => safeObj(overview?.login_stats), [overview?.login_stats]);

  const totalUsers = safeNumber(totals.total_users);
  const totalProducts = safeNumber(totals.total_products);
  const totalOrders = safeNumber(totals.total_orders);
  const avgRating = safeNumber(totals.avg_rating);
  const ratingCount = safeNumber(totals.total_ratings);

  const recentOrders = safeArray(recent.recent_orders);

  const ordersSeries = useMemo(
    () => pickAdaptiveSeries(ts, "orders", selectedDays),
    [ts, selectedDays]
  );

  const registrationsSeries = useMemo(
    () => pickAdaptiveSeries(ts, "registrations", selectedDays),
    [ts, selectedDays]
  );

  const loginsSeries = useMemo(
    () => pickAdaptiveSeries(loginStats, "logins", selectedDays),
    [loginStats, selectedDays]
  );

  const ordersTrendRows = ordersSeries.rows;
  const registrationsTrendRows = registrationsSeries.rows;
  const loginsTrendRows = loginsSeries.rows;

  const ordersBucketLabel = titleCaseBucket(ordersSeries.bucket);
  const registrationsBucketLabel = titleCaseBucket(registrationsSeries.bucket);
  const loginsBucketLabel = titleCaseBucket(loginsSeries.bucket);

  const logins7 = safeNumber(loginStats.last_7_days);
  const logins30 = safeNumber(loginStats.last_30_days);

  const latestOrdersPoint = lastOf(ordersTrendRows);
  const latestRegsPoint = lastOf(registrationsTrendRows);
  const latestLoginsPoint = lastOf(loginsTrendRows);
  const topProduct = topProducts[0] || null;

  const reviewedDataHealthy = !error;
  const demoUsed = Boolean(meta?.demo_used);

  const ordersChartData = useMemo(() => {
    const labels = ordersTrendRows.map((x) => safeStr(x.date));
    const values = ordersTrendRows.map((x) => safeNumber(x.count));

    return {
      labels,
      datasets: [
        {
          label: `Orders (${ordersBucketLabel})`,
          data: values,
          borderWidth: 2,
          tension: 0.35,
          pointRadius: 2,
          fill: true,
          backgroundColor: "rgba(15, 23, 42, 0.06)",
          borderColor: "rgba(15, 23, 42, 0.75)",
        },
      ],
    };
  }, [ordersTrendRows, ordersBucketLabel]);

  const regsChartData = useMemo(() => {
    const labels = registrationsTrendRows.map((x) => safeStr(x.date));
    const values = registrationsTrendRows.map((x) => safeNumber(x.count));

    return {
      labels,
      datasets: [
        {
          label: demoUsed
            ? `Registrations (${registrationsBucketLabel}) — Demo-backed`
            : `Registrations (${registrationsBucketLabel})`,
          data: values,
          borderWidth: 2,
          tension: 0.35,
          pointRadius: 2,
          fill: true,
          backgroundColor: "rgba(2, 132, 199, 0.08)",
          borderColor: "rgba(2, 132, 199, 0.85)",
        },
      ],
    };
  }, [registrationsTrendRows, registrationsBucketLabel, demoUsed]);

  const loginsChartData = useMemo(() => {
    const labels = loginsTrendRows.map((x) => safeStr(x.date));
    const values = loginsTrendRows.map((x) => safeNumber(x.count));

    return {
      labels,
      datasets: [
        {
          label: `User logins (${loginsBucketLabel})`,
          data: values,
          borderWidth: 2,
          tension: 0.35,
          pointRadius: 2,
          fill: true,
          backgroundColor: "rgba(88, 28, 135, 0.08)",
          borderColor: "rgba(88, 28, 135, 0.80)",
        },
      ],
    };
  }, [loginsTrendRows, loginsBucketLabel]);

  const chartOptions = useMemo(
    () => ({
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          display: true,
          labels: {
            boxWidth: 10,
            boxHeight: 10,
            color: "rgba(51, 65, 85, 0.92)",
            font: { size: 11, weight: "600" },
          },
        },
        tooltip: { intersect: false, mode: "index" },
      },
      interaction: { mode: "index", intersect: false },
      scales: {
        x: {
          grid: { color: "rgba(148, 163, 184, 0.22)" },
          ticks: {
            color: "rgba(71, 85, 105, 0.9)",
            maxRotation: 0,
            autoSkip: true,
            font: { size: 11, weight: "600" },
          },
        },
        y: {
          beginAtZero: true,
          grid: { color: "rgba(148, 163, 184, 0.22)" },
          ticks: {
            color: "rgba(71, 85, 105, 0.9)",
            font: { size: 11, weight: "600" },
          },
        },
      },
    }),
    []
  );

  const openOrder = (orderId) => {
    const id = safeStr(orderId, "");
    if (!id) return;
    navigate(`/dashboard/admin/orders/${id}`);
  };

  return (
    <AdminLayout>
      <div className="space-y-6">
        {/* -----------------------------------------------------------------
           Executive header
        ----------------------------------------------------------------- */}
        <Card className="border border-slate-200 bg-white p-6">
          <SectionHeader
            icon={<ShieldCheck className="h-5 w-5" />}
            title="Admin Dashboard"
            subtitle="Executive oversight of users, catalogue quality, orders, and platform activity."
            action={
              <div className="flex flex-wrap items-center gap-2">
                <label className="sr-only" htmlFor="admin-overview-days">
                  Select reporting window
                </label>
                <select
                  id="admin-overview-days"
                  value={selectedDays}
                  onChange={(e) => setSelectedDays(Number(e.target.value) || 90)}
                  className="h-11 rounded-2xl border border-slate-200 bg-white px-4 text-sm font-bold text-slate-700 shadow-sm outline-none transition focus:border-emerald-300"
                >
                  {DAY_RANGE_OPTIONS.map((daysOption) => (
                    <option key={daysOption} value={daysOption}>
                      Last {daysOption} days
                    </option>
                  ))}
                </select>

                <button
                  type="button"
                  onClick={() => refetch()}
                  className="inline-flex h-11 items-center gap-2 rounded-2xl border border-slate-200 bg-white px-4 text-sm font-bold text-slate-700 shadow-sm transition hover:bg-slate-50"
                >
                  <RefreshCw className="h-4 w-4" />
                  Refresh
                </button>
              </div>
            }
          />

          <div className="mt-5 flex flex-wrap items-center gap-2">
            <StatusPill tone={reviewedDataHealthy ? "success" : "danger"}>
              {reviewedDataHealthy ? "Live overview loaded" : "Overview unavailable"}
            </StatusPill>

            {demoUsed ? (
              <StatusPill tone="warn">Registration analytics include demo-supported data</StatusPill>
            ) : null}

            <StatusPill>
              Reporting window: <span className="font-extrabold">Last {selectedDays} days</span>
            </StatusPill>
          </div>

          {error ? (
            <div className="mt-4 rounded-2xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">
              <div className="flex items-start gap-3">
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                <div>
                  <div className="font-extrabold">Dashboard data could not be fully loaded.</div>
                  <div className="mt-1 font-medium">
                    {status ? `Server responded with HTTP ${status}. ` : ""}
                    Use refresh to retry the live overview.
                  </div>
                </div>
              </div>
            </div>
          ) : null}
        </Card>

        {/* -----------------------------------------------------------------
           KPI overview
        ----------------------------------------------------------------- */}
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
          <MetricCard
            icon={<Users className="h-5 w-5" />}
            label="Registered users"
            value={loading ? "…" : totalUsers}
            sub="Total accounts on the platform"
          />

          <MetricCard
            icon={<Package className="h-5 w-5" />}
            label="Catalogue size"
            value={loading ? "…" : totalProducts}
            sub="Tracked product listings"
          />

          <MetricCard
            icon={<ShoppingBasket className="h-5 w-5" />}
            label="Orders processed"
            value={loading ? "…" : totalOrders}
            sub="Orders recorded in the overview"
          />

          <MetricCard
            icon={<Star className="h-5 w-5" />}
            label="Average product rating"
            value={loading ? "…" : `${avgRating.toFixed(1)} / 5`}
            sub={loading ? "Loading review quality…" : `${ratingCount} ${pluralize(ratingCount, "review")}`}
          />
        </div>

        {/* -----------------------------------------------------------------
           Activity + operational snapshot
        ----------------------------------------------------------------- */}
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
          {/* User login activity */}
          <Card className="border border-slate-200 bg-white p-5 xl:col-span-2">
            <SectionHeader
              icon={<LogIn className="h-5 w-5" />}
              title="User login activity"
              subtitle={`${loginsBucketLabel} engagement pattern across the selected reporting window.`}
            />

            <div className="mt-5 grid grid-cols-1 gap-3 sm:grid-cols-3">
              <MicroStat
                label="Last 7 days"
                value={loading ? "…" : logins7}
                sub="Recent login volume"
              />
              <MicroStat
                label="Last 30 days"
                value={loading ? "…" : logins30}
                sub="Monthly engagement"
              />
              <MicroStat
                label={`Latest tracked ${loginsBucketLabel}`}
                value={loading ? "…" : safeNumber(latestLoginsPoint?.count, 0)}
                sub={safeStr(latestLoginsPoint?.date, `Most recent ${loginsBucketLabel.toLowerCase()} bucket`)}
              />
            </div>

            <div className="mt-5">
              {loginsTrendRows.length === 0 ? (
                <EmptyState message="No login activity trend is available yet." />
              ) : (
                <div className="h-[310px]">
                  <Line data={loginsChartData} options={chartOptions} />
                </div>
              )}
            </div>
          </Card>

          {/* Operational snapshot */}
          <Card className="border border-slate-200 bg-white p-5">
            <SectionHeader
              icon={<Activity className="h-5 w-5" />}
              title="Operational snapshot"
              subtitle="Fast-read signals for platform monitoring."
            />

            <div className="mt-5 space-y-3">
              <InsightRow
                label="Recent orders shown"
                value={`${recentOrders.length} ${pluralize(recentOrders.length, "order")}`}
                emphasis
              />
              <InsightRow
                label={`Latest ${ordersBucketLabel.toLowerCase()} orders`}
                value={`${safeNumber(latestOrdersPoint?.count, 0)} orders`}
              />
              <InsightRow
                label={`Latest ${registrationsBucketLabel.toLowerCase()} registrations`}
                value={`${safeNumber(latestRegsPoint?.count, 0)} registrations`}
              />
              <InsightRow
                label="Top listed product by orders"
                value={topProduct ? safeStr(topProduct.name, "—") : "No ranked products yet"}
                emphasis={Boolean(topProduct)}
              />
            </div>

            <div className="mt-5 rounded-2xl border border-slate-200 bg-slate-50 p-4">
              <div className="flex items-center gap-2">
                <BarChart3 className="h-4 w-4 text-emerald-700" />
                <h3 className="text-sm font-extrabold text-slate-900">Top products</h3>
              </div>

              {loading ? (
                <div className="mt-4 text-sm font-medium text-slate-500">Loading ranked products…</div>
              ) : topProducts.length === 0 ? (
                <div className="mt-4">
                  <EmptyState message="No top product ranking is available yet." />
                </div>
              ) : (
                <ul className="mt-4 space-y-2">
                  {topProducts.slice(0, 5).map((p, idx) => {
                    const name = safeStr(p?.name, "Product");
                    const orders = safeNumber(p?.orders, 0);

                    return (
                      <li
                        key={`${name}-${idx}`}
                        className="flex items-center gap-3 rounded-2xl border border-slate-200 bg-white px-3 py-3"
                      >
                        <div className="grid h-8 w-8 place-items-center rounded-xl border border-slate-200 bg-slate-50 text-xs font-extrabold text-slate-700">
                          {idx + 1}
                        </div>

                        <div className="min-w-0 flex-1">
                          <div className="truncate text-sm font-extrabold text-slate-900">{name}</div>
                          <div className="text-xs font-semibold text-slate-500">Order count</div>
                        </div>

                        <div className="inline-flex items-center rounded-full border border-emerald-200 bg-emerald-50 px-2.5 py-1 text-xs font-extrabold text-emerald-700">
                          {orders}
                        </div>
                      </li>
                    );
                  })}
                </ul>
              )}
            </div>
          </Card>
        </div>

        {/* -----------------------------------------------------------------
           Recent orders worklist
        ----------------------------------------------------------------- */}
        <Card className="border border-slate-200 bg-white p-5">
          <SectionHeader
            icon={<ClipboardList className="h-5 w-5" />}
            title="Recent orders"
            subtitle="Most recent order activity for operational follow-up and order inspection."
          />

          <div className="mt-5">
            {loading ? (
              <div className="text-sm font-medium text-slate-600">Loading recent orders…</div>
            ) : recentOrders.length === 0 ? (
              <EmptyState message="No recent orders are available." />
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full min-w-[860px] text-sm">
                  <thead className="border-b border-slate-200 text-slate-500">
                    <tr>
                      <th className="py-3 pr-4 text-left text-xs font-bold uppercase tracking-wide">Order</th>
                      <th className="py-3 pr-4 text-left text-xs font-bold uppercase tracking-wide">Customer / Farmer</th>
                      <th className="py-3 pr-4 text-left text-xs font-bold uppercase tracking-wide">Created</th>
                      <th className="py-3 pr-4 text-right text-xs font-bold uppercase tracking-wide">Total</th>
                      <th className="py-3 text-right text-xs font-bold uppercase tracking-wide">Status overview</th>
                    </tr>
                  </thead>

                  <tbody>
                    {recentOrders.slice(0, 8).map((o, idx) => {
                      const orderId = safeStr(o.order_id || o.id || "");
                      const customer = safeStr(o.customer_name || o.buyer_name || "Customer");
                      const farmer = safeStr(o.farmer_name || "Farmer");
                      const created = fmtDateTime(o.created_at);

                      const pay = safeStr(o.payment_status || "—");
                      const del = safeStr(o.delivery_status || "—");
                      const st = safeStr(o.order_status || o.status || "—");
                      const total = fmtNAD(o.total);

                      return (
                        <tr
                          key={orderId || idx}
                          className="cursor-pointer border-b border-slate-100 transition hover:bg-slate-50"
                          onClick={() => openOrder(orderId)}
                          onKeyDown={(e) => e.key === "Enter" && openOrder(orderId)}
                          role="button"
                          tabIndex={0}
                          title="Open order detail"
                        >
                          <td className="py-4 pr-4 align-top">
                            <div className="font-extrabold text-slate-900">{shortId(orderId)}</div>
                            <div className="mt-0.5 text-xs font-semibold text-slate-500">Order reference</div>
                          </td>

                          <td className="py-4 pr-4 align-top">
                            <div className="font-semibold text-slate-900">{customer}</div>
                            <div className="mt-0.5 text-xs font-semibold text-slate-500">{farmer}</div>
                          </td>

                          <td className="py-4 pr-4 align-top whitespace-nowrap text-slate-700">{created}</td>

                          <td className="py-4 pr-4 align-top text-right font-extrabold text-slate-900 whitespace-nowrap">
                            {total}
                          </td>

                          <td className="py-4 align-top text-right">
                            <div className="inline-flex flex-wrap justify-end gap-2">
                              <Badge>Paid: {pay}</Badge>
                              <Badge>Delivery: {del}</Badge>
                              <Badge>Status: {st}</Badge>
                              <Badge>
                                Review <ArrowUpRight className="ml-1 h-3.5 w-3.5" />
                              </Badge>
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </Card>

        {/* -----------------------------------------------------------------
           Trend analysis
        ----------------------------------------------------------------- */}
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
          <Card className="border border-slate-200 bg-white p-5">
            <SectionHeader
              icon={<ClipboardList className="h-5 w-5" />}
              title="Orders trend"
              subtitle={`${ordersBucketLabel} order trajectory across the selected reporting window.`}
            />

            <div className="mt-5">
              {ordersTrendRows.length === 0 ? (
                <EmptyState message="No order trend data is available yet." />
              ) : (
                <div className="h-[300px]">
                  <Line data={ordersChartData} options={chartOptions} />
                </div>
              )}
            </div>
          </Card>

          <Card className="border border-slate-200 bg-white p-5">
            <SectionHeader
              icon={<UserPlus className="h-5 w-5" />}
              title="Registration trend"
              subtitle={`${registrationsBucketLabel} registration movement over the same reporting horizon.`}
            />

            <div className="mt-5">
              {registrationsTrendRows.length === 0 ? (
                <EmptyState message="No registration trend data is available yet." />
              ) : (
                <div className="h-[300px]">
                  <Line data={regsChartData} options={chartOptions} />
                </div>
              )}
            </div>
          </Card>
        </div>
      </div>
    </AdminLayout>
  );
}