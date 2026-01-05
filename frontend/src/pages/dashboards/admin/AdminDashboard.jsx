// ============================================================================
// AdminDashboard.jsx — AgroConnect Namibia (Admin Overview)
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Admin governance dashboard for platform overview.
//   • Key totals (users/products/orders/avg rating)
//   • Recent activity lists (orders/registrations/reviews)
//   • Trend charts (orders + registrations)
//
// NOTE:
//   useApi supports fallback arrays and returns usedEndpoint.
// ============================================================================

import React, { useMemo } from "react";
import { Line } from "react-chartjs-2";
import {
  Users,
  ShoppingBasket,
  Package,
  Star,
  ClipboardList,
  UserPlus,
  MessageSquare,
} from "lucide-react";

import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Tooltip,
  Legend,
} from "chart.js";

import useApi from "../../../hooks/useApi";
import AdminLayout from "../../../components/AdminLayout";
import Card from "../../../components/ui/Card";
import EmptyState from "../../../components/ui/EmptyState";

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Tooltip, Legend);

// ---------------------------------------------------------------------------
// Null-safe helpers
// ---------------------------------------------------------------------------
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

// ---------------------------------------------------------------------------
// Endpoint list (fallback compatible across backend versions)
// ---------------------------------------------------------------------------
const OVERVIEW_ENDPOINTS = ["/admin/reports/overview", "/admin/overview"];

// ---------------------------------------------------------------------------
// Normalize backend response into ONE stable shape for the UI
// ---------------------------------------------------------------------------
function normalizeOverview(raw) {
  const d = raw && typeof raw === "object" ? raw : {};

  // Shape A (reports): { totals, recent, time_series }
  if (d.totals && (d.recent || d.time_series)) {
    return {
      totals: d.totals || {},
      recent: d.recent || {},
      time_series: d.time_series || {},
    };
  }

  // Shape B (older): { success, kpis, recent:{users/products/orders} }
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
    };
  }

  // Shape C fallback (unknown / partial)
  return {
    totals: d.totals || {},
    recent: d.recent || {},
    time_series: d.time_series || {},
  };
}

export default function AdminDashboard() {
  const { data: rawOverview, loading, error, status, refetch, usedEndpoint } = useApi(
    OVERVIEW_ENDPOINTS,
    { initialData: undefined }
  );

  const overview = useMemo(() => normalizeOverview(rawOverview), [rawOverview]);

  const totals = overview?.totals || {};
  const recent = overview?.recent || {};
  const ts = overview?.time_series || {};

  const totalUsers = safeNumber(totals.total_users);
  const totalProducts = safeNumber(totals.total_products);
  const totalOrders = safeNumber(totals.total_orders);

  const avgRating = safeNumber(totals.avg_rating);
  const ratingCount = safeNumber(totals.total_ratings);

  const recentOrders = safeArray(recent.recent_orders);
  const recentRegs = safeArray(recent.recent_registrations);
  const recentRatings = safeArray(recent.recent_ratings);

  const dailyOrders = safeArray(ts.daily_orders);
  const dailyRegs = safeArray(ts.daily_registrations);

  const ordersChartData = useMemo(() => {
    const labels = dailyOrders.map((x) => safeStr(x.date));
    const values = dailyOrders.map((x) => safeNumber(x.count));
    return {
      labels,
      datasets: [{ label: "Orders", data: values, borderWidth: 2, tension: 0.35, pointRadius: 2 }],
    };
  }, [dailyOrders]);

  const regsChartData = useMemo(() => {
    const labels = dailyRegs.map((x) => safeStr(x.date));
    const values = dailyRegs.map((x) => safeNumber(x.count));
    return {
      labels,
      datasets: [
        { label: "Registrations", data: values, borderWidth: 2, tension: 0.35, pointRadius: 2 },
      ],
    };
  }, [dailyRegs]);

  const chartOptions = useMemo(
    () => ({
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: true } },
    }),
    []
  );

  const AccentIconBox = ({ children }) => (
    <div className="h-10 w-10 rounded-2xl bg-white border border-[#B7E4C7] shadow-sm grid place-items-center">
      {children}
    </div>
  );

  return (
    <AdminLayout>
      <div className="space-y-6">
        {/* Header */}
        <Card className="p-6">
          <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3">
            <div>
              <div className="text-sm text-slate-500">AgroConnect Namibia</div>
              <h1 className="text-2xl font-extrabold text-slate-900">Admin Dashboard</h1>
              <p className="text-sm text-slate-600 mt-1">
                Governance overview for users, products, orders, and customer feedback.
              </p>

              {usedEndpoint ? (
                <div className="mt-2 text-xs text-slate-400">
                  Data source: <span className="font-semibold">{usedEndpoint}</span>
                </div>
              ) : null}
            </div>

            <div className="flex items-center gap-2">
              {error ? (
                <span className="inline-flex items-center gap-2 px-3 py-2 rounded-xl text-xs font-semibold border border-red-200 bg-red-50 text-red-700">
                  Failed to load overview
                </span>
              ) : null}

              <button type="button" onClick={refetch} className="btn-primary">
                Refresh
              </button>
            </div>
          </div>

          {error ? (
            <div className="mt-3 text-sm text-slate-600">
              {safeStr(error)} {status ? <span className="text-slate-400">(HTTP {status})</span> : null}
            </div>
          ) : null}
        </Card>

        {/* Totals */}
        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
          <Card className="p-4">
            <div className="flex items-center gap-3">
              <AccentIconBox>
                <Users className="h-5 w-5 text-[#2D6A4F]" />
              </AccentIconBox>
              <div>
                <div className="text-xs text-slate-500 font-semibold">Total Users</div>
                <div className="text-xl font-extrabold text-slate-900">{loading ? "…" : totalUsers}</div>
              </div>
            </div>
          </Card>

          <Card className="p-4">
            <div className="flex items-center gap-3">
              <AccentIconBox>
                <Package className="h-5 w-5 text-[#2D6A4F]" />
              </AccentIconBox>
              <div>
                <div className="text-xs text-slate-500 font-semibold">Total Products</div>
                <div className="text-xl font-extrabold text-slate-900">
                  {loading ? "…" : totalProducts}
                </div>
              </div>
            </div>
          </Card>

          <Card className="p-4">
            <div className="flex items-center gap-3">
              <AccentIconBox>
                <ShoppingBasket className="h-5 w-5 text-[#2D6A4F]" />
              </AccentIconBox>
              <div>
                <div className="text-xs text-slate-500 font-semibold">Total Orders</div>
                <div className="text-xl font-extrabold text-slate-900">{loading ? "…" : totalOrders}</div>
              </div>
            </div>
          </Card>

          <Card className="p-4">
            <div className="flex items-center gap-3">
              <AccentIconBox>
                <Star className="h-5 w-5 text-[#2D6A4F]" />
              </AccentIconBox>
              <div>
                <div className="text-xs text-slate-500 font-semibold">Avg Rating</div>
                <div className="text-xl font-extrabold text-slate-900">
                  {loading ? "…" : `${avgRating.toFixed(1)} / 5`}
                  <span className="text-sm text-slate-500 font-semibold"> ({ratingCount})</span>
                </div>
              </div>
            </div>
          </Card>
        </div>

        {/* Recent lists */}
        <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
          <Card className="p-4">
            <div className="flex items-center gap-2 mb-3">
              <ClipboardList className="h-5 w-5 text-[#2D6A4F]" />
              <h3 className="font-extrabold text-slate-900">Recent Orders</h3>
            </div>
            {loading ? (
              <div className="text-sm text-slate-600">Loading…</div>
            ) : recentOrders.length === 0 ? (
              <EmptyState message="No recent orders available." />
            ) : (
              <ul className="space-y-2">
                {recentOrders.slice(0, 6).map((o, idx) => (
                  <li key={o.id || idx} className="text-sm text-slate-700">
                    <span className="font-semibold text-slate-900">{safeStr(o.order_id || o.id || "Order")}</span>{" "}
                    — {safeStr(o.customer_name || o.buyer_name || o.customer || "Customer")}
                  </li>
                ))}
              </ul>
            )}
          </Card>

          <Card className="p-4">
            <div className="flex items-center gap-2 mb-3">
              <UserPlus className="h-5 w-5 text-[#2D6A4F]" />
              <h3 className="font-extrabold text-slate-900">Recent Registrations</h3>
            </div>
            {loading ? (
              <div className="text-sm text-slate-600">Loading…</div>
            ) : recentRegs.length === 0 ? (
              <EmptyState message="No recent registrations available." />
            ) : (
              <ul className="space-y-2">
                {recentRegs.slice(0, 6).map((u, idx) => (
                  <li key={u.id || idx} className="text-sm text-slate-700">
                    <span className="font-semibold text-slate-900">{safeStr(u.full_name || u.name || "User")}</span>{" "}
                    — {safeStr(u.email || "")}
                  </li>
                ))}
              </ul>
            )}
          </Card>

          <Card className="p-4">
            <div className="flex items-center gap-2 mb-3">
              <MessageSquare className="h-5 w-5 text-[#2D6A4F]" />
              <h3 className="font-extrabold text-slate-900">Latest Reviews</h3>
            </div>
            {loading ? (
              <div className="text-sm text-slate-600">Loading…</div>
            ) : recentRatings.length === 0 ? (
              <EmptyState message="No recent reviews available." />
            ) : (
              <ul className="space-y-2">
                {recentRatings.slice(0, 6).map((r, idx) => (
                  <li key={r.id || idx} className="text-sm text-slate-700">
                    <span className="font-semibold text-slate-900">{safeStr(r.customer_name || "Customer")}</span>{" "}
                    rated <span className="font-semibold text-slate-900">{safeNumber(r.rating)}</span>/5 —{" "}
                    {safeStr(r.product_name || "")}
                  </li>
                ))}
              </ul>
            )}
          </Card>
        </div>

        {/* Trends */}
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          <Card className="p-4">
            <div className="flex items-center gap-2 mb-3">
              <ClipboardList className="h-5 w-5 text-[#2D6A4F]" />
              <h3 className="font-extrabold text-slate-900">Orders Trend</h3>
            </div>
            {dailyOrders.length === 0 ? (
              <EmptyState message="No order time-series available." />
            ) : (
              <div className="h-[260px]">
                <Line data={ordersChartData} options={chartOptions} />
              </div>
            )}
          </Card>

          <Card className="p-4">
            <div className="flex items-center gap-2 mb-3">
              <UserPlus className="h-5 w-5 text-[#2D6A4F]" />
              <h3 className="font-extrabold text-slate-900">Registration Trend</h3>
            </div>
            {dailyRegs.length === 0 ? (
              <EmptyState message="No registration time-series available." />
            ) : (
              <div className="h-[260px]">
                <Line data={regsChartData} options={chartOptions} />
              </div>
            )}
          </Card>
        </div>
      </div>
    </AdminLayout>
  );
}
