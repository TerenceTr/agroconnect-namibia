// ============================================================================
// src/pages/dashboards/farmer/FarmerDashboard.jsx — Farmer Overview (NEW IA)
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Farmer "Dashboard" is now the Overview page.
//   Route: /dashboard/farmer/overview
//
// RESPONSIBILITIES:
//   • Header: title + range + search + refresh + manage products + add product
//   • KPI row (SPEC metrics)
//   • Main grid:
//       Left (wide): Revenue trend chart (paid only)
//       Right (stacked): Recent Orders, Top Products snapshot, AI Alerts snapshot (top 3)
//   • No dev warning banners; per-widget error states + Retry
//
// UI UPDATE:
//   ✅ Matches reference style: neutral canvas + crisp white cards + soft emerald accents
//   ✅ Adds search icon + consistent button hierarchy
//
// CRITICAL FIX (runtime issues you saw):
//   ✅ No Chart.js usage here (uses SimpleBarChart only)
//   ✅ Null-safe helpers everywhere
// ============================================================================

import React, { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Plus, RefreshCcw, ArrowRight, AlertTriangle, Search } from "lucide-react";

import FarmerLayout from "../../../components/FarmerLayout";
import { useAuth } from "../../../components/auth/AuthProvider";
import useApi from "../../../hooks/useApi";

import SimpleBarChart from "../../../components/ui/SimpleBarChart";
import FarmerKpiRow from "./dashboard/FarmerKpiRow";
import AddProductModal from "../../../components/modals/AddProductModal";

// ----------------------------------------------------------------------------
// Null-safe helpers
// ----------------------------------------------------------------------------
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
function dateKey(d) {
  try {
    const dt = new Date(d);
    if (Number.isNaN(dt.getTime())) return null;
    return dt.toISOString().slice(0, 10);
  } catch {
    return null;
  }
}

// ----------------------------------------------------------------------------
// Range options
// ----------------------------------------------------------------------------
const TIME_WINDOWS = [
  { label: "Last 7 days", value: 7 },
  { label: "Last 30 days", value: 30 },
  { label: "Last 90 days", value: 90 },
];

const LOW_STOCK_THRESHOLD = 5;

// ----------------------------------------------------------------------------
// Endpoints (fallback compatible across backend versions)
// ----------------------------------------------------------------------------
const epOverview = (farmerId) =>
  [
    `/farmer/overview`,
    `/farmer/reports/overview`,
    `/farmer/dashboard/overview`,
    farmerId ? `/farmer/${farmerId}/overview` : null,
  ].filter(Boolean);

const epProducts = (farmerId) =>
  [`/products`, farmerId ? `/farmer/${farmerId}/products` : null, `/farmer/products`].filter(Boolean);

const epOrders = (farmerId) =>
  [farmerId ? `/orders/farmer/${farmerId}` : null, `/orders/farmer`, `/orders`].filter(Boolean);

const epRatings = (farmerId) =>
  [farmerId ? `/ratings/farmer/${farmerId}` : null, `/ratings/farmer`, `/farmer/ratings`, `/ratings`].filter(Boolean);

const epAiAlerts = (farmerId) =>
  [`/ai/stock-alerts`, farmerId ? `/ai/stock-alerts/${farmerId}` : null, `/ai/alerts/stock-alerts`].filter(Boolean);

// ----------------------------------------------------------------------------
// Domain helpers
// ----------------------------------------------------------------------------
function isPaid(order) {
  const p =
    order?.payment_status ??
    order?.paymentStatus ??
    order?.payment ??
    order?.paid ??
    order?.is_paid;

  if (typeof p === "boolean") return p;
  const s = String(p || "").toLowerCase();
  return s === "paid" || s === "success" || s === "completed" || s === "true";
}

function orderTotal(order) {
  return (
    safeNumber(order?.total) ||
    safeNumber(order?.amount) ||
    safeNumber(order?.total_amount) ||
    safeNumber(order?.totalAmount) ||
    0
  );
}

export default function FarmerDashboard() {
  const nav = useNavigate();
  const { user, logout } = useAuth();
  const farmerId = user?.id;

  const [days, setDays] = useState(7);
  const [query, setQuery] = useState("");
  const [addOpen, setAddOpen] = useState(false);

  // Memoize params to avoid object-identity refetch storms
  const overviewParams = useMemo(() => ({ farmerId, days, q: query }), [farmerId, days, query]);
  const ordersParams = useMemo(() => ({ farmerId, days, q: query }), [farmerId, days, query]);
  const ratingsParams = useMemo(() => ({ farmerId, days }), [farmerId, days]);
  const alertsParams = useMemo(() => ({ farmerId, limit: 3 }), [farmerId]);

  // 1) Try master endpoint first
  const overviewRes = useApi(epOverview(farmerId), {
    enabled: Boolean(farmerId),
    params: overviewParams,
    initialData: undefined,
    deps: [farmerId, days, query],
  });

  const overviewFailed = Boolean(overviewRes.error);

  // 2) Fallback sources (only when overview fails)
  const productsRes = useApi(epProducts(farmerId), {
    enabled: Boolean(farmerId) && overviewFailed,
    params: { farmerId },
    initialData: undefined,
    deps: [farmerId, overviewFailed],
  });

  const ordersRes = useApi(epOrders(farmerId), {
    enabled: Boolean(farmerId) && overviewFailed,
    params: ordersParams,
    initialData: undefined,
    deps: [farmerId, days, query, overviewFailed],
  });

  const ratingsRes = useApi(epRatings(farmerId), {
    enabled: Boolean(farmerId) && overviewFailed,
    params: ratingsParams,
    initialData: undefined,
    deps: [farmerId, days, overviewFailed],
  });

  // AI alerts snapshot (top 3)
  const alertsRes = useApi(epAiAlerts(farmerId), {
    enabled: Boolean(farmerId),
    params: alertsParams,
    initialData: undefined,
    deps: [farmerId],
  });

  // ----------------------------------------------------------------------------
  // Normalize overview response OR compute fallback aggregation
  // ----------------------------------------------------------------------------
  const normalized = useMemo(() => {
    // If overview worked, respect its shape (master endpoint)
    if (overviewRes.data && !overviewRes.error) {
      const d = overviewRes.data;
      return {
        from: "overview",
        productCount: safeNumber(d.product_count),
        ordersReceived: safeNumber(d.orders_received_count),
        revenuePaidTotal: safeNumber(d.revenue_paid_total),
        avgRating: safeNumber(d.avg_rating),
        feedbackCount: safeNumber(d.feedback_count),
        farmerRankLabel: d.farmer_rank ? safeStr(d.farmer_rank) : "—",
        lowStockCount:
          d.low_stock_count === undefined || d.low_stock_count === null
            ? null
            : safeNumber(d.low_stock_count),
        revenueByDay: safeArray(d.revenue_by_day),
        recentOrders: safeArray(d.recent_orders),
        topProducts: safeArray(d.top_products),
      };
    }

    // Fallback aggregation (best effort)
    const productsRaw = productsRes.data;
    const ordersRaw = ordersRes.data;
    const ratingsRaw = ratingsRes.data;

    const products = Array.isArray(productsRaw)
      ? productsRaw
      : safeArray(productsRaw?.products ?? productsRaw?.items);
    const orders = Array.isArray(ordersRaw)
      ? ordersRaw
      : safeArray(ordersRaw?.orders ?? ordersRaw?.items);
    const ratings = Array.isArray(ratingsRaw)
      ? ratingsRaw
      : safeArray(ratingsRaw?.ratings ?? ratingsRaw?.items);

    // Farmer-owned products
    const myProducts = products.filter((p) => {
      const owner = p?.farmer_id ?? p?.farmerId ?? p?.owner_id ?? p?.ownerId ?? p?.user_id;
      return String(owner || "") === String(farmerId || "");
    });

    const myProductIds = new Set(myProducts.map((p) => String(p?.id ?? p?.product_id ?? "")));

    // Farmer sales orders (best effort)
    const myOrders = orders.filter((o) => {
      const direct = o?.farmer_id ?? o?.farmerId;
      if (String(direct || "") === String(farmerId || "")) return true;

      const pid = String(o?.product_id ?? o?.productId ?? o?.product?.id ?? "");
      if (pid && myProductIds.has(pid)) return true;

      const nestedOwner =
        o?.product?.farmer_id ?? o?.product?.farmerId ?? o?.product?.owner_id ?? o?.product?.ownerId;
      if (String(nestedOwner || "") === String(farmerId || "")) return true;

      return false;
    });

    // Search filter (product/buyer/order id)
    const q = query.trim().toLowerCase();
    const filteredOrders = !q
      ? myOrders
      : myOrders.filter((o) => {
          const oid = safeStr(o?.order_id ?? o?.id ?? "");
          const buyer = safeStr(o?.buyer_name ?? o?.customer_name ?? o?.customer ?? "");
          const productName = safeStr(o?.product_name ?? o?.product?.name ?? o?.product ?? "");
          return (
            oid.toLowerCase().includes(q) ||
            buyer.toLowerCase().includes(q) ||
            productName.toLowerCase().includes(q)
          );
        });

    const paidOrders = filteredOrders.filter(isPaid);

    // Ratings for farmer products
    const myRatings = ratings.filter((r) => {
      const direct = r?.farmer_id ?? r?.farmerId;
      if (String(direct || "") === String(farmerId || "")) return true;

      const pid = String(r?.product_id ?? r?.productId ?? r?.product?.id ?? "");
      if (pid && myProductIds.has(pid)) return true;

      return false;
    });

    const ratingVals = myRatings
      .map((r) => safeNumber(r?.rating ?? r?.score))
      .filter((n) => n > 0);

    const avgRating = ratingVals.length
      ? ratingVals.reduce((a, b) => a + b, 0) / ratingVals.length
      : 0;

    const revenuePaidTotal = paidOrders.reduce((sum, o) => sum + orderTotal(o), 0);
    const ordersReceived = filteredOrders.length;

    const lowStockCount = myProducts.filter((p) => {
      const qty = safeNumber(p?.stock ?? p?.quantity ?? p?.qty ?? p?.units);
      return qty <= LOW_STOCK_THRESHOLD;
    }).length;

    // Revenue by day
    const revMap = new Map();
    for (const o of paidOrders) {
      const dk = dateKey(o?.created_at ?? o?.date ?? o?.createdAt);
      if (!dk) continue;
      revMap.set(dk, (revMap.get(dk) || 0) + orderTotal(o));
    }
    const revenueByDay = Array.from(revMap.entries())
      .sort((a, b) => a[0].localeCompare(b[0]))
      .map(([date, value]) => ({ date, value }));

    // Recent orders
    const recentOrders = [...filteredOrders]
      .sort((a, b) => {
        const ta = new Date(a?.created_at ?? a?.date ?? 0).getTime();
        const tb = new Date(b?.created_at ?? b?.date ?? 0).getTime();
        return tb - ta;
      })
      .slice(0, 6);

    // Top products snapshot: most ordered in range
    const countByPid = new Map();
    for (const o of filteredOrders) {
      const pid = String(o?.product_id ?? o?.productId ?? o?.product?.id ?? "");
      if (!pid) continue;
      countByPid.set(pid, (countByPid.get(pid) || 0) + 1);
    }

    const topProducts = [...countByPid.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([pid, count]) => {
        const p = myProducts.find((x) => String(x?.id ?? x?.product_id ?? "") === pid);
        return {
          product_id: pid,
          name: p?.name ?? p?.product_name ?? "Product",
          orders: count,
          stock: safeNumber(p?.stock ?? p?.quantity ?? p?.qty ?? p?.units),
        };
      });

    return {
      from: "fallback",
      productCount: myProducts.length,
      ordersReceived,
      revenuePaidTotal,
      avgRating,
      feedbackCount: myRatings.length,
      farmerRankLabel: "—",
      lowStockCount,
      revenueByDay,
      recentOrders,
      topProducts,
    };
  }, [
    farmerId,
    query,
    overviewRes.data,
    overviewRes.error,
    productsRes.data,
    ordersRes.data,
    ratingsRes.data,
  ]);

  const rangeLabel = TIME_WINDOWS.find((t) => t.value === days)?.label || `Last ${days} days`;

  const loading =
    overviewRes.loading ||
    (overviewFailed && (productsRes.loading || ordersRes.loading || ratingsRes.loading));

  const showFallbackNotice = overviewFailed && normalized.from === "fallback";

  const onLogout = () => {
    logout();
    nav("/login");
  };

  const onRefresh = () => {
    overviewRes.refetch();
    if (overviewFailed) {
      productsRes.refetch();
      ordersRes.refetch();
      ratingsRes.refetch();
    }
    alertsRes.refetch();
  };

  return (
    <FarmerLayout>
      <div className="space-y-6">
        {/* Header */}
        <div className="rounded-3xl bg-white border border-slate-200 shadow-sm p-6">
          <div className="flex flex-col xl:flex-row xl:items-center xl:justify-between gap-4">
            <div className="min-w-0">
              <div className="text-xs text-slate-500">AgroConnect Namibia</div>
              <h1 className="text-2xl font-extrabold text-slate-900">Farmer Overview</h1>
              <p className="text-sm text-slate-600 mt-1">
                Performance snapshot • <span className="font-semibold">{rangeLabel}</span>
              </p>

              {showFallbackNotice ? (
                <div className="mt-3 inline-flex items-center gap-2 text-xs font-semibold px-3 py-1 rounded-full border border-amber-200 bg-amber-50 text-amber-800">
                  <AlertTriangle className="h-4 w-4" />
                  Partial data source (fallback)
                </div>
              ) : null}
            </div>

            <div className="flex flex-wrap items-center gap-2 justify-start xl:justify-end">
              {/* Range */}
              <select
                value={days}
                onChange={(e) => setDays(Number(e.target.value))}
                className="h-10 px-3 rounded-2xl border border-slate-200 bg-white text-sm font-semibold text-slate-800"
              >
                {TIME_WINDOWS.map((t) => (
                  <option key={t.value} value={t.value}>
                    {t.label}
                  </option>
                ))}
              </select>

              {/* Search */}
              <div className="h-10 w-[280px] max-w-full rounded-2xl border border-slate-200 bg-white px-3 flex items-center gap-2">
                <Search className="h-4 w-4 text-slate-400" />
                <input
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder="Search products, orders, buyers…"
                  className="w-full outline-none text-sm text-slate-800"
                />
              </div>

              <button
                type="button"
                onClick={onRefresh}
                className="h-10 px-4 rounded-2xl border border-slate-200 bg-white hover:bg-slate-50 text-sm font-semibold text-slate-800 inline-flex items-center gap-2"
              >
                <RefreshCcw className="h-4 w-4" />
                Refresh
              </button>

              <button
                type="button"
                onClick={() => nav("/dashboard/farmer/products")}
                className="h-10 px-4 rounded-2xl border border-slate-200 bg-white hover:bg-slate-50 text-sm font-semibold text-slate-800 inline-flex items-center gap-2"
              >
                Manage Products <ArrowRight className="h-4 w-4" />
              </button>

              <button
                type="button"
                onClick={() => setAddOpen(true)}
                className="h-10 px-4 rounded-2xl bg-emerald-600 hover:bg-emerald-700 text-white text-sm font-semibold inline-flex items-center gap-2 shadow-sm"
              >
                <Plus className="h-4 w-4" />
                Add Product
              </button>

              <button
                type="button"
                onClick={onLogout}
                className="h-10 px-4 rounded-2xl border border-slate-200 bg-white hover:bg-slate-50 text-sm font-semibold text-slate-800"
              >
                Logout
              </button>
            </div>
          </div>
        </div>

        {/* KPI Row (SPEC) */}
        <FarmerKpiRow
          loading={loading}
          rangeLabel={rangeLabel}
          productCount={normalized.productCount}
          ordersReceived={normalized.ordersReceived}
          revenuePaidTotal={normalized.revenuePaidTotal}
          avgRating={normalized.avgRating}
          feedbackCount={normalized.feedbackCount}
          farmerRankLabel={normalized.farmerRankLabel}
          lowStockCount={normalized.lowStockCount}
          currencyPrefix="N$ "
        />

        {/* Main grid */}
        <div className="grid grid-cols-1 xl:grid-cols-12 gap-6">
          {/* Left: Revenue trend */}
          <div className="xl:col-span-8 rounded-3xl bg-white border border-slate-200 shadow-sm p-4">
            <div className="flex items-center justify-between gap-3 mb-2">
              <div>
                <div className="text-sm font-extrabold text-slate-900">Revenue Trend</div>
                <div className="text-xs text-slate-500">Paid orders only • {rangeLabel}</div>
              </div>

              {overviewRes.error ? (
                <button
                  type="button"
                  onClick={overviewRes.refetch}
                  className="h-9 px-3 rounded-2xl border border-slate-200 bg-white hover:bg-slate-50 text-sm font-semibold text-slate-800"
                >
                  Retry
                </button>
              ) : null}
            </div>

            <SimpleBarChart
              labels={safeArray(normalized.revenueByDay).map((r) => safeStr(r?.date))}
              values={safeArray(normalized.revenueByDay).map((r) => safeNumber(r?.value))}
              height={280}
              valuePrefix="N$ "
            />
          </div>

          {/* Right stack */}
          <div className="xl:col-span-4 space-y-6">
            {/* Recent Orders */}
            <div className="rounded-3xl bg-white border border-slate-200 shadow-sm p-4">
              <div className="flex items-center justify-between gap-3 mb-3">
                <div>
                  <div className="text-sm font-extrabold text-slate-900">Recent Orders</div>
                  <div className="text-xs text-slate-500">Most recent sales orders</div>
                </div>
                <button
                  type="button"
                  onClick={() => nav("/dashboard/farmer/orders")}
                  className="text-sm font-semibold text-emerald-700 hover:text-emerald-800"
                >
                  View
                </button>
              </div>

              {overviewFailed && ordersRes.error ? (
                <div className="rounded-2xl border border-rose-200 bg-rose-50 p-3 text-sm text-rose-700 flex items-center justify-between gap-3">
                  <div>Couldn’t load orders.</div>
                  <button
                    type="button"
                    onClick={ordersRes.refetch}
                    className="h-9 px-3 rounded-2xl bg-white border border-rose-200 text-rose-700 font-semibold"
                  >
                    Retry
                  </button>
                </div>
              ) : safeArray(normalized.recentOrders).length === 0 ? (
                <div className="text-sm text-slate-500">No recent orders.</div>
              ) : (
                <ul className="space-y-2">
                  {safeArray(normalized.recentOrders).slice(0, 6).map((o, idx) => {
                    const oid = safeStr(o?.order_id ?? o?.id ?? "Order");
                    const buyer = safeStr(o?.buyer_name ?? o?.customer_name ?? o?.customer ?? "Buyer");
                    const total = orderTotal(o);
                    return (
                      <li key={`${oid}-${idx}`} className="rounded-2xl border border-slate-200 p-3">
                        <div className="flex items-start justify-between gap-3">
                          <div className="min-w-0">
                            <div className="text-sm font-extrabold text-slate-900 truncate">{oid}</div>
                            <div className="text-xs text-slate-500 truncate">{buyer}</div>
                          </div>
                          <div className="text-sm font-extrabold text-slate-900">N$ {total.toFixed(2)}</div>
                        </div>
                      </li>
                    );
                  })}
                </ul>
              )}
            </div>

            {/* Top Products snapshot */}
            <div className="rounded-3xl bg-white border border-slate-200 shadow-sm p-4">
              <div className="flex items-center justify-between gap-3 mb-3">
                <div>
                  <div className="text-sm font-extrabold text-slate-900">Top Products</div>
                  <div className="text-xs text-slate-500">Most ordered in range</div>
                </div>
                <button
                  type="button"
                  onClick={() => nav("/dashboard/farmer/products")}
                  className="text-sm font-semibold text-emerald-700 hover:text-emerald-800"
                >
                  View
                </button>
              </div>

              {safeArray(normalized.topProducts).length === 0 ? (
                <div className="text-sm text-slate-500">No products yet. Add your first product.</div>
              ) : (
                <ul className="space-y-2">
                  {safeArray(normalized.topProducts).slice(0, 5).map((p, idx) => (
                    <li key={`${p?.product_id || idx}`} className="rounded-2xl border border-slate-200 p-3">
                      <div className="flex items-center justify-between gap-3">
                        <div className="min-w-0">
                          <div className="text-sm font-extrabold text-slate-900 truncate">
                            {safeStr(p?.name ?? "Product")}
                          </div>
                          <div className="text-xs text-slate-500">
                            Orders: <span className="font-semibold">{safeNumber(p?.orders)}</span>
                          </div>
                        </div>
                        <div className="text-xs text-slate-500">
                          Stock: <span className="font-semibold">{safeNumber(p?.stock)}</span>
                        </div>
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </div>

            {/* AI Alerts snapshot */}
            <div className="rounded-3xl bg-white border border-slate-200 shadow-sm p-4">
              <div className="flex items-center justify-between gap-3 mb-3">
                <div>
                  <div className="text-sm font-extrabold text-slate-900">AI Alerts</div>
                  <div className="text-xs text-slate-500">Top alerts (model output)</div>
                </div>
                <button
                  type="button"
                  onClick={() => nav("/dashboard/farmer/products")}
                  className="text-sm font-semibold text-emerald-700 hover:text-emerald-800"
                >
                  View all
                </button>
              </div>

              {alertsRes.error ? (
                <div className="rounded-2xl border border-rose-200 bg-rose-50 p-3 text-sm text-rose-700 flex items-center justify-between gap-3">
                  <div>Couldn’t load alerts.</div>
                  <button
                    type="button"
                    onClick={alertsRes.refetch}
                    className="h-9 px-3 rounded-2xl bg-white border border-rose-200 text-rose-700 font-semibold"
                  >
                    Retry
                  </button>
                </div>
              ) : alertsRes.loading ? (
                <div className="text-sm text-slate-600">Loading alerts…</div>
              ) : (
                (() => {
                  const list = Array.isArray(alertsRes.data)
                    ? alertsRes.data
                    : safeArray(alertsRes.data?.alerts);

                  if (list.length === 0) return <div className="text-sm text-slate-500">No alerts right now.</div>;

                  return (
                    <ul className="space-y-2">
                      {list.slice(0, 3).map((a, idx) => (
                        <li key={a?.id || idx} className="rounded-2xl border border-slate-200 p-3">
                          <div className="text-sm font-extrabold text-slate-900">
                            {safeStr(a?.title ?? a?.product_name ?? "Stock alert")}
                          </div>
                          <div className="text-xs text-slate-500 mt-1">
                            {safeStr(a?.message ?? a?.reason ?? "Attention needed")}
                          </div>
                        </li>
                      ))}
                    </ul>
                  );
                })()
              )}
            </div>
          </div>
        </div>
      </div>

      <AddProductModal
        open={addOpen}
        onClose={() => setAddOpen(false)}
        onCreated={() => {
          setAddOpen(false);
          onRefresh();
        }}
      />
    </FarmerLayout>
  );
}
