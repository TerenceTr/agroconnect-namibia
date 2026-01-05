// ============================================================================
// src/pages/dashboards/farmer/FarmerProductsPage.jsx — Products (Inventory + Insights)
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Farmer products module (master’s-level structure).
//
// SECTIONS (your spec):
//   A) Manage Products (CRUD + filters + optional quick stock edit)
//   B) Top Products (Most Ordered - computed from farmer orders)
//   C) AI Trends (Demand Index) (safe placeholder if endpoint missing)
//   D) AI Stock Alerts (full list + filters; safe if endpoint missing)
//
// NOTE:
//   This file is designed to be robust even if some endpoints are not implemented yet.
//   It shows friendly “not available” states with Retry, without dev text.
// ============================================================================

import React, { useMemo, useState } from "react";
import { Plus, Search, Pencil, Trash2, Package, Star, RefreshCcw, AlertTriangle, BarChart3 } from "lucide-react";

import useApi from "../../../hooks/useApi";
import api from "../../../api";
import { useAuth } from "../../../components/auth/AuthProvider";
import FarmerLayout from "../../../components/FarmerLayout";

import Card, { CardHeader, CardTitle, CardContent } from "../../../components/ui/Card";
import EmptyState from "../../../components/ui/EmptyState";
import SimpleBarChart from "../../../components/ui/SimpleBarChart";

import AddProductModal from "../../../components/modals/AddProductModal";
import EditProductModal from "../../../components/modals/EditProductModal";
import DeleteProductModal from "../../../components/modals/DeleteProductModal";

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------
function toNumber(v, fallback = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}
function safeArray(v) {
  return Array.isArray(v) ? v : [];
}
function safeStr(v, fallback = "") {
  if (typeof v === "string") return v;
  if (v == null) return fallback;
  return String(v);
}
function getProductId(p) {
  return p?.id || p?.product_id || p?.productId || null;
}
function getOwnerId(p) {
  return p?.farmer_id || p?.user_id || p?.owner_id || p?.seller_id || null;
}
function getName(p) {
  return p?.product_name || p?.name || "Product";
}
function isLowStock(p, threshold = 5) {
  const qty = toNumber(p?.stock ?? p?.quantity ?? p?.qty ?? p?.units ?? 0, 0);
  return qty <= threshold;
}

function Stars({ value }) {
  const v = Math.max(0, Math.min(5, Number(value) || 0));
  const full = Math.round(v);
  return (
    <div className="flex items-center gap-1">
      {Array.from({ length: 5 }).map((_, i) => (
        <Star
          key={i}
          size={14}
          className={i < full ? "text-emerald-600 fill-emerald-600" : "text-slate-300"}
        />
      ))}
    </div>
  );
}

const TABS = [
  { key: "manage", label: "Manage Products" },
  { key: "top", label: "Top Products" },
  { key: "trends", label: "AI Trends" },
  { key: "alerts", label: "AI Stock Alerts" },
];

const LOW_STOCK_THRESHOLD = 5;

export default function FarmerProductsPage() {
  const { user } = useAuth();
  const farmerId = user?.id;

  const [tab, setTab] = useState("manage");

  // Manage filters
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState("all"); // all | available | unavailable
  const [lowOnly, setLowOnly] = useState(false);

  // CRUD modals
  const [addOpen, setAddOpen] = useState(false);
  const [editOpen, setEditOpen] = useState(false);
  const [editProduct, setEditProduct] = useState(null);
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [deleteProduct, setDeleteProduct] = useState(null);

  // Inline stock edits (optional)
  const [stockEdit, setStockEdit] = useState({}); // productId -> qty
  const [savingStock, setSavingStock] = useState(null); // productId
  const [stockError, setStockError] = useState("");

  // Base datasets
  const productsRes = useApi(["/products", farmerId ? `/farmer/${farmerId}/products` : null, "/farmer/products"].filter(Boolean), {
    enabled: Boolean(farmerId),
    params: { farmerId },
    initialData: undefined,
    deps: [farmerId],
  });

  const ratingsRes = useApi(
    [farmerId ? `/ratings/farmer/${farmerId}` : null, "/ratings/farmer", "/ratings"].filter(Boolean),
    {
      enabled: Boolean(farmerId),
      params: { farmerId, days: 90 },
      initialData: undefined,
      deps: [farmerId],
    }
  );

  const ordersRes = useApi(
    [farmerId ? `/orders/farmer/${farmerId}` : null, "/orders/farmer", "/orders"].filter(Boolean),
    {
      enabled: Boolean(farmerId),
      params: { farmerId, days: 90 },
      initialData: undefined,
      deps: [farmerId],
    }
  );

  // AI trends + alerts (optional endpoints; safe if missing)
  const trendsRes = useApi(["/ai/market-trends", "/ai/trends", "/ai/insights/trends"], {
    enabled: tab === "trends",
    params: { farmerId, days: 30 },
    initialData: undefined,
    deps: [tab, farmerId],
  });

  const alertsRes = useApi(["/ai/stock-alerts", "/ai/alerts/stock-alerts"], {
    enabled: tab === "alerts",
    params: { farmerId },
    initialData: undefined,
    deps: [tab, farmerId],
  });

  // Normalize arrays
  const allProducts = useMemo(() => {
    const raw = productsRes.data?.items ?? productsRes.data?.products ?? productsRes.data ?? [];
    return Array.isArray(raw) ? raw : [];
  }, [productsRes.data]);

  const allRatings = useMemo(() => {
    const raw = ratingsRes.data?.items ?? ratingsRes.data?.ratings ?? ratingsRes.data ?? [];
    return Array.isArray(raw) ? raw : [];
  }, [ratingsRes.data]);

  const allOrders = useMemo(() => {
    const raw = ordersRes.data?.items ?? ordersRes.data?.orders ?? ordersRes.data ?? [];
    return Array.isArray(raw) ? raw : [];
  }, [ordersRes.data]);

  const myProducts = useMemo(() => {
    if (!farmerId) return [];
    return allProducts.filter((p) => String(getOwnerId(p)) === String(farmerId));
  }, [allProducts, farmerId]);

  // Rating summary per product
  const ratingMap = useMemo(() => {
    const map = new Map(); // productId -> { sum, count }
    for (const r of allRatings) {
      const pid = r?.product_id ?? r?.productId ?? r?.product?.id;
      if (pid == null) continue;

      const score = toNumber(r?.rating_score ?? r?.rating ?? r?.score ?? 0, 0);
      const prev = map.get(String(pid)) || { sum: 0, count: 0 };
      map.set(String(pid), { sum: prev.sum + score, count: prev.count + 1 });
    }

    const out = new Map();
    for (const [pid, v] of map.entries()) {
      out.set(pid, { avg: v.count ? v.sum / v.count : 0, count: v.count });
    }
    return out;
  }, [allRatings]);

  // Manage view filtered list
  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return myProducts.filter((p) => {
      const matchesQuery = !q ? true : getName(p).toLowerCase().includes(q);

      const pStatus = String(p?.status || "available").toLowerCase();
      const matchesStatus =
        status === "all"
          ? true
          : status === "available"
          ? pStatus === "available"
          : pStatus !== "available";

      const matchesLow = !lowOnly ? true : isLowStock(p, LOW_STOCK_THRESHOLD);

      return matchesQuery && matchesStatus && matchesLow;
    });
  }, [myProducts, query, status, lowOnly]);

  // Top products: most ordered (best-effort grouping)
  const topMostOrdered = useMemo(() => {
    const myIds = new Set(myProducts.map((p) => String(getProductId(p) ?? "")));
    const counts = new Map(); // pid -> count

    for (const o of allOrders) {
      const pid = String(o?.product_id ?? o?.productId ?? o?.product?.id ?? "");
      if (!pid || !myIds.has(pid)) continue;
      counts.set(pid, (counts.get(pid) || 0) + 1);
    }

    return [...counts.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([pid, count]) => {
        const p = myProducts.find((x) => String(getProductId(x) ?? "") === pid);
        return {
          pid,
          name: getName(p),
          orders: count,
          stock: toNumber(p?.stock ?? p?.quantity ?? 0, 0),
        };
      });
  }, [allOrders, myProducts]);

  const openEdit = (p) => {
    setEditProduct(p);
    setEditOpen(true);
  };
  const openDelete = (p) => {
    setDeleteProduct(p);
    setDeleteOpen(true);
  };

  const onCreated = async () => {
    setAddOpen(false);
    await productsRes.refetch();
  };
  const onUpdated = async () => {
    setEditOpen(false);
    setEditProduct(null);
    await productsRes.refetch();
  };
  const onDeleted = async () => {
    setDeleteOpen(false);
    setDeleteProduct(null);
    await productsRes.refetch();
  };

  // Optional quick stock update
  const saveStock = async (p) => {
    const pid = getProductId(p);
    if (!pid) return;
    setStockError("");
    setSavingStock(pid);

    try {
      const nextQty = toNumber(stockEdit[String(pid)], toNumber(p?.quantity ?? p?.stock ?? 0, 0));

      // Common update endpoints:
      //   PUT /products/:id
      //   PATCH /products/:id
      // Adjust to match your backend.
      await api.patch(`/products/${pid}`, { quantity: nextQty });

      await productsRes.refetch();
    } catch (e) {
      // Friendly UI, detailed info goes to console only
      console.error("Stock update failed", e);
      setStockError("Couldn’t update stock right now. Please try again.");
    } finally {
      setSavingStock(null);
    }
  };

  return (
    <FarmerLayout>
      <div className="space-y-6">
        {/* Header */}
        <Card variant="surface">
          <CardHeader>
            <div>
              <CardTitle>Products</CardTitle>
              <p className="text-sm text-slate-600 mt-1">
                Inventory management, performance, and AI insights.
              </p>
            </div>

            <button
              type="button"
              onClick={() => setAddOpen(true)}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-emerald-600 text-white font-semibold hover:bg-emerald-700"
            >
              <Plus size={16} />
              Add Product
            </button>
          </CardHeader>

          <CardContent>
            {/* Tabs */}
            <div className="flex flex-wrap gap-2">
              {TABS.map((t) => (
                <button
                  key={t.key}
                  type="button"
                  onClick={() => setTab(t.key)}
                  className={[
                    "h-9 px-3 rounded-xl border text-sm font-semibold",
                    tab === t.key
                      ? "border-emerald-200 bg-emerald-50 text-emerald-800"
                      : "border-slate-200 bg-white text-slate-800 hover:bg-slate-50",
                  ].join(" ")}
                >
                  {t.label}
                </button>
              ))}
              <button
                type="button"
                onClick={() => {
                  productsRes.refetch();
                  ratingsRes.refetch();
                  ordersRes.refetch();
                  if (tab === "trends") trendsRes.refetch();
                  if (tab === "alerts") alertsRes.refetch();
                }}
                className="ml-auto h-9 px-3 rounded-xl border border-slate-200 bg-white hover:bg-slate-50 text-sm font-semibold text-slate-800 inline-flex items-center gap-2"
              >
                <RefreshCcw className="h-4 w-4" />
                Refresh
              </button>
            </div>
          </CardContent>
        </Card>

        {/* SECTION A: Manage */}
        {tab === "manage" && (
          <Card variant="surface">
            <CardHeader>
              <div className="flex items-center gap-2">
                <Package size={18} className="text-emerald-700" />
                <div>
                  <CardTitle>Manage Products</CardTitle>
                  <p className="text-xs text-slate-500 mt-1">
                    Showing {filtered.length} of {myProducts.length}
                  </p>
                </div>
              </div>
            </CardHeader>

            <CardContent>
              {/* Filters */}
              <div className="flex flex-col lg:flex-row lg:items-center gap-3 mb-4">
                <div className="flex-1">
                  <div className="flex items-center gap-2 bg-white rounded-2xl border border-slate-200 px-3 py-2 shadow-sm">
                    <Search size={18} className="text-slate-400" />
                    <input
                      value={query}
                      onChange={(e) => setQuery(e.target.value)}
                      placeholder="Search by product name…"
                      className="w-full outline-none text-sm text-slate-700"
                    />
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <span className="text-sm text-slate-600">Status:</span>
                  <select
                    value={status}
                    onChange={(e) => setStatus(e.target.value)}
                    className="bg-white border border-slate-200 text-slate-800 rounded-xl px-3 py-2 text-sm shadow-sm outline-none"
                  >
                    <option value="all">All</option>
                    <option value="available">Available</option>
                    <option value="unavailable">Unavailable</option>
                  </select>
                </div>

                <label className="inline-flex items-center gap-2 text-sm font-semibold text-slate-700">
                  <input type="checkbox" checked={lowOnly} onChange={(e) => setLowOnly(e.target.checked)} />
                  Low stock only (≤ {LOW_STOCK_THRESHOLD})
                </label>
              </div>

              {/* Errors (friendly) */}
              {productsRes.error ? (
                <div className="mb-4 rounded-xl border border-rose-200 bg-rose-50 p-3 text-sm text-rose-700 flex items-center justify-between gap-3">
                  <div>Couldn’t load products.</div>
                  <button
                    type="button"
                    onClick={productsRes.refetch}
                    className="h-9 px-3 rounded-xl bg-white border border-rose-200 text-rose-700 font-semibold"
                  >
                    Retry
                  </button>
                </div>
              ) : null}

              {stockError ? (
                <div className="mb-4 rounded-xl border border-amber-200 bg-amber-50 p-3 text-sm text-amber-800">
                  {stockError}
                </div>
              ) : null}

              {productsRes.loading ? (
                <p className="text-sm text-slate-500">Loading…</p>
              ) : filtered.length === 0 ? (
                <EmptyState message="No products found. Add your first product." />
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
                  {filtered.map((p) => {
                    const pid = getProductId(p);
                    const name = getName(p);

                    const price = toNumber(p?.price ?? 0, 0).toFixed(2);
                    const qty = toNumber(p?.quantity ?? p?.stock ?? 0, 0);
                    const pStatus = String(p?.status || "available").toLowerCase();

                    const badge =
                      pStatus === "available"
                        ? "bg-emerald-50 text-emerald-800 border-emerald-200"
                        : "bg-amber-50 text-amber-800 border-amber-200";

                    const rs = ratingMap.get(String(pid)) || { avg: 0, count: 0 };

                    return (
                      <div
                        key={String(pid)}
                        className="rounded-3xl border border-slate-200 bg-white shadow-sm overflow-hidden hover:shadow-md transition"
                      >
                        <div className="h-36 bg-slate-100">
                          {p?.image_url ? (
                            <img src={p.image_url} alt={name} className="w-full h-full object-cover" />
                          ) : (
                            <div className="w-full h-full flex items-center justify-center text-slate-400 text-sm">
                              No image
                            </div>
                          )}
                        </div>

                        <div className="p-4 space-y-3">
                          <div className="flex items-start justify-between gap-3">
                            <div className="min-w-0">
                              <div className="font-semibold text-slate-900 truncate">{name}</div>
                              <div className="text-xs text-slate-500 mt-1">
                                N$ {price} • Stock: {qty}
                              </div>

                              <div className="mt-2 flex items-center gap-2">
                                <Stars value={rs.avg} />
                                <span className="text-xs text-slate-500">
                                  {rs.count ? `${rs.avg.toFixed(1)} (${rs.count})` : "No reviews"}
                                </span>
                              </div>
                            </div>

                            <span className={`px-3 py-1 rounded-full text-xs font-semibold border ${badge}`}>
                              {pStatus}
                            </span>
                          </div>

                          {/* Optional quick stock update */}
                          <div className="rounded-xl border border-slate-200 p-3 bg-slate-50/50">
                            <div className="text-xs font-semibold text-slate-700 mb-2">Quick Stock Update</div>
                            <div className="flex items-center gap-2">
                              <input
                                type="number"
                                value={stockEdit[String(pid)] ?? qty}
                                onChange={(e) => setStockEdit((s) => ({ ...s, [String(pid)]: e.target.value }))}
                                className="h-9 w-28 px-2 rounded-lg border border-slate-200 bg-white text-sm"
                              />
                              <button
                                type="button"
                                onClick={() => saveStock(p)}
                                disabled={savingStock === pid}
                                className="h-9 px-3 rounded-xl bg-white border border-slate-200 hover:bg-slate-50 text-sm font-semibold text-slate-800 disabled:opacity-60"
                              >
                                {savingStock === pid ? "Saving…" : "Save"}
                              </button>

                              {isLowStock(p, LOW_STOCK_THRESHOLD) ? (
                                <span className="ml-auto inline-flex items-center gap-1 text-xs font-semibold px-2 py-1 rounded-full border border-amber-200 bg-amber-50 text-amber-800">
                                  <AlertTriangle className="h-3.5 w-3.5" />
                                  Low stock
                                </span>
                              ) : null}
                            </div>
                          </div>

                          {p?.description ? (
                            <p className="text-sm text-slate-600 line-clamp-2">{String(p.description)}</p>
                          ) : (
                            <p className="text-sm text-slate-400">No description</p>
                          )}

                          <div className="flex items-center justify-end gap-2 pt-1">
                            <button
                              type="button"
                              onClick={() => openEdit(p)}
                              className="inline-flex items-center gap-2 px-3 py-2 rounded-xl border border-slate-200 bg-white hover:bg-slate-50 text-slate-800 text-sm"
                            >
                              <Pencil size={16} />
                              Edit
                            </button>

                            <button
                              type="button"
                              onClick={() => openDelete(p)}
                              className="inline-flex items-center gap-2 px-3 py-2 rounded-xl bg-rose-600 hover:bg-rose-500 text-white text-sm"
                            >
                              <Trash2 size={16} />
                              Delete
                            </button>
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </CardContent>
          </Card>
        )}

        {/* SECTION B: Top Products */}
        {tab === "top" && (
          <Card variant="surface">
            <CardHeader>
              <div className="flex items-center gap-2">
                <BarChart3 size={18} className="text-emerald-700" />
                <div>
                  <CardTitle>Top Products</CardTitle>
                  <p className="text-xs text-slate-500 mt-1">Most ordered (range: last 90 days)</p>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              {ordersRes.error ? (
                <div className="rounded-xl border border-rose-200 bg-rose-50 p-3 text-sm text-rose-700 flex items-center justify-between gap-3">
                  <div>Couldn’t load orders to compute rankings.</div>
                  <button
                    type="button"
                    onClick={ordersRes.refetch}
                    className="h-9 px-3 rounded-xl bg-white border border-rose-200 text-rose-700 font-semibold"
                  >
                    Retry
                  </button>
                </div>
              ) : topMostOrdered.length === 0 ? (
                <EmptyState message="No rankings yet. Orders will appear here once customers purchase." />
              ) : (
                <ul className="space-y-2">
                  {topMostOrdered.map((r) => (
                    <li key={r.pid} className="rounded-xl border border-slate-200 bg-white p-4 flex items-center justify-between">
                      <div className="min-w-0">
                        <div className="text-sm font-extrabold text-slate-900 truncate">{r.name}</div>
                        <div className="text-xs text-slate-500">
                          Orders: <span className="font-semibold">{r.orders}</span>
                        </div>
                      </div>
                      <div className="text-xs text-slate-500">
                        Stock: <span className="font-semibold">{r.stock}</span>
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>
        )}

        {/* SECTION C: AI Trends */}
        {tab === "trends" && (
          <Card variant="surface">
            <CardHeader>
              <div className="flex items-center gap-2">
                <BarChart3 size={18} className="text-emerald-700" />
                <div>
                  <CardTitle>AI Trends (Demand Index)</CardTitle>
                  <p className="text-xs text-slate-500 mt-1">If not available yet, this will show “coming soon”.</p>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              {trendsRes.error ? (
                <div className="rounded-xl border border-amber-200 bg-amber-50 p-3 text-sm text-amber-800">
                  Demand trends are not available right now.
                </div>
              ) : trendsRes.loading ? (
                <div className="text-sm text-slate-600">Loading trends…</div>
              ) : (
                (() => {
                  const rows = safeArray(trendsRes.data?.series ?? trendsRes.data);
                  if (rows.length === 0) {
                    return <EmptyState message="Demand trends coming soon." />;
                  }
                  return (
                    <SimpleBarChart
                      labels={rows.map((x) => safeStr(x?.date ?? x?.label))}
                      values={rows.map((x) => toNumber(x?.demand_index ?? x?.value ?? 0, 0))}
                      height={280}
                      valuePrefix=""
                    />
                  );
                })()
              )}
            </CardContent>
          </Card>
        )}

        {/* SECTION D: AI Stock Alerts */}
        {tab === "alerts" && (
          <Card variant="surface">
            <CardHeader>
              <div className="flex items-center gap-2">
                <AlertTriangle size={18} className="text-emerald-700" />
                <div>
                  <CardTitle>AI Stock Alerts</CardTitle>
                  <p className="text-xs text-slate-500 mt-1">Model-based alerts for inventory risks.</p>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              {alertsRes.error ? (
                <div className="rounded-xl border border-rose-200 bg-rose-50 p-3 text-sm text-rose-700 flex items-center justify-between gap-3">
                  <div>Couldn’t load alerts.</div>
                  <button
                    type="button"
                    onClick={alertsRes.refetch}
                    className="h-9 px-3 rounded-xl bg-white border border-rose-200 text-rose-700 font-semibold"
                  >
                    Retry
                  </button>
                </div>
              ) : alertsRes.loading ? (
                <div className="text-sm text-slate-600">Loading alerts…</div>
              ) : (
                (() => {
                  const list = Array.isArray(alertsRes.data) ? alertsRes.data : safeArray(alertsRes.data?.alerts);
                  if (list.length === 0) return <EmptyState message="No alerts right now." />;

                  return (
                    <ul className="space-y-2">
                      {list.map((a, idx) => (
                        <li key={a?.id || idx} className="rounded-xl border border-slate-200 bg-white p-4">
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
            </CardContent>
          </Card>
        )}
      </div>

      {/* Modals */}
      <AddProductModal open={addOpen} onClose={() => setAddOpen(false)} onCreated={onCreated} />

      <EditProductModal
        open={editOpen}
        onClose={() => setEditOpen(false)}
        product={editProduct}
        onUpdated={onUpdated}
      />

      <DeleteProductModal
        open={deleteOpen}
        onClose={() => setDeleteOpen(false)}
        product={deleteProduct}
        onDeleted={onDeleted}
      />
    </FarmerLayout>
  );
}
