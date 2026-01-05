// ============================================================================
// src/pages/dashboards/farmer/FarmerOrdersPage.jsx — Farmer Orders (Stable Page)
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Dedicated Orders workflow page (filters + table + order details drawer).
//
// WHY THIS FILE EXISTS:
//   The Orders route must never crash / must never “chunk fail” from runtime code.
//   Keep dependencies light and UI consistent with the new neutral/green shell.
//
// RESPONSIBILITIES:
//   • Fetch farmer orders (supports fallback endpoints)
//   • Provide time-window filter + search
//   • Render a stable table (null-safe)
//   • Provide a lightweight details drawer (no extra deps)
// ============================================================================

import React, { useMemo, useState } from "react";
import { Search, RefreshCcw, X } from "lucide-react";

import FarmerLayout from "../../../components/FarmerLayout";
import { useAuth } from "../../../components/auth/AuthProvider";
import useApi from "../../../hooks/useApi";

// --------------------------------------------------------------------
// Null-safe helpers (defensive UI: never crash)
// --------------------------------------------------------------------
function safeArray(v) {
  return Array.isArray(v) ? v : [];
}
function safeStr(v, fallback = "") {
  if (typeof v === "string") return v;
  if (v == null) return fallback;
  return String(v);
}
function safeNumber(v, fallback = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}
function formatDate(v) {
  const s = safeStr(v, "—");
  if (s === "—") return s;
  try {
    const d = new Date(s);
    if (Number.isNaN(d.getTime())) return s;
    return d.toLocaleDateString();
  } catch {
    return s;
  }
}

const TIME_WINDOWS = [
  { label: "Last 7 days", value: 7 },
  { label: "Last 30 days", value: 30 },
  { label: "Last 90 days", value: 90 },
];

// Endpoint fallback list (backend variations)
const epOrders = (farmerId) =>
  [
    farmerId ? `/orders/farmer/${farmerId}` : null, // preferred (RESTful)
    `/orders/farmer`, // older fallback
    `/orders`, // legacy fallback
  ].filter(Boolean);

export default function FarmerOrdersPage() {
  const { user } = useAuth();
  const farmerId = user?.id;

  const [days, setDays] = useState(30);
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState(null);

  const res = useApi(epOrders(farmerId), {
    enabled: Boolean(farmerId),
    params: { farmerId, days, q: query },
    initialData: undefined,
    deps: [farmerId, days, query],
  });

  const rows = useMemo(() => {
    const raw = res.data?.orders ?? res.data?.items ?? res.data ?? [];
    const list = Array.isArray(raw) ? raw : [];
    const q = query.trim().toLowerCase();

    if (!q) return list;

    return list.filter((o) => {
      const oid = safeStr(o?.order_id ?? o?.id ?? "");
      const buyer = safeStr(o?.buyer_name ?? o?.customer_name ?? o?.customer ?? "");
      const product = safeStr(o?.product_name ?? o?.product?.name ?? "");
      return (
        oid.toLowerCase().includes(q) ||
        buyer.toLowerCase().includes(q) ||
        product.toLowerCase().includes(q)
      );
    });
  }, [res.data, query]);

  // Selected order (normalized display fields)
  const selectedView = useMemo(() => {
    const o = selected && typeof selected === "object" ? selected : null;
    if (!o) return null;

    const oid = safeStr(o.order_id ?? o.id ?? "Order");
    const buyer = safeStr(o.buyer_name ?? o.customer_name ?? o.customer ?? "—");
    const product = safeStr(o.product_name ?? o.product?.name ?? "—");
    const total = safeNumber(o.total ?? o.amount ?? o.total_amount ?? 0, 0);
    const pay = safeStr(o.payment_status ?? o.paymentStatus ?? o.payment ?? "—");
    const date = formatDate(o.created_at ?? o.date ?? o.createdAt ?? "—");

    const qty = safeNumber(o.quantity ?? o.qty ?? 0, 0);
    const status = safeStr(o.status ?? o.order_status ?? "—");
    const phone = safeStr(o.customer_phone ?? o.buyer_phone ?? "—");
    const address = safeStr(o.delivery_address ?? o.address ?? "—");

    return { oid, buyer, product, total, pay, date, qty, status, phone, address, raw: o };
  }, [selected]);

  const closeDrawer = () => setSelected(null);

  return (
    <FarmerLayout>
      <div className="space-y-6">
        {/* Header */}
        <div className="rounded-3xl bg-white border border-slate-200 shadow-sm p-6">
          <div className="flex flex-col xl:flex-row xl:items-center xl:justify-between gap-4">
            <div>
              <div className="text-xs text-slate-500">Farmer</div>
              <h1 className="text-2xl font-extrabold text-slate-900">Orders</h1>
              <p className="text-sm text-slate-600 mt-1">Search and review your recent sales orders.</p>
            </div>

            <div className="flex flex-wrap items-center gap-2">
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

              <div className="h-10 w-[280px] max-w-full rounded-2xl border border-slate-200 bg-white px-3 flex items-center gap-2">
                <Search className="h-4 w-4 text-slate-400" />
                <input
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder="Search order id, buyer, product…"
                  className="w-full outline-none text-sm text-slate-800"
                />
              </div>

              <button
                type="button"
                onClick={() => res.refetch?.()}
                className="h-10 px-4 rounded-2xl border border-slate-200 bg-white hover:bg-slate-50 text-sm font-semibold text-slate-800 inline-flex items-center gap-2"
              >
                <RefreshCcw className="h-4 w-4" />
                Refresh
              </button>
            </div>
          </div>
        </div>

        {/* Table */}
        <div className="rounded-3xl bg-white border border-slate-200 shadow-sm overflow-hidden">
          {res.error ? (
            <div className="p-4 text-sm text-rose-700 bg-rose-50 border-b border-rose-200 flex items-center justify-between gap-3">
              <div>Couldn’t load orders.</div>
              <button
                type="button"
                onClick={() => res.refetch?.()}
                className="h-9 px-3 rounded-2xl bg-white border border-rose-200 text-rose-700 font-semibold"
              >
                Retry
              </button>
            </div>
          ) : null}

          <div className="p-4">
            {res.loading ? (
              <div className="text-sm text-slate-600">Loading…</div>
            ) : safeArray(rows).length === 0 ? (
              <div className="text-sm text-slate-500">No orders found.</div>
            ) : (
              <div className="overflow-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="text-left text-slate-500 border-b border-slate-200">
                      <th className="py-2 pr-4">Order</th>
                      <th className="py-2 pr-4">Buyer</th>
                      <th className="py-2 pr-4">Product</th>
                      <th className="py-2 pr-4">Total</th>
                      <th className="py-2 pr-4">Payment</th>
                      <th className="py-2 pr-2">Date</th>
                    </tr>
                  </thead>
                  <tbody>
                    {safeArray(rows).slice(0, 100).map((o, idx) => {
                      const oid = safeStr(o?.order_id ?? o?.id ?? `#${idx + 1}`);
                      const buyer = safeStr(o?.buyer_name ?? o?.customer_name ?? o?.customer ?? "—");
                      const product = safeStr(o?.product_name ?? o?.product?.name ?? "—");
                      const total = safeNumber(o?.total ?? o?.amount ?? o?.total_amount ?? 0, 0);
                      const pay = safeStr(o?.payment_status ?? o?.paymentStatus ?? o?.payment ?? "—");
                      const date = formatDate(o?.created_at ?? o?.date ?? o?.createdAt ?? "—");

                      return (
                        <tr
                          key={oid}
                          className="border-b border-slate-100 last:border-b-0 hover:bg-slate-50 cursor-pointer"
                          onClick={() => setSelected(o)}
                          title="Click to view details"
                        >
                          <td className="py-3 pr-4 font-semibold text-slate-900">{oid}</td>
                          <td className="py-3 pr-4 text-slate-700">{buyer}</td>
                          <td className="py-3 pr-4 text-slate-700">{product}</td>
                          <td className="py-3 pr-4 font-semibold text-slate-900">N$ {total.toFixed(2)}</td>
                          <td className="py-3 pr-4 text-slate-700">{pay}</td>
                          <td className="py-3 pr-2 text-slate-700">{date}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>

                <div className="mt-3 text-xs text-slate-400">
                  Tip: click a row to open the order details drawer.
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Details Drawer (lightweight, no extra deps) */}
      {selectedView && (
        <div className="fixed inset-0 z-50">
          {/* overlay */}
          <button
            type="button"
            aria-label="Close order details"
            className="absolute inset-0 bg-black/30"
            onClick={closeDrawer}
          />

          {/* panel */}
          <div className="absolute right-0 top-0 h-full w-full max-w-[520px] bg-white shadow-2xl border-l border-slate-200">
            <div className="p-5 border-b border-slate-200 flex items-start justify-between gap-3">
              <div className="min-w-0">
                <div className="text-xs text-slate-500">Order Details</div>
                <div className="text-lg font-extrabold text-slate-900 truncate">{selectedView.oid}</div>
                <div className="text-sm text-slate-600 mt-1">
                  Buyer: <span className="font-semibold text-slate-900">{selectedView.buyer}</span>
                </div>
              </div>

              <button
                type="button"
                onClick={closeDrawer}
                className="h-10 w-10 rounded-2xl border border-slate-200 bg-white hover:bg-slate-50 grid place-items-center"
                aria-label="Close drawer"
              >
                <X className="h-5 w-5 text-slate-700" />
              </button>
            </div>

            <div className="p-5 space-y-4 overflow-auto h-[calc(100%-76px)]">
              <div className="rounded-2xl border border-slate-200 p-4">
                <div className="grid grid-cols-2 gap-3 text-sm">
                  <div>
                    <div className="text-xs text-slate-500">Product</div>
                    <div className="font-semibold text-slate-900">{selectedView.product}</div>
                  </div>
                  <div>
                    <div className="text-xs text-slate-500">Quantity</div>
                    <div className="font-semibold text-slate-900">{selectedView.qty || "—"}</div>
                  </div>
                  <div>
                    <div className="text-xs text-slate-500">Total</div>
                    <div className="font-extrabold text-slate-900">N$ {selectedView.total.toFixed(2)}</div>
                  </div>
                  <div>
                    <div className="text-xs text-slate-500">Payment</div>
                    <div className="font-semibold text-slate-900">{selectedView.pay}</div>
                  </div>
                  <div>
                    <div className="text-xs text-slate-500">Status</div>
                    <div className="font-semibold text-slate-900">{selectedView.status}</div>
                  </div>
                  <div>
                    <div className="text-xs text-slate-500">Date</div>
                    <div className="font-semibold text-slate-900">{selectedView.date}</div>
                  </div>
                </div>
              </div>

              <div className="rounded-2xl border border-slate-200 p-4">
                <div className="text-sm font-extrabold text-slate-900 mb-2">Contact</div>
                <div className="text-sm text-slate-700">
                  <div>
                    <span className="text-slate-500">Phone:</span>{" "}
                    <span className="font-semibold">{selectedView.phone}</span>
                  </div>
                  <div className="mt-1">
                    <span className="text-slate-500">Address:</span>{" "}
                    <span className="font-semibold">{selectedView.address}</span>
                  </div>
                </div>
              </div>

              <div className="flex gap-2">
                <button type="button" className="btn-secondary flex-1" onClick={closeDrawer}>
                  Close
                </button>
                <button type="button" className="btn-primary flex-1" onClick={() => res.refetch?.()}>
                  Refresh Orders
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </FarmerLayout>
  );
}
