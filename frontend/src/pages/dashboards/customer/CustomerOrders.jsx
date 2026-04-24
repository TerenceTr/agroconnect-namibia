// ============================================================================
// frontend/src/pages/dashboards/customer/CustomerOrders.jsx
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Customer Orders page.
//   • Displays customer order history + status lifecycle
//   • Adds a polished summary layer above the reusable OrderHistory component
//   • Provides lightweight client-side filtering, sorting, and pagination
//
// NOTE:
//   This page is wrapped with DashboardLayout at route-level in App.js,
//   so it must remain content-only (no extra layout wrapper here).
//
// THIS UPDATE:
//   ✅ Introduces structured pagination with a maximum of 6 orders per page
//   ✅ Keeps filters/search/sort working across the full filtered result set
//   ✅ Shows "showing X–Y of Z" context for clearer archive navigation
//   ✅ Adds compact page controls suited to a professional dashboard workspace
// ============================================================================

import React, { useEffect, useMemo, useState } from "react";
import {
  ClipboardList,
  Search,
  RefreshCcw,
  CreditCard,
  Truck,
  Package,
  CalendarDays,
  SlidersHorizontal,
  AlertTriangle,
  ChevronLeft,
  ChevronRight,
} from "lucide-react";

import OrderHistory from "../../../components/customer/OrderHistory";
import useCustomerOrders from "../../../hooks/useCustomerOrders";

const ORDERS_PER_PAGE = 6;

// -----------------------------------------------------------------------------
// Small safe helpers
// -----------------------------------------------------------------------------
function safeArray(value) {
  return Array.isArray(value) ? value : [];
}

function safeStr(value, fallback = "") {
  if (value == null) return fallback;
  const s = String(value).trim();
  return s || fallback;
}

function safeNumber(value, fallback = 0) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function lower(value, fallback = "") {
  return safeStr(value, fallback).toLowerCase();
}

function firstNonEmpty(...values) {
  for (const value of values) {
    const s = safeStr(value, "");
    if (s) return s;
  }
  return "";
}

function formatMoney(value) {
  return `N$ ${safeNumber(value, 0).toFixed(2)}`;
}

function formatShortDate(value) {
  const raw = safeStr(value, "");
  if (!raw) return "—";

  const dt = new Date(raw);
  if (Number.isNaN(dt.getTime())) return raw;

  return dt.toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
  });
}

function normalizeStatusLabel(value, fallback = "—") {
  const s = safeStr(value, "");
  if (!s) return fallback;

  return s
    .replace(/_/g, " ")
    .toLowerCase()
    .replace(/\b([a-z])/g, (m) => m.toUpperCase());
}

function getArrayFromPossibleShape(value) {
  if (Array.isArray(value)) return value;
  if (Array.isArray(value?.items)) return value.items;
  if (Array.isArray(value?.data)) return value.data;
  if (Array.isArray(value?.orders)) return value.orders;
  return [];
}

function normalizeOrder(raw = {}) {
  const items = getArrayFromPossibleShape(raw?.items ?? raw?.order_items ?? raw?.lines);
  const orderId = firstNonEmpty(raw?.order_id, raw?.id, raw?.uuid);
  const orderDate = firstNonEmpty(raw?.order_date, raw?.created_at, raw?.placed_at);
  const orderStatus = lower(raw?.order_status ?? raw?.status, "pending");
  const paymentStatus = lower(
    raw?.payment_visibility_status ?? raw?.payment_status ?? raw?.payment?.status,
    "pending"
  );
  const deliveryStatus = lower(
    raw?.delivery_status ?? raw?.status_delivery ?? raw?.farmer_delivery_status,
    orderStatus
  );

  const total = safeNumber(
    raw?.customer_order_total ??
      raw?.order_total_customer ??
      raw?.total_amount ??
      raw?.order_total ??
      raw?.total ??
      raw?.grand_total,
    0
  );

  const farmersFromItems = Array.from(
    new Set(
      safeArray(items)
        .map((it) =>
          firstNonEmpty(
            it?.farmer_name,
            it?.seller_name,
            it?.farmer?.name,
            it?.supplier_name
          )
        )
        .filter(Boolean)
    )
  );

  const itemsPreview =
    firstNonEmpty(raw?.items_preview, raw?.itemsPreview) ||
    safeArray(items)
      .slice(0, 2)
      .map((it) => firstNonEmpty(it?.product_name, it?.name, "Item"))
      .filter(Boolean)
      .join(", ");

  const farmerNames = farmersFromItems.join(", ");
  const itemCount = safeNumber(raw?.item_count ?? raw?.itemCount ?? items.length, items.length);

  const deliveryAddress = firstNonEmpty(
    raw?.delivery_address,
    raw?.delivery_location,
    raw?.customer_address,
    raw?.customer_location
  );

  const uniqueFarmerIds = Array.from(
    new Set(
      safeArray(items)
        .map((it) => firstNonEmpty(it?.farmer_id, it?.seller_id))
        .filter(Boolean)
    )
  );

  const multiFarmer =
    Boolean(raw?.multi_farmer_order) ||
    Boolean(raw?.has_other_farmers_items) ||
    uniqueFarmerIds.length > 1 ||
    farmersFromItems.length > 1;

  return {
    ...raw,
    id: orderId,
    order_id: orderId,
    orderDate,
    total,
    total_amount: total,
    status: orderStatus,
    order_status: orderStatus,
    payment_status: paymentStatus,
    payment_visibility_status: paymentStatus,
    delivery_status: deliveryStatus,
    items,
    itemCount,
    itemsPreview,
    farmerNames,
    deliveryAddress,
    multiFarmer,
  };
}

function statusTone(status) {
  const s = lower(status, "");
  if (s === "completed" || s === "paid" || s === "delivered") {
    return "border-emerald-200 bg-emerald-50 text-emerald-800";
  }
  if (
    s === "partial" ||
    s === "pending" ||
    s === "preparing" ||
    s === "in transit" ||
    s === "in_transit"
  ) {
    return "border-amber-200 bg-amber-50 text-amber-800";
  }
  if (s === "cancelled" || s === "failed") {
    return "border-rose-200 bg-rose-50 text-rose-800";
  }
  return "border-slate-200 bg-slate-50 text-slate-700";
}

function buildPaginationItems(currentPage, totalPages) {
  if (totalPages <= 1) return [1];
  if (totalPages <= 5) return Array.from({ length: totalPages }, (_, i) => i + 1);

  const items = [1];
  const start = Math.max(2, currentPage - 1);
  const end = Math.min(totalPages - 1, currentPage + 1);

  if (start > 2) items.push("left-ellipsis");
  for (let page = start; page <= end; page += 1) items.push(page);
  if (end < totalPages - 1) items.push("right-ellipsis");

  items.push(totalPages);
  return items;
}

function StatCard({ icon: Icon, label, value, subtext }) {
  return (
    <div className="rounded-2xl border border-[#D8F3DC] bg-white p-4 shadow-sm">
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="text-xs font-bold uppercase tracking-wide text-slate-500">{label}</div>
          <div className="mt-1 text-2xl font-black tracking-tight text-slate-900">{value}</div>
          {subtext ? <div className="mt-1 text-xs text-slate-500">{subtext}</div> : null}
        </div>

        <div className="grid h-11 w-11 place-items-center rounded-2xl border border-[#D8F3DC] bg-[#F4FBF7]">
          <Icon className="h-5 w-5 text-[#2D6A4F]" />
        </div>
      </div>
    </div>
  );
}

function PaginationControls({ currentPage, totalPages, onPageChange }) {
  const pageItems = useMemo(
    () => buildPaginationItems(currentPage, totalPages),
    [currentPage, totalPages]
  );

  if (totalPages <= 1) return null;

  return (
    <div className="flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-slate-200 bg-[#F8FCF9] px-3 py-3">
      <div className="text-xs font-medium text-slate-500">
        Page <span className="font-bold text-slate-800">{currentPage}</span> of{" "}
        <span className="font-bold text-slate-800">{totalPages}</span>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <button
          type="button"
          onClick={() => onPageChange(currentPage - 1)}
          disabled={currentPage <= 1}
          className="inline-flex h-9 items-center gap-1 rounded-xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-700 transition hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-50"
        >
          <ChevronLeft className="h-4 w-4" />
          Previous
        </button>

        <div className="flex flex-wrap items-center gap-2">
          {pageItems.map((item) => {
            if (typeof item !== "number") {
              return (
                <span
                  key={item}
                  className="inline-flex h-9 min-w-9 items-center justify-center rounded-xl px-2 text-sm font-semibold text-slate-400"
                >
                  …
                </span>
              );
            }

            const active = item === currentPage;
            return (
              <button
                key={item}
                type="button"
                onClick={() => onPageChange(item)}
                aria-current={active ? "page" : undefined}
                className={`inline-flex h-9 min-w-9 items-center justify-center rounded-xl border px-3 text-sm font-semibold transition ${
                  active
                    ? "border-[#95D5B2] bg-[#EAF7F0] text-[#1B4332]"
                    : "border-slate-200 bg-white text-slate-700 hover:bg-slate-50"
                }`}
              >
                {item}
              </button>
            );
          })}
        </div>

        <button
          type="button"
          onClick={() => onPageChange(currentPage + 1)}
          disabled={currentPage >= totalPages}
          className="inline-flex h-9 items-center gap-1 rounded-xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-700 transition hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-50"
        >
          Next
          <ChevronRight className="h-4 w-4" />
        </button>
      </div>
    </div>
  );
}

export default function CustomerOrders() {
  const ordersState = useCustomerOrders();

  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const [sortBy, setSortBy] = useState("newest");
  const [currentPage, setCurrentPage] = useState(1);

  const rawOrders = safeArray(ordersState?.orders);
  const normalizedOrders = useMemo(
    () => rawOrders.map((order) => normalizeOrder(order)),
    [rawOrders]
  );

  const filteredOrders = useMemo(() => {
    const q = lower(search, "");

    let next = [...normalizedOrders];

    if (statusFilter !== "all") {
      next = next.filter((order) => {
        if (statusFilter === "paid") return order.payment_status === "paid";
        if (statusFilter === "delivered") return order.delivery_status === "delivered";
        if (statusFilter === "multi_farmer") return order.multiFarmer;
        return order.status === statusFilter;
      });
    }

    if (q) {
      next = next.filter((order) => {
        const haystack = [
          order.order_id,
          order.itemsPreview,
          order.farmerNames,
          order.deliveryAddress,
          order.status,
          order.payment_status,
          order.delivery_status,
        ]
          .map((v) => lower(v, ""))
          .join(" ");

        return haystack.includes(q);
      });
    }

    next.sort((a, b) => {
      if (sortBy === "highest_total") {
        return safeNumber(b.total, 0) - safeNumber(a.total, 0);
      }

      if (sortBy === "lowest_total") {
        return safeNumber(a.total, 0) - safeNumber(b.total, 0);
      }

      if (sortBy === "oldest") {
        return new Date(a.orderDate || 0).getTime() - new Date(b.orderDate || 0).getTime();
      }

      return new Date(b.orderDate || 0).getTime() - new Date(a.orderDate || 0).getTime();
    });

    return next;
  }, [normalizedOrders, search, statusFilter, sortBy]);

  const stats = useMemo(() => {
    const totalOrders = filteredOrders.length;
    const paidOrders = filteredOrders.filter((o) => o.payment_status === "paid").length;
    const deliveredOrders = filteredOrders.filter((o) => o.delivery_status === "delivered").length;
    const totalValue = filteredOrders.reduce((sum, o) => sum + safeNumber(o.total, 0), 0);
    const latestDate = filteredOrders[0]?.orderDate || normalizedOrders[0]?.orderDate || "";

    return {
      totalOrders,
      paidOrders,
      deliveredOrders,
      totalValue,
      latestDate,
    };
  }, [filteredOrders, normalizedOrders]);

  const hasMultiFarmerOrders = useMemo(
    () => filteredOrders.some((order) => order.multiFarmer),
    [filteredOrders]
  );

  const totalPages = Math.max(1, Math.ceil(filteredOrders.length / ORDERS_PER_PAGE));
  const safeCurrentPage = Math.min(currentPage, totalPages);

  const paginatedOrders = useMemo(() => {
    if (!filteredOrders.length) return [];

    const startIndex = (safeCurrentPage - 1) * ORDERS_PER_PAGE;
    return filteredOrders.slice(startIndex, startIndex + ORDERS_PER_PAGE);
  }, [filteredOrders, safeCurrentPage]);

  const visibleRange = useMemo(() => {
    if (!filteredOrders.length) {
      return { start: 0, end: 0 };
    }

    const start = (safeCurrentPage - 1) * ORDERS_PER_PAGE + 1;
    const end = Math.min(start + ORDERS_PER_PAGE - 1, filteredOrders.length);
    return { start, end };
  }, [filteredOrders.length, safeCurrentPage]);

  useEffect(() => {
    setCurrentPage(1);
  }, [search, statusFilter, sortBy]);

  useEffect(() => {
    if (currentPage > totalPages) {
      setCurrentPage(totalPages);
    }
  }, [currentPage, totalPages]);

  const refresh = () => {
    ordersState?.reload?.();
  };

  const handlePageChange = (nextPage) => {
    const target = Math.min(Math.max(Number(nextPage) || 1, 1), totalPages);
    setCurrentPage(target);

    if (typeof window !== "undefined") {
      window.requestAnimationFrame(() => {
        const anchor = document.getElementById("customer-orders-history");
        anchor?.scrollIntoView({ behavior: "smooth", block: "start" });
      });
    }
  };

  return (
    <div className="space-y-6">
      <section className="overflow-hidden rounded-3xl border border-[#D8F3DC] bg-white shadow-sm">
        <div className="bg-gradient-to-r from-[#F4FBF7] via-white to-[#EEF8F2] p-6">
          <div className="flex flex-col gap-4 xl:flex-row xl:items-center xl:justify-between">
            <div>
              <div className="text-xs font-semibold uppercase tracking-wide text-[#2D6A4F]">
                Customer commerce
              </div>
              <h1 className="mt-1 text-2xl font-black tracking-tight text-slate-900">
                My Orders
              </h1>
              <p className="mt-1 max-w-3xl text-sm text-slate-600">
                Review your purchases, payment progress, delivery lifecycle, and farmer-linked
                order activity in one organized workspace.
              </p>

              <div className="mt-3 flex flex-wrap items-center gap-2">
                <span className="inline-flex items-center rounded-full border border-[#B7E4C7] bg-[#EAF7F0] px-3 py-1 text-xs font-bold text-[#1B4332]">
                  {normalizedOrders.length} total orders
                </span>

                <span className="inline-flex items-center rounded-full border border-slate-200 bg-slate-50 px-3 py-1 text-xs font-bold text-slate-700">
                  Max {ORDERS_PER_PAGE} orders per page
                </span>

                {hasMultiFarmerOrders ? (
                  <span className="inline-flex items-center rounded-full border border-amber-200 bg-amber-50 px-3 py-1 text-xs font-bold text-amber-800">
                    Multi-farmer orders detected
                  </span>
                ) : null}

                {stats.latestDate ? (
                  <span className="inline-flex items-center rounded-full border border-slate-200 bg-slate-50 px-3 py-1 text-xs font-bold text-slate-700">
                    Latest order: {formatShortDate(stats.latestDate)}
                  </span>
                ) : null}
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={refresh}
                className="inline-flex h-11 items-center gap-2 rounded-2xl border border-[#D8F3DC] bg-white px-4 text-sm font-semibold text-slate-800 transition hover:bg-slate-50"
              >
                <RefreshCcw className="h-4 w-4" />
                Refresh orders
              </button>
            </div>
          </div>
        </div>
      </section>

      <section className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          icon={ClipboardList}
          label="Orders"
          value={stats.totalOrders}
          subtext="Visible after filters"
        />
        <StatCard
          icon={CreditCard}
          label="Paid"
          value={stats.paidOrders}
          subtext="Payment confirmed"
        />
        <StatCard
          icon={Truck}
          label="Delivered"
          value={stats.deliveredOrders}
          subtext="Reached final delivery state"
        />
        <StatCard
          icon={Package}
          label="Order value"
          value={formatMoney(stats.totalValue)}
          subtext="Visible combined total"
        />
      </section>

      <section className="rounded-3xl border border-[#D8F3DC] bg-white p-4 shadow-sm">
        <div className="flex flex-col gap-3 xl:flex-row xl:items-center xl:justify-between">
          <div className="flex min-w-0 flex-1 flex-col gap-3 md:flex-row">
            <div className="flex min-w-0 flex-1 items-center gap-2 rounded-2xl border border-slate-200 bg-white px-3">
              <Search className="h-4 w-4 text-slate-400" />
              <input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search by order ID, items, farmers, or address"
                className="h-11 w-full bg-transparent text-sm text-slate-800 outline-none placeholder:text-slate-400"
              />
            </div>

            <div className="inline-flex items-center gap-2 rounded-2xl border border-slate-200 bg-white px-3">
              <SlidersHorizontal className="h-4 w-4 text-slate-400" />
              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="h-11 bg-transparent text-sm font-semibold text-slate-800 outline-none"
              >
                <option value="all">All orders</option>
                <option value="pending">Pending</option>
                <option value="completed">Completed</option>
                <option value="cancelled">Cancelled</option>
                <option value="paid">Paid</option>
                <option value="delivered">Delivered</option>
                <option value="multi_farmer">Multi-farmer</option>
              </select>
            </div>

            <div className="inline-flex items-center gap-2 rounded-2xl border border-slate-200 bg-white px-3">
              <CalendarDays className="h-4 w-4 text-slate-400" />
              <select
                value={sortBy}
                onChange={(e) => setSortBy(e.target.value)}
                className="h-11 bg-transparent text-sm font-semibold text-slate-800 outline-none"
              >
                <option value="newest">Newest first</option>
                <option value="oldest">Oldest first</option>
                <option value="highest_total">Highest total</option>
                <option value="lowest_total">Lowest total</option>
              </select>
            </div>
          </div>

          <div className="text-sm text-slate-500">
            Showing <span className="font-bold text-slate-800">{filteredOrders.length}</span> of{" "}
            <span className="font-bold text-slate-800">{normalizedOrders.length}</span> orders
          </div>
        </div>

        {hasMultiFarmerOrders ? (
          <div className="mt-4 rounded-2xl border border-amber-200 bg-amber-50 p-3 text-sm text-amber-900">
            <div className="flex items-start gap-2">
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
              <div>
                Multi-farmer orders are present in your history. When you expand those orders, keep
                payment evidence and farmer payment scopes aligned correctly per farmer section.
              </div>
            </div>
          </div>
        ) : null}
      </section>

      {filteredOrders.length > 0 ? (
        <section className="rounded-3xl border border-[#D8F3DC] bg-white p-4 shadow-sm">
          <div className="mb-3 flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
            <div className="text-sm font-extrabold text-slate-900">Visible order status mix</div>
            <div className="text-xs text-slate-500">
              Filtered archive • {filteredOrders.length} result{filteredOrders.length === 1 ? "" : "s"}
            </div>
          </div>

          <div className="flex flex-wrap gap-2">
            {[
              {
                label: "Pending",
                value: filteredOrders.filter((o) => o.status === "pending").length,
                key: "pending",
              },
              {
                label: "Completed",
                value: filteredOrders.filter((o) => o.status === "completed").length,
                key: "completed",
              },
              {
                label: "Cancelled",
                value: filteredOrders.filter((o) => o.status === "cancelled").length,
                key: "cancelled",
              },
              {
                label: "Paid",
                value: filteredOrders.filter((o) => o.payment_status === "paid").length,
                key: "paid",
              },
              {
                label: "Delivered",
                value: filteredOrders.filter((o) => o.delivery_status === "delivered").length,
                key: "delivered",
              },
            ]
              .filter((x) => x.value > 0)
              .map((x) => (
                <span
                  key={`${x.label}-${x.key}`}
                  className={`inline-flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-bold ${statusTone(
                    x.key
                  )}`}
                >
                  {x.label}
                  <span className="rounded-full bg-white/70 px-2 py-0.5 text-[11px]">{x.value}</span>
                </span>
              ))}
          </div>
        </section>
      ) : null}

      <section
        id="customer-orders-history"
        className="overflow-hidden rounded-3xl border border-[#D8F3DC] bg-white shadow-sm"
      >
        <div className="border-b border-[#D8F3DC] bg-[#F8FCF9] px-5 py-4">
          <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
            <div>
              <div className="text-sm font-extrabold text-slate-900">Detailed order history</div>
              <div className="text-xs text-slate-500">
                Full order cards, item scopes, payment evidence, and progress details.
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-3 text-xs text-slate-500">
              <span>
                Sorted by <span className="font-semibold text-slate-700">{normalizeStatusLabel(sortBy)}</span>
              </span>
              <span>
                Showing <span className="font-semibold text-slate-700">{visibleRange.start}</span>–
                <span className="font-semibold text-slate-700">{visibleRange.end}</span> of{" "}
                <span className="font-semibold text-slate-700">{filteredOrders.length}</span>
              </span>
            </div>
          </div>
        </div>

        <div className="space-y-4 p-4 md:p-5">
          <PaginationControls
            currentPage={safeCurrentPage}
            totalPages={totalPages}
            onPageChange={handlePageChange}
          />

          <OrderHistory
            orders={paginatedOrders}
            loading={Boolean(ordersState?.loading)}
            onRefresh={refresh}
          />

          <PaginationControls
            currentPage={safeCurrentPage}
            totalPages={totalPages}
            onPageChange={handlePageChange}
          />
        </div>
      </section>
    </div>
  );
}