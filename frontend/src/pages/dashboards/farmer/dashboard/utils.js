// ============================================================================
// frontend/src/pages/dashboards/farmer/dashboard/utils.js — AgroConnect Namibia
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Shared helpers for FarmerDashboard (keeps UI files small + consistent).
//
// RESPONSIBILITIES:
//   • Handle backend field variations safely (ids, dates, totals, names)
//   • Normalize fulfillment + payment status into stable UI buckets
//   • Provide small formatting helpers (titleCase, number parsing)
// ============================================================================

import { parseISO } from "date-fns";

export function toNumber(v, fallback = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

export function titleCase(s) {
  const str = String(s || "");
  if (!str) return "";
  return str.charAt(0).toUpperCase() + str.slice(1);
}

export function pickDate(o) {
  const raw =
    o?.created_at ||
    o?.createdAt ||
    o?.order_date ||
    o?.ordered_at ||
    o?.timestamp ||
    o?.date ||
    null;

  if (!raw) return null;
  if (raw instanceof Date) return raw;

  try {
    return parseISO(String(raw));
  } catch {
    const d = new Date(String(raw));
    return Number.isNaN(d.getTime()) ? null : d;
  }
}

// -------------------- Product field helpers --------------------
export function getProductId(p) {
  return p?.id || p?.product_id || p?.productId || null;
}

export function getProductOwnerId(p) {
  // Supports multiple schemas
  return p?.farmer_id || p?.user_id || p?.owner_id || p?.seller_id || null;
}

export function getProductName(p) {
  return p?.product_name || p?.name || "Product";
}

// -------------------- Order field helpers --------------------
export function getOrderId(o) {
  return o?.id || o?.order_id || o?.orderId || null;
}

export function getOrderProductId(o) {
  return o?.product_id || o?.productId || o?.product?.id || o?.product?.product_id || null;
}

export function getOrderProductName(o) {
  return (
    o?.product_name ||
    o?.productName ||
    o?.product?.product_name ||
    o?.product?.name ||
    "Product"
  );
}

export function getOrderBuyerLabel(o) {
  return (
    o?.buyer_name ||
    o?.customer_name ||
    o?.customerName ||
    o?.buyer?.full_name ||
    o?.buyer?.name ||
    (o?.buyer_id ? `Customer #${o.buyer_id}` : "Customer")
  );
}

export function getOrderTotal(o) {
  // supports: orders.total, total_amount, amount, grand_total
  return toNumber(o?.total ?? o?.total_amount ?? o?.amount ?? o?.grand_total ?? 0, 0);
}

// -------------------- Status normalization --------------------
export function normalizeFulfillmentStatus(o) {
  const raw =
    o?.status ||
    o?.order_status ||
    o?.fulfillment_status ||
    o?.delivery_status ||
    "pending";

  const s = String(raw).toLowerCase();

  if (["cancelled", "canceled", "rejected", "failed"].includes(s)) return "cancelled";
  if (["delivered", "collected", "completed", "done"].includes(s)) return "delivered";

  if (
    [
      "shipped",
      "in_transit",
      "in-transit",
      "out_for_delivery",
      "processing",
      "confirmed",
      "accepted",
    ].includes(s)
  ) {
    return "in_progress";
  }

  return "pending";
}

export function fulfillmentLabel(bucket) {
  if (bucket === "pending") return "Pending";
  if (bucket === "in_progress") return "In progress";
  if (bucket === "delivered") return "Delivered/Collected";
  if (bucket === "cancelled") return "Cancelled";
  return "Pending";
}

export function normalizePaymentStatus(o) {
  // If your backend joins payments into orders, map those
  const raw = o?.payment_status || o?.paymentStatus || o?.payment_state || null;

  if (raw != null) {
    const s = String(raw).toLowerCase();
    if (["paid", "complete", "completed", "success", "successful"].includes(s)) return "paid";
    if (["unpaid", "pending", "due", "failed"].includes(s)) return "unpaid";
    return "unknown";
  }

  // boolean fallbacks
  const paidBool =
    o?.paid ?? o?.is_paid ?? o?.payment_complete ?? o?.paymentComplete ?? null;

  if (paidBool === true) return "paid";
  if (paidBool === false) return "unpaid";

  return "unknown";
}

export function badgeForFulfillment(bucket) {
  if (bucket === "delivered") return "bg-emerald-50 text-emerald-800 border-emerald-200";
  if (bucket === "cancelled") return "bg-rose-50 text-rose-800 border-rose-200";
  if (bucket === "in_progress") return "bg-sky-50 text-sky-800 border-sky-200";
  return "bg-amber-50 text-amber-800 border-amber-200";
}

export function badgeForPayment(bucket) {
  if (bucket === "paid") return "bg-emerald-50 text-emerald-800 border-emerald-200";
  if (bucket === "unpaid") return "bg-amber-50 text-amber-800 border-amber-200";
  return "bg-slate-50 text-slate-700 border-slate-200";
}
