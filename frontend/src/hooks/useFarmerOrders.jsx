// ============================================================================
// frontend/src/hooks/useFarmerOrders.jsx — Shared Orders Hook (Farmer)
// ----------------------------------------------------------------------------
// FILE ROLE:
//   One shared place to fetch + normalize farmer orders for:
//   • Farmer dashboard "Recent Orders" card
//   • FarmerOrdersPage table + drawer
//
// THIS UPDATE:
//   ✅ Exports backward-compatible normalizer alias: _normalizeOrderForFarmer
//   ✅ Unifies order + item normalization across pages/components
//   ✅ Keeps API prefix resilience (/api vs baseURL already includes /api)
//   ✅ Stable shape for UI badges + partial delivery editing
//   ✅ Includes payment_date + delivery_date for table/drawer use
//   ✅ Adds payment_status_badge + payment proof fields (proof URL/name + reference)
//   ✅ Fixes “No orders found” for envelope payloads
//   ✅ Fixes “No orders found” when user object does not expose `id`
//   ✅ Safe fallback behavior when caller passes enabled=false due missing user?.id
//   ✅ Supports "All time" requests (days <= 0) via all_time flag
//   ✅ Fetch fallback with /orders/my endpoints when ID is unavailable
//   ✅ Prefers auth-scoped farmer endpoints first: /orders/farmer/me|my
//   ✅ Avoids over-filtering when endpoint is auth-scoped
//   ✅ NEW: customer_name/email/phone/location normalized for drawer
//   ✅ NEW: is_new_for_farmer normalized for notification dot/bell
//   ✅ NEW: checkout fee/VAT/bank detail fields normalized for farmer UI
//
// SHARED / MULTI-FARMER ORDER FIX:
//   ✅ Treats shared orders as "my scoped slice" for farmer UI
//   ✅ Main total becomes farmer subtotal when backend provides it
//   ✅ Customer order total is preserved separately
//   ✅ Delivery status prefers farmer_delivery_status for shared orders
//   ✅ Payment visibility prefers farmer-scoped payment summary
//   ✅ Trusts backend-scoped items first, then falls back to client item filter
//
// ORDER ID FIX:
//   ✅ Preserves canonical order identity on normalized rows
//   ✅ Supports BOTH raw backend payloads and already-normalized rows
//   ✅ Exposes oid + order_id + id aliases to prevent save/update failures
//
// BUYER / STATUS UI FIX:
//   ✅ Normalizes buyer/customer address for the order page
//   ✅ Prefers farmer-owned items only
//   ✅ Marks farmer UI status as completed when farmer payment is confirmed paid
// ============================================================================

import { useMemo } from "react";
import useApi from "./useApi";

// -------------------------
// Defensive helpers
// -------------------------
export function safeArray(v) {
  return Array.isArray(v) ? v : [];
}

export function safeStr(v, fallback = "") {
  if (typeof v === "string") return v;
  if (v == null) return fallback;
  return String(v);
}

export function safeNumber(v, fallback = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

export function safeBool(v, fallback = false) {
  if (typeof v === "boolean") return v;
  if (typeof v === "number") return v !== 0;
  if (typeof v === "string") {
    const s = v.trim().toLowerCase();
    if (!s) return fallback;
    if (["1", "true", "yes", "y", "on"].includes(s)) return true;
    if (["0", "false", "no", "n", "off"].includes(s)) return false;
  }
  return fallback;
}

export function firstDefined(...vals) {
  for (const v of vals) {
    if (v !== undefined && v !== null) return v;
  }
  return undefined;
}

/**
 * Badge-safe label normalizer:
 * - Keeps "paid/unpaid/refunded" etc.
 * - Prevents empty/undefined
 * - Collapses weird values into a readable token
 */
export function safeBadgeText(v, fallback = "—") {
  const s = safeStr(v, "").trim();
  if (!s) return fallback;
  return s.toLowerCase();
}

export function formatDate(v) {
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

export function formatDateTime(v) {
  const s = safeStr(v, "—");
  if (s === "—") return s;
  try {
    const d = new Date(s);
    if (Number.isNaN(d.getTime())) return s;
    return d.toLocaleString();
  } catch {
    return s;
  }
}

// Date picker helper:
// - Accepts ISO ("2026-01-11T00:00:00") or date-only ("2026-01-11")
// - Returns YYYY-MM-DD for <input type="date" />
export function toDateInputValue(v) {
  const s = safeStr(v, "").trim();
  if (!s) return "";
  if (/^\d{4}-\d{2}-\d{2}$/.test(s)) return s;

  try {
    const d = new Date(s);
    if (Number.isNaN(d.getTime())) return s.slice(0, 10);

    const yyyy = d.getFullYear();
    const mm = String(d.getMonth() + 1).padStart(2, "0");
    const dd = String(d.getDate()).padStart(2, "0");
    return `${yyyy}-${mm}-${dd}`;
  } catch {
    return s.slice(0, 10);
  }
}

// -------------------------
// Envelope / payload helpers
// -------------------------
function unwrapApiDataEnvelope(raw) {
  if (raw == null) return raw;
  if (Array.isArray(raw)) return raw;
  if (typeof raw !== "object") return raw;

  if (Object.prototype.hasOwnProperty.call(raw, "data") && raw.data != null) {
    return raw.data;
  }
  if (Object.prototype.hasOwnProperty.call(raw, "result") && raw.result != null) {
    return raw.result;
  }
  if (Object.prototype.hasOwnProperty.call(raw, "payload") && raw.payload != null) {
    return raw.payload;
  }

  return raw;
}

function pickArrayFromPayload(raw, candidateKeys = []) {
  const payload = unwrapApiDataEnvelope(raw);

  if (Array.isArray(payload)) return payload;
  if (payload == null || typeof payload !== "object") return [];

  for (const key of candidateKeys) {
    const v = payload?.[key];
    if (Array.isArray(v)) return v;

    if (v && typeof v === "object") {
      const nested = unwrapApiDataEnvelope(v);
      if (Array.isArray(nested)) return nested;

      for (const nk of candidateKeys) {
        if (Array.isArray(nested?.[nk])) return nested[nk];
      }
    }
  }

  const singleOrder =
    firstDefined(
      payload?.order,
      payload?.item,
      payload?.result?.order,
      payload?.data?.order
    ) || null;

  if (singleOrder && typeof singleOrder === "object") {
    return [singleOrder];
  }

  const vals = Object.values(payload);
  if (vals.length > 0 && vals.every((x) => x && typeof x === "object")) {
    const maybeOrders = vals.filter(
      (x) =>
        x?.order_id != null ||
        x?.orderId != null ||
        x?.oid != null ||
        x?.id != null ||
        x?.status != null ||
        x?.payment_status != null
    );
    if (maybeOrders.length > 0) return maybeOrders;
  }

  return [];
}

// -------------------------
// Session / ID resolution (robust)
// -------------------------
function safeJsonParse(v) {
  try {
    return JSON.parse(v);
  } catch {
    return null;
  }
}

function canUseBrowserApis() {
  return typeof window !== "undefined";
}

function readLocalStorage(key) {
  if (!canUseBrowserApis()) return null;
  try {
    return window.localStorage.getItem(key);
  } catch {
    return null;
  }
}

function readStoredUser() {
  const keys = ["user", "auth_user", "currentUser", "profile", "auth", "session"];
  for (const k of keys) {
    const raw = readLocalStorage(k);
    if (!raw) continue;
    const parsed = safeJsonParse(raw);
    if (parsed && typeof parsed === "object") return parsed;
  }
  return null;
}

function readStoredAccessToken() {
  return (
    readLocalStorage("token") ||
    readLocalStorage("accessToken") ||
    readLocalStorage("access_token") ||
    ""
  );
}

function decodeJwtPayload(token) {
  const t = safeStr(token, "").trim();
  if (!t) return null;

  const parts = t.split(".");
  if (parts.length < 2) return null;

  try {
    const base64Url = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const pad = base64Url.length % 4;
    const padded = base64Url + (pad ? "=".repeat(4 - pad) : "");

    if (typeof atob === "function") {
      const json = atob(padded);
      return safeJsonParse(json);
    }

    if (typeof Buffer !== "undefined") {
      const json = Buffer.from(padded, "base64").toString("utf8");
      return safeJsonParse(json);
    }

    return null;
  } catch {
    return null;
  }
}

function firstNonEmpty(...vals) {
  for (const v of vals) {
    const s = safeStr(v, "").trim();
    if (s) return s;
  }
  return "";
}

function pickId(userLike) {
  if (!userLike || typeof userLike !== "object") return "";

  const flat = firstNonEmpty(
    userLike.id,
    userLike.user_id,
    userLike.userId,
    userLike.farmer_id,
    userLike.farmerId,
    userLike.sub,
    userLike.uid
  );
  if (flat) return flat;

  return firstNonEmpty(
    userLike?.user?.id,
    userLike?.user?.user_id,
    userLike?.user?.farmer_id,
    userLike?.profile?.id,
    userLike?.profile?.user_id,
    userLike?.profile?.farmer_id,
    userLike?.farmer?.id,
    userLike?.farmer?.farmer_id,
    userLike?.data?.id,
    userLike?.data?.user_id,
    userLike?.data?.farmer_id
  );
}

function looksLikeUuid(v) {
  const s = safeStr(v, "").trim();
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
    s
  );
}

function normalizeIdValue(v) {
  return safeStr(v, "").trim();
}

function idsEqual(a, b) {
  const aa = normalizeIdValue(a);
  const bb = normalizeIdValue(b);
  if (!aa || !bb) return false;
  return aa === bb;
}

export function resolveFarmerId(explicitFarmerId = null) {
  const explicit = firstNonEmpty(explicitFarmerId);
  if (explicit) return explicit;

  const storedUser = readStoredUser();
  const userId = pickId(storedUser);
  if (userId) return userId;

  const token = readStoredAccessToken();
  const jwt = decodeJwtPayload(token);

  const tokenId = firstNonEmpty(
    jwt?.sub,
    jwt?.identity,
    jwt?.user_id,
    jwt?.userId,
    jwt?.id,
    jwt?.farmer_id,
    jwt?.farmerId,
    jwt?.user?.id,
    jwt?.profile?.id
  );

  return tokenId || "";
}

// -------------------------
// Endpoints (API-prefix resilient)
// -------------------------
function uniqEndpoints(list) {
  const out = [];
  const seen = new Set();

  for (const x of list || []) {
    if (!x) continue;
    if (seen.has(x)) continue;
    seen.add(x);
    out.push(x);
  }
  return out;
}

function isAuthScopedFarmerEndpoint(path) {
  const p = safeStr(path, "");
  return /\/orders\/farmer\/(me|my)(\/|$)/i.test(p);
}

function isBuyerScopedEndpoint(path) {
  const p = safeStr(path, "");
  return /\/orders\/(me|my)(\/|$)/i.test(p) && !/\/orders\/farmer\//i.test(p);
}

export const epFarmerOrders = (farmerId) => {
  const fid = safeStr(farmerId, "").trim();

  const endpoints = [];

  endpoints.push("/api/orders/farmer/me");
  endpoints.push("/orders/farmer/me");
  endpoints.push("/api/orders/farmer/my");
  endpoints.push("/orders/farmer/my");

  if (fid) {
    endpoints.push(`/api/orders/farmer/${fid}`);
    endpoints.push(`/orders/farmer/${fid}`);

    const encoded = encodeURIComponent(fid);
    endpoints.push(`/api/orders/farmer/${encoded}`);
    endpoints.push(`/orders/farmer/${encoded}`);

    if (!looksLikeUuid(fid)) {
      endpoints.push(`/api/orders?farmer_id=${encodeURIComponent(fid)}`);
      endpoints.push(`/orders?farmer_id=${encodeURIComponent(fid)}`);
    }
  }

  endpoints.push("/api/orders/me");
  endpoints.push("/orders/me");
  endpoints.push("/api/orders/my");
  endpoints.push("/orders/my");

  endpoints.push("/api/orders");
  endpoints.push("/orders");

  return uniqEndpoints(endpoints);
};

// -------------------------
// Farmer-scope helpers
// -------------------------
function getOrderFarmerId(rawOrder) {
  const o = rawOrder && typeof rawOrder === "object" ? rawOrder : {};
  return firstNonEmpty(
    o.farmer_id,
    o.farmerId,
    o.owner_id,
    o.ownerId,
    o.seller_id,
    o.sellerId,
    o.user_id,
    o.userId,
    o.payment_scope_user_id
  );
}

function getItemFarmerId(rawItem) {
  const it = rawItem && typeof rawItem === "object" ? rawItem : {};
  return firstNonEmpty(
    it.farmer_id,
    it.farmerId,
    it.owner_id,
    it.ownerId,
    it.seller_id,
    it.sellerId,
    it.user_id,
    it.userId
  );
}

function rawOrderBelongsToFarmer(rawOrder, farmerId) {
  const fid = normalizeIdValue(farmerId);
  if (!fid) return true;

  const orderOwner = getOrderFarmerId(rawOrder);
  if (orderOwner) return idsEqual(orderOwner, fid);

  const items = safeArray(
    firstDefined(rawOrder?.items, rawOrder?.order_items, rawOrder?.orderItems)
  );
  const itemOwners = items.map(getItemFarmerId).filter(Boolean);
  if (itemOwners.length > 0) return itemOwners.some((x) => idsEqual(x, fid));

  return true;
}

// -------------------------
// Item normalization
// -------------------------
export function normalizeOrderItem(it) {
  const raw = it && typeof it === "object" ? it : {};

  const order_item_id = safeStr(
    firstDefined(raw.order_item_id, raw.orderItemId, raw.id, raw.item_id, "")
  );
  const product_id = safeStr(
    firstDefined(raw.product_id, raw.productId, raw.product?.id, "")
  );

  const quantity = safeNumber(firstDefined(raw.quantity, raw.qty, 0), 0);
  const unit_price = safeNumber(firstDefined(raw.unit_price, raw.unitPrice, 0), 0);

  const computedLine = Number((unit_price * quantity).toFixed(2));
  const line_total = safeNumber(
    firstDefined(raw.line_total, raw.lineTotal, raw.total, computedLine),
    computedLine
  );

  const delivery_status = safeStr(
    firstDefined(raw.delivery_status, raw.item_delivery_status, raw.fulfillment_status, "pending")
  ).toLowerCase();

  const delivered_qty = safeNumber(
    firstDefined(raw.delivered_qty, raw.delivered_quantity, raw.deliveredQty, 0),
    0
  );

  const item_payment_status = safeBadgeText(
    firstDefined(raw.item_payment_status, raw.payment_status, raw.paymentStatus, raw.payment, ""),
    ""
  );

  const item_payment_visibility_status = safeBadgeText(
    firstDefined(
      raw.item_payment_visibility_status,
      raw.itemPaymentVisibilityStatus,
      raw.payment_visibility_status,
      raw.paymentVisibilityStatus,
      ""
    ),
    ""
  );

  return {
    ...raw,

    order_item_id,
    item_id: order_item_id,
    id: order_item_id,

    product_id,
    product_name: safeStr(
      firstDefined(raw.product_name, raw.name, raw.product?.product_name, "Item")
    ),
    quantity,
    qty: quantity,
    unit: safeStr(firstDefined(raw.unit, "")),

    unit_price,
    line_total,

    delivery_status,
    item_delivery_status: delivery_status,

    delivered_qty,
    delivered_quantity: delivered_qty,

    item_payment_status,
    item_payment_visibility_status,
    item_payment_status_badge:
      item_payment_visibility_status || item_payment_status || "—",

    farmer_id: firstNonEmpty(
      raw.farmer_id,
      raw.farmerId,
      raw.owner_id,
      raw.seller_id,
      raw.user_id
    ),
    belongs_to_current_farmer: safeBool(firstDefined(raw.belongs_to_current_farmer, false), false),

    raw,
  };
}

// -------------------------
// Payment reference parser helper
// -------------------------
function tryParseJsonObject(raw) {
  if (raw && typeof raw === "object" && !Array.isArray(raw)) return raw;

  const s = safeStr(raw, "").trim();
  if (!s || !s.startsWith("{") || !s.endsWith("}")) return null;
  try {
    const parsed = JSON.parse(s);
    return parsed && typeof parsed === "object" ? parsed : null;
  } catch {
    return null;
  }
}

// -------------------------
// Order normalization (base)
// -------------------------
export function normalizeOrder(raw) {
  const o = raw && typeof raw === "object" ? raw : {};
  const root = o?.raw && typeof o.raw === "object" ? o.raw : o;

  // IMPORTANT:
  // Preserve identity from BOTH raw backend objects and already-normalized rows.
  const oid = safeStr(
    firstDefined(
      o.oid,
      o.order_id,
      o.orderId,
      o.id,
      o.order_uuid,
      o.uuid,
      root.order_id,
      root.orderId,
      root.id,
      root.order_uuid,
      root.uuid,
      ""
    )
  );

  const buyer = safeStr(
    firstDefined(
      o.buyer_name,
      o.customer_name,
      o.customer,
      o.customerName,
      o.buyer,
      root.buyer_name,
      root.customer_name,
      root.customer,
      root.customerName,
      root.buyer,
      root?.customer_obj?.name,
      "—"
    )
  );

  const buyer_location = safeStr(
    firstDefined(
      o.buyer_location,
      o.customer_location,
      o.delivery_location,
      o.deliveryLocation,
      o.location,
      root.buyer_location,
      root.customer_location,
      root.delivery_location,
      root.deliveryLocation,
      root.location,
      root?.customer_obj?.location,
      ""
    )
  );

  const buyer_address = safeStr(
    firstDefined(
      o.buyer_address,
      o.customer_address,
      o.delivery_address,
      o.deliveryAddress,
      o.address,
      root.buyer_address,
      root.customer_address,
      root.delivery_address,
      root.deliveryAddress,
      root.address,
      buyer_location,
      ""
    )
  );

  const total = safeNumber(
    firstDefined(
      o.total,
      o.order_total,
      o.total_amount,
      o.grand_total,
      o.gross_total,
      o.amount,
      root.total,
      root.order_total,
      root.total_amount,
      root.grand_total,
      root.gross_total,
      root.amount,
      0
    ),
    0
  );

  const customer_order_total = safeNumber(
    firstDefined(
      o.customer_order_total,
      o.order_total_customer,
      root.customer_order_total,
      root.order_total_customer,
      total
    ),
    total
  );

  const farmer_order_total = safeNumber(
    firstDefined(
      o.farmer_order_total,
      o.farmer_subtotal,
      root.farmer_order_total,
      root.farmer_subtotal,
      total
    ),
    total
  );

  // Checkout financials / fee flow
  // These support staged checkout where the farmer sets delivery first,
  // VAT is shown separately, and EFT/bank instructions can be exposed to the UI.
  const products_subtotal = safeNumber(
    firstDefined(
      o.products_subtotal,
      root.products_subtotal,
      o.subtotal,
      root.subtotal,
      farmer_order_total,
      total
    ),
    total
  );

  const delivery_fee = safeNumber(
    firstDefined(o.delivery_fee, root.delivery_fee, 0),
    0
  );

  const delivery_fee_status = safeStr(
    firstDefined(o.delivery_fee_status, root.delivery_fee_status, "")
  );

  const vat_rate = safeNumber(
    firstDefined(o.vat_rate, root.vat_rate, 0.15),
    0.15
  );

  const vat_amount = safeNumber(
    firstDefined(o.vat_amount, root.vat_amount, o.vat, root.vat, 0),
    0
  );

  const grand_total = safeNumber(
    firstDefined(o.grand_total, root.grand_total, total),
    total
  );

  const checkout_flow_active = safeBool(
    firstDefined(o.checkout_flow_active, root.checkout_flow_active, false),
    false
  );

  const checkout_ready = safeBool(
    firstDefined(o.checkout_ready, root.checkout_ready, !checkout_flow_active),
    !checkout_flow_active
  );

  const checkout_stage = safeStr(
    firstDefined(o.checkout_stage, root.checkout_stage, "")
  );

  const bank_details =
    firstDefined(o.bank_details, root.bank_details, null) || null;

  const bank_name = safeStr(
    firstDefined(o.bank_name, root.bank_name, bank_details?.bank_name, "")
  );

  const account_name = safeStr(
    firstDefined(o.account_name, root.account_name, bank_details?.account_name, "")
  );

  const account_number = safeStr(
    firstDefined(o.account_number, root.account_number, bank_details?.account_number, "")
  );

  const branch_code = safeStr(
    firstDefined(o.branch_code, root.branch_code, bank_details?.branch_code, "")
  );

  const payment_instructions = safeStr(
    firstDefined(
      o.payment_instructions,
      root.payment_instructions,
      bank_details?.payment_instructions,
      ""
    )
  );

  const status = safeStr(
    firstDefined(o.status, o.order_status, root.status, root.order_status, "—")
  ).toLowerCase();

  const pay = safeStr(
    firstDefined(
      o.payment_status,
      o.paymentStatus,
      o.payment,
      root.payment_status,
      root.paymentStatus,
      root.payment,
      "unpaid"
    )
  ).toLowerCase();

  const payment_visibility_status = safeStr(
    firstDefined(
      o.payment_visibility_status,
      o.paymentVisibilityStatus,
      o.payment_visibility,
      o.paymentVisibility,
      root.payment_visibility_status,
      root.paymentVisibilityStatus,
      root.payment_visibility,
      root.paymentVisibility,
      ""
    )
  ).toLowerCase();

  let payment_reference = safeStr(
    firstDefined(
      o.payment_reference,
      o.payment_proof_reference,
      o.paymentProofReference,
      o.paymentReference,
      root.payment_reference,
      root.payment_proof_reference,
      root.paymentProofReference,
      root.paymentReference,
      ""
    )
  );

  let payment_proof_url = safeStr(
    firstDefined(
      o.payment_proof_url,
      o.paymentProofUrl,
      o.proof_url,
      o.proofUrl,
      root.payment_proof_url,
      root.paymentProofUrl,
      root.proof_url,
      root.proofUrl,
      ""
    )
  );

  let payment_proof_name = safeStr(
    firstDefined(
      o.payment_proof_name,
      o.paymentProofName,
      o.proof_name,
      o.proofName,
      root.payment_proof_name,
      root.paymentProofName,
      root.proof_name,
      root.proofName,
      ""
    )
  );

  const parsedRef = tryParseJsonObject(
    firstDefined(
      o.payment_reference_raw,
      root.payment_reference_raw,
      payment_reference,
      root.payment_reference
    )
  );

  if (parsedRef) {
    payment_reference = safeStr(
      firstDefined(parsedRef.reference, parsedRef.ref, payment_reference)
    );
    payment_proof_url = safeStr(
      firstDefined(payment_proof_url, parsedRef.proof_url, parsedRef.proofUrl, "")
    );
    payment_proof_name = safeStr(
      firstDefined(payment_proof_name, parsedRef.proof_name, parsedRef.proofName, "")
    );
  }

  const deliveryMethod = safeStr(
    firstDefined(o.delivery_method, root.delivery_method, "—")
  );
  const deliveryStatus = safeStr(
    firstDefined(o.delivery_status, root.delivery_status, "—")
  ).toLowerCase();

  const expectedDeliveryDate = safeStr(
    firstDefined(
      o.expected_delivery_date,
      o.expectedDeliveryDate,
      root.expected_delivery_date,
      root.expectedDeliveryDate,
      ""
    )
  );
  const deliveredAt = safeStr(
    firstDefined(o.delivered_at, o.deliveredAt, root.delivered_at, root.deliveredAt, "")
  );
  const deliveryDate = safeStr(
    firstDefined(
      o.delivery_date,
      o.deliveryDate,
      root.delivery_date,
      root.deliveryDate,
      deliveredAt,
      expectedDeliveryDate,
      ""
    )
  );

  const paidAt = safeStr(
    firstDefined(
      o.payment_date,
      o.paid_at,
      o.paidAt,
      root.payment_date,
      root.paid_at,
      root.paidAt,
      ""
    )
  );
  const paymentDate = safeStr(
    firstDefined(
      o.payment_date,
      o.paid_at,
      o.paidAt,
      root.payment_date,
      root.paid_at,
      root.paidAt,
      ""
    )
  );

  const address = safeStr(
    firstDefined(
      o.delivery_address,
      o.deliveryAddress,
      o.address,
      root.delivery_address,
      root.deliveryAddress,
      root.address,
      buyer_address,
      "—"
    )
  );
  const delivery_location = safeStr(
    firstDefined(
      o.delivery_location,
      o.deliveryLocation,
      root.delivery_location,
      root.deliveryLocation,
      buyer_location,
      ""
    )
  );

  const orderDateRaw = firstDefined(
    o.order_date,
    o.created_at,
    o.date,
    o.createdAt,
    root.order_date,
    root.created_at,
    root.date,
    root.createdAt,
    "—"
  );
  const orderDate = formatDateTime(orderDateRaw);

  const itemsRaw = safeArray(
    firstDefined(o.items, o.order_items, o.orderItems, root.items, root.order_items, root.orderItems)
  );
  const items = itemsRaw.map(normalizeOrderItem);

  const itemCount = safeNumber(
    firstDefined(
      o.item_count,
      o.items_count,
      o.itemCount,
      o.scoped_item_count,
      root.item_count,
      root.items_count,
      root.itemCount,
      root.scoped_item_count,
      items.length,
      0
    ),
    0
  );

  const preview =
    safeStr(firstDefined(o.items_preview, root.items_preview, "")) ||
    items
      .slice(0, 2)
      .map((it) => safeStr(firstDefined(it?.product_name, it?.name, "Item")))
      .filter(Boolean)
      .join(", ");

  const customer_name = safeStr(
    firstDefined(
      o.customer_name,
      o.buyer_name,
      o.customer,
      o.customerName,
      root.customer_name,
      root.buyer_name,
      root.customer,
      root.customerName,
      buyer,
      "—"
    )
  );
  const customer_email = safeStr(
    firstDefined(
      o.customer_email,
      o.buyer_email,
      root.customer_email,
      root.buyer_email,
      ""
    )
  );
  const customer_phone = safeStr(
    firstDefined(
      o.customer_phone,
      o.buyer_phone,
      root.customer_phone,
      root.buyer_phone,
      ""
    )
  );
  const customer_location = safeStr(
    firstDefined(
      o.customer_location,
      o.buyer_location,
      root.customer_location,
      root.buyer_location,
      delivery_location,
      ""
    )
  );
  const customer_address = safeStr(
    firstDefined(
      o.customer_address,
      o.buyer_address,
      root.customer_address,
      root.buyer_address,
      address,
      buyer_address,
      ""
    )
  );

  const is_new_for_farmer = safeBool(
    firstDefined(o.is_new_for_farmer, o.isNewForFarmer, root.is_new_for_farmer, root.isNewForFarmer, false),
    false
  );

  const exclusive_for_farmer = safeBool(
    firstDefined(o.exclusive_for_farmer, root.exclusive_for_farmer, false),
    false
  );
  const has_other_farmers_items = safeBool(
    firstDefined(o.has_other_farmers_items, root.has_other_farmers_items, false),
    false
  );
  const order_field_locked_for_multi = safeBool(
    firstDefined(o.order_field_locked_for_multi, root.order_field_locked_for_multi, false),
    false
  );
  const multi_farmer_order = safeBool(
    firstDefined(
      o.multi_farmer_order,
      o.multiFarmerOrder,
      root.multi_farmer_order,
      root.multiFarmerOrder,
      has_other_farmers_items || order_field_locked_for_multi || safeStr(firstDefined(o.scope_mode, root.scope_mode, "")) === "farmer_shared"
    ),
    false
  );

  return {
    // IMPORTANT:
    // Keep all major ID aliases so page/save logic remains stable.
    oid,
    order_id: oid,
    id: oid,

    buyer,
    buyer_name: buyer,
    buyer_location,
    buyer_address,

    total,
    customer_order_total,
    farmer_order_total,

    // Checkout totals / fee breakdown
    products_subtotal,
    delivery_fee,
    delivery_fee_status,
    vat_rate,
    vat_amount,
    grand_total,
    checkout_flow_active,
    checkout_ready,
    checkout_stage,

    // Bank detail exposure for EFT / bank transfer views
    bank_details,
    bank_name,
    account_name,
    account_number,
    branch_code,
    payment_instructions,

    status,
    payment_status: pay,

    payment_visibility_status,
    payment_status_badge: payment_visibility_status || pay || "—",
    payment_reference,
    payment_proof_url,
    payment_proof_name,

    payment_date: paymentDate,
    paid_at: paidAt,
    payment_method: safeStr(firstDefined(o.payment_method, root.payment_method, "")),

    delivery_method: deliveryMethod,
    delivery_status: deliveryStatus,
    expected_delivery_date: expectedDeliveryDate,
    delivered_at: deliveredAt,
    delivery_date: deliveryDate,
    delivery_address: address,
    delivery_location,

    order_date: safeStr(orderDateRaw, ""),
    created_at: safeStr(firstDefined(o.created_at, o.createdAt, root.created_at, root.createdAt, ""), ""),
    orderDate,

    itemCount,
    itemsPreview: preview,
    items,

    farmer_id: firstNonEmpty(
      o.farmer_id,
      o.farmerId,
      o.owner_id,
      o.seller_id,
      o.user_id,
      o.payment_scope_user_id,
      root.farmer_id,
      root.farmerId,
      root.owner_id,
      root.seller_id,
      root.user_id,
      root.payment_scope_user_id
    ),

    payment_scope: safeStr(firstDefined(o.payment_scope, root.payment_scope, "")),
    payment_scope_user_id: safeStr(
      firstDefined(o.payment_scope_user_id, root.payment_scope_user_id, "")
    ),
    farmer_paid_total: safeNumber(
      firstDefined(o.farmer_paid_total, root.farmer_paid_total, 0),
      0
    ),
    farmer_due_total: safeNumber(
      firstDefined(o.farmer_due_total, root.farmer_due_total, 0),
      0
    ),
    farmer_payment_progress_pct: safeNumber(
      firstDefined(o.farmer_payment_progress_pct, root.farmer_payment_progress_pct, 0),
      0
    ),
    partial_payment_visible: safeBool(
      firstDefined(o.partial_payment_visible, root.partial_payment_visible, false),
      false
    ),
    has_partial_payment: safeBool(
      firstDefined(o.has_partial_payment, root.has_partial_payment, false),
      false
    ),

    farmer_delivery_status: safeStr(
      firstDefined(o.farmer_delivery_status, root.farmer_delivery_status, "")
    ).toLowerCase(),
    farmer_expected_delivery_date: safeStr(
      firstDefined(o.farmer_expected_delivery_date, root.farmer_expected_delivery_date, "")
    ),
    farmer_delivered_at: safeStr(
      firstDefined(o.farmer_delivered_at, root.farmer_delivered_at, "")
    ),
    farmer_ordered_quantity_total: safeNumber(
      firstDefined(o.farmer_ordered_quantity_total, root.farmer_ordered_quantity_total, 0),
      0
    ),
    farmer_delivered_quantity_total: safeNumber(
      firstDefined(o.farmer_delivered_quantity_total, root.farmer_delivered_quantity_total, 0),
      0
    ),

    exclusive_for_farmer,
    has_other_farmers_items,
    order_field_locked_for_multi,
    multi_farmer_order,
    scope_mode: safeStr(firstDefined(o.scope_mode, root.scope_mode, "")),

    customer_name,
    customer_email,
    customer_phone,
    customer_location,
    customer_address,
    is_new_for_farmer,

    raw: root,
  };
}

// -------------------------
// Farmer-aware normalization
// -------------------------
export function normalizeOrderForFarmer(raw, farmerId = null) {
  const n = normalizeOrder(raw);
  const r = n.raw || {};
  const fid = safeStr(farmerId, "").trim();

  const exclusiveRaw = firstDefined(r.exclusive_for_farmer, n.exclusive_for_farmer);
  const hasOtherRaw = firstDefined(r.has_other_farmers_items, n.has_other_farmers_items);
  const orderFieldsLocked = firstDefined(
    r.order_field_locked_for_multi,
    n.order_field_locked_for_multi
  );

  let multiFarmer = false;
  if (
    n.multi_farmer_order === true ||
    exclusiveRaw === false ||
    hasOtherRaw === true ||
    orderFieldsLocked === true ||
    safeStr(firstDefined(r.scope_mode, n.scope_mode, "")) === "farmer_shared"
  ) {
    multiFarmer = true;
  }

  // IMPORTANT:
  // Prefer backend-scoped ownership flags first.
  let scopedItems = n.items;
  const itemsMarkedMine = n.items.filter((it) => safeBool(it?.belongs_to_current_farmer, false));
  if (itemsMarkedMine.length > 0) {
    scopedItems = itemsMarkedMine;
  } else if (fid) {
    const itemsWithOwner = n.items.filter((it) => getItemFarmerId(it?.raw));
    if (itemsWithOwner.length > 0) {
      const mine = n.items.filter((it) => idsEqual(getItemFarmerId(it?.raw), fid));
      if (mine.length > 0) {
        const alreadyScoped = n.items.every(
          (it) => !getItemFarmerId(it?.raw) || idsEqual(getItemFarmerId(it?.raw), fid)
        );

        scopedItems = alreadyScoped ? n.items : mine;
      }
    }
  }

  const scopedItemCount = safeNumber(
    firstDefined(
      r.scoped_item_count,
      r.items_count_for_farmer,
      n.itemCount,
      scopedItems.length
    ),
    scopedItems.length
  );

  const customerOrderTotal = safeNumber(
    firstDefined(
      r.customer_order_total,
      r.order_total_customer,
      n.customer_order_total,
      n.total
    ),
    safeNumber(n.total, 0)
  );

  const farmerSubtotal = safeNumber(
    firstDefined(
      r.farmer_order_total,
      r.farmer_subtotal,
      n.farmer_order_total,
      n.total
    ),
    safeNumber(n.total, 0)
  );

  const mainTotal = multiFarmer ? farmerSubtotal : safeNumber(n.total, 0);

  const scopedDeliveryStatus = safeBadgeText(
    firstDefined(
      r.farmer_delivery_status,
      n.farmer_delivery_status,
      r.delivery_status,
      n.delivery_status,
      "pending"
    ),
    "pending"
  );

  const scopedExpectedDelivery = safeStr(
    firstDefined(
      r.farmer_expected_delivery_date,
      n.farmer_expected_delivery_date,
      r.expected_delivery_date,
      n.expected_delivery_date,
      ""
    )
  );

  const scopedDeliveredAt = safeStr(
    firstDefined(
      r.farmer_delivered_at,
      n.farmer_delivered_at,
      r.delivered_at,
      n.delivered_at,
      ""
    )
  );

  const paymentStatus = safeBadgeText(
    firstDefined(r.payment_status, n.payment_status, "unpaid"),
    "unpaid"
  );

  const paymentVisibilityStatus = safeBadgeText(
    firstDefined(
      r.payment_visibility_status,
      n.payment_visibility_status,
      paymentStatus
    ),
    paymentStatus
  );

  const paymentStatusBadge = paymentVisibilityStatus || paymentStatus || "—";

  // IMPORTANT:
  // Show completed in farmer UI once farmer payment scope is confirmed paid,
  // unless the order was cancelled.
  let effectiveStatus = safeBadgeText(firstDefined(r.status, n.status, "pending"), "pending");
  if (paymentVisibilityStatus === "paid" && effectiveStatus !== "cancelled") {
    effectiveStatus = "completed";
  }

  return {
    ...n,

    // keep ID aliases stable
    oid: n.oid,
    order_id: n.oid,
    id: n.oid,

    farmer_id: fid || n.farmer_id || null,

    exclusive_for_farmer: exclusiveRaw,
    has_other_farmers_items: hasOtherRaw,
    order_field_locked_for_multi: orderFieldsLocked,
    multiFarmer,
    multi_farmer_order: multiFarmer,
    scope_mode: safeStr(firstDefined(r.scope_mode, n.scope_mode, "")),

    total: mainTotal,
    order_total: mainTotal,
    total_amount: mainTotal,
    farmer_order_total: farmerSubtotal,
    customer_order_total: customerOrderTotal,

    status: effectiveStatus,
    order_status: effectiveStatus,

    delivery_status: multiFarmer
      ? scopedDeliveryStatus
      : safeBadgeText(n.delivery_status, "pending"),
    expected_delivery_date: multiFarmer
      ? scopedExpectedDelivery
      : safeStr(n.expected_delivery_date, ""),
    delivered_at: multiFarmer ? scopedDeliveredAt : safeStr(n.delivered_at, ""),
    delivery_date: multiFarmer
      ? safeStr(scopedDeliveredAt || scopedExpectedDelivery || "")
      : safeStr(n.delivery_date, ""),

    payment_status: paymentStatus,
    payment_visibility_status: paymentVisibilityStatus,
    payment_status_badge: paymentStatusBadge,

    items: scopedItems,
    itemCount: scopedItemCount,
    itemsPreview:
      safeStr(firstDefined(r.items_preview, "")) ||
      scopedItems
        .slice(0, 2)
        .map((it) => safeStr(firstDefined(it?.product_name, "Item")))
        .join(", "),

    primary_total_label: multiFarmer ? "My subtotal" : "Order total",
    secondary_total_label: multiFarmer ? "Customer order total" : "",
  };
}

// ✅ Backward-compat alias expected by FarmerOrdersPage
export const _normalizeOrderForFarmer = normalizeOrderForFarmer;

export function normalizeOrdersPayload(data, farmerId = null, applyOwnershipFilter = true) {
  const rows = pickArrayFromPayload(data, [
    "orders",
    "items",
    "results",
    "rows",
    "list",
    "data",
    "order",
  ]);

  const normalized = safeArray(rows)
    .map((x) => normalizeOrderForFarmer(x, farmerId))
    .filter((x) => x?.oid);

  if (!applyOwnershipFilter) return normalized;

  const fid = safeStr(farmerId, "").trim();
  if (!fid) return normalized;

  const rowsWithSignals = normalized.filter(
    (n) =>
      getOrderFarmerId(n?.raw) ||
      safeArray(firstDefined(n?.raw?.items, n?.raw?.order_items, n?.raw?.orderItems)).some((it) =>
        getItemFarmerId(it)
      )
  );

  if (rowsWithSignals.length === 0) {
    return normalized;
  }

  return normalized.filter((n) => rawOrderBelongsToFarmer(n?.raw, fid));
}

// -------------------------
// Shared Hook
// -------------------------
export default function useFarmerOrders({
  farmerId,
  days = 60,
  q = "",
  includeItems = true,
  enabled = true,
} = {}) {
  const resolvedFarmerId = useMemo(() => resolveFarmerId(farmerId), [farmerId]);

  const endpoints = useMemo(() => epFarmerOrders(resolvedFarmerId), [resolvedFarmerId]);

  const hasExplicitFarmerId = Boolean(safeStr(farmerId, "").trim());

  /**
   * Important behavior:
   * - If caller passes enabled=false ONLY because user?.id is missing
   *   we still fetch as long as resolver can use session/JWT or /orders/my.
   * - If caller explicitly passes a farmerId and enabled=false, respect disable.
   */
  const callerExplicitlyDisabled = enabled === false && hasExplicitFarmerId;

  const daysNum = Number(days);
  const allTime = !Number.isFinite(daysNum) || daysNum <= 0;
  const queryText = safeStr(q, "");

  const canFetch = Boolean(!callerExplicitlyDisabled && endpoints.length > 0);

  const requestParams = useMemo(
    () => ({
      ...(allTime ? { all_time: 1, allTime: 1 } : { days: Math.floor(daysNum) }),
      q: queryText,
      query: queryText,
      search: queryText,
      include_items: includeItems ? 1 : 0,
      includeItems: includeItems ? 1 : 0,
      ...(resolvedFarmerId
        ? { farmer_id: resolvedFarmerId, farmerId: resolvedFarmerId }
        : {}),
    }),
    [allTime, daysNum, queryText, includeItems, resolvedFarmerId]
  );

  const res = useApi(endpoints, {
    enabled: canFetch,
    params: requestParams,
    initialData: undefined,
    deps: [
      resolvedFarmerId,
      daysNum,
      queryText,
      includeItems,
      allTime,
      canFetch,
      endpoints.join("|"),
    ],
  });

  const orders = useMemo(() => {
    const used = safeStr(res.usedEndpoint, "");

    const endpointIsAuthScopedFarmer = isAuthScopedFarmerEndpoint(used);
    const endpointIsBuyerScoped = isBuyerScopedEndpoint(used);

    const applyOwnershipFilter = !(endpointIsAuthScopedFarmer || endpointIsBuyerScoped);
    const filterFarmerId = applyOwnershipFilter ? resolvedFarmerId : null;

    const out = normalizeOrdersPayload(res.data, filterFarmerId, applyOwnershipFilter);

    const toTs = (row) => {
      const raw = row?.raw || {};
      const direct = firstDefined(
        raw?.created_at,
        raw?.createdAt,
        raw?.order_date,
        raw?.date,
        row?.order_date,
        row?.created_at,
        ""
      );
      const ts = new Date(direct).getTime();
      return Number.isFinite(ts) ? ts : -1;
    };

    return [...out].sort((a, b) => toTs(b) - toTs(a));
  }, [res.data, res.usedEndpoint, resolvedFarmerId]);

  return {
    ...res,
    orders,
    farmerId: resolvedFarmerId,
    requestedFarmerId: farmerId,
    canFetch,
    inactiveReason: canFetch
      ? ""
      : "Missing farmer identifier in session or explicit fetch disabled.",
  };
}