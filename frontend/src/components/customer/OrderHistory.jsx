// ============================================================================
// frontend/src/components/customer/OrderHistory.jsx
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Customer order list with structured order presentation.
//
// THIS UPDATE:
//   ✅ Keeps rich order header + expandable farmer scopes
//   ✅ Keeps multi-farmer proof upload safely farmer-scoped
//   ✅ Splits EFT and cash-on-delivery customer guidance clearly
//   ✅ Hides proof-upload UI completely for cash scopes
//   ✅ Adds cash-aware checkout-stage labels and helper messaging
//   ✅ Fixes payment-proof upload call to match the new customerApi signature
//   ✅ Keeps backend-origin proof URL normalization for uploaded files
// ============================================================================

import React, { useMemo, useState } from "react";
import {
  RefreshCw,
  ChevronDown,
  ChevronUp,
  Package,
  Truck,
  CircleDollarSign,
  CheckCircle2,
  Upload,
  ExternalLink,
  CalendarDays,
  Store,
  Users,
  MapPin,
  FileText,
} from "lucide-react";
import api from "../../api";
import * as customerApi from "../../services/customerApi";

function formatMoney(n) {
  const v = Number(n || 0);
  return `N$ ${Number.isFinite(v) ? v.toFixed(2) : "0.00"}`;
}

function safeStr(v, fallback = "") {
  const s = String(v ?? "").trim();
  return s ? s : fallback;
}

function normalizePaymentMethod(value) {
  const raw = safeStr(value).toLowerCase();
  if (!raw) return "";

  if (["cash", "cod", "cash_on_delivery", "cash-on-delivery", "cash on delivery"].includes(raw)) {
    return "cash_on_delivery";
  }

  if (["eft", "bank_transfer", "bank-transfer", "bank transfer", "electronic transfer"].includes(raw)) {
    return "eft";
  }

  return raw;
}

function paymentMethodIsCash(value) {
  return normalizePaymentMethod(value) === "cash_on_delivery";
}

function paymentMethodIsEft(value) {
  return normalizePaymentMethod(value) === "eft";
}

// -----------------------------------------------------------------------------
// Backend-origin helper
// -----------------------------------------------------------------------------
function getBackendRoot() {
  const axiosBase = safeStr(api?.defaults?.baseURL, "");

  const envBase =
    safeStr(process.env.REACT_APP_API_BASE_URL, "") ||
    safeStr(process.env.REACT_APP_API_URL, "") ||
    safeStr(process.env.REACT_APP_BACKEND_URL, "");

  const base = axiosBase || envBase;
  if (!base) return "";

  return base.replace(/\/api\/?$/i, "").replace(/\/+$/, "");
}

function normalizeProofHref(url) {
  const raw = safeStr(url, "").trim();
  if (!raw) return "";

  if (/^(https?:)?\/\//i.test(raw) || raw.startsWith("blob:") || raw.startsWith("data:")) {
    return raw;
  }

  const backendRoot = getBackendRoot();
  const path = (raw.startsWith("/") ? raw : `/${raw}`).replace(/^\/api\/api\//, "/api/");

  if (backendRoot && (path.startsWith("/api/") || path.startsWith("/uploads/"))) {
    return `${backendRoot}${path}`;
  }

  return path;
}

function coerceOrderId(o, idx) {
  return safeStr(o?.order_id ?? o?.orderId ?? o?.id ?? o?.orderID ?? `#${idx + 1}`);
}

function formatDateMaybe(v) {
  const s = safeStr(v, "");
  if (!s) return "—";

  const t = Date.parse(s);
  if (Number.isFinite(t)) {
    return new Date(t).toLocaleString(undefined, {
      year: "numeric",
      month: "short",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
    });
  }

  return s;
}

function formatQty(v) {
  const n = Number(v);
  if (!Number.isFinite(n)) return "0";
  if (Number.isInteger(n)) return String(n);
  return n.toFixed(3).replace(/\.?0+$/, "");
}

function badgeCls(kind, rawValue) {
  const value = safeStr(rawValue, "pending").toLowerCase();

  if (kind === "payment") {
    if (value === "paid") return "border-emerald-200 bg-emerald-50 text-emerald-700";
    if (value === "partial" || value === "pending") {
      return "border-amber-200 bg-amber-50 text-amber-700";
    }
    if (value === "failed" || value === "refunded") {
      return "border-rose-200 bg-rose-50 text-rose-700";
    }
    return "border-slate-200 bg-slate-50 text-slate-700";
  }

  if (kind === "delivery") {
    if (value === "delivered" || value === "completed") {
      return "border-emerald-200 bg-emerald-50 text-emerald-700";
    }
    if (value === "in_transit" || value === "shipped") {
      return "border-sky-200 bg-sky-50 text-sky-700";
    }
    if (value === "partial") return "border-amber-200 bg-amber-50 text-amber-700";
    if (value === "cancelled") return "border-rose-200 bg-rose-50 text-rose-700";
    return "border-slate-200 bg-slate-50 text-slate-700";
  }

  if (value === "completed") return "border-emerald-200 bg-emerald-50 text-emerald-700";
  if (value === "cancelled") return "border-rose-200 bg-rose-50 text-rose-700";
  return "border-slate-200 bg-slate-50 text-slate-700";
}

function maskAccountNumber(value) {
  const raw = safeStr(value);
  if (!raw) return "";
  const digits = raw.replace(/\s+/g, "");
  if (digits.length <= 4) return digits;
  return `•••• ${digits.slice(-4)}`;
}

function checkoutStageCopy(scope = {}) {
  const stage = safeStr(scope?.checkout_stage).toLowerCase();

  if (stage === "payment_verified") {
    return {
      tone: "border-emerald-200 bg-emerald-50 text-emerald-800",
      title: "Payment verified",
      body: "The payment for this farmer scope has already been verified.",
    };
  }

  if (stage === "cash_received") {
    return {
      tone: "border-emerald-200 bg-emerald-50 text-emerald-800",
      title: "Cash received",
      body: "The farmer has confirmed receipt of cash for this scope.",
    };
  }

  if (stage === "payment_submitted") {
    return {
      tone: "border-amber-200 bg-amber-50 text-amber-800",
      title: "Payment submitted",
      body: "Your proof of payment has been uploaded and is awaiting farmer verification.",
    };
  }

  if (stage === "awaiting_customer_payment") {
    return {
      tone: "border-sky-200 bg-sky-50 text-sky-800",
      title: "Ready for payment",
      body: "The farmer has set the delivery fee. Review the final total and complete payment for this scope.",
    };
  }

  if (stage === "awaiting_cash_delivery") {
    return {
      tone: "border-amber-200 bg-amber-50 text-amber-800",
      title: "Cash on delivery selected",
      body: "No proof is required. The farmer will collect payment on delivery or pickup.",
    };
  }

  if (scope?.checkout_flow_active) {
    return {
      tone: "border-amber-200 bg-amber-50 text-amber-800",
      title: "Awaiting farmer delivery fee",
      body: "The farmer still needs to set the delivery fee. VAT and final total will update automatically after that.",
    };
  }

  return null;
}
function getItems(order) {
  if (Array.isArray(order?.items)) return order.items;
  if (Array.isArray(order?.order_items)) return order.order_items;
  return [];
}

function computeLineTotal(item) {
  const explicit = Number(item?.line_total ?? item?.total);
  if (Number.isFinite(explicit)) return explicit;

  const qty = Number(item?.quantity ?? item?.qty ?? 0);
  const unitPrice = Number(item?.unit_price ?? item?.price ?? 0);
  return Number.isFinite(qty) && Number.isFinite(unitPrice) ? qty * unitPrice : 0;
}

function getFarmerNames(order) {
  const items = getItems(order);
  const names = new Set();

  items.forEach((item) => {
    const farmerName =
      safeStr(item?.farmer_name) ||
      safeStr(item?.seller_name) ||
      safeStr(order?.farmer_name) ||
      safeStr(order?.seller_name);

    if (farmerName) names.add(farmerName);
  });

  return [...names];
}

function buildFarmerGroups(order) {
  const items = getItems(order);
  const groups = new Map();

  items.forEach((item, idx) => {
    const farmerId = safeStr(item?.farmer_id);
    const farmerName = safeStr(item?.farmer_name ?? item?.seller_name, "Farmer");
    const key = farmerId || `${farmerName.toLowerCase()}-${idx}`;

    if (!groups.has(key)) {
      groups.set(key, {
        scope_user_id: farmerId || null,
        farmer_id: farmerId || null,
        farmer_name: farmerName,
        items: [],
      });
    }

    groups.get(key).items.push(item);
  });

  return [...groups.values()].map((group) => ({
    ...group,
    item_count: group.items.length,
    subtotal: group.items.reduce((sum, item) => sum + computeLineTotal(item), 0),
  }));
}

function getItemsForScope(order, scope) {
  const items = getItems(order);
  const scopeUserId = safeStr(
    scope?.scope_user_id ?? scope?.payment_scope_user_id ?? scope?.user_id ?? scope?.farmer_id
  );
  const scopeFarmerName = safeStr(scope?.farmer_name);

  return items.filter((item) => {
    const itemFarmerId = safeStr(item?.farmer_id);
    const itemFarmerName = safeStr(item?.farmer_name ?? item?.seller_name);

    if (scopeUserId && itemFarmerId) return scopeUserId === itemFarmerId;
    if (scopeFarmerName && itemFarmerName) {
      return scopeFarmerName.toLowerCase() === itemFarmerName.toLowerCase();
    }
    return false;
  });
}

function getPaymentScopes(order, orderId) {
  const explicitScopes = Array.isArray(order?.payment_scopes)
    ? order.payment_scopes
    : Array.isArray(order?.farmer_payment_scopes)
      ? order.farmer_payment_scopes
      : [];

  if (explicitScopes.length) {
    return explicitScopes.map((scope, idx) => {
      const scopedItems = getItemsForScope(order, scope);
      const scopeUserId = safeStr(
        scope?.scope_user_id ??
          scope?.payment_scope_user_id ??
          scope?.user_id ??
          scope?.farmer_id
      );

      return {
        ...scope,
        scope_key:
          safeStr(scope?.scope_key) ||
          `${orderId}:${scopeUserId || safeStr(scope?.farmer_name, `scope-${idx + 1}`)}`,
        scope_user_id: scopeUserId || null,
        payment_scope_user_id: scopeUserId || null,
        farmer_id: safeStr(scope?.farmer_id) || scopeUserId || null,
        farmer_name: safeStr(scope?.farmer_name, "Farmer"),
        items: scopedItems,
        item_count: Number(scope?.item_count) > 0 ? Number(scope.item_count) : scopedItems.length,
        subtotal:
          Number(scope?.products_subtotal ?? scope?.subtotal) ||
          scopedItems.reduce((sum, item) => sum + computeLineTotal(item), 0),
        products_subtotal:
          Number(scope?.products_subtotal ?? scope?.subtotal) ||
          scopedItems.reduce((sum, item) => sum + computeLineTotal(item), 0),
        delivery_fee: Number(scope?.delivery_fee ?? 0) || 0,
        vat_amount: Number(scope?.vat_amount ?? scope?.vat ?? 0) || 0,
        vat_rate: Number(scope?.vat_rate ?? 0.15) || 0.15,
        grand_total:
          Number(scope?.grand_total ?? scope?.total_amount ?? scope?.total) ||
          scopedItems.reduce((sum, item) => sum + computeLineTotal(item), 0),
        checkout_flow_active: !!scope?.checkout_flow_active,
        checkout_ready:
          scope?.checkout_ready == null ? !scope?.checkout_flow_active : !!scope?.checkout_ready,
        checkout_stage: scope?.checkout_stage ?? null,
        bank_details: scope?.bank_details ?? null,
        bank_name: scope?.bank_name ?? scope?.bank_details?.bank_name ?? null,
        account_name: scope?.account_name ?? scope?.bank_details?.account_name ?? null,
        account_number: scope?.account_number ?? scope?.bank_details?.account_number ?? null,
        branch_code: scope?.branch_code ?? scope?.bank_details?.branch_code ?? null,
        payment_instructions:
          scope?.payment_instructions ?? scope?.bank_details?.payment_instructions ?? null,
        payment_status: safeStr(scope?.payment_visibility_status ?? scope?.payment_status, "unpaid"),
        payment_method: normalizePaymentMethod(scope?.payment_method),
        delivery_status: safeStr(scope?.delivery_status, order?.delivery_status ?? "pending"),
        expected_delivery_date: scope?.expected_delivery_date ?? null,
        delivered_at: scope?.delivered_at ?? null,
        payment_proof_url: normalizeProofHref(scope?.payment_proof_url),
        payment_proof_name: safeStr(scope?.payment_proof_name, "Proof of payment"),
        payment_reference: safeStr(scope?.payment_reference),
      };
    });
  }

  const grouped = buildFarmerGroups(order);

  if (grouped.length > 1) {
    return grouped.map((group) => ({
      scope_key: `${orderId}:${group.scope_user_id || group.farmer_name}`,
      scope_user_id: group.scope_user_id,
      payment_scope_user_id: group.scope_user_id,
      farmer_id: group.farmer_id,
      farmer_name: group.farmer_name,
      items: group.items,
      item_count: group.item_count,
      subtotal: group.subtotal,
      products_subtotal: group.subtotal,
      delivery_fee: Number(order?.delivery_fee ?? 0) || 0,
      vat_amount: Number(order?.vat_amount ?? 0) || 0,
      vat_rate: Number(order?.vat_rate ?? 0.15) || 0.15,
      grand_total: Number(order?.grand_total ?? group.subtotal) || group.subtotal,
      checkout_flow_active: !!order?.checkout_flow_active,
      checkout_ready:
        order?.checkout_ready == null ? !order?.checkout_flow_active : !!order?.checkout_ready,
      checkout_stage: order?.checkout_stage ?? null,
      bank_details: order?.bank_details ?? null,
      bank_name: order?.bank_name ?? null,
      account_name: order?.account_name ?? null,
      account_number: order?.account_number ?? null,
      branch_code: order?.branch_code ?? null,
      payment_instructions: order?.payment_instructions ?? null,
      payment_status: safeStr(order?.payment_visibility_status ?? order?.payment_status, "pending"),
      payment_method: normalizePaymentMethod(order?.payment_method),
      delivery_status: safeStr(order?.delivery_status ?? "pending"),
      expected_delivery_date: order?.expected_delivery_date ?? null,
      delivered_at: order?.delivered_at ?? null,
      payment_proof_url: "",
      payment_proof_name: "Proof of payment",
      payment_reference: "",
    }));
  }

  const singleGroup = grouped[0] || null;

  return [
    {
      scope_key: `${orderId}:order`,
      scope_user_id: singleGroup?.scope_user_id || null,
      payment_scope_user_id: singleGroup?.scope_user_id || null,
      farmer_id: singleGroup?.farmer_id || null,
      farmer_name: singleGroup?.farmer_name || getFarmerNames(order).join(", ") || "Order payment",
      items: singleGroup?.items || getItems(order),
      item_count: singleGroup?.item_count ?? getItems(order).length,
      subtotal: singleGroup?.subtotal ?? Number(order?.products_subtotal ?? order?.subtotal ?? 0),
      products_subtotal:
        singleGroup?.subtotal ?? Number(order?.products_subtotal ?? order?.subtotal ?? 0),
      delivery_fee: Number(order?.delivery_fee ?? 0) || 0,
      vat_amount: Number(order?.vat_amount ?? 0) || 0,
      vat_rate: Number(order?.vat_rate ?? 0.15) || 0.15,
      grand_total:
        Number(order?.grand_total ?? order?.total_amount ?? order?.order_total ?? order?.total ?? 0),
      checkout_flow_active: !!order?.checkout_flow_active,
      checkout_ready:
        order?.checkout_ready == null ? !order?.checkout_flow_active : !!order?.checkout_ready,
      checkout_stage: order?.checkout_stage ?? null,
      bank_details: order?.bank_details ?? null,
      bank_name: order?.bank_name ?? null,
      account_name: order?.account_name ?? null,
      account_number: order?.account_number ?? null,
      branch_code: order?.branch_code ?? null,
      payment_instructions: order?.payment_instructions ?? null,
      payment_status: safeStr(order?.payment_visibility_status ?? order?.payment_status, "pending"),
      payment_method: normalizePaymentMethod(order?.payment_method),
      delivery_status: safeStr(order?.delivery_status ?? "pending"),
      expected_delivery_date:
        order?.expected_delivery_date ?? order?.farmer_expected_delivery_date ?? null,
      delivered_at: order?.delivered_at ?? order?.farmer_delivered_at ?? null,
      payment_proof_url: normalizeProofHref(order?.payment_proof_url),
      payment_proof_name: safeStr(order?.payment_proof_name, "Proof of payment"),
      payment_reference: safeStr(order?.payment_reference),
    },
  ];
}
export default function OrderHistory({ orders = [], loading = false, onRefresh }) {
  const [expandedByOrder, setExpandedByOrder] = useState({});
  const [uploadingByScope, setUploadingByScope] = useState({});
  const [uploadErrorByScope, setUploadErrorByScope] = useState({});
  const [uploadRefByScope, setUploadRefByScope] = useState({});
  const [uploadFileByScope, setUploadFileByScope] = useState({});

  const list = useMemo(() => (Array.isArray(orders) ? orders : []), [orders]);

  function toggleExpanded(orderId) {
    setExpandedByOrder((prev) => ({
      ...prev,
      [orderId]: !prev[orderId],
    }));
  }

  async function handleUploadProof(orderId, scope) {
    const scopeKey = safeStr(scope?.scope_key, orderId);
    const file = uploadFileByScope?.[scopeKey];
    const reference = safeStr(uploadRefByScope?.[scopeKey]);

    if (!file) {
      setUploadErrorByScope((prev) => ({
        ...prev,
        [scopeKey]: "Please select a proof-of-payment file first.",
      }));
      return;
    }

    setUploadErrorByScope((prev) => ({ ...prev, [scopeKey]: "" }));
    setUploadingByScope((prev) => ({ ...prev, [scopeKey]: true }));

    try {
      // FIX:
      // customerApi.uploadPaymentProof now expects:
      //   (orderId, file, options)
      await customerApi.uploadPaymentProof(orderId, file, {
        reference,
        scope_user_id:
          scope?.payment_scope_user_id ??
          scope?.scope_user_id ??
          scope?.farmer_id ??
          undefined,
        payment_method: scope?.payment_method,
      });

      await Promise.resolve(onRefresh?.());

      setUploadFileByScope((prev) => ({ ...prev, [scopeKey]: null }));
      setUploadRefByScope((prev) => ({ ...prev, [scopeKey]: "" }));
    } catch (e) {
      setUploadErrorByScope((prev) => ({
        ...prev,
        [scopeKey]: e?.message ? String(e.message) : "Failed to upload proof of payment.",
      }));
    } finally {
      setUploadingByScope((prev) => ({ ...prev, [scopeKey]: false }));
    }
  }

  if (loading) {
    return (
      <div className="rounded-2xl border border-slate-200 bg-white px-4 py-5 text-sm text-slate-600">
        Loading orders…
      </div>
    );
  }

  if (!list.length) {
    return (
      <div className="rounded-2xl border border-slate-200 bg-white px-4 py-5">
        <div className="text-sm font-extrabold text-slate-900">No orders yet</div>
        <div className="mt-1 text-xs text-slate-600">
          When you checkout from the marketplace, your orders will appear here.
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {typeof onRefresh === "function" ? (
        <div className="flex justify-end">
          <button
            type="button"
            onClick={onRefresh}
            className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm font-medium text-slate-700 shadow-sm hover:bg-slate-50"
          >
            <RefreshCw className="h-4 w-4" />
            Refresh orders
          </button>
        </div>
      ) : null}

      {list.map((order, idx) => {
        const orderId = coerceOrderId(order, idx);
        const items = getItems(order);
        const orderStatus = safeStr(order?.status ?? order?.order_status ?? "pending");
        const paymentStatus = safeStr(
          order?.payment_visibility_status ?? order?.payment_status ?? "unpaid"
        );
        const deliveryStatus = safeStr(
          order?.delivery_status ?? order?.farmer_delivery_status ?? "pending"
        );

        const total = Number(
          order?.grand_total ?? order?.total ?? order?.total_amount ?? order?.order_total ?? 0
        );

        const created =
          order?.created_at ??
          order?.createdAt ??
          order?.order_date ??
          order?.orderDate ??
          order?.placed_at ??
          order?.placedAt ??
          "";

        const expectedDelivery =
          order?.expected_delivery_date ?? order?.farmer_expected_delivery_date ?? null;

        const deliveredAt = order?.delivered_at ?? order?.farmer_delivered_at ?? null;
        const deliveryAddress = safeStr(
          order?.delivery_address ?? order?.buyer_address ?? order?.buyer_location
        );
        const farmerNames = getFarmerNames(order);
        const expanded = !!expandedByOrder?.[orderId];

        const scopes = getPaymentScopes(order, orderId);
        const isMultiFarmerOrder =
          typeof order?.is_multi_farmer_order === "boolean"
            ? order.is_multi_farmer_order
            : scopes.length > 1;

        return (
          <div key={orderId} className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
            <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <div className="text-sm font-extrabold text-slate-900">Order #{orderId}</div>

                  <span
                    className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-semibold ${badgeCls(
                      "order",
                      orderStatus
                    )}`}
                  >
                    {orderStatus}
                  </span>

                  <span
                    className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-semibold ${badgeCls(
                      "payment",
                      paymentStatus
                    )}`}
                  >
                    Payment: {paymentStatus}
                  </span>

                  <span
                    className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-semibold ${badgeCls(
                      "delivery",
                      deliveryStatus
                    )}`}
                  >
                    Delivery: {deliveryStatus}
                  </span>
                </div>

                <div className="mt-2 grid grid-cols-1 gap-2 text-xs text-slate-600 sm:grid-cols-2 xl:grid-cols-4">
                  <div className="inline-flex items-center gap-1">
                    <CircleDollarSign className="h-3.5 w-3.5" />
                    Total: <span className="font-semibold text-slate-900">{formatMoney(total)}</span>
                  </div>

                  <div className="inline-flex items-center gap-1">
                    <CalendarDays className="h-3.5 w-3.5" />
                    Placed: {formatDateMaybe(created)}
                  </div>

                  <div className="inline-flex items-center gap-1">
                    <Truck className="h-3.5 w-3.5" />
                    Expected: {formatDateMaybe(expectedDelivery)}
                  </div>

                  <div className="inline-flex items-center gap-1">
                    <CheckCircle2 className="h-3.5 w-3.5" />
                    Delivered: {formatDateMaybe(deliveredAt)}
                  </div>
                </div>

                <div className="mt-2 flex flex-wrap items-center gap-4 text-xs text-slate-600">
                  <div className="inline-flex items-center gap-1">
                    <Package className="h-3.5 w-3.5" />
                    {items.length} item{items.length === 1 ? "" : "s"}
                  </div>

                  {farmerNames.length ? (
                    <div className="inline-flex items-center gap-1">
                      {isMultiFarmerOrder ? <Users className="h-3.5 w-3.5" /> : <Store className="h-3.5 w-3.5" />}
                      {farmerNames.join(", ")}
                    </div>
                  ) : null}

                  {deliveryAddress ? (
                    <div className="inline-flex items-center gap-1">
                      <MapPin className="h-3.5 w-3.5" />
                      {deliveryAddress}
                    </div>
                  ) : null}
                </div>
              </div>

              <button
                type="button"
                onClick={() => toggleExpanded(orderId)}
                className="inline-flex items-center justify-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50"
              >
                {expanded ? (
                  <>
                    Hide details
                    <ChevronUp className="h-4 w-4" />
                  </>
                ) : (
                  <>
                    View details
                    <ChevronDown className="h-4 w-4" />
                  </>
                )}
              </button>
            </div>

            {expanded ? (
              <div className="mt-4 border-t border-slate-200 pt-4">
                {isMultiFarmerOrder ? (
                  <div className="mb-4 rounded-xl border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-900">
                    This is a multi-farmer order. Payment evidence must be uploaded separately
                    inside each farmer section so each farmer only sees the proof linked to their
                    own payment scope.
                  </div>
                ) : null}

                <div>
                  <div className="mb-3 text-sm font-semibold text-slate-900">
                    {isMultiFarmerOrder ? "Farmer payment scopes" : "Payment and fulfillment"}
                  </div>

                  <div className="space-y-3">
                    {scopes.map((scope, scopeIdx) => {
                      const scopeKey = safeStr(scope?.scope_key, `${orderId}:scope:${scopeIdx + 1}`);
                      const scopeUserId = safeStr(
                        scope?.payment_scope_user_id ?? scope?.scope_user_id ?? scope?.farmer_id
                      );

                      const proofUrl = normalizeProofHref(scope?.payment_proof_url);
                      const proofName = safeStr(scope?.payment_proof_name, "Proof of payment");
                      const reference = safeStr(scope?.payment_reference);
                      const scopedItems = Array.isArray(scope?.items) ? scope.items : [];
                      const stageInfo = checkoutStageCopy(scope);
                      const eftSelected = paymentMethodIsEft(scope?.payment_method);
                      const cashSelected = paymentMethodIsCash(scope?.payment_method);

                      const uploadDisabled =
                        !eftSelected ||
                        (isMultiFarmerOrder && !scopeUserId) ||
                        (scope?.checkout_flow_active && !scope?.checkout_ready);

                      return (
                        <div
                          key={scopeKey}
                          className="rounded-xl border border-slate-200 bg-slate-50/50 p-4"
                        >
                          <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
                            <div className="min-w-0">
                              <div className="flex flex-wrap items-center gap-2">
                                <div className="text-sm font-semibold text-slate-900">
                                  {scope?.farmer_name || `Farmer scope ${scopeIdx + 1}`}
                                </div>

                                <span
                                  className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-semibold ${badgeCls(
                                    "payment",
                                    scope?.payment_status
                                  )}`}
                                >
                                  Payment: {safeStr(scope?.payment_status, "unpaid")}
                                </span>

                                <span
                                  className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-semibold ${badgeCls(
                                    "delivery",
                                    scope?.delivery_status
                                  )}`}
                                >
                                  Delivery: {safeStr(scope?.delivery_status, "pending")}
                                </span>
                              </div>
                              <div className="mt-2 grid grid-cols-1 gap-2 text-xs text-slate-600 sm:grid-cols-2 xl:grid-cols-4">
                                <div>
                                  Products:{" "}
                                  <span className="font-semibold text-slate-900">
                                    {formatMoney(scope?.products_subtotal ?? scope?.subtotal)}
                                  </span>
                                </div>

                                <div>
                                  Delivery fee:{" "}
                                  <span className="font-semibold text-slate-900">
                                    {scope?.checkout_flow_active && !scope?.checkout_ready
                                      ? "Pending farmer quote"
                                      : formatMoney(scope?.delivery_fee)}
                                  </span>
                                </div>

                                <div>VAT (15%): {formatMoney(scope?.vat_amount)}</div>
                                <div>
                                  Final total: {formatMoney(scope?.grand_total ?? scope?.total_amount)}
                                </div>
                              </div>

                              <div className="mt-2 grid grid-cols-1 gap-2 text-xs text-slate-600 sm:grid-cols-2 xl:grid-cols-4">
                                <div>
                                  Items:{" "}
                                  <span className="font-semibold text-slate-900">
                                    {Number(scope?.item_count ?? scopedItems.length) || scopedItems.length}
                                  </span>
                                </div>
                                <div>
                                  Payment method: {safeStr(scope?.payment_method, "Not set")}
                                </div>
                                <div>Expected: {formatDateMaybe(scope?.expected_delivery_date)}</div>
                                <div>Delivered: {formatDateMaybe(scope?.delivered_at)}</div>
                              </div>

                              {reference ? (
                                <div className="mt-2 text-xs text-slate-600">
                                  Reference: <span className="font-medium text-slate-800">{reference}</span>
                                </div>
                              ) : null}
                            </div>

                            {proofUrl ? (
                              <a
                                href={proofUrl}
                                target="_blank"
                                rel="noreferrer"
                                className="inline-flex items-center gap-2 rounded-xl border border-emerald-200 bg-white px-3 py-2 text-sm font-medium text-emerald-700 hover:underline"
                              >
                                <ExternalLink className="h-4 w-4" />
                                {proofName}
                              </a>
                            ) : cashSelected ? (
                              <span className="inline-flex items-center rounded-xl border border-amber-200 bg-white px-3 py-2 text-xs text-amber-700">
                                No proof required for cash on delivery
                              </span>
                            ) : (
                              <span className="inline-flex items-center rounded-xl border border-slate-200 bg-white px-3 py-2 text-xs text-slate-500">
                                No proof uploaded yet
                              </span>
                            )}
                          </div>

                          {stageInfo ? (
                            <div className={`mt-3 rounded-xl border px-3 py-3 text-xs ${stageInfo.tone}`}>
                              <div className="font-semibold">{stageInfo.title}</div>
                              <div className="mt-1">{stageInfo.body}</div>
                            </div>
                          ) : null}

                          {eftSelected ? (
                            <div className="mt-3 rounded-xl border border-slate-200 bg-white p-4">
                              <div className="text-sm font-semibold text-slate-900">Bank transfer details</div>

                              {scope?.bank_name || scope?.account_name || scope?.account_number ? (
                                <div className="mt-3 grid grid-cols-1 gap-2 text-xs text-slate-600 sm:grid-cols-2">
                                  <div>
                                    Bank:{" "}
                                    <span className="font-semibold text-slate-900">
                                      {safeStr(scope?.bank_name, "—")}
                                    </span>
                                  </div>

                                  <div>
                                    Account name:{" "}
                                    <span className="font-semibold text-slate-900">
                                      {safeStr(scope?.account_name, "—")}
                                    </span>
                                  </div>

                                  <div>
                                    Account number:{" "}
                                    <span className="font-semibold text-slate-900">
                                      {maskAccountNumber(scope?.account_number) || "—"}
                                    </span>
                                  </div>

                                  <div>
                                    Branch code:{" "}
                                    <span className="font-semibold text-slate-900">
                                      {safeStr(scope?.branch_code, "—")}
                                    </span>
                                  </div>

                                  {scope?.payment_instructions ? (
                                    <div className="sm:col-span-2">
                                      Instructions:{" "}
                                      <span className="font-medium text-slate-800">
                                        {scope.payment_instructions}
                                      </span>
                                    </div>
                                  ) : null}
                                </div>
                              ) : (
                                <p className="mt-2 text-xs text-slate-500">
                                  The farmer&apos;s bank details will appear here once they configure EFT
                                  payment details.
                                </p>
                              )}
                            </div>
                          ) : cashSelected ? (
                            <div className="mt-3 rounded-xl border border-amber-200 bg-amber-50 p-4">
                              <div className="text-sm font-semibold text-amber-900">Cash on delivery</div>
                              <p className="mt-2 text-xs leading-5 text-amber-800">
                                No proof upload is required for this farmer scope. Payment will be
                                collected on delivery or pickup after the final total is confirmed.
                              </p>
                            </div>
                          ) : null}

                          <div className="mt-3 space-y-2">
                            {scopedItems.length ? (
                              scopedItems.map((item, itemIdx) => {
                                const itemKey = safeStr(item?.order_item_id) || `${scopeKey}:item:${itemIdx + 1}`;

                                const itemDelivery = safeStr(
                                  item?.item_delivery_status ?? item?.delivery_status ?? "pending"
                                );

                                const productName = safeStr(item?.product_name ?? item?.name, "Product");
                                const unit = safeStr(item?.unit, "unit");
                                const qty = formatQty(item?.quantity);
                                const deliveredQty = formatQty(
                                  item?.delivered_quantity ?? item?.delivered_qty ?? 0
                                );

                                return (
                                  <div
                                    key={itemKey}
                                    className="rounded-xl border border-slate-200 bg-white p-3"
                                  >
                                    <div className="flex flex-col gap-2 lg:flex-row lg:items-start lg:justify-between">
                                      <div className="min-w-0">
                                        <div className="text-sm font-medium text-slate-900">
                                          {productName}
                                        </div>
                                        <div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-slate-600">
                                          <span>
                                            Qty: {qty} {unit}
                                          </span>
                                          <span>•</span>
                                          <span>Line total: {formatMoney(item?.line_total)}</span>
                                          <span>•</span>
                                          <span>Delivered qty: {deliveredQty}</span>
                                        </div>
                                      </div>

                                      <span
                                        className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-semibold ${badgeCls(
                                          "delivery",
                                          itemDelivery
                                        )}`}
                                      >
                                        {itemDelivery}
                                      </span>
                                    </div>
                                  </div>
                                );
                              })
                            ) : (
                              <div className="rounded-xl border border-slate-200 bg-white p-3 text-xs text-slate-500">
                                No scoped item details were returned.
                              </div>
                            )}
                          </div>
                          {eftSelected ? (
                            <div className="mt-4 rounded-xl border border-slate-200 bg-white p-4">
                              <div className="mb-2 flex items-center gap-2 text-sm font-semibold text-slate-900">
                                <FileText className="h-4 w-4" />
                                Submit payment proof for {scope?.farmer_name || "this farmer"}
                              </div>

                              <div className="grid grid-cols-1 gap-3 lg:grid-cols-[1fr_220px_auto]">
                                <input
                                  type="file"
                                  accept=".png,.jpg,.jpeg,.webp,.pdf"
                                  disabled={uploadDisabled}
                                  onChange={(e) =>
                                    setUploadFileByScope((prev) => ({
                                      ...prev,
                                      [scopeKey]: e.target.files?.[0] || null,
                                    }))
                                  }
                                  className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm text-slate-700 disabled:cursor-not-allowed disabled:bg-slate-100"
                                />

                                <input
                                  type="text"
                                  value={uploadRefByScope?.[scopeKey] ?? ""}
                                  disabled={uploadDisabled}
                                  onChange={(e) =>
                                    setUploadRefByScope((prev) => ({
                                      ...prev,
                                      [scopeKey]: e.target.value,
                                    }))
                                  }
                                  placeholder="Reference (optional)"
                                  className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm text-slate-700 outline-none focus:border-slate-400 disabled:cursor-not-allowed disabled:bg-slate-100"
                                />

                                <button
                                  type="button"
                                  onClick={() => handleUploadProof(orderId, scope)}
                                  disabled={uploadDisabled || !!uploadingByScope?.[scopeKey]}
                                  className="inline-flex items-center justify-center gap-2 rounded-xl bg-[#1F7A4D] px-4 py-2 text-sm font-semibold text-white hover:brightness-95 disabled:cursor-not-allowed disabled:opacity-60"
                                >
                                  <Upload className="h-4 w-4" />
                                  {uploadingByScope?.[scopeKey] ? "Uploading…" : "Upload"}
                                </button>
                              </div>

                              {uploadDisabled ? (
                                <p className="mt-2 text-xs text-amber-700">
                                  {isMultiFarmerOrder && !scopeUserId
                                    ? "This farmer scope is missing a stable farmer identifier, so scoped proof upload is disabled for safety."
                                    : scope?.checkout_flow_active && !scope?.checkout_ready
                                      ? "Proof upload stays disabled until the farmer sets the delivery fee and the final total is ready."
                                      : "Proof upload is only available for EFT / bank transfer scopes that are ready for payment."}
                                </p>
                              ) : (
                                <p className="mt-2 text-xs text-slate-500">
                                  Upload proof only after reviewing the final total for this farmer scope.
                                </p>
                              )}

                              {uploadErrorByScope?.[scopeKey] ? (
                                <p className="mt-2 text-xs font-medium text-rose-700">
                                  {uploadErrorByScope[scopeKey]}
                                </p>
                              ) : null}
                            </div>
                          ) : null}
                        </div>
                      );
                    })}
                  </div>
                </div>
              </div>
            ) : null}
          </div>
        );
      })}
    </div>
  );
}