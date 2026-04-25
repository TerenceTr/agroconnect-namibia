// ============================================================================
// frontend/src/pages/dashboards/farmer/FarmerOrdersPage.jsx
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Dedicated farmer orders workflow page:
//   • Modern, professional e-commerce look
//   • Filters + responsive table/list
//   • Order details slide-over drawer with item-level edits
//   • Multi-farmer safe editing (order-level fields auto-disabled)
//
// THIS UPDATE:
//   ✅ Robust farmer ID resolution from auth user + session fallback
//   ✅ Uses hook resolver path (even when user?.id is missing)
//   ✅ Enabled fetch flow by default (hook handles missing IDs safely)
//   ✅ Adds "All time" filter (value 0) to avoid hidden old records
//   ✅ Clear diagnostics when canFetch=false vs true-but-empty
//   ✅ Keeps payment updates enabled for multi-farmer scope
//   ✅ Uses shared hook normalizer alias (_normalizeOrderForFarmer) for consistency
//   ✅ Customer details panel in drawer
//   ✅ Delivery location + delivery address visibility improved
//   ✅ Payment proof extraction supports direct fields + JSON payment_reference
//   ✅ Preserves payment method/reference when farmer changes payment status
//   ✅ Supports deep-open from topbar notification via localStorage focus key
//   ✅ Reduces policy duplication via isOrderFieldsLockedForView helper
//   ✅ Safer delivered_qty clamping to ordered quantity (including zero-qty edge case)
//   ✅ Payment proof URLs now resolve against the backend root when needed
//
// MULTI-FARMER / SHARED-ORDER UX IMPROVEMENTS:
//   ✅ Farmer sees ONLY their scoped slice as the main total
//   ✅ Customer full order total is shown separately for context
//   ✅ Payment badge/summary uses farmer-scoped visibility state
//   ✅ Delivery badge/summary uses farmer-scoped delivery state
//   ✅ Drawer labels switch to:
//        - My subtotal
//        - Customer order total
//        - My payment
//        - My delivery
//   ✅ Shared order notice is clearer and more explicit
//
// SAVE BUTTON / ORDER ID FIX:
//   ✅ Save no longer silently exits when `oid` is missing on the view model
//   ✅ Order ID is resolved defensively from:
//        oid -> order_id -> id -> raw.order_id -> raw.id
//   ✅ Drawer now surfaces backend order ID for support/debug visibility
//   ✅ User gets a clear error if order identity is missing instead of a dead button
//   ✅ Page no longer re-normalizes already-normalized hook rows
//
// BUYER / ITEM DISPLAY FIX:
//   ✅ Table and drawer show buyer name plus buyer address/location
//   ✅ Drawer shows only farmer-owned items from the scoped hook payload
//   ✅ Status reads as Completed once farmer payment scope is confirmed paid
//
// FARMER DELIVERY / PAYMENT PROOF FIX:
//   ✅ Shared-order farmers can now update THEIR delivery status
//   ✅ Delivery method/date/address remain policy-locked when required
//   ✅ Save payload sends farmer_delivery_status for scoped delivery updates
//   ✅ Proof of payment is shown whenever backend exposes customer-uploaded proof
//
// CHECKOUT / EFT FLOW IMPROVEMENTS:
//   ✅ Delivery fee can be quoted from the drawer
//   ✅ Farmer can mark order ready for payment and notify customer
//   ✅ VAT / delivery fee / grand total visible in summary
//   ✅ EFT details panel shows exactly what the customer will see
//   ✅ Missing EFT details prompt the farmer to open Farmer Settings
//
// NOTIFICATION FOCUS UX:
//   ✅ New-order notifications open and focus the Order details section
//   ✅ Payment-proof notifications open and focus the "Payment evidence for my scope" panel
//   ✅ Same-tab clicks work immediately through a window CustomEvent
//   ✅ Focused section scrolls into view and is softly highlighted
//
// RUNTIME FIX:
//   ✅ Fixed "Cannot access 'customerDetails' before initialization"
//   ✅ customerDetails is now declared BEFORE openMessageCustomer
// ============================================================================

import React, {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  CalendarDays,
  Search,
  RefreshCcw,
  X,
  Save,
  Package,
  CreditCard,
  Truck,
  ShoppingBag,
  AlertTriangle,
  FileText,
  ArrowUpRight,
  MessageSquareText,
} from "lucide-react";

import FarmerLayout from "../../../components/FarmerLayout";
import { useAuth } from "../../../components/auth/AuthProvider";
import api from "../../../api";

import useFarmerOrders, {
  _normalizeOrderForFarmer,
  safeArray,
  safeStr,
  safeNumber,
  formatDate,
  formatDateTime,
  toDateInputValue,
  resolveFarmerId,
  firstDefined,
} from "../../../hooks/useFarmerOrders";

// --------------------------------------------------------------------
// Cross-component keys used by FarmerTopbar notifications
// --------------------------------------------------------------------
const FOCUS_ORDER_STORAGE_KEY = "agroconnect_farmer_focus_order_id";
const FOCUS_ORDER_CONTEXT_STORAGE_KEY = "agroconnect_farmer_focus_order_context";
const FARMER_NOTIFICATION_FOCUS_EVENT = "agroconnect:farmer-notification-focus";

const FOCUS_SECTION_ORDER_SUMMARY = "order_summary";
const FOCUS_SECTION_PAYMENT_EVIDENCE = "payment_evidence";
const FOCUS_SECTION_ITEMS = "items";
const FOCUS_SECTION_UPDATES = "updates";

// --------------------------------------------------------------------
// API prefix resilience for direct axios calls (PUT)
// --------------------------------------------------------------------
function ensureLeadingSlash(p) {
  const s = String(p || "").trim();
  if (!s) return "";
  return s.startsWith("/") ? s : `/${s}`;
}

function apiPath(p) {
  const path = ensureLeadingSlash(p);
  if (!path) return path;

  const base = String(api?.defaults?.baseURL || "");
  const baseEndsWithApi = /\/api\/?$/.test(base);

  if (baseEndsWithApi && path.startsWith("/api/")) return path.replace(/^\/api/, "");
  return path;
}

// --------------------------------------------------------------------
// Generic helpers
// --------------------------------------------------------------------
function firstNonEmpty(...vals) {
  for (const v of vals) {
    const s = safeStr(v, "").trim();
    if (s) return s;
  }
  return "";
}

function clampNumber(n, min, max) {
  const x = Number(n);
  if (!Number.isFinite(x)) return min;
  if (x < min) return min;
  if (Number.isFinite(max) && x > max) return max;
  return x;
}

function lower(v, fallback = "") {
  return safeStr(v, fallback).toLowerCase();
}

function formatMoney(v) {
  const n = safeNumber(v, 0);
  return `N$ ${n.toFixed(2)}`;
}

function formatPercent(v) {
  const n = safeNumber(v, 0);
  return `${n.toFixed(0)}%`;
}

function shortId(v, left = 8, right = 6) {
  const s = safeStr(v, "").trim();
  if (!s) return "—";
  if (s.length <= left + right + 3) return s;
  return `${s.slice(0, left)}…${s.slice(-right)}`;
}

function titleCaseWords(v) {
  const s = safeStr(v, "").trim();
  if (!s) return "—";
  return s
    .replace(/_/g, " ")
    .toLowerCase()
    .replace(/\b([a-z])/g, (m) => m.toUpperCase());
}

function statusKey(v, fallback = "") {
  if (v && typeof v === "object") {
    return lower(firstDefined(v.key, v.value, v.label), fallback);
  }
  return lower(v, fallback);
}

function statusLabel(v, fallback = "—") {
  if (v && typeof v === "object") {
    const s = firstNonEmpty(v.label, v.key, v.value);
    return s ? titleCaseWords(s) : fallback;
  }
  const s = safeStr(v, "").trim();
  return s ? titleCaseWords(s) : fallback;
}

function resolveIdFromAuthUser(user) {
  if (!user || typeof user !== "object") return "";
  return firstNonEmpty(
    user.id,
    user.user_id,
    user.userId,
    user.farmer_id,
    user.farmerId,
    user.sub,
    user.uid,
    user?.user?.id,
    user?.user?.user_id,
    user?.user?.userId,
    user?.profile?.id,
    user?.profile?.user_id
  );
}

function getItemId(it) {
  return safeStr(firstDefined(it?.order_item_id, it?.orderItemId, it?.item_id, it?.id, ""));
}

/**
 * Resolve order ID defensively.
 */
function resolveOrderId(orderLike) {
  const o = orderLike || {};
  return firstNonEmpty(
    o?.oid,
    o?.order_id,
    o?.orderId,
    o?.id,
    o?.raw?.order_id,
    o?.raw?.orderId,
    o?.raw?.id,
    o?.raw?.uuid,
    o?.uuid
  );
}

/**
 * Table-friendly display label.
 */
function getDisplayOrderLabel(orderLike, fallbackIndex = null) {
  const resolved = resolveOrderId(orderLike);
  if (resolved) return shortId(resolved);
  if (typeof fallbackIndex === "number") return `#${fallbackIndex + 1}`;
  return "—";
}

/**
 * Return the backend origin/root from the shared axios base URL.
 * Example:
 *   http://localhost:5000/api  -> http://localhost:5000
 *   https://domain.com/api/    -> https://domain.com
 */
function getBackendRoot() {
  const base = safeStr(api?.defaults?.baseURL, "").trim();
  if (!base) return "";

  return base.replace(/\/api\/?$/i, "").replace(/\/+$/, "");
}

/**
 * Normalize a payment proof URL so it opens correctly whether the backend returns:
 *   - absolute URLs
 *   - blob/data URLs
 *   - relative /api/... paths
 *   - relative /uploads/... paths
 *
 * Important:
 * Backend-served proof files must open from the backend host, not the CRA/Vite
 * frontend dev server, otherwise proof links may 404 in local development.
 */
function normalizeProofHref(url) {
  const raw = safeStr(url, "").trim();
  if (!raw) return "";

  // Already absolute or browser-local data/blob URL
  if (/^(https?:)?\/\//i.test(raw) || raw.startsWith("blob:") || raw.startsWith("data:")) {
    return raw;
  }

  const backendRoot = getBackendRoot();
  const path = (raw.startsWith("/") ? raw : `/${raw}`).replace(/^\/api\/api\//, "/api/");

  // Backend-served proof files should open from the API server, not the frontend dev server
  if (backendRoot && (path.startsWith("/api/") || path.startsWith("/uploads/"))) {
    return `${backendRoot}${path}`;
  }

  return path;
}

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

function normalizePaymentMethod(value) {
  const raw = lower(value, "");
  if (!raw) return "";

  if (["cash", "cod", "cash_on_delivery", "cash-on-delivery", "cash on delivery"].includes(raw)) {
    return "cash_on_delivery";
  }

  if (["eft", "bank_transfer", "bank-transfer", "bank transfer", "electronic transfer"].includes(raw)) {
    return "eft";
  }

  return raw;
}

function paymentMethodIsCash(methodRaw) {
  return normalizePaymentMethod(methodRaw) === "cash_on_delivery";
}

function paymentMethodIsEft(methodRaw) {
  return normalizePaymentMethod(methodRaw) === "eft";
}

function paymentMethodLooksBankLike(methodRaw) {
  const m = lower(methodRaw, "");
  return (
    paymentMethodIsEft(methodRaw) ||
    m.includes("bank") ||
    m.includes("transfer") ||
    m.includes("wire")
  );
}

function deliveryProgressRequiresConfirmedPayment(statusRaw) {
  const s = lower(statusRaw, "");
  return s === "in_transit" || s === "delivered" || s === "completed";
}

function extractPaymentDetails(orderLike) {
  const order = orderLike || {};
  const raw = order?.raw || {};

  const methodRaw = firstNonEmpty(order?.payment_method, raw?.payment_method);
  const normalizedMethod = normalizePaymentMethod(methodRaw);

  const reference = firstNonEmpty(order?.payment_reference, raw?.payment_reference);
  const referenceRaw = firstNonEmpty(order?.payment_reference_raw, raw?.payment_reference_raw);

  const statusRaw = firstNonEmpty(
    order?.payment_visibility_status,
    order?.payment_status,
    raw?.payment_visibility_status,
    raw?.payment_status
  );

  let proofUrl = firstNonEmpty(order?.payment_proof_url, raw?.payment_proof_url);
  let proofName = firstNonEmpty(order?.payment_proof_name, raw?.payment_proof_name);
  let resolvedReference = reference;
  let resolvedReferenceRaw = referenceRaw;

  const parsedRefObj = tryParseJsonObject(referenceRaw || reference || raw?.payment_reference);
  if (parsedRefObj) {
    resolvedReference = firstNonEmpty(parsedRefObj.reference, parsedRefObj.ref, resolvedReference);
    resolvedReferenceRaw = firstNonEmpty(referenceRaw, reference, safeStr(parsedRefObj, ""));
    proofUrl = firstNonEmpty(proofUrl, parsedRefObj.proof_url, parsedRefObj.proofUrl);
    proofName = firstNonEmpty(proofName, parsedRefObj.proof_name, parsedRefObj.proofName);
  }

  const normalizedProofUrl = normalizeProofHref(proofUrl);
  const hasSubmittedEvidence = Boolean(normalizedProofUrl || resolvedReference);

  return {
    methodRaw,
    normalizedMethod,
    methodKey: normalizedMethod || lower(methodRaw, ""),
    isBankLike: paymentMethodLooksBankLike(methodRaw),
    isEft: paymentMethodIsEft(methodRaw),
    isCash: paymentMethodIsCash(methodRaw),
    statusRaw,
    statusKey: lower(statusRaw, "unpaid"),
    reference: resolvedReference,
    referenceRaw: resolvedReferenceRaw || reference || "",
    proofUrl: normalizedProofUrl,
    proofName,
    hasSubmittedEvidence,
  };
}
/**
 * Multi-farmer policy helper.
 */
function isOrderFieldsLockedForView(orderLike) {
  const v = orderLike || {};
  const explicit = firstDefined(
    v?.order_field_locked_for_multi,
    v?.raw?.order_field_locked_for_multi
  );
  if (explicit === false) return false;
  if (explicit === true) return true;
  return Boolean(v?.multiFarmer);
}

/**
 * First-load-only loading gate.
 */
function useFirstLoadGate(loading, data, error) {
  const [painted, setPainted] = useState(false);

  useEffect(() => {
    if (!painted && !loading && (data !== undefined || error)) setPainted(true);
  }, [loading, data, error, painted]);

  return painted;
}

function normalizeFocusSection(sectionRaw) {
  const s = safeStr(sectionRaw, FOCUS_SECTION_ORDER_SUMMARY);
  if (
    s === FOCUS_SECTION_PAYMENT_EVIDENCE ||
    s === FOCUS_SECTION_ITEMS ||
    s === FOCUS_SECTION_UPDATES ||
    s === FOCUS_SECTION_ORDER_SUMMARY
  ) {
    return s;
  }
  return FOCUS_SECTION_ORDER_SUMMARY;
}

function readStoredFocusContext() {
  if (typeof window === "undefined") return null;

  const legacyOrderId = safeStr(window.localStorage.getItem(FOCUS_ORDER_STORAGE_KEY), "").trim();
  const rawCtx = safeStr(window.localStorage.getItem(FOCUS_ORDER_CONTEXT_STORAGE_KEY), "").trim();

  let parsedCtx = null;
  if (rawCtx) {
    try {
      const obj = JSON.parse(rawCtx);
      if (obj && typeof obj === "object") parsedCtx = obj;
    } catch {
      parsedCtx = null;
    }
  }

  const orderId = safeStr(parsedCtx?.orderId || legacyOrderId, "").trim();
  if (!orderId) return null;

  return {
    orderId,
    section: normalizeFocusSection(parsedCtx?.section),
    notificationType: safeStr(parsedCtx?.notificationType, ""),
  };
}

function clearStoredFocusContext() {
  if (typeof window === "undefined") return;
  window.localStorage.removeItem(FOCUS_ORDER_STORAGE_KEY);
  window.localStorage.removeItem(FOCUS_ORDER_CONTEXT_STORAGE_KEY);
}

// --------------------------------------------------------------------
// Checkout / EFT helpers
// --------------------------------------------------------------------
const READY_DELIVERY_FEE_STATUSES = new Set([
  "quoted",
  "ready_for_payment",
  "awaiting_customer_payment",
  "checkout_ready",
  "customer_notified",
  "finalized",
  "set",
]);

function extractBankDetails(orderLike) {
  const order = orderLike || {};
  const raw = order?.raw || {};
  const bank = order?.bank_details || raw?.bank_details || {};

  const bank_name = firstNonEmpty(order?.bank_name, raw?.bank_name, bank?.bank_name);
  const account_name = firstNonEmpty(order?.account_name, raw?.account_name, bank?.account_name);
  const account_number = firstNonEmpty(
    order?.account_number,
    raw?.account_number,
    bank?.account_number
  );
  const branch_code = firstNonEmpty(order?.branch_code, raw?.branch_code, bank?.branch_code);
  const payment_instructions = firstNonEmpty(
    order?.payment_instructions,
    raw?.payment_instructions,
    bank?.payment_instructions
  );

  return {
    bank_name,
    account_name,
    account_number,
    branch_code,
    payment_instructions,
    is_complete: Boolean(bank_name && account_name && account_number),
  };
}

function checkoutStageLabel(stageRaw) {
  const s = lower(stageRaw, "");
  if (s === "awaiting_customer_payment") return "Ready for payment";
  if (s === "awaiting_farmer_quote") return "Awaiting my quote";
  if (s === "payment_submitted") return "Proof submitted";
  if (s === "payment_verified") return "Payment verified";
  if (s === "awaiting_cash_delivery") return "Cash on delivery";
  if (s === "cash_received") return "Cash received";
  if (s === "legacy") return "Legacy order";
  return s ? titleCaseWords(s) : "—";
}

function paymentKeyForOrder(orderLike) {
  return statusKey(
    firstDefined(
      orderLike?.payment_visibility_status,
      orderLike?.payment_status_badge,
      orderLike?.payment_status
    ),
    "unpaid"
  );
}

function deliveryKeyForOrder(orderLike) {
  return statusKey(
    firstDefined(
      orderLike?.farmer_delivery_status,
      orderLike?.delivery_status,
      orderLike?.item_delivery_status
    ),
    ""
  );
}

function farmerLifecycleStatusForDisplay(orderLike, fallbackStatus = "pending") {
  const baseStatus = statusKey(fallbackStatus, "pending");
  const paymentKey = paymentKeyForOrder(orderLike);
  const deliveryKey = deliveryKeyForOrder(orderLike);

  if (baseStatus === "cancelled") return "cancelled";
  if (deliveryKey === "delivered" || deliveryKey === "completed") return "completed";
  if (deliveryKey === "in_transit") return "in_transit";
  if (paymentKey === "paid") return "payment_verified";

  return baseStatus;
}

function deliveryFeeStatusLabel(orderLike) {
  const paymentKey = paymentKeyForOrder(orderLike);

  if (paymentKey === "paid") {
    return "Payment verified";
  }

  const rawFeeStatus = firstDefined(orderLike?.delivery_fee_status, "");
  const s = safeStr(rawFeeStatus, "").trim();

  return s ? titleCaseWords(s) : "";
}

function deliveryFeeStatusTone(orderLike) {
  return paymentKeyForOrder(orderLike) === "paid" ? "emerald" : "slate";
}


function maskAccountNumber(value) {
  const s = safeStr(value, "").replace(/\s+/g, "");
  if (!s) return "—";
  if (s.length <= 4) return s;
  return `•••• ${s.slice(-4)}`;
}

const TIME_WINDOWS = [
  { label: "Last 14 days", value: 14 },
  { label: "Last 28 days", value: 28 },
  { label: "Last 60 days", value: 60 },
  { label: "Last 90 days", value: 90 },
  { label: "Last 180 days", value: 180 },
  { label: "Last 365 days", value: 365 },
  { label: "All time", value: 0 },
];

const PAYMENT_OPTIONS = [
  { value: "unpaid", label: "Unpaid" },
  { value: "paid", label: "Paid" },
  { value: "refunded", label: "Refunded" },
];

const DELIVERY_METHODS = [
  { value: "", label: "—" },
  { value: "delivery", label: "Delivery" },
  { value: "pickup", label: "Pickup" },
];

const DELIVERY_STATUSES = [
  { value: "", label: "—" },
  { value: "pending", label: "Pending" },
  { value: "preparing", label: "Preparing" },
  { value: "partial", label: "Partial" },
  { value: "in_transit", label: "In transit" },
  { value: "delivered", label: "Delivered" },
  { value: "cancelled", label: "Cancelled" },
];

const ITEM_DELIVERY_STATUSES = DELIVERY_STATUSES;

// --------------------------------------------------------------------
// UI: badges + tones
// --------------------------------------------------------------------
function Badge({ tone = "slate", children, title }) {
  const tones = {
    slate: "border-slate-200 bg-slate-50 text-slate-700",
    emerald: "border-emerald-200 bg-emerald-50 text-emerald-800",
    amber: "border-amber-200 bg-amber-50 text-amber-800",
    rose: "border-rose-200 bg-rose-50 text-rose-800",
    indigo: "border-indigo-200 bg-indigo-50 text-indigo-800",
    sky: "border-sky-200 bg-sky-50 text-sky-800",
  };

  return (
    <span
      title={title}
      className={`inline-flex items-center rounded-full border px-2.5 py-1 text-xs font-extrabold ${tones[tone] || tones.slate}`}
    >
      {children}
    </span>
  );
}

function toneForPayment(v) {
  const s = statusKey(v, "unpaid");
  if (s === "paid") return "emerald";
  if (s === "refunded") return "slate";
  return "amber";
}

function toneForOrderStatus(v) {
  const s = statusKey(v, "");

  if (s === "completed") return "emerald";
  if (s === "payment_verified") return "emerald";
  if (s === "in_transit") return "sky";
  if (s === "preparing") return "indigo";
  if (s === "partial") return "amber";
  if (s === "cancelled") return "rose";
  if (s === "pending") return "amber";

  return "slate";
}


function toneForDelivery(v) {
  const s = statusKey(v, "");
  if (s === "delivered") return "emerald";
  if (s === "cancelled") return "rose";
  if (s === "in_transit") return "sky";
  if (s === "preparing") return "indigo";
  if (s === "partial") return "amber";
  if (s === "pending") return "slate";
  return "slate";
}

// --------------------------------------------------------------------
// Tiny UI helpers
// --------------------------------------------------------------------
function StatCard({ icon: Icon, label, value, sub }) {
  return (
    <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="text-xs font-bold uppercase tracking-wide text-slate-500">{label}</div>
          <div className="mt-1 text-xl font-extrabold text-slate-900">{value}</div>
          {sub ? <div className="mt-1 text-xs text-slate-500">{sub}</div> : null}
        </div>
        {Icon ? (
          <div className="grid h-10 w-10 place-items-center rounded-xl border border-slate-200 bg-slate-50">
            <Icon className="h-5 w-5 text-slate-600" />
          </div>
        ) : null}
      </div>
    </div>
  );
}

function EmptyState({ title, message, onRefresh }) {
  return (
    <div className="rounded-2xl border border-dashed border-slate-300 bg-slate-50 p-10 text-center">
      <div className="mx-auto mb-3 grid h-12 w-12 place-items-center rounded-xl border border-slate-200 bg-white">
        <Package className="h-5 w-5 text-slate-500" />
      </div>
      <div className="text-base font-bold text-slate-900">{title || "No orders found"}</div>
      <div className="mt-1 text-sm text-slate-500">
        {message || "Try a different date range or search term."}
      </div>
      <button
        type="button"
        onClick={onRefresh}
        className="mt-4 inline-flex h-10 items-center gap-2 rounded-xl border border-slate-200 bg-white px-4 text-sm font-semibold text-slate-800 hover:bg-slate-50"
      >
        <RefreshCcw className="h-4 w-4" />
        Refresh
      </button>
    </div>
  );
}

export default function FarmerOrdersPage() {
  const navigate = useNavigate();
  const { user } = useAuth();

  const farmerIdFromUser = useMemo(() => resolveIdFromAuthUser(user), [user]);
  const farmerIdResolved = useMemo(
    () => resolveFarmerId(farmerIdFromUser || null),
    [farmerIdFromUser]
  );

  const [days, setDays] = useState(90);
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState(null);

  const [edit, setEdit] = useState({
    payment_status: "unpaid",
    delivery_method: "",
    delivery_status: "",
    delivery_address: "",
    expected_delivery_date: "",
    delivery_fee: "",
    ready_for_payment: false,
  });

  const [editItems, setEditItems] = useState({});

  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState("");
  const [saveSuccess, setSaveSuccess] = useState("");

  const [pendingFocusContext, setPendingFocusContext] = useState(null);
  const [activeFocusSection, setActiveFocusSection] = useState("");

  const summarySectionRef = useRef(null);
  const paymentEvidenceSectionRef = useRef(null);
  const itemsSectionRef = useRef(null);
  const updatesSectionRef = useRef(null);

  const res = useFarmerOrders({
    farmerId: farmerIdResolved || farmerIdFromUser || null,
    days,
    q: query,
    includeItems: true,
    enabled: true,
  });

  const activeFarmerId = safeStr(
    firstDefined(res?.farmerId, farmerIdResolved, farmerIdFromUser, "")
  );

  const painted = useFirstLoadGate(res.loading, res.data, res.error);

  const normalizedOrders = useMemo(() => safeArray(res.orders), [res.orders]);
  const rows = useMemo(() => {
    const q = safeStr(query).trim().toLowerCase();
    if (!q) return normalizedOrders;

    return normalizedOrders.filter((o) => {
      const payText = statusLabel(
        firstDefined(o?.payment_status_badge, o?.payment_visibility_status, o?.payment_status),
        ""
      );

      const hay = `${safeStr(resolveOrderId(o))} ${safeStr(o?.buyer)} ${safeStr(
        o?.buyer_location
      )} ${safeStr(o?.buyer_address)} ${safeStr(o?.delivery_location)} ${safeStr(
        o?.delivery_address
      )} ${safeStr(o?.itemsPreview)} ${safeStr(o?.status)} ${payText}`
        .toLowerCase()
        .trim();

      return hay.includes(q);
    });
  }, [normalizedOrders, query]);

  const selectedView = useMemo(() => {
    if (!selected || typeof selected !== "object") return null;

    if (safeStr(selected?.oid, "").trim()) {
      return selected;
    }

    return _normalizeOrderForFarmer(selected, activeFarmerId);
  }, [selected, activeFarmerId]);

  const selectedOrderId = useMemo(() => resolveOrderId(selectedView), [selectedView]);

  const orderFieldsLocked = useMemo(
    () => isOrderFieldsLockedForView(selectedView),
    [selectedView]
  );

  const scopedDeliveryEditable = Boolean(selectedView) && !saving;

  const openOrderFromFocusContext = useCallback(
    (ctx) => {
      const targetOrderId = safeStr(ctx?.orderId, "").trim();
      if (!targetOrderId) return false;

      const hit = safeArray(normalizedOrders).find(
        (o) => safeStr(resolveOrderId(o), "").trim() === targetOrderId
      );

      if (!hit) {
        setPendingFocusContext({
          orderId: targetOrderId,
          section: normalizeFocusSection(ctx?.section),
          notificationType: safeStr(ctx?.notificationType, ""),
        });
        return false;
      }

      setSelected(hit);
      setQuery("");
      setPendingFocusContext({
        orderId: targetOrderId,
        section: normalizeFocusSection(ctx?.section),
        notificationType: safeStr(ctx?.notificationType, ""),
      });
      return true;
    },
    [normalizedOrders]
  );

  useEffect(() => {
    if (!painted) return;

    const ctx = readStoredFocusContext();
    if (!ctx) return;

    openOrderFromFocusContext(ctx);
    clearStoredFocusContext();
  }, [painted, openOrderFromFocusContext]);

  useEffect(() => {
    if (typeof window === "undefined") return undefined;

    const onFocusOrder = (evt) => {
      const detail = evt?.detail || null;
      if (!detail || typeof detail !== "object") return;

      openOrderFromFocusContext(detail);

      const targetOrderId = safeStr(detail?.orderId, "").trim();
      const existsInRows = safeArray(normalizedOrders).some(
        (o) => safeStr(resolveOrderId(o), "").trim() === targetOrderId
      );

      if (!existsInRows) {
        res.refetch?.();
      }
    };

    window.addEventListener(FARMER_NOTIFICATION_FOCUS_EVENT, onFocusOrder);
    return () => window.removeEventListener(FARMER_NOTIFICATION_FOCUS_EVENT, onFocusOrder);
  }, [normalizedOrders, openOrderFromFocusContext, res]);

  useEffect(() => {
    if (!pendingFocusContext?.orderId) return;
    if (selectedOrderId && selectedOrderId === pendingFocusContext.orderId) return;

    const hit = safeArray(normalizedOrders).find(
      (o) => safeStr(resolveOrderId(o), "").trim() === pendingFocusContext.orderId
    );

    if (hit) {
      setSelected(hit);
      setQuery("");
    }
  }, [normalizedOrders, pendingFocusContext, selectedOrderId]);

  useEffect(() => {
    if (!selectedView || !pendingFocusContext?.orderId) return;

    const currentSelectedId = safeStr(resolveOrderId(selectedView), "").trim();
    if (!currentSelectedId || currentSelectedId !== pendingFocusContext.orderId) return;

    const section = normalizeFocusSection(pendingFocusContext.section);

    const refMap = {
      [FOCUS_SECTION_ORDER_SUMMARY]: summarySectionRef,
      [FOCUS_SECTION_PAYMENT_EVIDENCE]: paymentEvidenceSectionRef,
      [FOCUS_SECTION_ITEMS]: itemsSectionRef,
      [FOCUS_SECTION_UPDATES]: updatesSectionRef,
    };

    const targetRef = refMap[section] || summarySectionRef;
    const targetEl = targetRef?.current;

    const scrollTimer = window.setTimeout(() => {
      if (targetEl && typeof targetEl.scrollIntoView === "function") {
        targetEl.scrollIntoView({
          behavior: "smooth",
          block: "start",
        });
      }
      setActiveFocusSection(section);
    }, 120);

    const clearTimer = window.setTimeout(() => {
      setActiveFocusSection("");
    }, 2600);

    setPendingFocusContext(null);

    return () => {
      window.clearTimeout(scrollTimer);
      window.clearTimeout(clearTimer);
    };
  }, [pendingFocusContext, selectedView]);

  const selectedPayment = useMemo(() => extractPaymentDetails(selectedView), [selectedView]);
  const selectedBankDetails = useMemo(() => extractBankDetails(selectedView), [selectedView]);

  const selectedCheckoutReady = useMemo(() => {
    const feeStatus = lower(firstDefined(selectedView?.delivery_fee_status, ""), "");
    return Boolean(selectedView?.checkout_ready) || READY_DELIVERY_FEE_STATUSES.has(feeStatus);
  }, [selectedView]);

  const customerDetails = useMemo(() => {
    if (!selectedView) return null;
    const raw = selectedView?.raw || {};

    return {
      name: firstNonEmpty(
        selectedView?.customer_name,
        selectedView?.buyer_name,
        selectedView?.buyer,
        raw?.buyer_name,
        raw?.customer_name,
        "—"
      ),
      id: firstNonEmpty(selectedView?.buyer_id, raw?.buyer_id, raw?.user_id, ""),
      email: firstNonEmpty(
        selectedView?.customer_email,
        selectedView?.buyer_email,
        raw?.buyer_email,
        raw?.email,
        raw?.customer_email,
        raw?.buyer?.email
      ),
      phone: firstNonEmpty(
        selectedView?.customer_phone,
        selectedView?.buyer_phone,
        raw?.buyer_phone,
        raw?.phone,
        raw?.customer_phone,
        raw?.buyer?.phone
      ),
      location: firstNonEmpty(
        selectedView?.customer_location,
        selectedView?.buyer_location,
        raw?.buyer_location,
        raw?.customer_location
      ),
      address: firstNonEmpty(
        selectedView?.customer_address,
        selectedView?.buyer_address,
        raw?.buyer_address,
        raw?.customer_address,
        selectedView?.delivery_address,
        raw?.delivery_address
      ),
      deliveryLocation: firstNonEmpty(
        selectedView?.delivery_location,
        raw?.delivery_location,
        selectedView?.buyer_location,
        raw?.buyer_location
      ),
      deliveryAddress: firstNonEmpty(
        selectedView?.delivery_address,
        raw?.delivery_address,
        selectedView?.buyer_address,
        raw?.buyer_address,
        selectedView?.delivery_location,
        raw?.delivery_location,
        selectedView?.buyer_location
      ),
    };
  }, [selectedView]);

  const openMessageCustomer = useCallback(() => {
    if (!customerDetails?.id) return;
    const params = new URLSearchParams();
    params.set("customerId", String(customerDetails.id));
    if (selectedOrderId) params.set("orderId", String(selectedOrderId));
    params.set("subject", selectedOrderId ? `Order ${selectedOrderId}` : "Order conversation");
    navigate(`/dashboard/farmer/messages?${params.toString()}`);
  }, [customerDetails?.id, navigate, selectedOrderId]);

  const kpis = useMemo(() => {
    const totalOrders = rows.length;
    const paidOrders = rows.filter((o) => {
      const key = statusKey(
        firstDefined(o?.payment_visibility_status, o?.payment_status_badge, o?.payment_status),
        "unpaid"
      );
      return key === "paid";
    }).length;
    const deliveredOrders = rows.filter((o) => lower(o?.delivery_status) === "delivered").length;
    const gross = rows.reduce((sum, o) => sum + safeNumber(o?.total, 0), 0);

    return { totalOrders, paidOrders, deliveredOrders, gross };
  }, [rows]);

  function sectionCardClass(sectionName) {
    return [
      "rounded-2xl border border-slate-200 p-4 transition",
      activeFocusSection === sectionName
        ? "bg-emerald-50/40 ring-2 ring-emerald-200"
        : "bg-white",
    ].join(" ");
  }

  useEffect(() => {
    if (!selectedView) return;

    setEdit({
      payment_status:
        statusKey(
          firstDefined(
            selectedView.payment_status,
            selectedView.payment_visibility_status,
            selectedView.payment_status_badge,
            "unpaid"
          ),
          "unpaid"
        ) || "unpaid",
      delivery_method: safeStr(firstDefined(selectedView.delivery_method, "")) || "",
      delivery_status: safeStr(firstDefined(selectedView.delivery_status, "")) || "",
      delivery_address:
        safeStr(
          firstDefined(
            selectedView.delivery_address,
            selectedView.delivery_location,
            selectedView.buyer_address,
            selectedView.buyer_location,
            ""
          )
        ) || "",
      expected_delivery_date: toDateInputValue(
        firstDefined(selectedView.expected_delivery_date, "")
      ),
      delivery_fee: Number(
        safeNumber(firstDefined(selectedView.delivery_fee, 0), 0)
      ).toFixed(2),
      ready_for_payment: Boolean(selectedView.checkout_ready),
    });

    const byId = {};
    for (const it of safeArray(selectedView.items)) {
      const id = getItemId(it);
      if (!id) continue;
      byId[id] = {
        delivered_qty: safeStr(firstDefined(it?.delivered_qty, it?.delivered_quantity, "0")),
        delivery_status: safeStr(
          firstDefined(it?.delivery_status, it?.item_delivery_status, "pending")
        ),
      };
    }
    setEditItems(byId);
    setSaveError("");
    setSaveSuccess("");
  }, [selectedView]);

  const closeDrawer = () => {
    setSelected(null);
    setSaveError("");
    setSaveSuccess("");
    setSaving(false);
    setPendingFocusContext(null);
    setActiveFocusSection("");
  };
  const saveFarmerStatus = async () => {
    if (!selectedView) {
      setSaveError("No order is selected.");
      return;
    }

    if (!activeFarmerId) {
      setSaveError("Missing farmer session. Please refresh or log in again.");
      return;
    }

    const selectedOrderIdInner = resolveOrderId(selectedView);
    if (!selectedOrderIdInner) {
      setSaveError("This order is missing a stable backend ID. Refresh and try again.");
      return;
    }

    setSaveError("");
    setSaveSuccess("");
    setSaving(true);

    try {
      const originalById = {};
      for (const it of safeArray(selectedView.items)) {
        const id = getItemId(it);
        if (!id) continue;

        originalById[id] = {
          delivered_qty: safeStr(firstDefined(it?.delivered_qty, it?.delivered_quantity, "0")),
          delivery_status: lower(
            firstDefined(it?.delivery_status, it?.item_delivery_status, "pending")
          ),
          quantity: safeNumber(firstDefined(it?.quantity, 0), 0),
        };
      }

      const itemsPatch = [];
      for (const [itemId, edited] of Object.entries(editItems || {})) {
        const orig = originalById[itemId] || {
          delivered_qty: "0",
          delivery_status: "pending",
          quantity: 0,
        };

        const nextQtyStr =
          safeStr(firstDefined(edited?.delivered_qty, orig.delivered_qty, "0")) || "0";

        const nextStatusRaw = safeStr(firstDefined(edited?.delivery_status, ""), "");
        const nextStatus = lower(nextStatusRaw || orig.delivery_status || "pending");

        const qtyChanged = String(nextQtyStr) !== String(orig.delivered_qty);
        const statusChanged = String(nextStatus) !== String(orig.delivery_status);

        if (!qtyChanged && !statusChanged) continue;

        const orderedQty = safeNumber(orig.quantity, 0);
        const maxAllowed = Number.isFinite(orderedQty)
          ? Math.max(0, orderedQty)
          : Number.POSITIVE_INFINITY;

        const deliveredQty = clampNumber(nextQtyStr, 0, maxAllowed);

        itemsPatch.push({
          order_item_id: itemId,
          delivered_qty: deliveredQty,
          delivery_status: nextStatus,
        });
      }

      const canEditOrderFields = !isOrderFieldsLockedForView(selectedView);

      const currentPay = statusKey(
        firstDefined(
          selectedView.payment_status,
          selectedView.payment_visibility_status,
          selectedView.payment_status_badge,
          "unpaid"
        ),
        "unpaid"
      );
      const nextPay = lower(firstDefined(edit.payment_status, "unpaid"));
      const hasPaymentChange = currentPay !== nextPay;

      const paymentToPreserve = extractPaymentDetails(selectedView);
      const paymentMethodKey =
        paymentToPreserve.normalizedMethod ||
        normalizePaymentMethod(selectedView?.payment_method);

      const paymentIsEft = paymentMethodIsEft(paymentMethodKey);
      const paymentIsCash = paymentMethodIsCash(paymentMethodKey);

      const currentScopedDeliveryStatus = lower(firstDefined(selectedView.delivery_status, ""));
      const nextScopedDeliveryStatus = lower(firstDefined(edit.delivery_status, ""));
      const hasScopedDeliveryStatusChange =
        nextScopedDeliveryStatus !== currentScopedDeliveryStatus;

      const currentDeliveryMethod = lower(firstDefined(selectedView.delivery_method, ""));
      const currentExpectedDate = safeStr(
        firstDefined(toDateInputValue(selectedView.expected_delivery_date || ""), "")
      );
      const currentAddress = safeStr(
        firstDefined(
          selectedView.delivery_address,
          selectedView.delivery_location,
          selectedView.buyer_address,
          selectedView.buyer_location,
          ""
        )
      );

      const nextMethod = lower(firstDefined(edit.delivery_method, ""));
      const nextExpectedDate = safeStr(firstDefined(edit.expected_delivery_date, ""));
      const nextAddress = safeStr(firstDefined(edit.delivery_address, ""));

      const hasHeaderDeliveryChange =
        canEditOrderFields &&
        (nextMethod !== currentDeliveryMethod ||
          nextExpectedDate !== currentExpectedDate ||
          nextAddress !== currentAddress);

      const currentDeliveryFee = safeNumber(firstDefined(selectedView.delivery_fee, 0), 0);
      const nextDeliveryFee = clampNumber(
        firstDefined(edit.delivery_fee, "0"),
        0,
        Number.POSITIVE_INFINITY
      );
      const hasDeliveryFeeChange =
        canEditOrderFields && Math.abs(nextDeliveryFee - currentDeliveryFee) > 0.0001;

      const currentReadyForPayment = Boolean(selectedView.checkout_ready);
      const nextReadyForPayment = Boolean(edit.ready_for_payment);
      const hasReadyForPaymentChange =
        canEditOrderFields && nextReadyForPayment !== currentReadyForPayment;

      if ((hasDeliveryFeeChange || hasReadyForPaymentChange) && !canEditOrderFields) {
        setSaveError("Delivery fee can only be changed on your own split/exclusive orders.");
        setSaving(false);
        return;
      }

      if (
        (hasDeliveryFeeChange || nextReadyForPayment) &&
        paymentIsEft &&
        !selectedBankDetails.is_complete
      ) {
        setSaveError(
          "Complete your EFT / bank details in Farmer Settings before marking an EFT order ready for payment."
        );
        setSaving(false);
        return;
      }

      const scopeDeliveryMovingForward =
        hasScopedDeliveryStatusChange &&
        deliveryProgressRequiresConfirmedPayment(nextScopedDeliveryStatus);

      const itemDeliveryMovingForward = itemsPatch.some((patch) =>
        deliveryProgressRequiresConfirmedPayment(patch.delivery_status)
      );

      const eftEvidenceMissing =
        paymentIsEft &&
        !paymentToPreserve.hasSubmittedEvidence &&
        currentPay !== "paid";

      if (paymentIsEft && nextPay === "paid" && eftEvidenceMissing) {
        setSaveError(
          "EFT payment cannot be marked as paid until the customer submits proof of payment or a payment reference."
        );
        setSaving(false);
        return;
      }

      if (
        paymentIsEft &&
        (scopeDeliveryMovingForward || itemDeliveryMovingForward) &&
        nextPay !== "paid" &&
        currentPay !== "paid"
      ) {
        setSaveError(
          "EFT orders cannot move to in transit or delivered until payment is confirmed as paid."
        );
        setSaving(false);
        return;
      }

      if (
        !itemsPatch.length &&
        !hasPaymentChange &&
        !hasScopedDeliveryStatusChange &&
        !hasHeaderDeliveryChange &&
        !hasDeliveryFeeChange &&
        !hasReadyForPaymentChange
      ) {
        setSaveSuccess("Nothing to save.");
        setSaving(false);
        return;
      }

      const payload = {
        farmer_id: activeFarmerId,
        farmerId: activeFarmerId,

        ...(hasPaymentChange
          ? {
              payment_status: nextPay || "unpaid",
              payment_method: paymentMethodKey || paymentToPreserve.methodRaw || null,
              payment_reference:
                paymentToPreserve.referenceRaw || paymentToPreserve.reference || null,
            }
          : {}),

        ...(hasScopedDeliveryStatusChange
          ? {
              farmer_delivery_status: nextScopedDeliveryStatus || null,
            }
          : {}),

        ...(canEditOrderFields && (hasDeliveryFeeChange || hasReadyForPaymentChange)
          ? {
              delivery_fee: Number(nextDeliveryFee.toFixed(2)),
              delivery_fee_status: nextReadyForPayment
                ? "awaiting_customer_payment"
                : nextDeliveryFee > 0
                  ? "quoted"
                  : "pending_quote",
              ready_for_payment: nextReadyForPayment,
            }
          : {}),

        ...(canEditOrderFields && hasHeaderDeliveryChange
          ? {
              delivery_method: safeStr(firstDefined(edit.delivery_method, "")) || null,
              expected_delivery_date:
                safeStr(firstDefined(edit.expected_delivery_date, "")) || null,
              delivery_address: safeStr(firstDefined(edit.delivery_address, "")) || null,

              ...(hasScopedDeliveryStatusChange
                ? {
                    delivery_status: safeStr(firstDefined(edit.delivery_status, "")) || null,
                  }
                : {}),
            }
          : {}),

        ...(itemsPatch.length ? { items: itemsPatch } : {}),
      };

      const resp = await api.put(
        apiPath(`/api/orders/${selectedOrderIdInner}/farmer-status`),
        payload
      );

      const updatedRaw =
        firstDefined(resp?.data?.order, resp?.data?.data?.order, resp?.data?.data, null) || null;

      if (updatedRaw && typeof updatedRaw === "object") {
        const normalized = _normalizeOrderForFarmer(updatedRaw, activeFarmerId);
        setSelected(normalized);

        setEdit({
          payment_status:
            statusKey(
              firstDefined(
                normalized.payment_status,
                normalized.payment_visibility_status,
                normalized.payment_status_badge,
                "unpaid"
              ),
              "unpaid"
            ) || "unpaid",
          delivery_method: safeStr(firstDefined(normalized.delivery_method, "")) || "",
          delivery_status: safeStr(firstDefined(normalized.delivery_status, "")) || "",
          expected_delivery_date: toDateInputValue(
            firstDefined(normalized.expected_delivery_date, "")
          ),
          delivery_address: safeStr(
            firstDefined(
              normalized.delivery_address,
              normalized.delivery_location,
              normalized.buyer_address,
              normalized.buyer_location,
              ""
            )
          ),
          delivery_fee: Number(
            safeNumber(firstDefined(normalized.delivery_fee, 0), 0)
          ).toFixed(2),
          ready_for_payment: Boolean(normalized.checkout_ready),
        });

        const byId = {};
        for (const it of safeArray(normalized.items)) {
          const id = getItemId(it);
          if (!id) continue;
          byId[id] = {
            delivered_qty: safeStr(firstDefined(it?.delivered_qty, it?.delivered_quantity, "0")),
            delivery_status: safeStr(
              firstDefined(it?.delivery_status, it?.item_delivery_status, "pending")
            ),
          };
        }
        setEditItems(byId);
      }

      setSaveSuccess(
        nextReadyForPayment
          ? paymentIsCash
            ? "Saved successfully. The customer has been notified that the order is ready for cash on delivery."
            : "Saved successfully. The customer has been notified that the order is ready for payment."
          : paymentIsCash && hasPaymentChange && nextPay === "paid"
            ? "Saved successfully. Cash receipt has been recorded for your scope."
            : "Saved successfully."
      );

      await res.refetch?.();
    } catch (e) {
      const msg =
        e?.response?.data?.message ||
        e?.response?.data?.error ||
        "Failed to save changes.";
      setSaveError(msg);
      // eslint-disable-next-line no-console
      console.error("saveFarmerStatus error:", e);
    } finally {
      setSaving(false);
    }
  };

  const emptyTitle = !res.canFetch ? "Session missing farmer ID" : "No orders found";
  const emptyMessage = !res.canFetch
    ? res.inactiveReason || "Please log out and log in again, then refresh."
    : days <= 60
      ? "Try “Last 180 days” or “All time”, or remove your search term."
      : "Try a different date range or search term.";
      return (
        <FarmerLayout>
          <div className="space-y-6">
            <section className="overflow-hidden rounded-3xl border border-slate-200 bg-white shadow-sm">
              <div className="bg-gradient-to-r from-emerald-50 via-white to-teal-50 p-6">
                <div className="flex flex-col gap-4 xl:flex-row xl:items-center xl:justify-between">
                  <div>
                    <div className="text-xs font-semibold uppercase tracking-wide text-emerald-700">
                      Farmer commerce
                    </div>
                    <h1 className="mt-1 text-2xl font-black tracking-tight text-slate-900">Orders</h1>
                    <p className="mt-1 text-sm text-slate-600">
                      Manage farmer-scoped payments, deliveries, and item fulfillment in one workflow.
                    </p>
    
                    <div className="mt-3 flex flex-wrap items-center gap-2">
                      <Badge tone={res.canFetch ? "emerald" : "amber"}>
                        {res.canFetch ? "Session ready" : "Session check needed"}
                      </Badge>
                      <Badge tone="slate" title="Resolved farmer ID">
                        Farmer: {shortId(activeFarmerId)}
                      </Badge>
                      {days === 0 ? <Badge tone="indigo">All-time view</Badge> : null}
                    </div>
                  </div>
    
                  <div className="flex w-full flex-wrap items-center gap-2 xl:w-auto">
                    <div className="inline-flex h-10 items-center gap-2 rounded-xl border border-slate-200 bg-white px-3">
                      <CalendarDays className="h-4 w-4 text-slate-400" />
                      <select
                        value={days}
                        onChange={(e) => setDays(Number(e.target.value))}
                        className="h-8 bg-transparent text-sm font-semibold text-slate-800 outline-none"
                      >
                        {TIME_WINDOWS.map((t) => (
                          <option key={t.value} value={t.value}>
                            {t.label}
                          </option>
                        ))}
                      </select>
                    </div>
    
                    <div className="flex h-10 w-[360px] max-w-full items-center gap-2 rounded-xl border border-slate-200 bg-white px-3">
                      <Search className="h-4 w-4 text-slate-400" />
                      <input
                        value={query}
                        onChange={(e) => setQuery(e.target.value)}
                        placeholder="Search order ID, buyer, address, product…"
                        className="w-full bg-transparent text-sm text-slate-800 outline-none placeholder:text-slate-400"
                      />
                    </div>
    
                    <button
                      type="button"
                      onClick={() => res.refetch?.()}
                      className="inline-flex h-10 items-center gap-2 rounded-xl border border-slate-200 bg-white px-4 text-sm font-semibold text-slate-800 hover:bg-slate-50"
                    >
                      <RefreshCcw className="h-4 w-4" />
                      Refresh
                    </button>
                  </div>
                </div>
              </div>
            </section>
    
            <section className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
              <StatCard
                icon={ShoppingBag}
                label="Visible orders"
                value={kpis.totalOrders}
                sub={days === 0 ? "All-time window" : `${days} day window`}
              />
              <StatCard
                icon={CreditCard}
                label="Paid scope"
                value={kpis.paidOrders}
                sub="Farmer payment visibility = paid"
              />
              <StatCard
                icon={Truck}
                label="Delivered scope"
                value={kpis.deliveredOrders}
                sub="Farmer delivery status = delivered"
              />
              <StatCard
                icon={Package}
                label="Visible value"
                value={formatMoney(kpis.gross)}
                sub="Farmer-scoped filtered total"
              />
            </section>
    
            <section className="overflow-hidden rounded-3xl border border-slate-200 bg-white shadow-sm">
              {!res.canFetch ? (
                <div className="flex items-start justify-between gap-3 border-b border-amber-200 bg-amber-50 p-4 text-sm text-amber-900">
                  <div className="flex gap-2">
                    <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
                    <div>
                      <div className="font-bold">Missing farmer identifier in session.</div>
                      <div className="mt-0.5 text-amber-800">
                        {res.inactiveReason || "Please log out and log in again, then refresh."}
                      </div>
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={() => res.refetch?.()}
                    className="h-9 rounded-xl border border-amber-300 bg-white px-3 font-semibold text-amber-900"
                  >
                    Retry
                  </button>
                </div>
              ) : null}
    
              {res.error ? (
                <div className="flex items-center justify-between gap-3 border-b border-rose-200 bg-rose-50 p-4 text-sm text-rose-700">
                  <div>Couldn’t load orders.</div>
                  <button
                    type="button"
                    onClick={() => res.refetch?.()}
                    className="h-9 rounded-xl border border-rose-200 bg-white px-3 font-semibold text-rose-700"
                  >
                    Retry
                  </button>
                </div>
              ) : null}
    
              <div className="p-4">
                {!painted && res.loading ? (
                  <div className="rounded-2xl border border-slate-200 bg-slate-50 p-6 text-sm text-slate-600">
                    Loading orders…
                  </div>
                ) : safeArray(rows).length === 0 ? (
                  <EmptyState
                    title={emptyTitle}
                    message={emptyMessage}
                    onRefresh={() => res.refetch?.()}
                  />
                ) : (
                  <>
                    <div className="hidden overflow-auto lg:block">
                      <table className="min-w-full text-sm">
                        <thead className="sticky top-0 z-10 bg-slate-50">
                          <tr className="border-b border-slate-200 text-left text-xs font-bold uppercase tracking-wide text-slate-500">
                            <th className="px-3 py-3">Order</th>
                            <th className="px-3 py-3">Buyer</th>
                            <th className="px-3 py-3">My items</th>
                            <th className="px-3 py-3">Visible total</th>
                            <th className="px-3 py-3">Status</th>
                            <th className="px-3 py-3">My payment</th>
                            <th className="px-3 py-3">My delivery</th>
                            <th className="px-3 py-3">Placed</th>
                          </tr>
                        </thead>
                        <tbody>
                          {safeArray(rows).slice(0, 200).map((o, idx) => {
                            const orderId = resolveOrderId(o);
                            const oidLabel = getDisplayOrderLabel(o, idx);
                            const rowKey = orderId || `row-${idx}`;
    
                            const buyer = safeStr(firstDefined(o?.buyer, o?.buyer_name, "—"));
                            const buyerLoc = safeStr(firstDefined(o?.buyer_location, ""));
                            const buyerAddress = safeStr(
                              firstDefined(o?.buyer_address, o?.delivery_address, "")
                            );
                            const itemsPreview = safeStr(firstDefined(o?.itemsPreview, ""));
                            const itemCount = safeNumber(firstDefined(o?.itemCount, 0), 0);
                            const total = safeNumber(firstDefined(o?.total, 0), 0);
    
                            const statusRaw = firstDefined(o?.status, "—");
                            const displayStatusRaw = farmerLifecycleStatusForDisplay(o, statusRaw);
                            const payRaw = firstDefined(
                              o?.payment_visibility_status,
                              o?.payment_status_badge,
                              o?.payment_status,
                              "unpaid"
                            );
                            const deliveryRaw = firstDefined(o?.delivery_status, "—");
    
                            const statusText = statusLabel(statusRaw, "—");
                            const payText = statusLabel(payRaw, "Unpaid");
                            const deliveryText = statusLabel(deliveryRaw, "—");
    
                            const dtPlaced = formatDateTime(
                              firstDefined(o?.order_date, o?.raw?.created_at, o?.raw?.order_date, "—")
                            );
                            const payDate = formatDate(firstDefined(o?.payment_date, "—"));
                            const delivDate = formatDate(firstDefined(o?.delivery_date, "—"));
    
                            return (
                              <tr
                                key={rowKey}
                                className="cursor-pointer border-b border-slate-100 transition hover:bg-emerald-50/40"
                                onClick={() => setSelected(o)}
                                title="Open order details"
                              >
                                <td className="px-3 py-3">
                                  <div className="font-bold text-slate-900" title={orderId || oidLabel}>
                                    {oidLabel}
                                  </div>
                                  {o?.multiFarmer ? (
                                    <div className="mt-1 flex flex-wrap gap-1">
                                      <Badge tone="amber" title="Contains items from multiple farmers">
                                        multi-farmer
                                      </Badge>
                                      <Badge tone="sky" title="Main total is your scoped share">
                                        my slice
                                      </Badge>
                                    </div>
                                  ) : null}
                                </td>
    
                                <td className="px-3 py-3">
                                  <div className="font-semibold text-slate-900">{buyer}</div>
                                  <div className="text-xs text-slate-500">{buyerLoc || "—"}</div>
                                  <div className="text-[11px] text-slate-400">
                                    Address: {buyerAddress || "—"}
                                  </div>
                                </td>
    
                                <td className="px-3 py-3 text-slate-700">
                                  {itemsPreview ? (
                                    <span className="font-semibold text-slate-900">{itemsPreview}</span>
                                  ) : (
                                    <span className="text-slate-400">—</span>
                                  )}
                                  {itemCount ? (
                                    <span className="text-slate-400"> · {itemCount} item(s)</span>
                                  ) : null}
                                </td>
    
                                <td className="px-3 py-3">
                                  <div className="font-bold text-slate-900">{formatMoney(total)}</div>
                                  {o?.multiFarmer ? (
                                    <div className="text-[11px] text-slate-400">
                                      Farmer-scoped subtotal
                                    </div>
                                  ) : null}
                                </td>
    
                                <td className="px-3 py-3">
                                  <Badge tone={toneForOrderStatus(displayStatusRaw)}>{statusText}</Badge>
                                </td>
    
                                <td className="px-3 py-3">
                                  <div className="flex flex-col gap-1">
                                    <Badge tone={toneForPayment(payRaw)}>{payText}</Badge>
                                    <span className="text-xs text-slate-500">
                                      Method: {statusLabel(firstDefined(o?.payment_method, "—"), "—")}
                                    </span>
                                    <span className="text-xs text-slate-500">
                                      {statusKey(payRaw) === "paid" ? payDate : "—"}
                                    </span>
                                  </div>
                                </td>
    
                                <td className="px-3 py-3">
                                  <div className="flex flex-col gap-1">
                                    <div className="flex items-center gap-2">
                                      <Badge tone="slate" title="Method">
                                        {statusLabel(firstDefined(o?.delivery_method, "—"), "—")}
                                      </Badge>
                                      <Badge tone={toneForDelivery(deliveryRaw)} title="Status">
                                        {deliveryText}
                                      </Badge>
                                    </div>
                                    <span className="text-xs text-slate-500">{delivDate}</span>
                                  </div>
                                </td>
    
                                <td className="px-3 py-3 text-slate-700">{dtPlaced}</td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
    
                    <div className="space-y-3 lg:hidden">
                      {safeArray(rows).slice(0, 120).map((o, idx) => {
                        const oidLabel = getDisplayOrderLabel(o, idx);
                        const buyer = safeStr(firstDefined(o?.buyer, o?.buyer_name, "—"));
                        const buyerAddress = safeStr(firstDefined(o?.buyer_address, o?.delivery_address, ""));
                        const itemsPreview = safeStr(firstDefined(o?.itemsPreview, ""));
                        const statusRaw = firstDefined(o?.status, "—");
                        const displayStatusRaw = farmerLifecycleStatusForDisplay(o, statusRaw);
                        const payRaw = firstDefined(
                          o?.payment_visibility_status,
                          o?.payment_status_badge,
                          o?.payment_status,
                          "unpaid"
                        );
                        const deliveryRaw = firstDefined(o?.delivery_status, "—");
    
                        const statusText = statusLabel(statusRaw, "—");
                        const payText = statusLabel(payRaw, "Unpaid");
                        const deliveryText = statusLabel(deliveryRaw, "—");
    
                        return (
                          <button
                            key={resolveOrderId(o) || `mobile-row-${idx}`}
                            type="button"
                            onClick={() => setSelected(o)}
                            className="w-full rounded-2xl border border-slate-200 bg-white p-4 text-left shadow-sm hover:bg-slate-50"
                          >
                            <div className="flex items-start justify-between gap-2">
                              <div className="min-w-0">
                                <div className="truncate font-bold text-slate-900">{oidLabel}</div>
                                <div className="mt-0.5 text-xs text-slate-500">{buyer}</div>
                                <div className="mt-0.5 text-[11px] text-slate-400">
                                  {buyerAddress || "—"}
                                </div>
                              </div>
                              <div className="text-sm font-bold text-slate-900">
                                {formatMoney(o?.total)}
                              </div>
                            </div>
    
                            <div className="mt-2 text-xs text-slate-600">
                              {itemsPreview || "—"}
                              {o?.multiFarmer ? (
                                <span className="ml-2 inline-flex flex-wrap gap-1 align-middle">
                                  <Badge tone="amber">multi-farmer</Badge>
                                  <Badge tone="sky">my slice</Badge>
                                </span>
                              ) : null}
                            </div>
    
                            <div className="mt-3 flex flex-wrap gap-2">
                              <Badge tone={toneForOrderStatus(displayStatusRaw)}>{statusText}</Badge>
                              <Badge tone={toneForPayment(payRaw)}>{payText}</Badge>
                              <Badge tone={toneForDelivery(deliveryRaw)}>{deliveryText}</Badge>
                            </div>
                          </button>
                        );
                      })}
                    </div>
    
                    <div className="mt-3 text-xs text-slate-400">
                      Tip: click an order to open your scoped details and update fulfillment.
                    </div>
                  </>
                )}
              </div>
            </section>
          </div>
          {selectedView ? (
        <div className="fixed inset-0 z-50">
          <button
            type="button"
            aria-label="Close order details"
            className="absolute inset-0 bg-slate-900/40 backdrop-blur-[1px]"
            onClick={closeDrawer}
          />

          <aside className="absolute right-0 top-0 h-full w-full max-w-[620px] border-l border-slate-200 bg-white shadow-2xl">
            <header className="border-b border-slate-200 bg-white p-5">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                    Order details
                  </div>
                  <div
                    className="truncate text-xl font-black text-slate-900"
                    title={selectedOrderId || selectedView.oid || "—"}
                  >
                    {selectedOrderId ? shortId(selectedOrderId) : selectedView.oid || "—"}
                  </div>

                  <div className="mt-1 text-xs text-slate-500">
                    Backend order ID:{" "}
                    <span className="font-semibold text-slate-700">
                      {selectedOrderId || "Missing"}
                    </span>
                  </div>

                  <div className="mt-1 text-sm text-slate-600">
                    Buyer:{" "}
                    <span className="font-semibold text-slate-900">
                      {customerDetails?.name || selectedView.buyer || "—"}
                    </span>
                  </div>
                  <div className="mt-0.5 text-xs text-slate-500">
                    Placed:{" "}
                    {firstNonEmpty(
                      selectedView.orderDate,
                      formatDateTime(
                        firstDefined(
                          selectedView?.order_date,
                          selectedView?.raw?.created_at,
                          selectedView?.raw?.order_date,
                          ""
                        )
                      ),
                      "—"
                    )}
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={openMessageCustomer}
                    disabled={!customerDetails?.id}
                    className="inline-flex h-10 items-center gap-2 rounded-xl border border-emerald-200 bg-emerald-50 px-3 text-sm font-semibold text-emerald-700 hover:bg-emerald-100 disabled:cursor-not-allowed disabled:border-slate-200 disabled:bg-slate-100 disabled:text-slate-400"
                  >
                    <MessageSquareText className="h-4 w-4" />
                    Message customer
                  </button>

                  <button
                    type="button"
                    onClick={closeDrawer}
                    className="grid h-10 w-10 place-items-center rounded-xl border border-slate-200 bg-white hover:bg-slate-50"
                    aria-label="Close drawer"
                  >
                    <X className="h-5 w-5 text-slate-700" />
                  </button>
                </div>
              </div>
            </header>

            <div className="h-[calc(100%-92px)] overflow-auto p-5">
              <div className="space-y-4">
                {!selectedOrderId ? (
                  <div className="rounded-2xl border border-rose-200 bg-rose-50 p-3 text-sm text-rose-800">
                    <div className="font-extrabold">Order ID missing</div>
                    <div className="mt-1">
                      This order cannot be updated until a valid backend order ID is present in the
                      page state.
                    </div>
                  </div>
                ) : null}

                {selectedView.multiFarmer ? (
                  <div className="rounded-2xl border border-amber-200 bg-amber-50 p-3 text-sm text-amber-900">
                    <div className="font-extrabold">Shared multi-farmer order</div>
                    <div className="mt-1">
                      You are viewing only{" "}
                      <span className="font-bold">
                        your items, your payment scope, and your delivery scope
                      </span>
                      . Header-level delivery fields may stay locked, but{" "}
                      <span className="font-bold">your delivery status</span> is still editable.
                    </div>
                  </div>
                ) : null}

                <section
                  ref={summarySectionRef}
                  className={sectionCardClass(FOCUS_SECTION_ORDER_SUMMARY)}
                >
                  <div className="mb-3 flex items-center justify-between gap-3">
                    <div className="text-sm font-extrabold text-slate-900">Order summary</div>
                    {activeFocusSection === FOCUS_SECTION_ORDER_SUMMARY ? (
                      <Badge tone="emerald">Opened from notification</Badge>
                    ) : null}
                  </div>

                  <div className="grid grid-cols-2 gap-3 text-sm">
                    <div>
                      <div className="text-xs text-slate-500">
                        {selectedView.multiFarmer ? "My subtotal" : "Order total"}
                      </div>
                      <div className="font-extrabold text-slate-900">
                        {formatMoney(selectedView.total)}
                      </div>
                    </div>

                    <div>
                      <div className="text-xs text-slate-500">Order status</div>
                      <Badge tone={toneForOrderStatus(selectedView.status)}>
                        {statusLabel(selectedView.status, "—")}
                      </Badge>
                    </div>

                    <div>
                      <div className="text-xs text-slate-500">Products subtotal</div>
                      <div className="font-semibold text-slate-900">
                        {formatMoney(selectedView.products_subtotal || selectedView.total)}
                      </div>
                    </div>

                    <div>
                      <div className="text-xs text-slate-500">Delivery fee</div>
                      <div className="font-semibold text-slate-900">
                        {formatMoney(selectedView.delivery_fee || 0)}
                      </div>
                    </div>

                    <div>
                      <div className="text-xs text-slate-500">VAT (15%)</div>
                      <div className="font-semibold text-slate-900">
                        {formatMoney(selectedView.vat_amount || 0)}
                      </div>
                    </div>

                    <div>
                      <div className="text-xs text-slate-500">Grand total</div>
                      <div className="font-extrabold text-slate-900">
                        {formatMoney(selectedView.grand_total || selectedView.total)}
                      </div>
                    </div>

                    <div className="col-span-2">
                      <div className="text-xs text-slate-500">Checkout stage</div>
                      <div className="flex flex-wrap items-center gap-2">
                        <Badge tone={selectedCheckoutReady ? "emerald" : "amber"}>
                          {checkoutStageLabel(selectedView.checkout_stage)}
                        </Badge>
                        {deliveryFeeStatusLabel(selectedView) ? (
                          <Badge tone={deliveryFeeStatusTone(selectedView)}>
                            Fee status: {deliveryFeeStatusLabel(selectedView)}
                          </Badge>
                        ) : null}
                      </div>
                    </div>

                    {selectedView.multiFarmer ? (
                      <div>
                        <div className="text-xs text-slate-500">Customer order total</div>
                        <div className="font-extrabold text-slate-900">
                          {formatMoney(selectedView.customer_order_total)}
                        </div>
                      </div>
                    ) : null}

                    {selectedView.multiFarmer ? (
                      <div>
                        <div className="text-xs text-slate-500">My payment progress</div>
                        <div className="font-extrabold text-slate-900">
                          {formatPercent(selectedView.farmer_payment_progress_pct)}
                        </div>
                      </div>
                    ) : null}

                    <div>
                      <div className="text-xs text-slate-500">
                        {selectedView.multiFarmer ? "My payment" : "Payment"}
                      </div>
                      <div className="flex flex-col gap-1">
                        <Badge
                          tone={toneForPayment(
                            firstDefined(
                              selectedView.payment_visibility_status,
                              selectedView.payment_status_badge,
                              selectedView.payment_status
                            )
                          )}
                        >
                          {statusLabel(
                            firstDefined(
                              selectedView.payment_visibility_status,
                              selectedView.payment_status_badge,
                              selectedView.payment_status,
                              "unpaid"
                            ),
                            "Unpaid"
                          )}
                        </Badge>

                        <div className="text-xs text-slate-500">
                          Method:{" "}
                          <span className="font-semibold text-slate-700">
                            {statusLabel(firstDefined(selectedView.payment_method, "—"), "—")}
                          </span>
                        </div>

                        <div className="text-xs text-slate-500">
                          {statusKey(
                            firstDefined(
                              selectedView.payment_visibility_status,
                              selectedView.payment_status_badge,
                              selectedView.payment_status
                            )
                          ) === "paid"
                            ? formatDate(selectedView.payment_date || "—")
                            : "—"}
                        </div>
                      </div>
                    </div>

                    <div>
                      <div className="text-xs text-slate-500">
                        {selectedView.multiFarmer ? "My delivery" : "Delivery"}
                      </div>
                      <div className="flex flex-col gap-1">
                        <div className="flex items-center gap-2">
                          <Badge tone="slate">
                            {statusLabel(selectedView.delivery_method || "—", "—")}
                          </Badge>
                          <Badge tone={toneForDelivery(selectedView.delivery_status)}>
                            {statusLabel(selectedView.delivery_status || "—", "—")}
                          </Badge>
                        </div>
                        <div className="text-xs text-slate-500">
                          {formatDate(selectedView.delivery_date || "—")}
                        </div>
                      </div>
                    </div>

                    {selectedView.multiFarmer ? (
                      <>
                        <div>
                          <div className="text-xs text-slate-500">My paid total</div>
                          <div className="font-semibold text-slate-900">
                            {formatMoney(selectedView.farmer_paid_total)}
                          </div>
                        </div>

                        <div>
                          <div className="text-xs text-slate-500">My due total</div>
                          <div className="font-semibold text-slate-900">
                            {formatMoney(selectedView.farmer_due_total)}
                          </div>
                        </div>
                      </>
                    ) : null}

                    <div className="col-span-2">
                      <div className="text-xs text-slate-500">
                        {selectedView.multiFarmer ? "My expected / delivered" : "Expected / Delivered"}
                      </div>
                      <div className="font-semibold text-slate-900">
                        {formatDate(selectedView.expected_delivery_date || "—")}
                        {safeStr(selectedView.delivered_at)
                          ? ` • ${formatDate(selectedView.delivered_at)}`
                          : ""}
                      </div>
                    </div>

                    <div className="col-span-2">
                      <div className="text-xs text-slate-500">Buyer location</div>
                      <div className="font-semibold text-slate-900">
                        {customerDetails?.location || "—"}
                      </div>
                    </div>

                    <div className="col-span-2">
                      <div className="text-xs text-slate-500">Buyer address</div>
                      <div className="font-semibold text-slate-900">
                        {customerDetails?.address || customerDetails?.deliveryAddress || "—"}
                      </div>
                    </div>

                    <div className="col-span-2">
                      <div className="text-xs text-slate-500">Delivery location</div>
                      <div className="font-semibold text-slate-900">
                        {customerDetails?.deliveryLocation || "—"}
                      </div>
                    </div>

                    <div className="col-span-2">
                      <div className="text-xs text-slate-500">Delivery address</div>
                      <div className="font-semibold text-slate-900">
                        {customerDetails?.deliveryAddress || "—"}
                      </div>
                    </div>
                  </div>
                </section>

                <section
                  ref={paymentEvidenceSectionRef}
                  className={sectionCardClass(FOCUS_SECTION_PAYMENT_EVIDENCE)}
                >
                  <div className="mb-3 flex items-start justify-between gap-3">
                    <div>
                      <div className="text-sm font-extrabold text-slate-900">
                        Payment evidence for my scope
                      </div>
                      <div className="mt-1 text-xs text-slate-500">
                        This is the exact panel opened by payment-proof notifications.
                      </div>
                    </div>

                    {activeFocusSection === FOCUS_SECTION_PAYMENT_EVIDENCE ? (
                      <Badge tone="emerald">Opened from notification</Badge>
                    ) : selectedPayment.proofUrl ? (
                      <Badge tone="emerald">Proof available</Badge>
                    ) : selectedPayment.isCash ? (
                      <Badge tone="amber">Cash order</Badge>
                    ) : selectedPayment.isBankLike ? (
                      <Badge tone="amber">Awaiting proof</Badge>
                    ) : (
                      <Badge tone="slate">No proof linked</Badge>
                    )}
                  </div>

                  <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                    <div>
                      <div className="text-xs text-slate-500">Payment method</div>
                      <div className="font-semibold text-slate-900">
                        {selectedPayment.isCash
                          ? "Cash on Delivery"
                          : selectedPayment.isEft
                            ? "EFT / Bank Transfer"
                            : selectedPayment.methodRaw
                              ? titleCaseWords(selectedPayment.methodRaw)
                              : "—"}
                      </div>
                    </div>

                    <div>
                      <div className="text-xs text-slate-500">Payment reference</div>
                      <div className="break-all font-semibold text-slate-900">
                        {selectedPayment.reference || "—"}
                      </div>
                    </div>

                    <div className="sm:col-span-2">
                      {selectedPayment.proofUrl ? (
                        <div className="rounded-xl border border-emerald-200 bg-emerald-50 p-3">
                          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                            <div className="min-w-0">
                              <div className="flex items-center gap-2 text-sm font-bold text-emerald-900">
                                <FileText className="h-4 w-4" />
                                Uploaded proof on file
                              </div>
                              <div className="mt-1 truncate text-xs text-emerald-800">
                                {selectedPayment.proofName || "Proof file available"}
                              </div>
                            </div>

                            <a
                              href={selectedPayment.proofUrl}
                              target="_blank"
                              rel="noreferrer"
                              className="inline-flex h-10 shrink-0 items-center justify-center gap-2 rounded-xl border border-emerald-300 bg-white px-4 text-sm font-semibold text-emerald-900 hover:bg-emerald-100/40"
                            >
                              View proof
                              <ArrowUpRight className="h-4 w-4" />
                            </a>
                          </div>
                        </div>
                      ) : selectedPayment.isCash ? (
                        <div className="rounded-xl border border-amber-200 bg-amber-50 p-3 text-sm text-amber-900">
                          This scope uses cash on delivery. No proof-of-payment upload is required before delivery.
                          Mark the payment as paid only after cash is actually received.
                        </div>
                      ) : selectedPayment.isBankLike ? (
                        <div className="rounded-xl border border-amber-200 bg-amber-50 p-3 text-sm text-amber-900">
                          Payment method is EFT/bank transfer, but no proof file or payment reference is linked yet
                          for your scope.
                        </div>
                      ) : (
                        <div className="rounded-xl border border-slate-200 bg-slate-50 p-3 text-sm text-slate-600">
                          No proof-of-payment file is currently linked to this farmer payment scope.
                        </div>
                      )}
                    </div>

                    <div className="sm:col-span-2">
                      <div className="rounded-xl border border-slate-200 bg-slate-50 p-3">
                        <div className="mb-2 text-sm font-bold text-slate-900">
                          EFT details the customer will see
                        </div>

                        {selectedBankDetails.is_complete ? (
                          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                            <div>
                              <div className="text-xs text-slate-500">Bank</div>
                              <div className="font-semibold text-slate-900">
                                {selectedBankDetails.bank_name}
                              </div>
                            </div>

                            <div>
                              <div className="text-xs text-slate-500">Account name</div>
                              <div className="font-semibold text-slate-900">
                                {selectedBankDetails.account_name}
                              </div>
                            </div>

                            <div>
                              <div className="text-xs text-slate-500">Account number</div>
                              <div className="font-semibold text-slate-900">
                                {maskAccountNumber(selectedBankDetails.account_number)}
                              </div>
                            </div>

                            <div>
                              <div className="text-xs text-slate-500">Branch code</div>
                              <div className="font-semibold text-slate-900">
                                {selectedBankDetails.branch_code || "—"}
                              </div>
                            </div>

                            <div className="sm:col-span-2">
                              <div className="text-xs text-slate-500">Instructions</div>
                              <div className="font-semibold text-slate-900">
                                {selectedBankDetails.payment_instructions || "—"}
                              </div>
                            </div>
                          </div>
                        ) : (
                          <div className="rounded-xl border border-amber-200 bg-amber-50 p-3 text-sm text-amber-800">
                            EFT details are incomplete. Customers cannot complete EFT checkout until you save your
                            bank details.
                            <div className="mt-2">
                              <Link
                                to="/dashboard/farmer/settings"
                                className="inline-flex items-center gap-2 rounded-xl border border-amber-200 bg-white px-3 py-2 text-sm font-bold text-slate-900 hover:bg-slate-50"
                              >
                                Open Farmer Settings
                              </Link>
                            </div>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                </section>

                <section className="rounded-2xl border border-slate-200 bg-white p-4">
                  <div className="mb-3 text-sm font-extrabold text-slate-900">Customer details</div>
                  <div className="grid grid-cols-1 gap-3 text-sm sm:grid-cols-2">
                    <div>
                      <div className="text-xs text-slate-500">Name</div>
                      <div className="font-semibold text-slate-900">
                        {customerDetails?.name || "—"}
                      </div>
                    </div>

                    <div>
                      <div className="text-xs text-slate-500">Customer ID</div>
                      <div className="font-semibold text-slate-900">
                        {customerDetails?.id ? shortId(customerDetails.id) : "—"}
                      </div>
                    </div>

                    <div>
                      <div className="text-xs text-slate-500">Phone</div>
                      <div className="font-semibold text-slate-900">
                        {customerDetails?.phone || "—"}
                      </div>
                    </div>

                    <div>
                      <div className="text-xs text-slate-500">Email</div>
                      <div className="break-all font-semibold text-slate-900">
                        {customerDetails?.email || "—"}
                      </div>
                    </div>

                    <div className="sm:col-span-2">
                      <div className="text-xs text-slate-500">Customer location</div>
                      <div className="font-semibold text-slate-900">
                        {customerDetails?.location || "—"}
                      </div>
                    </div>

                    <div className="sm:col-span-2">
                      <div className="text-xs text-slate-500">Customer address</div>
                      <div className="font-semibold text-slate-900">
                        {customerDetails?.address || "—"}
                      </div>
                    </div>
                  </div>
                </section>

                <section
                  ref={itemsSectionRef}
                  className={sectionCardClass(FOCUS_SECTION_ITEMS)}
                >
                  <div className="mb-3 flex items-center justify-between gap-3">
                    <div className="text-sm font-extrabold text-slate-900">
                      {selectedView.multiFarmer ? "My items" : "Items"}
                    </div>
                    {activeFocusSection === FOCUS_SECTION_ITEMS ? (
                      <Badge tone="emerald">Opened from notification</Badge>
                    ) : null}
                  </div>

                  {safeArray(selectedView.items).length === 0 ? (
                    <div className="text-sm text-slate-500">
                      No item details available for this order.
                    </div>
                  ) : (
                    <ul className="space-y-3">
                      {safeArray(selectedView.items).map((it, idx) => {
                        const id = getItemId(it) || `${idx}`;
                        const name = safeStr(firstDefined(it?.product_name, "Item"));
                        const orderedQty = safeNumber(firstDefined(it?.quantity, 0), 0);
                        const unit = safeStr(firstDefined(it?.unit, ""));
                        const unitPrice = safeNumber(firstDefined(it?.unit_price, 0), 0);
                        const lineTotal = safeNumber(
                          firstDefined(it?.line_total, unitPrice * orderedQty),
                          0
                        );

                        const deliveredQty = safeStr(
                          firstDefined(
                            editItems?.[id]?.delivered_qty,
                            it?.delivered_qty,
                            it?.delivered_quantity,
                            "0"
                          )
                        );
                        const itemStatus = safeStr(
                          firstDefined(
                            editItems?.[id]?.delivery_status,
                            it?.delivery_status,
                            it?.item_delivery_status,
                            "pending"
                          )
                        );

                        return (
                          <li key={id} className="rounded-xl border border-slate-200 bg-white p-3">
                            <div className="flex items-start justify-between gap-3">
                              <div className="min-w-0">
                                <div className="truncate font-semibold text-slate-900">{name}</div>
                                <div className="mt-1 text-xs text-slate-500">
                                  Ordered:{" "}
                                  <span className="font-semibold text-slate-700">{orderedQty}</span>
                                  {unit ? <span className="text-slate-400"> {unit}</span> : null}
                                  <span className="text-slate-400"> • </span>
                                  Unit:{" "}
                                  <span className="font-semibold text-slate-700">
                                    {formatMoney(unitPrice)}
                                  </span>
                                </div>
                              </div>
                              <div className="text-right">
                                <div className="text-[11px] text-slate-500">Line total</div>
                                <div className="font-extrabold text-slate-900">
                                  {formatMoney(lineTotal)}
                                </div>
                              </div>
                            </div>

                            <div className="mt-3 grid grid-cols-1 gap-3 sm:grid-cols-2">
                              <div>
                                <div className="mb-1 text-xs font-semibold text-slate-600">
                                  Delivered qty
                                </div>
                                <input
                                  type="number"
                                  step="0.001"
                                  min="0"
                                  max={orderedQty || 0}
                                  value={deliveredQty}
                                  onChange={(e) =>
                                    setEditItems((s) => ({
                                      ...(s || {}),
                                      [id]: {
                                        ...(s?.[id] || {}),
                                        delivered_qty: e.target.value,
                                      },
                                    }))
                                  }
                                  placeholder="0"
                                  className="h-11 w-full rounded-xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-900 outline-none focus:ring-2 focus:ring-emerald-200"
                                />
                                <div className="mt-1 text-[11px] text-slate-400">
                                  Tip: use values above 0 for partial deliveries.
                                </div>
                              </div>

                              <div>
                                <div className="mb-1 text-xs font-semibold text-slate-600">
                                  Item delivery status
                                </div>
                                <select
                                  value={itemStatus}
                                  onChange={(e) =>
                                    setEditItems((s) => ({
                                      ...(s || {}),
                                      [id]: {
                                        ...(s?.[id] || {}),
                                        delivery_status: e.target.value,
                                      },
                                    }))
                                  }
                                  className="h-11 w-full rounded-xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-900 outline-none focus:ring-2 focus:ring-emerald-200"
                                >
                                  {ITEM_DELIVERY_STATUSES.map((s) => (
                                    <option key={s.value || s.label} value={s.value}>
                                      {s.label}
                                    </option>
                                  ))}
                                </select>
                                <div className="mt-1">
                                  <Badge tone={toneForDelivery(itemStatus)} title="Preview">
                                    {statusLabel(itemStatus || "—", "—")}
                                  </Badge>
                                </div>
                              </div>
                            </div>
                          </li>
                        );
                      })}
                    </ul>
                  )}
                </section>

                <section
                  ref={updatesSectionRef}
                  className={sectionCardClass(FOCUS_SECTION_UPDATES)}
                >
                  <div className="mb-3 flex items-center justify-between gap-3">
                    <div className="text-sm font-extrabold text-slate-900">
                      {selectedView.multiFarmer ? "Update my order scope" : "Update order status"}
                    </div>
                    {activeFocusSection === FOCUS_SECTION_UPDATES ? (
                      <Badge tone="emerald">Opened from notification</Badge>
                    ) : null}
                  </div>

                  {saveError ? (
                    <div className="mb-3 rounded-xl border border-rose-200 bg-rose-50 p-3 text-sm text-rose-700">
                      {saveError}
                    </div>
                  ) : null}

                  {saveSuccess ? (
                    <div className="mb-3 rounded-xl border border-emerald-200 bg-emerald-50 p-3 text-sm text-emerald-800">
                      {saveSuccess}
                    </div>
                  ) : null}

                  {orderFieldsLocked ? (
                    <div className="mb-3 rounded-xl border border-slate-200 bg-slate-50 p-3 text-sm text-slate-700">
                      Header-level delivery fields are locked for this shared order in your current
                      policy. You can still update <span className="font-bold">your delivery status</span>,{" "}
                      <span className="font-bold">your item delivery</span>, and{" "}
                      <span className="font-bold">your payment scope</span>.
                    </div>
                  ) : null}

                  <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                    <div>
                      <div className="mb-1 text-xs font-semibold text-slate-600">
                        {selectedView.multiFarmer ? "My payment status" : "Payment status"}
                      </div>
                      <select
                        value={edit.payment_status}
                        onChange={(e) =>
                          setEdit((s) => ({ ...s, payment_status: e.target.value }))
                        }
                        disabled={saving}
                        className="h-11 w-full rounded-xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-900 outline-none focus:ring-2 focus:ring-emerald-200 disabled:cursor-not-allowed disabled:bg-slate-50 disabled:opacity-60"
                        title={selectedView.multiFarmer ? "Applies only to your items" : ""}
                      >
                        {PAYMENT_OPTIONS.map((p) => (
                          <option key={p.value} value={p.value}>
                            {p.label}
                          </option>
                        ))}
                      </select>
                    </div>

                    <div className="sm:col-span-2 -mt-1 space-y-1 text-[11px]">
                      <div className="text-amber-700">
                        Payment updates are scoped to your products. Delivery address defaults from
                        customer address/location.
                      </div>

                      {selectedPayment.isEft ? (
                        <div className="text-sky-700">
                          EFT rule: do not mark payment as paid until the customer submits proof of
                          payment or a payment reference. Also do not move delivery to in transit or
                          delivered until payment is confirmed as paid.
                        </div>
                      ) : selectedPayment.isCash ? (
                        <div className="text-emerald-700">
                          Cash rule: no proof upload is required. Delivery may proceed without proof,
                          but mark payment as paid only after cash is actually received.
                        </div>
                      ) : null}
                    </div>

                    <div>
                      <div className="mb-1 text-xs font-semibold text-slate-600">
                        Delivery method
                      </div>
                      <select
                        value={edit.delivery_method}
                        onChange={(e) =>
                          setEdit((s) => ({ ...s, delivery_method: e.target.value }))
                        }
                        disabled={orderFieldsLocked || saving}
                        className="h-11 w-full rounded-xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-900 outline-none focus:ring-2 focus:ring-emerald-200 disabled:cursor-not-allowed disabled:bg-slate-50 disabled:opacity-60"
                        title={orderFieldsLocked ? "Locked for this shared order" : ""}
                      >
                        {DELIVERY_METHODS.map((m) => (
                          <option key={m.value || m.label} value={m.value}>
                            {m.label}
                          </option>
                        ))}
                      </select>
                    </div>

                    <div>
                      <div className="mb-1 text-xs font-semibold text-slate-600">
                        {selectedView.multiFarmer ? "My delivery status" : "Delivery status"}
                      </div>
                      <select
                        value={edit.delivery_status}
                        onChange={(e) =>
                          setEdit((s) => ({ ...s, delivery_status: e.target.value }))
                        }
                        disabled={!scopedDeliveryEditable}
                        className="h-11 w-full rounded-xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-900 outline-none focus:ring-2 focus:ring-emerald-200 disabled:cursor-not-allowed disabled:bg-slate-50 disabled:opacity-60"
                        title={
                          selectedView.multiFarmer
                            ? "Applies to your scoped delivery status"
                            : "Delivery status"
                        }
                      >
                        {DELIVERY_STATUSES.map((s) => (
                          <option key={s.value || s.label} value={s.value}>
                            {s.label}
                          </option>
                        ))}
                      </select>

                      <div className="mt-1 text-[11px] text-slate-500">
                        {selectedPayment.isEft
                          ? "For EFT orders, in transit and delivered require confirmed paid status."
                          : selectedPayment.isCash
                            ? "For cash orders, delivery can proceed without proof upload."
                            : "Update the delivery state for your scoped order slice."}
                      </div>
                    </div>

                    <div>
                      <div className="mb-1 text-xs font-semibold text-slate-600">
                        Delivery fee
                      </div>
                      <input
                        type="number"
                        min="0"
                        step="0.01"
                        value={edit.delivery_fee}
                        onChange={(e) =>
                          setEdit((s) => ({ ...s, delivery_fee: e.target.value }))
                        }
                        disabled={orderFieldsLocked || saving}
                        className="h-11 w-full rounded-xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-900 outline-none focus:ring-2 focus:ring-emerald-200 disabled:cursor-not-allowed disabled:bg-slate-50 disabled:opacity-60"
                        title={orderFieldsLocked ? "Locked for this shared order" : ""}
                      />
                    </div>

                    <div className="flex items-end">
                      <label className="flex w-full items-center gap-3 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-800">
                        <input
                          type="checkbox"
                          checked={Boolean(edit.ready_for_payment)}
                          onChange={(e) =>
                            setEdit((s) => ({ ...s, ready_for_payment: e.target.checked }))
                          }
                          disabled={orderFieldsLocked || saving}
                        />
                        Mark ready for payment and notify customer
                      </label>
                    </div>

                    <div className="sm:col-span-2 -mt-1 text-[11px] text-sky-700">
                      When this is checked, the customer will see the delivery fee, VAT, final total,
                      and your EFT details for bank-transfer orders.
                    </div>

                    <div>
                      <div className="mb-1 text-xs font-semibold text-slate-600">
                        Expected delivery date
                      </div>
                      <input
                        type="date"
                        value={edit.expected_delivery_date}
                        onChange={(e) =>
                          setEdit((s) => ({ ...s, expected_delivery_date: e.target.value }))
                        }
                        disabled={orderFieldsLocked || saving}
                        className="h-11 w-full rounded-xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-900 outline-none focus:ring-2 focus:ring-emerald-200 disabled:cursor-not-allowed disabled:bg-slate-50 disabled:opacity-60"
                        title={orderFieldsLocked ? "Locked for this shared order" : ""}
                      />
                    </div>

                    <div className="sm:col-span-2">
                      <div className="mb-1 text-xs font-semibold text-slate-600">
                        Delivery address (optional)
                      </div>
                      <input
                        value={edit.delivery_address}
                        onChange={(e) =>
                          setEdit((s) => ({ ...s, delivery_address: e.target.value }))
                        }
                        placeholder="Address / location notes"
                        disabled={orderFieldsLocked || saving}
                        className="h-11 w-full rounded-xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-900 outline-none focus:ring-2 focus:ring-emerald-200 disabled:cursor-not-allowed disabled:bg-slate-50 disabled:opacity-60"
                        title={orderFieldsLocked ? "Locked for this shared order" : ""}
                      />
                    </div>
                  </div>

                  <div className="mt-4 flex gap-2">
                    <button
                      type="button"
                      className="h-11 flex-1 rounded-xl border border-slate-200 bg-white font-extrabold text-slate-800 hover:bg-slate-50"
                      onClick={closeDrawer}
                    >
                      Close
                    </button>

                    <button
                      type="button"
                      className="inline-flex h-11 flex-1 items-center justify-center gap-2 rounded-xl bg-emerald-600 font-extrabold text-white hover:bg-emerald-700 disabled:cursor-not-allowed disabled:opacity-60"
                      onClick={saveFarmerStatus}
                      disabled={saving}
                      title={
                        orderFieldsLocked
                          ? "Save my delivery status + item delivery + payment"
                          : "Save payment + delivery + item updates"
                      }
                    >
                      <Save className="h-4 w-4" />
                      {saving ? "Saving…" : "Save changes"}
                    </button>
                  </div>

                  <button
                    type="button"
                    className="mt-2 inline-flex h-11 w-full items-center justify-center gap-2 rounded-xl border border-slate-200 bg-white font-bold text-slate-800 hover:bg-slate-50"
                    onClick={() => res.refetch?.()}
                  >
                    <RefreshCcw className="h-4 w-4" />
                    Refresh orders
                  </button>
                </section>
              </div>
            </div>
          </aside>
        </div>
      ) : null}
    </FarmerLayout>
  );
}
