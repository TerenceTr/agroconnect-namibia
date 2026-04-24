// ============================================================================
// frontend/src/pages/dashboards/admin/AdminModerationPage.jsx
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Admin Product Moderation Dashboard.
//
// THIS UPDATE:
//   ✅ Uses page space better with responsive product cards instead of one long list
//   ✅ Adds client-side pagination so the admin does not need to scroll to the bottom
//   ✅ Keeps review-before-approval workflow
//   ✅ Keeps rejection reason required
//   ✅ Keeps SLA and moderation summary cards
//   ✅ Keeps a wide, professional review workspace for master's-level UX
//
// PAGINATION RULE:
//   - Products are paged client-side after normalization/filtering
//   - This avoids overlong moderation pages even if backend paging is absent
// ============================================================================

import React, { useCallback, useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  CheckCircle,
  ChevronLeft,
  ChevronRight,
  Clock,
  Download,
  Eye,
  Hash,
  Package,
  RefreshCcw,
  Search,
  ShieldCheck,
  UserRound,
  X,
  XCircle,
} from "lucide-react";

import api from "../../../api";
import AdminLayout from "../../../components/AdminLayout";
import Card from "../../../components/ui/Card";
import EmptyState from "../../../components/ui/EmptyState";
import useApi from "../../../hooks/useApi";

// ----------------------------------------------------------------------------
// Configuration
// ----------------------------------------------------------------------------
const SLA_HOURS = 48;
const PAGE_SIZE_PENDING = 8;
const PAGE_SIZE_REVIEWED = 8;

const PENDING_ENDPOINTS = ["/admin/products/pending", "/admin/products/products/pending"];
const LIST_ENDPOINTS = ["/admin/products", "/admin/products/products"];
const STATS_ENDPOINTS = ["/admin/products/stats", "/admin/products/products/stats"];
const SLA_ENDPOINTS = [
  "/admin/reports/moderation-sla",
  "/admin/reports/moderation-sla?period=month&span=1",
];

const INLINE_IMG_PLACEHOLDER = `data:image/svg+xml;utf8,${encodeURIComponent(`
<svg xmlns="http://www.w3.org/2000/svg" width="300" height="300">
  <rect width="100%" height="100%" fill="#F8FAFC"/>
  <rect x="1" y="1" width="298" height="298" rx="20" ry="20" fill="none" stroke="#CBD5E1"/>
  <text x="50%" y="50%" dominant-baseline="middle" text-anchor="middle"
        font-family="Arial, sans-serif" font-size="24" font-weight="700" fill="#64748B">IMG</text>
</svg>
`)}`;

// ----------------------------------------------------------------------------
// Endpoint helpers
// ----------------------------------------------------------------------------
function detailEndpoints(productId) {
  const id = safeStr(productId);
  if (!id) return [];
  return [`/admin/products/${id}`, `/admin/products/products/${id}`];
}

// ----------------------------------------------------------------------------
// Small helpers
// ----------------------------------------------------------------------------
const safeArray = (v) => (Array.isArray(v) ? v : []);
const safeStr = (v) => (typeof v === "string" ? v : v == null ? "" : String(v));

function safeNumber(v, fallback = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

function unwrapApiPayload(responseData) {
  if (
    responseData &&
    typeof responseData === "object" &&
    !Array.isArray(responseData) &&
    Object.prototype.hasOwnProperty.call(responseData, "data")
  ) {
    return responseData.data;
  }
  return responseData;
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

function fmtDate(iso) {
  try {
    if (!iso) return "—";
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return "—";
    return d.toLocaleString();
  } catch {
    return "—";
  }
}

function hoursBetween(a, b) {
  try {
    if (!a || !b) return null;
    return Math.round((new Date(b) - new Date(a)) / 36e5);
  } catch {
    return null;
  }
}

function ageFromNowHours(d) {
  try {
    if (!d) return null;
    return Math.round((Date.now() - new Date(d)) / 36e5);
  } catch {
    return null;
  }
}

function percent(numerator, denominator) {
  if (!denominator) return 0;
  return Math.round((safeNumber(numerator, 0) / safeNumber(denominator, 0)) * 100);
}

function pluralize(value, one, many = `${one}s`) {
  return safeNumber(value, 0) === 1 ? one : many;
}

function tabLabel(tab) {
  if (tab === "approved") return "approved";
  if (tab === "rejected") return "rejected";
  return "pending";
}

function titleCaseWords(v) {
  return safeStr(v)
    .replace(/[_-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/\b\w/g, (m) => m.toUpperCase());
}

function formatFieldLabel(key) {
  const map = {
    product_name: "Product name",
    description: "Description",
    category: "Category",
    price: "Price",
    quantity: "Quantity",
    unit: "Unit",
    pack_size: "Pack size",
    pack_unit: "Pack unit",
    image_url: "Image URL",
  };
  return map[key] || titleCaseWords(key);
}

function prettyValue(value) {
  if (value == null || value === "") return "—";
  if (typeof value === "number") return String(value);
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (typeof value === "object") {
    try {
      return JSON.stringify(value);
    } catch {
      return String(value);
    }
  }
  return String(value);
}

function pendingStateTone(hours) {
  if (hours == null) return "neutral";
  if (hours > SLA_HOURS) return "danger";
  if (hours > 24) return "warn";
  return "neutral";
}

function reviewDecisionTone(status) {
  const s = safeStr(status).toLowerCase();
  if (["available", "approved"].includes(s)) return "ok";
  if (s === "rejected") return "danger";
  if (s === "pending") return "warn";
  return "neutral";
}

// ----------------------------------------------------------------------------
// API helpers
// ----------------------------------------------------------------------------
function errMsg(e) {
  const r = e?.response?.data;
  return r?.message || r?.error || e?.message || "Request failed.";
}

async function apiPost(path, body) {
  const res = await api.post(path, body ?? {});
  const payload = res?.data;

  if (payload && payload.success === false) {
    throw new Error(payload.error || payload.message || "Request failed.");
  }

  if (
    payload &&
    payload.success === true &&
    Object.prototype.hasOwnProperty.call(payload, "data")
  ) {
    return payload.data;
  }

  return payload;
}

async function apiGetFirst(paths) {
  let lastErr = null;

  for (const path of safeArray(paths)) {
    try {
      const res = await api.get(path);
      const payload = res?.data;

      if (payload && payload.success === false) {
        throw new Error(payload.error || payload.message || "Request failed.");
      }

      return unwrapApiPayload(payload);
    } catch (e) {
      lastErr = e;
      const status = e?.response?.status;
      if (status === 404 || status === 405) continue;
      break;
    }
  }

  throw lastErr || new Error("Failed to load product details.");
}

async function downloadExport({ report, format, period, span, slaHours }) {
  const res = await api.get("/admin/reports/export", {
    params: {
      report,
      format,
      period,
      span,
      sla_hours: slaHours,
    },
    responseType: "blob",
  });

  const blob = res?.data instanceof Blob ? res.data : new Blob([res?.data ?? ""]);
  const ext = format === "csv" ? "csv" : "pdf";
  const stamp = new Date().toISOString().slice(0, 10);
  const filename = `${report}_${period}_${span}_${stamp}.${ext}`;

  const url = window.URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();

  setTimeout(() => window.URL.revokeObjectURL(url), 1500);
}

// ----------------------------------------------------------------------------
// Normalization helpers
// ----------------------------------------------------------------------------
function normalizeProduct(p) {
  const id = safeStr(p?.product_id || p?.id || "");
  const name = safeStr(p?.product_name || p?.name || "Product");

  const farmerName =
    safeStr(p?.farmer_name) ||
    safeStr(p?.farmer?.name) ||
    safeStr(p?.farmer?.full_name) ||
    safeStr(p?.farmer?.email) ||
    "Farmer";

  const farmerId = safeStr(p?.farmer_id || p?.farmer?.id || p?.user_id || "");
  const farmerEmail = safeStr(p?.farmer_email || p?.farmer?.email || "");
  const farmerPhone = safeStr(p?.farmer_phone || p?.farmer?.phone || "");
  const farmerLocation = safeStr(p?.farmer_location || p?.farmer?.location || "");

  const status = safeStr(p?.status || "").toLowerCase();
  const createdAt = p?.created_at || p?.createdAt || null;
  const updatedAt = p?.updated_at || p?.updatedAt || null;
  const reviewedAt = p?.reviewed_at || p?.reviewedAt || p?.status_updated_at || null;
  const submittedAt = p?.submitted_at || p?.submittedAt || createdAt || null;

  const category = safeStr(p?.category || "");
  const unit = safeStr(p?.unit || "");
  const price = safeNumber(p?.price, 0);
  const quantity = safeNumber(p?.quantity, 0);
  const packSize = safeNumber(p?.pack_size, 0);
  const packUnit = safeStr(p?.pack_unit || "");
  const description = safeStr(p?.description || "");
  const rejectionReason = safeStr(p?.rejection_reason || p?.reason || "");
  const imageUrl = safeStr(
    p?.image_url || p?.imageUrl || p?.image_path || p?.imagePath || ""
  );

  const moderationChanges =
    p?.moderation_changes && typeof p.moderation_changes === "object"
      ? p.moderation_changes
      : null;

  return {
    raw: p,
    id,
    name,
    farmerName,
    farmerId,
    farmerEmail,
    farmerPhone,
    farmerLocation,
    status,
    createdAt,
    updatedAt,
    reviewedAt,
    submittedAt,
    category,
    unit,
    price,
    quantity,
    packSize,
    packUnit,
    description,
    rejectionReason,
    imageUrl,
    moderationChanges,
  };
}

function matchesQuery(product, q) {
  const s = safeStr(q).trim().toLowerCase();
  if (!s) return true;

  const hay = [
    product.name,
    product.farmerName,
    product.farmerEmail,
    product.category,
    product.status,
    product.id,
  ]
    .join(" ")
    .toLowerCase();

  return hay.includes(s);
}

function extractListItems(responseData) {
  const payload = unwrapApiPayload(responseData);
  return safeArray(payload?.items || payload || []);
}

function extractChangedFields(product) {
  return safeArray(product?.moderationChanges?.changed_fields);
}

function extractDiffRows(product) {
  const diff = product?.moderationChanges?.diff;
  if (!diff || typeof diff !== "object") return [];

  return Object.entries(diff).map(([field, value]) => ({
    field,
    from: value?.from,
    to: value?.to,
  }));
}

// ----------------------------------------------------------------------------
// Stateless UI helpers
// ----------------------------------------------------------------------------
function Pill({ tone = "neutral", children }) {
  const cls =
    tone === "danger"
      ? "border-rose-200 bg-rose-50 text-rose-800"
      : tone === "warn"
      ? "border-amber-200 bg-amber-50 text-amber-900"
      : tone === "ok"
      ? "border-emerald-200 bg-emerald-50 text-emerald-800"
      : "border-slate-200 bg-slate-50 text-slate-700";

  return (
    <span
      className={[
        "inline-flex items-center gap-2 rounded-full border px-3 py-1.5",
        "text-[11px] font-extrabold",
        cls,
      ].join(" ")}
    >
      {children}
    </span>
  );
}

function SegmentedTab({ active, onClick, label, count }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={[
        "inline-flex items-center gap-2 rounded-xl px-4 py-2 text-sm font-extrabold",
        "border transition",
        active
          ? "border-slate-900 bg-slate-900 text-white"
          : "border-slate-200 bg-white text-slate-800 hover:bg-slate-50",
      ].join(" ")}
    >
      {label}
      <span
        className={[
          "rounded-full border px-2 py-0.5 text-[11px] font-extrabold",
          active
            ? "border-white/30 bg-white/10 text-white"
            : "border-slate-200 bg-slate-50 text-slate-700",
        ].join(" ")}
      >
        {count}
      </span>
    </button>
  );
}

function ProductThumb({ src, alt, className = "h-16 w-16" }) {
  return (
    <img
      src={src || INLINE_IMG_PLACEHOLDER}
      alt={alt || "Product"}
      className={`${className} rounded-2xl border border-slate-200 bg-white object-cover`}
      onError={(e) => {
        if (e.currentTarget.src !== INLINE_IMG_PLACEHOLDER) {
          e.currentTarget.src = INLINE_IMG_PLACEHOLDER;
        }
      }}
    />
  );
}

function StatCard({ title, value, subtext, tone = "slate" }) {
  const accents =
    tone === "emerald"
      ? "border-emerald-200 bg-emerald-50/70 text-emerald-900"
      : tone === "amber"
      ? "border-amber-200 bg-amber-50/70 text-amber-900"
      : tone === "rose"
      ? "border-rose-200 bg-rose-50/70 text-rose-900"
      : "border-slate-200 bg-white text-slate-900";

  return (
    <Card className={`rounded-2xl border p-4 shadow-sm ${accents}`}>
      <div className="text-xs font-bold uppercase tracking-wide text-slate-500">{title}</div>
      <div className="mt-2 text-2xl font-black">{value}</div>
      <div className="mt-1 text-xs font-semibold text-slate-600">{subtext}</div>
    </Card>
  );
}

function KeyValue({ label, value, mono = false }) {
  return (
    <div>
      <div className="text-[11px] font-bold uppercase tracking-wide text-slate-500">{label}</div>
      <div className={`mt-1 text-sm font-semibold text-slate-900 ${mono ? "font-mono" : ""}`}>
        {value || "—"}
      </div>
    </div>
  );
}

function PaginationBar({
  page,
  totalPages,
  totalItems,
  pageSize,
  onPageChange,
}) {
  if (totalPages <= 1) return null;

  const start = (page - 1) * pageSize + 1;
  const end = Math.min(totalItems, page * pageSize);

  const pages = [];
  const windowStart = Math.max(1, page - 2);
  const windowEnd = Math.min(totalPages, page + 2);

  for (let p = windowStart; p <= windowEnd; p += 1) {
    pages.push(p);
  }

  return (
    <div className="flex flex-col gap-3 rounded-2xl border border-slate-200 bg-white px-4 py-3 shadow-sm md:flex-row md:items-center md:justify-between">
      <div className="text-sm font-semibold text-slate-600">
        Showing <span className="font-extrabold text-slate-900">{start}</span> to{" "}
        <span className="font-extrabold text-slate-900">{end}</span> of{" "}
        <span className="font-extrabold text-slate-900">{totalItems}</span> items
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <button
          type="button"
          onClick={() => onPageChange(Math.max(1, page - 1))}
          disabled={page === 1}
          className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm font-extrabold text-slate-800 hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-50"
        >
          <ChevronLeft className="h-4 w-4" />
          Prev
        </button>

        {windowStart > 1 ? (
          <>
            <button
              type="button"
              onClick={() => onPageChange(1)}
              className="rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm font-extrabold text-slate-700 hover:bg-slate-50"
            >
              1
            </button>
            {windowStart > 2 ? <span className="px-1 text-slate-400">…</span> : null}
          </>
        ) : null}

        {pages.map((p) => (
          <button
            key={p}
            type="button"
            onClick={() => onPageChange(p)}
            className={[
              "rounded-xl border px-3 py-2 text-sm font-extrabold transition",
              p === page
                ? "border-slate-900 bg-slate-900 text-white"
                : "border-slate-200 bg-white text-slate-700 hover:bg-slate-50",
            ].join(" ")}
          >
            {p}
          </button>
        ))}

        {windowEnd < totalPages ? (
          <>
            {windowEnd < totalPages - 1 ? <span className="px-1 text-slate-400">…</span> : null}
            <button
              type="button"
              onClick={() => onPageChange(totalPages)}
              className="rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm font-extrabold text-slate-700 hover:bg-slate-50"
            >
              {totalPages}
            </button>
          </>
        ) : null}

        <button
          type="button"
          onClick={() => onPageChange(Math.min(totalPages, page + 1))}
          disabled={page === totalPages}
          className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm font-extrabold text-slate-800 hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-50"
        >
          Next
          <ChevronRight className="h-4 w-4" />
        </button>
      </div>
    </div>
  );
}

// ----------------------------------------------------------------------------
// Review workspace drawer
// ----------------------------------------------------------------------------
function ProductReviewDrawer({
  open,
  product,
  loading,
  error,
  busy,
  onClose,
  onApprove,
  onRequestReject,
}) {
  const changedFields = extractChangedFields(product);
  const diffRows = extractDiffRows(product);
  const queueAge = ageFromNowHours(product?.submittedAt || product?.createdAt);
  const isPending = safeStr(product?.status).toLowerCase() === "pending";
  const decisionTone = reviewDecisionTone(product?.status);
  const queueTone = pendingStateTone(queueAge);
  const hasModerationDiff = changedFields.length > 0 || diffRows.length > 0;

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-[70] flex justify-end">
      <div
        className="absolute inset-0 bg-slate-900/45 backdrop-blur-[2px]"
        onClick={() => (!busy ? onClose() : null)}
      />

      <div className="relative h-full w-full max-w-[min(97vw,1500px)] overflow-hidden border-l border-slate-200 bg-white shadow-2xl">
        <div className="flex h-full flex-col">
          {/* -----------------------------------------------------------------
             Professional review header:
             - keeps only the most important identifiers
             - removes repeated explanatory text
             - keeps the panel visually compact
          ----------------------------------------------------------------- */}
          <div className="border-b border-slate-200 bg-white px-6 py-4">
            <div className="flex items-start justify-between gap-4">
              <div className="min-w-0">
                <div className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                  Review product listing
                </div>
                <h3 className="truncate text-[28px] font-black tracking-tight text-slate-900">
                  {product?.name || "Product"}
                </h3>

                <div className="mt-2 flex flex-wrap items-center gap-2">
                  <Pill tone={decisionTone}>{titleCaseWords(product?.status || "pending")}</Pill>

                  <Pill tone="neutral">
                    <Hash className="h-3.5 w-3.5" /> {product?.id || "—"}
                  </Pill>

                  <Pill tone={queueTone}>
                    <Clock className="h-3.5 w-3.5" />
                    Queue age: {queueAge != null ? `${queueAge}h` : "—"}
                  </Pill>

                  {queueAge != null && queueAge > SLA_HOURS ? (
                    <Pill tone="danger">
                      <AlertTriangle className="h-3.5 w-3.5" /> SLA breach risk
                    </Pill>
                  ) : null}
                </div>
              </div>

              <button
                className="rounded-xl p-2 text-slate-500 transition hover:bg-slate-100 hover:text-slate-900"
                onClick={() => (!busy ? onClose() : null)}
                type="button"
                aria-label="Close review drawer"
              >
                <X className="h-5 w-5" />
              </button>
            </div>
          </div>

          {/* -----------------------------------------------------------------
             Review workspace:
             - softer canvas background so unused space does not look blank
             - wider left content area
             - single sticky decision rail on the right
          ----------------------------------------------------------------- */}
          <div className="flex-1 overflow-y-auto bg-slate-100/70">
            {loading ? (
              <div className="p-6">
                <div className="rounded-2xl border border-slate-200 bg-white p-4 text-sm font-semibold text-slate-600 shadow-sm">
                  Loading product details…
                </div>
              </div>
            ) : error ? (
              <div className="p-6">
                <div className="rounded-2xl border border-rose-200 bg-rose-50 p-4 text-sm font-semibold text-rose-800 shadow-sm">
                  {error}
                </div>
              </div>
            ) : !product ? (
              <div className="p-6">
                <div className="rounded-2xl border border-slate-200 bg-white p-4 text-sm font-semibold text-slate-600 shadow-sm">
                  No product details available.
                </div>
              </div>
            ) : (
              <div className="mx-auto grid max-w-[1480px] grid-cols-1 gap-6 p-6 xl:grid-cols-[minmax(0,1.45fr)_360px]">
                {/* =============================================================
                    Main review content
                ============================================================= */}
                <div className="space-y-6">
                  {/* ----------------------------------------------------------
                     Listing overview card
                     - combines hero, product summary, and description
                     - removes duplicated blocks from the previous design
                  ---------------------------------------------------------- */}
                  <Card className="rounded-3xl border border-slate-200 bg-white p-6 shadow-sm">
                    <div className="grid grid-cols-1 gap-6 2xl:grid-cols-[220px_minmax(0,1fr)]">
                      <ProductThumb
                        src={product.imageUrl}
                        alt={product.name}
                        className="h-56 w-full rounded-3xl 2xl:w-[220px]"
                      />

                      <div className="min-w-0 space-y-5">
                        <div>
                          <div className="text-2xl font-black tracking-tight text-slate-900">
                            {product.name}
                          </div>
                          <div className="mt-1 text-sm font-semibold text-slate-600">
                            Submitted by {product.farmerName || "—"}
                          </div>
                        </div>

                        <div className="grid grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-6">
                          <KeyValue label="Category" value={product.category || "—"} />
                          <KeyValue label="Selling unit" value={product.unit || "—"} />
                          <KeyValue label="Stock" value={String(product.quantity || 0)} />
                          <KeyValue label="Price" value={fmtNAD(product.price)} />
                          <KeyValue
                            label="Submitted"
                            value={fmtDate(product.submittedAt || product.createdAt)}
                          />
                          <KeyValue label="Listing ID" value={product.id || "—"} mono />
                        </div>

                        {product.unit === "pack" ? (
                          <div className="rounded-2xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm font-semibold text-amber-900">
                            Pack setup: {product.packSize > 0 ? product.packSize : "—"}{" "}
                            {product.packUnit || "unit"}
                          </div>
                        ) : null}

                        <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                          <div className="mb-2 text-xs font-bold uppercase tracking-wide text-slate-500">
                            Product description
                          </div>
                          <div className="text-sm leading-7 text-slate-700">
                            {product.description || "No description was provided by the farmer."}
                          </div>
                        </div>
                      </div>
                    </div>
                  </Card>

                  {/* ----------------------------------------------------------
                     Supporting review cards
                  ---------------------------------------------------------- */}
                  <div className="grid grid-cols-1 gap-6 2xl:grid-cols-2">
                    <Card className="rounded-3xl border border-slate-200 bg-white p-5 shadow-sm">
                      <div className="flex items-center gap-2 text-sm font-black text-slate-900">
                        <UserRound className="h-4 w-4" /> Farmer details
                      </div>

                      <div className="mt-4 grid grid-cols-1 gap-4 sm:grid-cols-2">
                        <KeyValue label="Farmer name" value={product.farmerName} />
                        <KeyValue label="Farmer ID" value={product.farmerId || "—"} mono />
                        <KeyValue label="Email" value={product.farmerEmail || "—"} />
                        <KeyValue label="Phone" value={product.farmerPhone || "—"} />
                        <div className="sm:col-span-2">
                          <KeyValue label="Location" value={product.farmerLocation || "—"} />
                        </div>
                      </div>
                    </Card>

                    <Card className="rounded-3xl border border-slate-200 bg-white p-5 shadow-sm">
                      <div className="flex items-center gap-2 text-sm font-black text-slate-900">
                        <Package className="h-4 w-4" /> Listing details
                      </div>

                      <div className="mt-4 grid grid-cols-1 gap-4 sm:grid-cols-2">
                        <KeyValue label="Status" value={titleCaseWords(product.status || "pending")} />
                        <KeyValue label="Queue age" value={queueAge != null ? `${queueAge}h` : "—"} />
                        <KeyValue label="Category" value={product.category || "—"} />
                        <KeyValue label="Selling unit" value={product.unit || "—"} />
                        <KeyValue label="Quantity" value={String(product.quantity || 0)} />
                        <KeyValue label="Price" value={fmtNAD(product.price)} />
                        <KeyValue
                          label="Pack size"
                          value={product.packSize > 0 ? String(product.packSize) : "—"}
                        />
                        <KeyValue label="Pack unit" value={product.packUnit || "—"} />
                      </div>
                    </Card>
                  </div>

                  {/* ----------------------------------------------------------
                     Moderation change history
                     - only large when real change data exists
                     - first submissions get a short compact note instead
                  ---------------------------------------------------------- */}
                  <Card className="rounded-3xl border border-slate-200 bg-white p-5 shadow-sm">
                    <div className="flex items-center gap-2 text-sm font-black text-slate-900">
                      <ShieldCheck className="h-4 w-4" /> Moderation context
                    </div>

                    {hasModerationDiff ? (
                      <>
                        <div className="mt-4 flex flex-wrap gap-2">
                          {changedFields.map((field) => (
                            <Pill key={field} tone="warn">
                              {formatFieldLabel(field)}
                            </Pill>
                          ))}
                        </div>

                        <div className="mt-4 overflow-x-auto rounded-2xl border border-slate-200">
                          <table className="w-full min-w-[700px] text-sm">
                            <thead className="bg-slate-50 text-slate-600">
                              <tr>
                                <th className="px-4 py-3 text-left font-extrabold">Field</th>
                                <th className="px-4 py-3 text-left font-extrabold">Previous value</th>
                                <th className="px-4 py-3 text-left font-extrabold">Current value</th>
                              </tr>
                            </thead>
                            <tbody>
                              {diffRows.map((row) => (
                                <tr key={row.field} className="border-t border-slate-200">
                                  <td className="px-4 py-3 font-extrabold text-slate-900">
                                    {formatFieldLabel(row.field)}
                                  </td>
                                  <td className="px-4 py-3 text-slate-700">{prettyValue(row.from)}</td>
                                  <td className="px-4 py-3 text-slate-700">{prettyValue(row.to)}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </>
                    ) : (
                      <div className="mt-4 rounded-2xl border border-slate-200 bg-slate-50 p-4 text-sm leading-6 text-slate-700">
                        No previous farmer edit-diff was recorded for this item. This appears to be a
                        first-time submission rather than a resubmission after changes.
                      </div>
                    )}
                  </Card>
                </div>

                {/* =============================================================
                    Decision rail
                    - one cleaner sticky panel instead of multiple repetitive cards
                    - contains SLA context, decision actions, and compact guidance
                ============================================================= */}
                <div className="xl:sticky xl:top-6 xl:self-start">
                  <Card className="rounded-3xl border border-slate-200 bg-white p-5 shadow-sm">
                    <div className="text-lg font-black text-slate-900">Decision panel</div>
                    <p className="mt-2 text-sm leading-6 text-slate-600">
                      Finalise the moderation decision after confirming listing quality, farmer
                      identity, and product accuracy.
                    </p>

                    <div className="mt-5 space-y-3">
                      <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                        <div className="text-[11px] font-bold uppercase tracking-wide text-slate-500">
                          Current status
                        </div>
                        <div className="mt-2">
                          <Pill tone={decisionTone}>{titleCaseWords(product.status || "pending")}</Pill>
                        </div>
                      </div>

                      <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                        <div className="text-[11px] font-bold uppercase tracking-wide text-slate-500">
                          SLA / queue timing
                        </div>
                        <div className="mt-2 text-xl font-black text-slate-900">
                          {queueAge != null ? `${queueAge}h` : "—"}
                        </div>
                        <div className="mt-1 text-xs font-semibold text-slate-600">
                          {queueAge != null && queueAge > SLA_HOURS
                            ? "This item is outside the 48-hour review target."
                            : "This item is currently within the 48-hour review target."}
                        </div>
                      </div>

                      <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                        <div className="text-[11px] font-bold uppercase tracking-wide text-slate-500">
                          Quick decision checks
                        </div>
                        <ul className="mt-2 space-y-2 text-sm leading-6 text-slate-700">
                          <li>Confirm the product title and description are clear and credible.</li>
                          <li>Confirm price, stock, unit, and pack setup are commercially sensible.</li>
                          <li>Reject only with a specific reason the farmer can correct.</li>
                        </ul>
                      </div>
                    </div>

                    {isPending ? (
                      <div className="mt-5 grid grid-cols-1 gap-3">
                        <button
                          className="btn-danger"
                          disabled={busy || !product}
                          onClick={() => onRequestReject(product)}
                          type="button"
                        >
                          <XCircle className="h-4 w-4" /> Reject listing
                        </button>

                        <button
                          className={[
                            "inline-flex items-center justify-center gap-2 rounded-xl border px-4 py-3 text-sm font-extrabold shadow-sm transition",
                            "border-emerald-200 bg-emerald-50 text-emerald-800",
                            "hover:border-emerald-300 hover:bg-emerald-100",
                            "focus:outline-none focus:ring-2 focus:ring-emerald-200",
                            busy ? "cursor-not-allowed opacity-60" : "",
                          ].join(" ")}
                          disabled={busy || !product}
                          onClick={() => onApprove(product)}
                          type="button"
                        >
                          <CheckCircle className="h-4 w-4" />
                          {busy ? "Approving…" : "Approve listing"}
                        </button>
                      </div>
                    ) : (
                      <div className="mt-5 rounded-2xl border border-slate-200 bg-slate-50 p-4 text-sm font-semibold text-slate-700">
                        This product already has a recorded moderation outcome.
                      </div>
                    )}

                    {safeStr(product?.rejectionReason).trim() ? (
                      <div className="mt-4 rounded-2xl border border-rose-200 bg-rose-50 p-4 text-sm leading-6 text-rose-800">
                        <div className="mb-1 text-xs font-bold uppercase tracking-wide text-rose-700">
                          Current rejection reason
                        </div>
                        {product.rejectionReason}
                      </div>
                    ) : null}

                    <div className="mt-4">
                      <button
                        className="btn-secondary w-full"
                        onClick={onClose}
                        disabled={busy}
                        type="button"
                      >
                        Close review
                      </button>
                    </div>
                  </Card>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

// ----------------------------------------------------------------------------
// Reject modal
// ----------------------------------------------------------------------------
function RejectModal({
  open,
  target,
  busy,
  reason,
  onReasonChange,
  onClose,
  onSubmit,
}) {
  if (!open) return null;

  return (
    <div className="fixed inset-0 z-[80] flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/40" onClick={() => (!busy ? onClose() : null)} />

      <div className="relative w-full max-w-lg rounded-2xl border border-slate-200 bg-white p-5 shadow-xl">
        <div className="flex items-start justify-between gap-4">
          <div className="min-w-0">
            <h3 className="text-lg font-extrabold text-slate-900">Reject product</h3>
            <p className="mt-1 truncate text-sm text-slate-600">{target?.name || "Product"}</p>
          </div>

          <button
            className="rounded-xl p-2 hover:bg-slate-100"
            onClick={() => (!busy ? onClose() : null)}
            type="button"
            aria-label="Close"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <label className="mb-2 mt-4 block text-xs font-extrabold text-slate-700">
          Rejection reason (required)
        </label>

        <textarea
          value={reason}
          onChange={(e) => onReasonChange(e.target.value)}
          rows={5}
          disabled={busy}
          className="w-full rounded-xl border border-slate-200 p-3 text-sm focus:outline-none focus:ring-2 focus:ring-slate-200"
          placeholder="State the issue clearly, for example: missing product image quality, incorrect pricing format, incomplete product description, or category mismatch."
        />

        <div className="mt-5 flex justify-end gap-2">
          <button className="btn-secondary" onClick={onClose} disabled={busy} type="button">
            Cancel
          </button>
          <button
            className="btn-danger"
            disabled={busy || safeStr(reason).trim().length < 5}
            onClick={() => onSubmit(reason)}
            type="button"
          >
            <XCircle className="h-4 w-4" />
            {busy ? "Rejecting…" : "Reject"}
          </button>
        </div>
      </div>
    </div>
  );
}

// ----------------------------------------------------------------------------
// Toast
// ----------------------------------------------------------------------------
function Toast({ toast, onClose }) {
  if (!toast) return null;

  const tone =
    toast.type === "ok"
      ? "border-emerald-200 bg-emerald-50 text-emerald-900"
      : "border-rose-200 bg-rose-50 text-rose-900";

  return (
    <div className="fixed right-4 top-4 z-[90] max-w-sm">
      <div className={`rounded-2xl border p-4 shadow-lg ${tone}`}>
        <div className="flex items-start justify-between gap-3">
          <div className="text-sm font-extrabold">{toast.msg}</div>
          <button type="button" className="rounded-lg p-1 hover:bg-black/5" onClick={onClose}>
            <X className="h-4 w-4" />
          </button>
        </div>
      </div>
    </div>
  );
}

// ----------------------------------------------------------------------------
// Main page
// ----------------------------------------------------------------------------
export default function AdminModerationPage() {
  const [tab, setTab] = useState("pending");
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(1);
  const [busyId, setBusyId] = useState(null);
  const [toast, setToast] = useState(null);

  const [rejectOpen, setRejectOpen] = useState(false);
  const [rejectTarget, setRejectTarget] = useState(null);
  const [rejectReason, setRejectReason] = useState("");

  const [reviewOpen, setReviewOpen] = useState(false);
  const [reviewSeed, setReviewSeed] = useState(null);
  const [reviewProduct, setReviewProduct] = useState(null);
  const [reviewLoading, setReviewLoading] = useState(false);
  const [reviewError, setReviewError] = useState("");

  useEffect(() => {
    if (!toast) return undefined;
    const t = setTimeout(() => setToast(null), 3500);
    return () => clearTimeout(t);
  }, [toast]);

  // Reset pagination whenever the working set changes materially
  useEffect(() => {
    setPage(1);
  }, [tab, query]);

  const slaRes = useApi(SLA_ENDPOINTS, {
    params: { period: "month", span: 1, sla_hours: SLA_HOURS },
  });

  const statsRes = useApi(STATS_ENDPOINTS);

  const pendingRes = useApi(PENDING_ENDPOINTS, {
    enabled: tab === "pending",
    params: { q: query, limit: 200 },
  });

  const listRes = useApi(LIST_ENDPOINTS, {
    enabled: tab !== "pending",
    params: {
      status: tab === "approved" ? "available" : tab === "rejected" ? "rejected" : "pending",
      q: query,
      limit: 200,
    },
  });

  const stats = useMemo(() => {
    const payload = unwrapApiPayload(statsRes.data) || {};
    return {
      pending: safeNumber(payload.pending, 0),
      approved: safeNumber(payload.approved, 0),
      rejected: safeNumber(payload.rejected, 0),
      total: safeNumber(payload.total, 0),
    };
  }, [statsRes.data]);

  const rawRows = useMemo(() => {
    if (tab === "pending") return extractListItems(pendingRes.data);
    return extractListItems(listRes.data);
  }, [tab, pendingRes.data, listRes.data]);

  const normalized = useMemo(
    () => rawRows.map(normalizeProduct).filter((x) => x.id),
    [rawRows]
  );

  const items = useMemo(
    () => normalized.filter((p) => matchesQuery(p, query)),
    [normalized, query]
  );

  const pageSize = tab === "pending" ? PAGE_SIZE_PENDING : PAGE_SIZE_REVIEWED;
  const totalPages = Math.max(1, Math.ceil(items.length / pageSize));
  const safePage = Math.min(page, totalPages);
  const pagedItems = useMemo(() => {
    const start = (safePage - 1) * pageSize;
    return items.slice(start, start + pageSize);
  }, [items, pageSize, safePage]);

  const rowMeta = useCallback(
    (product) => {
      if (tab === "pending") {
        const hours = ageFromNowHours(product.submittedAt || product.createdAt || product.updatedAt);
        return { hours, breached: hours != null && hours > SLA_HOURS };
      }

      const hours = hoursBetween(
        product.submittedAt || product.createdAt,
        product.reviewedAt || product.updatedAt
      );
      return { hours, breached: hours != null && hours > SLA_HOURS };
    },
    [tab]
  );

  const pendingBreaches = useMemo(() => {
    if (tab !== "pending") return 0;
    return items.reduce((acc, product) => (rowMeta(product).breached ? acc + 1 : acc), 0);
  }, [tab, items, rowMeta]);

  const slaSummary = useMemo(() => {
    const payload = unwrapApiPayload(slaRes.data) || {};
    const summary = payload.summary || {};

    const reviewed = safeNumber(
      summary.reviewed || summary.reviewed_total || summary.total_reviewed,
      0
    );
    const breached = safeNumber(
      summary.breached || summary.breached_total || summary.total_breached,
      0
    );
    const avgHours = safeNumber(
      summary.avg_hours || summary.avgHours || summary.average_hours,
      0
    );

    return {
      reviewed,
      breached,
      avgHours,
      onTime: Math.max(reviewed - breached, 0),
      onTimeRate: reviewed > 0 ? percent(reviewed - breached, reviewed) : 0,
    };
  }, [slaRes.data]);


  const filteredLabel = useMemo(() => {
    if (!query.trim()) {
      return `Showing ${pagedItems.length} ${pluralize(pagedItems.length, "item")} on this page.`;
    }
    return `Showing ${items.length} filtered ${pluralize(items.length, "item")} across ${totalPages} ${pluralize(totalPages, "page")}.`;
  }, [items.length, pagedItems.length, query, totalPages]);

  const explanationText = useMemo(() => {
    if (slaSummary.reviewed === 0) {
      return "No products were approved or rejected during the selected monthly SLA window yet.";
    }
    return `${slaSummary.onTime} of ${slaSummary.reviewed} reviewed products were completed within the ${SLA_HOURS} hour service target.`;
  }, [slaSummary]);

  const activeReviewProduct = useMemo(
    () => (reviewProduct ? normalizeProduct(reviewProduct) : reviewSeed),
    [reviewProduct, reviewSeed]
  );

  const refresh = useCallback(() => {
    pendingRes.refetch?.();
    listRes.refetch?.();
    slaRes.refetch?.();
    statsRes.refetch?.();
  }, [listRes, pendingRes, slaRes, statsRes]);

  const closeReviewDrawer = useCallback(() => {
    if (busyId) return;
    setReviewOpen(false);
    setReviewLoading(false);
    setReviewError("");
  }, [busyId]);

  const openReviewDrawer = useCallback(async (product) => {
    setReviewSeed(product);
    setReviewProduct(product?.raw || product || null);
    setReviewError("");
    setReviewOpen(true);
    setReviewLoading(true);

    try {
      const payload = await apiGetFirst(detailEndpoints(product?.id));
      setReviewProduct(payload);
      setReviewError("");
    } catch (e) {
      setReviewError(errMsg(e) || "Failed to load product details.");
    } finally {
      setReviewLoading(false);
    }
  }, []);

  const openRejectModal = useCallback((product) => {
    setRejectTarget(product);
    setRejectReason("");
    setRejectOpen(true);
  }, []);

  const closeRejectModal = useCallback(() => {
    if (busyId) return;
    setRejectOpen(false);
    setRejectTarget(null);
    setRejectReason("");
  }, [busyId]);

  const approve = async (product) => {
    setBusyId(product.id);
    try {
      await apiPost(`/admin/products/${product.id}/approve`, {});
      setToast({ type: "ok", msg: "Product approved. The farmer has been notified." });
      setReviewOpen(false);
      setReviewError("");
      refresh();
    } catch (e) {
      setToast({ type: "err", msg: errMsg(e) });
    } finally {
      setBusyId(null);
    }
  };

  const submitReject = async (reason) => {
    if (!rejectTarget?.id) return;

    setBusyId(rejectTarget.id);
    try {
      await apiPost(`/admin/products/${rejectTarget.id}/reject`, { reason });
      setToast({ type: "ok", msg: "Product rejected. The farmer has been notified." });
      setRejectOpen(false);
      setRejectTarget(null);
      setRejectReason("");
      setReviewOpen(false);
      setReviewError("");
      refresh();
    } catch (e) {
      setToast({ type: "err", msg: errMsg(e) });
    } finally {
      setBusyId(null);
    }
  };

  const exportReport = async (format) => {
    try {
      await downloadExport({
        report: "moderation_sla",
        format,
        period: "month",
        span: 6,
        slaHours: SLA_HOURS,
      });
    } catch (e) {
      setToast({ type: "err", msg: errMsg(e) });
    }
  };

  const loading = (tab === "pending" ? pendingRes.loading : listRes.loading) || false;
  const error = (tab === "pending" ? pendingRes.error : listRes.error) || null;
  const summaryError = statsRes.error || slaRes.error || null;

  return (
    <AdminLayout>
      <Toast toast={toast} onClose={() => setToast(null)} />

      <div className="space-y-6">
        {/* Header */}
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1fr)_auto] xl:items-start">
          <div className="min-w-0">
            <div className="text-xs font-semibold text-slate-500">AgroConnect Namibia</div>
            <h1 className="text-2xl font-extrabold text-slate-900">Product Moderation</h1>
            <p className="mt-1 max-w-4xl text-sm text-slate-600">
              Review farmer submissions, publish compliant products to the marketplace, and track
              moderation turnaround against the service target.
            </p>

            <div className="mt-3 flex flex-wrap items-center gap-2">
              <Pill tone="neutral">
                <ShieldCheck className="h-3.5 w-3.5" />
                SLA target: <span className="font-black">{SLA_HOURS}h</span>
              </Pill>

              <Pill tone="warn">Pending queue: {stats.pending}</Pill>
              <Pill tone="ok">Approved catalogue: {stats.approved}</Pill>
              <Pill tone="danger">Rejected: {stats.rejected}</Pill>

              {tab === "pending" && stats.pending > 0 ? (
                <Pill tone={pendingBreaches > 0 ? "danger" : "neutral"}>
                  Queue breaches visible: {pendingBreaches}
                </Pill>
              ) : null}

              {summaryError ? (
                <Pill tone="danger">Some moderation summary data failed to load</Pill>
              ) : null}
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button className="btn-secondary" onClick={refresh} type="button">
              <RefreshCcw className="h-4 w-4" /> Refresh
            </button>
          </div>
        </div>

        {/* KPI cards */}
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 2xl:grid-cols-4">
          <StatCard
            title="Pending for approval"
            value={stats.pending}
            subtext="Products awaiting an admin decision. These remain hidden from customers."
            tone="amber"
          />

          <StatCard
            title="Approved products"
            value={stats.approved}
            subtext="Products currently accepted for marketplace visibility."
            tone="emerald"
          />

          <StatCard
            title="Rejected products"
            value={stats.rejected}
            subtext="Products returned to farmers for correction and resubmission."
            tone="rose"
          />

          <StatCard
            title="Total tracked products"
            value={stats.total}
            subtext="All products currently represented in the moderation catalogue."
            tone="slate"
          />
        </div>

        {/* SLA summary */}
        <Card className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
          <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
            <div className="min-w-0">
              <div className="text-lg font-extrabold text-slate-900">Moderation SLA (Monthly)</div>
              <p className="mt-1 max-w-4xl text-sm text-slate-600">
                <span className="font-bold text-slate-800">SLA Target: {SLA_HOURS}h</span> means each
                submitted product should be reviewed within 48 hours of submission. In the monthly SLA
                summary, <span className="font-bold text-slate-800">Reviewed</span> counts products that
                were approved or rejected during the month, while{" "}
                <span className="font-bold text-slate-800">Breached</span> counts reviews that exceeded
                the 48-hour target.
              </p>
            </div>

            <div className="flex shrink-0 gap-2">
              <button onClick={() => exportReport("csv")} className="btn-secondary" type="button">
                <Download className="h-4 w-4" /> CSV
              </button>
              <button onClick={() => exportReport("pdf")} className="btn-secondary" type="button">
                <Download className="h-4 w-4" /> PDF
              </button>
            </div>
          </div>

          <div className="mt-5 grid grid-cols-1 gap-4 md:grid-cols-2 2xl:grid-cols-4">
            <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
              <div className="text-xs font-bold uppercase tracking-wide text-slate-500">Service target</div>
              <div className="mt-2 text-2xl font-black text-slate-900">{SLA_HOURS}h</div>
              <div className="mt-1 text-xs font-semibold text-slate-600">Required maximum review turnaround.</div>
            </div>

            <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
              <div className="text-xs font-bold uppercase tracking-wide text-slate-500">Reviewed this month</div>
              <div className="mt-2 text-2xl font-black text-slate-900">{slaSummary.reviewed}</div>
              <div className="mt-1 text-xs font-semibold text-slate-600">Approved and rejected decisions recorded in the monthly window.</div>
            </div>

            <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
              <div className="text-xs font-bold uppercase tracking-wide text-slate-500">Breached</div>
              <div className="mt-2 text-2xl font-black text-rose-700">{slaSummary.breached}</div>
              <div className="mt-1 text-xs font-semibold text-slate-600">Items reviewed later than the target threshold.</div>
            </div>

            <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
              <div className="text-xs font-bold uppercase tracking-wide text-slate-500">On-time compliance</div>
              <div className="mt-2 text-2xl font-black text-emerald-700">{slaSummary.onTimeRate}%</div>
              <div className="mt-1 text-xs font-semibold text-slate-600">
                {slaSummary.avgHours > 0 ? `Average turnaround: ${slaSummary.avgHours.toFixed(1)}h` : "No average available yet."}
              </div>
            </div>
          </div>

          <div className="mt-4 rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm font-semibold text-slate-700">
            {explanationText}
          </div>
        </Card>

        {/* Controls */}
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1fr)_340px] xl:items-center">
          <div className="flex flex-wrap gap-2">
            <SegmentedTab active={tab === "pending"} onClick={() => setTab("pending")} label="Pending" count={stats.pending} />
            <SegmentedTab active={tab === "approved"} onClick={() => setTab("approved")} label="Approved" count={stats.approved} />
            <SegmentedTab active={tab === "rejected"} onClick={() => setTab("rejected")} label="Rejected" count={stats.rejected} />
          </div>

          <div className="flex w-full items-center gap-2 rounded-2xl border border-slate-200 bg-white px-3 py-2">
            <Search className="h-4 w-4 text-slate-400" />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search by product, farmer, or product ID"
              className="w-full bg-transparent text-sm outline-none"
            />
            {query ? (
              <button
                type="button"
                className="rounded-lg p-1 hover:bg-slate-100"
                onClick={() => setQuery("")}
                aria-label="Clear"
              >
                <X className="h-4 w-4 text-slate-500" />
              </button>
            ) : null}
          </div>
        </div>

        {/* Queue summary */}
        <Card className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
          <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
            <div>
              <div className="text-sm font-extrabold text-slate-900">
                {tab === "pending"
                  ? "Pending review queue"
                  : tab === "approved"
                  ? "Approved product catalogue"
                  : "Rejected products awaiting correction"}
              </div>
              <div className="mt-1 text-xs font-semibold text-slate-500">
                {filteredLabel}
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <Pill tone={tab === "pending" ? "warn" : tab === "approved" ? "ok" : "danger"}>
                {tab === "pending"
                  ? "Not customer-visible until approved"
                  : tab === "approved"
                  ? "Visible to customers"
                  : "Farmer action required before re-approval"}
              </Pill>

              <Pill tone="neutral">
                {items.length} filtered {pluralize(items.length, "item")} • {totalPages} {pluralize(totalPages, "page")}
              </Pill>
            </div>
          </div>
        </Card>

        {/* Product cards */}
        <Card className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
          {loading ? (
            <div className="text-sm text-slate-600">Loading moderation records…</div>
          ) : items.length === 0 ? (
            <EmptyState
              message={
                query.trim()
                  ? `No ${tabLabel(tab)} products match the current search.`
                  : tab === "pending"
                  ? "No products are currently waiting for approval."
                  : tab === "approved"
                  ? "No approved products are available in the current dataset."
                  : "No rejected products are available in the current dataset."
              }
            />
          ) : (
            <>
              <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
                {pagedItems.map((product) => {
                  const meta = rowMeta(product);
                  const busy = busyId === product.id;
                  const queueTone = pendingStateTone(meta.hours);
                  const statusTone = reviewDecisionTone(product.status);
                  const changeCount = extractChangedFields(product).length;

                  return (
                    <div
                      key={product.id}
                      className={[
                        "rounded-2xl border p-4 shadow-sm transition",
                        product.status === "rejected"
                          ? "border-rose-200 bg-rose-50/40"
                          : product.status === "pending"
                          ? "border-slate-200 bg-white"
                          : "border-emerald-200 bg-emerald-50/30",
                      ].join(" ")}
                    >
                      <div className="flex items-start gap-4">
                        <ProductThumb src={product.imageUrl} alt={product.name} />

                        <div className="min-w-0 flex-1">
                          <div className="flex flex-wrap items-center gap-2">
                            <div className="truncate text-sm font-extrabold text-slate-900">
                              {product.name}
                            </div>

                            <Pill tone={statusTone}>
                              {titleCaseWords(product.status || "pending")}
                            </Pill>

                            <Pill tone={queueTone}>
                              <Clock className="h-3.5 w-3.5" />
                              {tab === "pending"
                                ? `Queue age: ${meta.hours != null ? `${meta.hours}h` : "—"}`
                                : `Turnaround: ${meta.hours != null ? `${meta.hours}h` : "—"}`}
                            </Pill>

                            {meta.breached ? (
                              <Pill tone="danger">
                                <AlertTriangle className="h-3.5 w-3.5" />
                                SLA breach
                              </Pill>
                            ) : null}
                          </div>

                          <div className="mt-2 text-xs font-semibold text-slate-600">
                            Farmer: <span className="font-extrabold text-slate-800">{product.farmerName}</span>
                          </div>

                          <div className="mt-3 grid grid-cols-2 gap-3 text-xs text-slate-600 sm:grid-cols-4">
                            <div>
                              <div className="font-bold uppercase tracking-wide text-slate-500">Category</div>
                              <div className="mt-1 font-semibold text-slate-800">{product.category || "—"}</div>
                            </div>
                            <div>
                              <div className="font-bold uppercase tracking-wide text-slate-500">Price</div>
                              <div className="mt-1 font-semibold text-slate-800">{fmtNAD(product.price)}</div>
                            </div>
                            <div>
                              <div className="font-bold uppercase tracking-wide text-slate-500">Stock</div>
                              <div className="mt-1 font-semibold text-slate-800">{product.quantity}</div>
                            </div>
                            <div>
                              <div className="font-bold uppercase tracking-wide text-slate-500">Unit</div>
                              <div className="mt-1 font-semibold text-slate-800">
                                {product.unit || "—"}
                                {product.unit === "pack" && product.packSize > 0
                                  ? ` • ${product.packSize} ${product.packUnit || "unit"}`
                                  : ""}
                              </div>
                            </div>
                          </div>

                          <div className="mt-3 flex flex-wrap items-center gap-2 text-xs font-semibold text-slate-500">
                            <span>{tab === "pending" ? "Submitted" : "Reviewed"}: {fmtDate(tab === "pending" ? product.submittedAt || product.createdAt : product.reviewedAt || product.updatedAt)}</span>
                            {changeCount > 0 ? (
                              <>
                                <span>•</span>
                                <span>{changeCount} tracked {pluralize(changeCount, "change")}</span>
                              </>
                            ) : null}
                          </div>

                          {tab === "rejected" && product.rejectionReason ? (
                            <div className="mt-3 rounded-xl border border-rose-200 bg-white/80 p-3 text-xs leading-6 text-rose-800">
                              <span className="font-extrabold">Reason:</span> {product.rejectionReason}
                            </div>
                          ) : null}
                        </div>

                        <div className="flex shrink-0 items-start">
                          <button
                            className={[
                              "inline-flex items-center gap-2 rounded-xl border px-4 py-2 text-sm font-extrabold shadow-sm transition",
                              "border-slate-200 bg-white text-slate-800 hover:bg-slate-50",
                              busy ? "cursor-not-allowed opacity-60" : "",
                            ].join(" ")}
                            disabled={busy}
                            onClick={() => openReviewDrawer(product)}
                            type="button"
                            title="Open the full product review panel"
                          >
                            <Eye className="h-4 w-4" /> Review details
                          </button>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>

              <div className="mt-5">
                <PaginationBar
                  page={safePage}
                  totalPages={totalPages}
                  totalItems={items.length}
                  pageSize={pageSize}
                  onPageChange={setPage}
                />
              </div>
            </>
          )}

          {error ? (
            <div className="mt-4 rounded-2xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm font-semibold text-rose-800">
              {safeStr(error) || "Failed to load moderation records."}
            </div>
          ) : null}
        </Card>
      </div>

      <ProductReviewDrawer
        open={reviewOpen}
        product={activeReviewProduct}
        loading={reviewLoading}
        error={reviewError}
        busy={Boolean(busyId)}
        onClose={closeReviewDrawer}
        onApprove={approve}
        onRequestReject={openRejectModal}
      />

      <RejectModal
        open={rejectOpen}
        target={rejectTarget}
        busy={Boolean(busyId)}
        reason={rejectReason}
        onReasonChange={setRejectReason}
        onClose={closeRejectModal}
        onSubmit={submitReject}
      />
    </AdminLayout>
  );
}