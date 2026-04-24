// ============================================================================
// frontend/src/pages/dashboards/farmer/FarmerProductsPage.jsx
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Farmer products module.
//
// SECTIONS:
//   A) Manage Products
//      - Product list + filters
//      - "+ Add Product" collapsible form
//      - Quick stock edit + edit/delete modals
//   B) Top Products
//      - Top products ranked by quantity sold
//      - Revenue used as tie-breaker
//      - Farmer market rank shown as "Rank #x of y"
//      - Top farmers list includes farmer name + location
//   C) AI Trends (Demand Index)
//      - Uses /api/ai/market-trends
//      - Falls back to real demand signal from orders history
//   D) AI Stock Alerts
//      - Uses /api/ai/stock-alerts
//      - Farmer-friendly red / orange / green language
//
// KEY FIXES IN THIS VERSION:
//   ✅ Cleaner, compile-safe full file
//   ✅ Farmer rank shown as rank out of total farmers
//   ✅ Top 3 farmers include farmer name + location
//   ✅ Top products rank by quantity sold, revenue as tie-breaker
//   ✅ Top products include linked farmer + location
//   ✅ Snapshot window drives ranking window
//   ✅ Simpler stock alert UI with Red / Orange / Green meaning
//
// UNIT / QUANTITY FIX (THIS UPDATE):
//   ✅ UI unit options now match the real backend/product model:
//        each, kg, g, l, ml, pack
//   ✅ Removed invalid selling units from the form:
//        box, crate, bag
//   ✅ When unit = "pack", the form requires:
//        pack_size + pack_unit
//   ✅ Quantity field now explains what stock means for the chosen unit
//   ✅ "pack" now means:
//        - price = price per pack
//        - quantity = number of packs in stock
//        - pack_size + pack_unit describe what one pack contains
// ============================================================================

import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import {
  Plus,
  Search,
  Pencil,
  Trash2,
  Package,
  Star,
  RefreshCcw,
  AlertTriangle,
  BarChart3,
  Tag,
  CalendarDays,
  Image as ImageIcon,
  Link2,
  MapPin,
  CheckCircle2,
  ShieldCheck,
  Boxes,
  FileText,
  CircleDollarSign,
} from "lucide-react";

import useApi from "../../../hooks/useApi";
import api from "../../../api";
import { useAuth } from "../../../components/auth/AuthProvider";
import FarmerLayout from "../../../components/FarmerLayout";
import usePublicSystemSettings from "../../../hooks/usePublicSystemSettings";

import Card, { CardHeader, CardTitle, CardContent } from "../../../components/ui/Card";
import EmptyState from "../../../components/ui/EmptyState";

import EditProductModal from "../../../components/modals/EditProductModal";
import DeleteProductModal from "../../../components/modals/DeleteProductModal";

import {
  PLACEHOLDER_IMG,
  resolveProductImageCandidates,
  getBundledProductImageNames,
} from "../../../utils/productImage";

// ----------------------------------------------------------------------------
// Namibia top-level categories
// ----------------------------------------------------------------------------
const NAMIBIA_TOP_CATEGORIES = [
  "Fresh Produce",
  "Animal Products",
  "Fish & Seafood",
  "Staples",
  "Nuts, Seeds & Oils",
  "Honey & Sweeteners",
  "Value-Added & Processed (Farm-made)",
  "Farm Supplies",
  "Wild Harvest",
];

// ----------------------------------------------------------------------------
// Time windows
// ----------------------------------------------------------------------------
const FARMER_TIME_WINDOWS = [
  { label: "Last 7 days", value: 7 },
  { label: "Last 14 days", value: 14 },
  { label: "Last 28 days", value: 28 },
  { label: "Last 60 days", value: 60 },
  { label: "Last 90 days", value: 90 },
  { label: "Last 180 days", value: 180 },
  { label: "Last 365 days", value: 365 },
  { label: "Last 730 days", value: 730 },
];

// ----------------------------------------------------------------------------
// Unit options
// IMPORTANT:
//   These must match the backend/database allowed values.
//   Valid units: each, kg, g, l, ml, pack
// ----------------------------------------------------------------------------
const UNIT_OPTIONS = [
  { value: "each", label: "each" },
  { value: "kg", label: "kg" },
  { value: "g", label: "g" },
  { value: "l", label: "L" },
  { value: "ml", label: "ml" },
  { value: "pack", label: "pack" },
];

// When a product is sold as "pack", these fields describe the content of one pack.
// Example:
//   unit      = pack
//   price     = 35
//   quantity  = 34
//   pack_size = 250
//   pack_unit = g
// Means:
//   N$35 per pack, 34 packs in stock, each pack contains 250 g.
const PACK_UNIT_OPTIONS = [
  { value: "each", label: "each" },
  { value: "kg", label: "kg" },
  { value: "g", label: "g" },
  { value: "l", label: "L" },
  { value: "ml", label: "ml" },
];

const LOW_STOCK_THRESHOLD = 5;
const MAX_IMAGE_MB = 5;
const MIN_ROWS_FOR_MARKET_RANKING_FALLBACK = 3;

// ----------------------------------------------------------------------------
// API helpers
// ----------------------------------------------------------------------------
function isAbsoluteUrl(u) {
  return /^([a-z][a-z\d+\-.]*:)?\/\//i.test(String(u || ""));
}

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

function uniqEndpoints(list) {
  const out = [];
  const seen = new Set();

  for (const item of list || []) {
    if (!item) continue;
    if (seen.has(item)) continue;
    seen.add(item);
    out.push(item);
  }

  return out;
}

// ----------------------------------------------------------------------------
// Defensive helpers
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

function hasValue(v) {
  return v !== undefined && v !== null && String(v).trim() !== "";
}

function resolveFarmerId(user) {
  return user?.id ?? user?.user_id ?? user?.farmer_id ?? null;
}

function getProductId(p) {
  return p?.id ?? p?.product_id ?? p?.productId ?? null;
}

function getOwnerId(p) {
  return p?.farmer_id ?? p?.user_id ?? p?.owner_id ?? p?.seller_id ?? null;
}

function getName(p) {
  return p?.product_name ?? p?.name ?? "Product";
}

function getCategory(p) {
  return p?.category ?? p?.product_category ?? p?.productCategory ?? p?.type ?? p?.group ?? "";
}

function getStatus(p) {
  return safeStr(p?.status ?? p?.product_status ?? p?.state ?? "available")
    .trim()
    .toLowerCase();
}

function getProductFarmerName(p) {
  return (
    p?.farmer_name ??
    p?.seller_name ??
    p?.owner_name ??
    p?.user_name ??
    p?.farmer?.name ??
    p?.seller?.name ??
    "Farmer"
  );
}

function getProductFarmerLocation(p) {
  return (
    p?.farmer_location ??
    p?.location ??
    p?.region ??
    p?.town ??
    p?.city ??
    p?.farmer?.location ??
    p?.seller?.location ??
    ""
  );
}

function isLowStock(p, threshold = 5) {
  const qty = toNumber(p?.stock ?? p?.quantity ?? p?.qty ?? p?.units ?? 0, 0);
  return qty <= threshold;
}

function fmtMoneyNAD(v) {
  return toNumber(v, 0).toFixed(2);
}

function fmtQty(v) {
  const n = toNumber(v, 0);
  return n % 1 === 0
    ? String(n.toFixed(0))
    : String(n.toFixed(3)).replace(/0+$/, "").replace(/\.$/, "");
}

function unwrapApiDataEnvelope(raw) {
  if (raw == null) return raw;
  if (Array.isArray(raw)) return raw;
  if (typeof raw !== "object") return raw;

  if (Object.prototype.hasOwnProperty.call(raw, "data") && raw.data != null) {
    return raw.data;
  }

  return raw;
}

function pickArrayFromPayload(raw, candidateKeys = []) {
  const payload = unwrapApiDataEnvelope(raw);

  if (Array.isArray(payload)) return payload;
  if (payload == null || typeof payload !== "object") return [];

  for (const key of candidateKeys) {
    const maybe = payload?.[key];
    if (Array.isArray(maybe)) return maybe;

    const nested = unwrapApiDataEnvelope(maybe);
    if (Array.isArray(nested)) return nested;

    if (nested && typeof nested === "object") {
      for (const nestedKey of candidateKeys) {
        if (Array.isArray(nested?.[nestedKey])) return nested[nestedKey];
      }
    }
  }

  return [];
}

function getOrderItems(order) {
  const first = safeArray(order?.items ?? order?.order_items ?? order?.orderItems);
  if (first.length) return first;

  const u = unwrapApiDataEnvelope(order);
  return safeArray(u?.items ?? u?.order_items ?? u?.orderItems);
}

// ----------------------------------------------------------------------------
// Category normalization
// ----------------------------------------------------------------------------
function isTopCategory(cat) {
  const s = safeStr(cat).trim().toLowerCase();
  return NAMIBIA_TOP_CATEGORIES.some((c) => c.toLowerCase() === s);
}

function normalizeCategory(rawCategory, productName = "") {
  const raw = safeStr(rawCategory).trim();
  if (!raw) return "Fresh Produce";

  if (isTopCategory(raw)) {
    const match = NAMIBIA_TOP_CATEGORIES.find((c) => c.toLowerCase() === raw.toLowerCase());
    return match || raw;
  }

  const s = `${raw} ${safeStr(productName)}`.toLowerCase();

  if (/(wild|\bnara\b|mopane|mushroom|veld)/.test(s)) return "Wild Harvest";
  if (/(feed|forage|lucerne|hay|bran|seedling|nursery|hide|skin|wool|mohair|suppl(y|ies))/.test(s)) {
    return "Farm Supplies";
  }
  if (/(honey|sweetener|syrup|beeswax)/.test(s)) return "Honey & Sweeteners";
  if (/(fish|seafood|hake|tilapia|oyster|prawn|shrimp|crab|smoked fish|dried fish)/.test(s)) {
    return "Fish & Seafood";
  }
  if (/(nut|seed|groundnut|peanut|sunflower|sesame|pumpkin seed|oil|olive)/.test(s)) {
    return "Nuts, Seeds & Oils";
  }
  if (/(staple|grain|cereal|mahangu|maize|corn|sorghum|rice|wheat|legume|pulse|bean|cowpea|lentil)/.test(s)) {
    return "Staples";
  }
  if (/(animal|dairy|milk|omaere|yoghurt|yogurt|cheese|butter|egg|meat|poultry|beef|goat|chicken|lamb|pork|game)/.test(s)) {
    return "Animal Products";
  }
  if (/(value|processed|farm-made|meal|flour|jam|dried fruit|pickle|atchar|sauce|chutney|biltong)/.test(s)) {
    return "Value-Added & Processed (Farm-made)";
  }

  return "Fresh Produce";
}

// ----------------------------------------------------------------------------
// Unit / quantity UX helpers
// ----------------------------------------------------------------------------
function isPackUnit(unit) {
  return safeStr(unit).trim().toLowerCase() === "pack";
}

function quantityLabelForUnit(unit) {
  const u = safeStr(unit).trim().toLowerCase();

  if (u === "each") return "Quantity in stock (items)";
  if (u === "kg") return "Quantity in stock (kg)";
  if (u === "g") return "Quantity in stock (g)";
  if (u === "l") return "Quantity in stock (L)";
  if (u === "ml") return "Quantity in stock (ml)";
  if (u === "pack") return "Quantity in stock (number of packs)";
  return "Quantity in stock";
}

function quantityPlaceholderForUnit(unit) {
  const u = safeStr(unit).trim().toLowerCase();

  if (u === "each") return "e.g. 34";
  if (u === "kg") return "e.g. 34";
  if (u === "g") return "e.g. 34000";
  if (u === "l") return "e.g. 20";
  if (u === "ml") return "e.g. 20000";
  if (u === "pack") return "e.g. 34 packs";
  return "Quantity";
}

function quantityHelpForUnit(unit) {
  const u = safeStr(unit).trim().toLowerCase();

  if (u === "each") {
    return "Use this when you sell single items. Quantity means the number of items in stock.";
  }
  if (u === "kg") {
    return "Quantity means the total stock available in kilograms.";
  }
  if (u === "g") {
    return "Quantity means the total stock available in grams.";
  }
  if (u === "l") {
    return "Quantity means the total stock available in litres.";
  }
  if (u === "ml") {
    return "Quantity means the total stock available in millilitres.";
  }
  if (u === "pack") {
    return "Quantity means how many packs you have in stock. Then enter the size of one pack below.";
  }
  return "";
}

function unitLabelForPreview(unit) {
  const u = safeStr(unit).trim().toLowerCase();
  if (!u) return "unit";
  if (u === "l") return "litre";
  if (u === "ml") return "millilitre";
  if (u === "kg") return "kilogram";
  if (u === "g") return "gram";
  if (u === "each") return "item";
  if (u === "pack") return "pack";
  return u;
}

function packDescription(packSize, packUnit) {
  const size = safeStr(packSize).trim();
  const unit = safeStr(packUnit).trim().toLowerCase();
  if (!size || !unit) return "Not yet specified";
  return `${size} ${unit === "l" ? "L" : unit}`;
}

function imageReadinessLabel(file, imageUrl) {
  if (file) return "Image file selected";
  if (safeStr(imageUrl).trim()) return "Image reference provided";
  return "No image yet";
}

// ----------------------------------------------------------------------------
// Stock alert helpers
// ----------------------------------------------------------------------------
function getRiskLevelMeta(levelRaw) {
  const level = safeStr(levelRaw, "unknown").toLowerCase();

  if (level === "high") {
    return {
      level,
      label: "Restock now",
      shortLabel: "High",
      badge: "border-red-200 bg-red-50 text-red-700",
      softPanel: "border-red-200 bg-red-50",
      bar: "bg-red-500",
      tone: "text-red-700",
      meaning: "You may run short before the selected period ends.",
      defaultAction: "Add more stock now for this product.",
    };
  }

  if (level === "medium") {
    return {
      level,
      label: "Plan soon",
      shortLabel: "Medium",
      badge: "border-orange-200 bg-orange-50 text-orange-700",
      softPanel: "border-orange-200 bg-orange-50",
      bar: "bg-orange-500",
      tone: "text-orange-700",
      meaning: "Stock may become low soon.",
      defaultAction: "Prepare more stock soon.",
    };
  }

  if (level === "low") {
    return {
      level,
      label: "Stock okay",
      shortLabel: "Low",
      badge: "border-green-200 bg-green-50 text-green-700",
      softPanel: "border-green-200 bg-green-50",
      bar: "bg-green-500",
      tone: "text-green-700",
      meaning: "You have enough stock for this period.",
      defaultAction: "No urgent restock needed right now.",
    };
  }

  return {
    level,
    label: "Check data",
    shortLabel: "Unknown",
    badge: "border-slate-200 bg-slate-50 text-slate-700",
    softPanel: "border-slate-200 bg-slate-50",
    bar: "bg-slate-400",
    tone: "text-slate-700",
    meaning: "There is not enough data yet.",
    defaultAction: "Keep updating stock and sales data.",
  };
}

function normalizeStockAlertsForView(alertRows, products, snapshotDays) {
  const productMap = new Map(safeArray(products).map((p) => [String(getProductId(p)), p]));
  const severityRank = { high: 3, medium: 2, low: 1, unknown: 0 };

  return safeArray(alertRows)
    .map((row, idx) => {
      const productId = safeStr(row?.product_id ?? row?.productId ?? row?.id ?? "", "");
      const product = productMap.get(productId) || null;

      const forecastDemand = Math.max(
        0,
        toNumber(row?.forecast_demand ?? row?.demand_forecast ?? row?.predicted_demand ?? 0, 0)
      );

      const currentStock = Math.max(
        0,
        toNumber(row?.current_stock ?? row?.available_stock ?? product?.quantity ?? product?.stock ?? 0, 0)
      );

      const recommendedRestock = Math.max(
        0,
        toNumber(row?.recommended_restock ?? row?.restock_qty ?? Math.max(0, forecastDemand - currentStock), 0)
      );

      const stockGap = Math.max(0, forecastDemand - currentStock);
      const coverageRatio = forecastDemand > 0 ? currentStock / forecastDemand : currentStock > 0 ? 999 : 0;
      const coveragePercent = Number(
        Math.max(0, Math.min(999, coverageRatio * 100)).toFixed(0)
      );
      const daysOfCover =
        forecastDemand > 0 ? Number(((currentStock / forecastDemand) * snapshotDays).toFixed(1)) : null;

      const risk = getRiskLevelMeta(row?.risk_level ?? row?.severity);

      return {
        id: safeStr(row?.id ?? row?.alert_id ?? `${productId || "alert"}-${idx}`),
        product_id: productId,
        product_name: safeStr(row?.product_name ?? row?.title ?? getName(product) ?? "Stock alert"),
        category: safeStr(product?.category ?? row?.category ?? ""),
        unit: safeStr(product?.unit ?? row?.unit ?? "units"),
        risk_level: risk.level,
        risk,
        forecast_demand: forecastDemand,
        current_stock: currentStock,
        recommended_restock: recommendedRestock,
        stock_gap: stockGap,
        coverage_percent: coveragePercent,
        days_of_cover: daysOfCover,
        recommendation: safeStr(row?.recommendation ?? row?.message ?? risk.defaultAction),
        generated_at: row?.generated_at ?? row?.computed_at ?? row?.observed_at ?? "",
        model_version: safeStr(row?.model_version ?? row?.modelVersion ?? ""),
      };
    })
    .sort((a, b) => {
      const sev = severityRank[b.risk_level] - severityRank[a.risk_level];
      if (sev !== 0) return sev;
      if (b.stock_gap !== a.stock_gap) return b.stock_gap - a.stock_gap;
      return a.product_name.localeCompare(b.product_name);
    });
}

function buildStockAlertSummary(alerts) {
  return safeArray(alerts).reduce(
    (acc, row) => {
      acc.total += 1;
      acc[row.risk_level] = (acc[row.risk_level] || 0) + 1;
      acc.coverageSum += toNumber(row?.coverage_percent, 0);
      acc.coverageN += 1;
      return acc;
    },
    { total: 0, high: 0, medium: 0, low: 0, unknown: 0, coverageSum: 0, coverageN: 0 }
  );
}

function getAverageCoverPercent(summary) {
  const n = toNumber(summary?.coverageN, 0);
  if (!n) return null;
  return toNumber(summary?.coverageSum, 0) / n;
}

function formatCoverValueSimple(percent) {
  const p = toNumber(percent, NaN);
  if (!Number.isFinite(p)) return "—";
  if (p >= 100) return `${(p / 100).toFixed(1)}x`;
  return `${Math.round(p)}%`;
}

function coverSubtitleSimple(percent) {
  const p = toNumber(percent, NaN);
  if (!Number.isFinite(p)) return "No stock cover data";
  return p >= 100 ? "times expected sales" : "of expected sales covered";
}

function coverMeaningSimple(percent) {
  const p = toNumber(percent, NaN);
  if (!Number.isFinite(p)) return "We do not have enough data yet.";
  if (p >= 300) return "You have much more stock than expected sales.";
  if (p >= 150) return "You have more stock than expected sales.";
  if (p >= 100) return "You have enough stock for the selected period.";
  if (p >= 70) return "Stock may be enough, but monitor closely.";
  return "Stock may not be enough for the selected period.";
}

function getCoverTone(percent) {
  const p = toNumber(percent, NaN);

  if (!Number.isFinite(p)) {
    return { card: "border-slate-200 bg-slate-50", text: "text-slate-700" };
  }
  if (p < 100) {
    return { card: "border-red-200 bg-red-50", text: "text-red-700" };
  }
  if (p < 150) {
    return { card: "border-orange-200 bg-orange-50", text: "text-orange-700" };
  }
  return { card: "border-green-200 bg-green-50", text: "text-green-700" };
}

function getAlertRowSurfaceClasses(riskLevel) {
  if (riskLevel === "high") return "border-red-200 bg-white";
  if (riskLevel === "medium") return "border-orange-200 bg-white";
  if (riskLevel === "low") return "border-green-200 bg-white";
  return "border-slate-200 bg-white";
}

function formatAlertTime(ts) {
  const s = safeStr(ts, "").trim();
  if (!s) return "";
  try {
    const d = new Date(s);
    if (Number.isNaN(d.getTime())) return s;
    return d.toLocaleString();
  } catch {
    return s;
  }
}

// ----------------------------------------------------------------------------
// Demand trend helpers
// ----------------------------------------------------------------------------
function dateKeyLocal(d) {
  const yy = d.getFullYear();
  const mm = String(d.getMonth() + 1).padStart(2, "0");
  const dd = String(d.getDate()).padStart(2, "0");
  return `${yy}-${mm}-${dd}`;
}

function prettyDayLabel(dayKey) {
  const d = new Date(`${dayKey}T00:00:00`);
  if (Number.isNaN(d.getTime())) return dayKey;
  return d.toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

function parseDayKey(value) {
  if (!hasValue(value)) return "";
  const d = new Date(String(value));
  if (Number.isNaN(d.getTime())) return "";
  d.setHours(0, 0, 0, 0);
  return dateKeyLocal(d);
}

function getOrderDateRaw(order, item = null) {
  return (
    item?.created_at ??
    item?.createdAt ??
    item?.date ??
    order?.created_at ??
    order?.createdAt ??
    order?.order_date ??
    order?.orderDate ??
    order?.placed_at ??
    ""
  );
}

function buildRecentDayKeys(days) {
  const out = [];
  const today = new Date();
  today.setHours(0, 0, 0, 0);

  for (let i = days - 1; i >= 0; i -= 1) {
    const d = new Date(today);
    d.setDate(today.getDate() - i);
    out.push(dateKeyLocal(d));
  }

  return out;
}

function downsampleSeries(rows, maxPoints = 24) {
  const list = safeArray(rows);
  if (list.length <= maxPoints) return list;

  const bucketSize = Math.ceil(list.length / maxPoints);
  const out = [];

  for (let i = 0; i < list.length; i += bucketSize) {
    const chunk = list.slice(i, i + bucketSize);
    if (!chunk.length) continue;

    const sum = chunk.reduce((acc, x) => acc + toNumber(x?.value, 0), 0);
    const avg = sum / chunk.length;

    out.push({
      label: safeStr(chunk[0]?.label),
      value: Number(avg.toFixed(2)),
    });
  }

  return out;
}

function normalizeTrendRowsForChart(rawRows, snapshotDays) {
  const list = safeArray(rawRows);

  const normalized = list
    .map((row, i) => {
      const labelRaw =
        row?.date ??
        row?.day ??
        row?.bucket_date ??
        row?.period ??
        row?.label ??
        row?.week ??
        row?.month ??
        "";

      const dayKey = parseDayKey(labelRaw);
      const label = dayKey ? prettyDayLabel(dayKey) : safeStr(labelRaw, `Point ${i + 1}`);

      const value = toNumber(
        row?.demand_index ??
          row?.demandIndex ??
          row?.index ??
          row?.value ??
          row?.score ??
          row?.predicted_demand ??
          row?.forecast_demand ??
          NaN,
        NaN
      );

      return { label, sortKey: dayKey || "", value };
    })
    .filter((x) => Number.isFinite(x.value));

  if (!normalized.length) return [];

  const sorted = [...normalized].sort((a, b) => safeStr(a.sortKey).localeCompare(safeStr(b.sortKey)));
  const maxPoints = snapshotDays >= 180 ? 30 : 24;
  return downsampleSeries(sorted, maxPoints);
}

function buildDemandIndexFromOrders(orders, days) {
  const dayKeys = buildRecentDayKeys(days);
  const buckets = new Map(
    dayKeys.map((k) => [k, { qty: 0, orders: 0, revenue: 0 }])
  );

  for (const order of safeArray(orders)) {
    const items = getOrderItems(order);
    let countedOrder = false;
    const orderDayKey = parseDayKey(getOrderDateRaw(order));

    if (items.length) {
      for (const item of items) {
        const dk = parseDayKey(getOrderDateRaw(order, item)) || orderDayKey;
        if (!dk || !buckets.has(dk)) continue;

        const bucket = buckets.get(dk);
        if (!bucket) continue;

        const qty = Math.max(0, toNumber(item?.quantity ?? item?.qty ?? 0, 0));
        const revenue = Math.max(0, toNumber(item?.line_total ?? item?.total ?? 0, 0));

        bucket.qty += qty;
        bucket.revenue += revenue;

        if (!countedOrder) {
          bucket.orders += 1;
          countedOrder = true;
        }
      }
    }
  }

  const rawRows = dayKeys.map((dk) => {
    const b = buckets.get(dk) || { qty: 0, orders: 0, revenue: 0 };
    return {
      dayKey: dk,
      label: prettyDayLabel(dk),
      qty: b.qty,
      orders: b.orders,
      revenue: b.revenue,
    };
  });

  const activeRows = rawRows.filter((x) => x.qty > 0 || x.orders > 0 || x.revenue > 0);
  if (!activeRows.length) return [];

  const maxQty = Math.max(...rawRows.map((x) => x.qty), 1);
  const maxOrders = Math.max(...rawRows.map((x) => x.orders), 1);
  const maxRevenue = Math.max(...rawRows.map((x) => x.revenue), 1);

  let prevSmoothed = 0;
  const enriched = rawRows.map((row) => {
    const rawSignal =
      0.55 * (row.qty / maxQty) +
      0.25 * (row.orders / maxOrders) +
      0.2 * (row.revenue / maxRevenue);

    const smoothed = prevSmoothed === 0 ? rawSignal : 0.65 * rawSignal + 0.35 * prevSmoothed;
    prevSmoothed = smoothed;

    return {
      label: row.label,
      value: Number((Math.max(0, smoothed * 100)).toFixed(2)),
    };
  });

  const maxPoints = days >= 180 ? 30 : 24;
  return downsampleSeries(enriched, maxPoints);
}

function buildDemandSummary(series) {
  const rows = safeArray(series).filter((x) => Number.isFinite(toNumber(x?.value, NaN)));

  if (!rows.length) {
    return {
      latest: 0,
      average: 0,
      peak: 0,
      peakLabel: "—",
      directionLabel: "Stable",
      activePoints: 0,
    };
  }

  const latest = toNumber(rows[rows.length - 1]?.value, 0);
  const previous = toNumber(rows[Math.max(0, rows.length - 2)]?.value, latest);
  const average = rows.reduce((sum, row) => sum + toNumber(row?.value, 0), 0) / rows.length;
  const peakRow = [...rows].sort((a, b) => toNumber(b?.value, 0) - toNumber(a?.value, 0))[0];
  const delta = latest - previous;

  let directionLabel = "Stable";
  if (delta >= 8) directionLabel = "Rising";
  else if (delta <= -8) directionLabel = "Cooling";

  return {
    latest: Number(latest.toFixed(1)),
    average: Number(average.toFixed(1)),
    peak: Number(toNumber(peakRow?.value, 0).toFixed(1)),
    peakLabel: safeStr(peakRow?.label, "—"),
    directionLabel,
    activePoints: rows.filter((x) => toNumber(x?.value, 0) > 0).length,
  };
}

// ----------------------------------------------------------------------------
// Ranking helpers
// ----------------------------------------------------------------------------
function normalizeFarmerLeaderboardRows(raw) {
  const rows = pickArrayFromPayload(raw, [
    "rankings",
    "leaderboard",
    "farmers",
    "rows",
    "items",
    "results",
    "data",
    "top_farmers",
    "top_three",
  ]);

  return safeArray(rows)
    .map((r, idx) => {
      const rank = toNumber(r?.rank ?? r?.position ?? idx + 1, idx + 1);
      const totalFarmers = Math.max(
        0,
        Math.round(
          toNumber(
            r?.total_farmers ??
              r?.totalFarmers ??
              raw?.total_farmers ??
              raw?.totalFarmers ??
              0,
            0
          )
        )
      );

      return {
        key: safeStr(r?.farmer_id ?? r?.farmerId ?? r?.id ?? idx),
        id: r?.farmer_id ?? r?.farmerId ?? r?.user_id ?? r?.id ?? null,
        name:
          r?.farmer_name ??
          r?.farmerName ??
          r?.name ??
          r?.display_name ??
          r?.farmer?.name ??
          "Farmer",
        location:
          r?.farmer_location ??
          r?.location ??
          r?.region ??
          r?.town ??
          r?.city ??
          r?.farmer?.location ??
          "Location not set",
        email: safeStr(r?.email ?? r?.farmer_email ?? ""),
        rank,
        totalFarmers,
        revenue: toNumber(r?.revenue_total ?? r?.revenue ?? r?.sales ?? 0, 0),
        orders: toNumber(r?.orders_count ?? r?.orders ?? r?.order_count ?? 0, 0),
        qty: toNumber(r?.qty_sold ?? r?.quantity_sold ?? r?.qty ?? 0, 0),
      };
    })
    .filter((row) => hasValue(row.id) || row.revenue > 0 || row.orders > 0 || row.qty > 0);
}

function resolveFarmerIdentityFromOrder(order, item = null) {
  return {
    id:
      item?.farmer_id ??
      item?.farmerId ??
      item?.seller_id ??
      item?.sellerId ??
      item?.product?.farmer_id ??
      item?.product?.seller_id ??
      order?.farmer_id ??
      order?.seller_id ??
      order?.farmer?.id ??
      null,
    email: safeStr(
      item?.farmer_email ??
        item?.seller_email ??
        order?.farmer_email ??
        order?.seller_email ??
        "",
      ""
    ).trim().toLowerCase(),
    name: safeStr(
      item?.farmer_name ??
        item?.seller_name ??
        item?.product?.farmer_name ??
        order?.farmer_name ??
        order?.seller_name ??
        order?.farmer?.name ??
        "Farmer",
      "Farmer"
    ).trim(),
    location: safeStr(
      item?.farmer_location ??
        item?.seller_location ??
        item?.product?.farmer_location ??
        order?.farmer_location ??
        order?.seller_location ??
        order?.farmer?.location ??
        "Location not set",
      "Location not set"
    ).trim(),
  };
}

function resolveFarmerKey(identity) {
  if (hasValue(identity?.id)) return `id:${String(identity.id)}`;
  if (hasValue(identity?.email)) return `email:${String(identity.email).toLowerCase()}`;
  return `name:${safeStr(identity?.name, "Farmer").toLowerCase()}`;
}

function buildFarmerLeaderboardFromOrders(rawOrders) {
  const orders = safeArray(rawOrders);
  if (!orders.length) return [];

  const agg = new Map();

  for (const order of orders) {
    const items = getOrderItems(order);
    const seenKeysInOrder = new Set();

    if (items.length) {
      for (const item of items) {
        const identity = resolveFarmerIdentityFromOrder(order, item);
        const key = resolveFarmerKey(identity);

        const qty = Math.max(0, toNumber(item?.quantity ?? item?.qty ?? 0, 0));
        const revenue = Math.max(
          0,
          toNumber(
            item?.line_total ??
              item?.lineTotal ??
              item?.total ??
              toNumber(item?.unit_price ?? item?.price ?? 0, 0) * qty,
            0
          )
        );

        const prev = agg.get(key) || {
          id: identity.id,
          email: identity.email,
          name: identity.name,
          location: identity.location,
          orders: 0,
          revenue: 0,
          qty: 0,
        };

        prev.id = prev.id || identity.id;
        prev.email = prev.email || identity.email;
        prev.name = prev.name === "Farmer" ? identity.name : prev.name;
        prev.location =
          prev.location === "Location not set" ? identity.location : prev.location;
        prev.revenue += revenue;
        prev.qty += qty;

        if (!seenKeysInOrder.has(key)) {
          prev.orders += 1;
          seenKeysInOrder.add(key);
        }

        agg.set(key, prev);
      }
    }
  }

  const sorted = [...agg.values()]
    .filter((r) => r.revenue > 0 || r.orders > 0 || r.qty > 0)
    .sort((a, b) => {
      if (b.revenue !== a.revenue) return b.revenue - a.revenue;
      if (b.orders !== a.orders) return b.orders - a.orders;
      if (b.qty !== a.qty) return b.qty - a.qty;
      return safeStr(a.name).localeCompare(safeStr(b.name));
    });

  const total = sorted.length;

  return sorted.map((r, idx) => ({
    key: `${r.id ?? r.email ?? r.name}:${idx}`,
    id: r.id ?? null,
    email: r.email ?? "",
    name: r.name || "Farmer",
    location: r.location || "Location not set",
    rank: idx + 1,
    totalFarmers: total,
    revenue: toNumber(r.revenue, 0),
    orders: toNumber(r.orders, 0),
    qty: toNumber(r.qty, 0),
  }));
}

function formatRankOutOf(rank, total) {
  if (!rank && !total) return "Rank unavailable";
  if (total > 0) return `Rank #${rank} of ${total}`;
  return `Rank #${rank}`;
}

// ----------------------------------------------------------------------------
// Status badges
// ----------------------------------------------------------------------------
function statusBadgeClasses(status) {
  const s = safeStr(status, "").toLowerCase();

  if (s === "pending") return "bg-orange-50 text-orange-800 border-orange-200";
  if (s === "rejected") return "bg-red-50 text-red-700 border-red-200";
  if (s === "approved") return "bg-green-50 text-green-700 border-green-200";
  if (s === "available" || s === "active" || s === "published") {
    return "bg-green-50 text-green-700 border-green-200";
  }
  if (s === "unavailable") return "bg-slate-50 text-slate-700 border-slate-200";
  return "bg-slate-50 text-slate-700 border-slate-200";
}

function statusLabel(status) {
  const s = safeStr(status, "").toLowerCase();
  return s || "—";
}

// ----------------------------------------------------------------------------
// Reusable UI helpers
// ----------------------------------------------------------------------------
function DemandStatCard({ label, value, sub }) {
  return (
    <div className="rounded-2xl border border-slate-200 bg-slate-50 p-3">
      <div className="text-[11px] font-semibold uppercase tracking-wide text-slate-500">
        {label}
      </div>
      <div className="mt-1 text-xl font-black text-slate-900">{value}</div>
      {sub ? <div className="mt-1 text-xs text-slate-500">{sub}</div> : null}
    </div>
  );
}

function SimpleAlertSummaryCard({ label, value, sub, tone = "slate" }) {
  const tones = {
    red: "border-red-200 bg-red-50 text-red-700",
    orange: "border-orange-200 bg-orange-50 text-orange-700",
    green: "border-green-200 bg-green-50 text-green-700",
    slate: "border-slate-200 bg-slate-50 text-slate-700",
  };

  return (
    <div className={`rounded-2xl border p-4 ${tones[tone] || tones.slate}`}>
      <div className="text-[11px] font-semibold uppercase tracking-wide opacity-80">{label}</div>
      <div className="mt-1 text-2xl font-black">{value}</div>
      {sub ? <div className="mt-1 text-xs opacity-90">{sub}</div> : null}
    </div>
  );
}

function DemandIndexChart({ rows = [], height = 320 }) {
  const series = safeArray(rows).filter((x) => Number.isFinite(toNumber(x?.value, NaN)));

  if (!series.length) {
    return (
      <div className="grid h-full place-items-center text-sm text-slate-500">
        No demand series available.
      </div>
    );
  }

  const width = 1000;
  const chartHeight = 220;
  const left = 44;
  const right = 16;
  const top = 12;
  const bottom = 34;
  const innerW = width - left - right;
  const innerH = chartHeight - top - bottom;

  const maxY = 100;
  const points = series.map((row, idx) => {
    const x = left + (idx * innerW) / Math.max(1, series.length - 1);
    const y = top + innerH - (Math.max(0, Math.min(maxY, toNumber(row?.value, 0))) / maxY) * innerH;
    return { x, y, label: safeStr(row?.label) };
  });

  const linePath = points
    .map((p, idx) => `${idx === 0 ? "M" : "L"} ${p.x.toFixed(2)} ${p.y.toFixed(2)}`)
    .join(" ");

  const areaPath = `${linePath} L ${points[points.length - 1].x.toFixed(2)} ${(top + innerH).toFixed(2)} L ${points[0].x.toFixed(2)} ${(top + innerH).toFixed(2)} Z`;

  const ticks = [0, 25, 50, 75, 100];

  return (
    <div className="w-full" style={{ height }}>
      <div className="h-full rounded-2xl border border-slate-200 bg-white p-4">
        <svg viewBox={`0 0 ${width} ${chartHeight}`} className="h-full w-full">
          <defs>
            <linearGradient id="demandArea" x1="0" x2="0" y1="0" y2="1">
              <stop offset="0%" stopColor="rgb(16 185 129)" stopOpacity="0.22" />
              <stop offset="100%" stopColor="rgb(16 185 129)" stopOpacity="0.03" />
            </linearGradient>
          </defs>

          {ticks.map((tick) => {
            const y = top + innerH - (tick / maxY) * innerH;
            return (
              <g key={tick}>
                <line
                  x1={left}
                  y1={y}
                  x2={width - right}
                  y2={y}
                  stroke="rgb(226 232 240)"
                  strokeDasharray="4 4"
                />
                <text
                  x={left - 10}
                  y={y + 4}
                  textAnchor="end"
                  fontSize="11"
                  fill="rgb(100 116 139)"
                >
                  {tick}
                </text>
              </g>
            );
          })}

          <path d={areaPath} fill="url(#demandArea)" />
          <path
            d={linePath}
            fill="none"
            stroke="rgb(5 150 105)"
            strokeWidth="3"
            strokeLinecap="round"
            strokeLinejoin="round"
          />

          {points.map((p, idx) => {
            const major = idx === points.length - 1 || idx === 0 || idx % Math.ceil(points.length / 8) === 0;
            return (
              <g key={`${p.label}-${idx}`}>
                <circle cx={p.x} cy={p.y} r={major ? 4 : 2.5} fill="rgb(5 150 105)" />
                {major ? (
                  <text
                    x={p.x}
                    y={chartHeight - 8}
                    textAnchor="middle"
                    fontSize="10"
                    fill="rgb(100 116 139)"
                  >
                    {p.label}
                  </text>
                ) : null}
              </g>
            );
          })}
        </svg>
      </div>
    </div>
  );
}

// ----------------------------------------------------------------------------
// Image uploader helper
// ----------------------------------------------------------------------------
async function tryUploadImageBestEffort({ file, productId }) {
  if (!file) return null;

  const form = new FormData();
  form.append("image", file);
  form.append("file", file);
  form.append("photo", file);
  if (productId) form.append("product_id", String(productId));

  const base = String(api?.defaults?.baseURL || "");
  const root = base.replace(/\/api\/?$/, "");

  const endpoints = uniqEndpoints(
    [
      productId ? `/api/products/${productId}/image` : null,
      productId ? `/products/${productId}/image` : null,
      productId ? `/api/products/${productId}/upload-image` : null,
      productId ? `/products/${productId}/upload-image` : null,
      "/api/products/upload-image",
      "/products/upload-image",
      "/api/uploads",
      "/uploads",
      "/api/upload",
      "/upload",
      "/uploads/public_images",
      "/api/uploads/public_images",
    ].filter(Boolean)
  );

  const buildTryUrls = (ep) => {
    const raw = ensureLeadingSlash(ep);
    const normalized = apiPath(raw);
    const urls = [normalized];

    if (root && isAbsoluteUrl(root)) {
      urls.push(`${root}${raw}`);
      if (normalized !== raw) urls.push(`${root}${normalized}`);
    }

    return uniqEndpoints(urls);
  };

  for (const ep of endpoints) {
    for (const url of buildTryUrls(ep)) {
      try {
        const res = await api.post(url, form, {
          headers: { "Content-Type": "multipart/form-data" },
        });

        const d = res?.data;
        const uploadedUrl =
          d?.image_url ||
          d?.url ||
          d?.file_url ||
          d?.path ||
          d?.location ||
          d?.public_url ||
          (d?.filename ? `/uploads/public_images/${d.filename}` : null);

        if (typeof uploadedUrl === "string" && uploadedUrl.trim()) {
          return uploadedUrl.trim();
        }
      } catch {
        // try next endpoint
      }
    }
  }

  return null;
}

// ----------------------------------------------------------------------------
// First-load-only loading gate
// ----------------------------------------------------------------------------
function useFirstLoadGate(loading, data, error) {
  const [hasPainted, setHasPainted] = useState(false);

  useEffect(() => {
    if (!hasPainted && !loading && (data !== undefined || error)) {
      setHasPainted(true);
    }
  }, [loading, data, error, hasPainted]);

  return hasPainted;
}

// ----------------------------------------------------------------------------
// Product image component
// ----------------------------------------------------------------------------
function ProductImage({ product, alt, cacheBust }) {
  const pid = product?.id ?? product?.product_id ?? product?.productId ?? null;
  const imageUrl =
    product?.image_url ??
    product?.imageUrl ??
    product?.image ??
    product?.image_path ??
    product?.imagePath ??
    product?.image_filename ??
    product?.imageFileName ??
    "";

  const name = product?.product_name ?? product?.name ?? "";
  const cat = product?.category ?? product?.product_category ?? product?.productCategory ?? "";
  const snap = product?.imageSrc || product?.image_src || "";
  const bust = product?.image_cache_bust ?? product?.imageCacheBust ?? cacheBust ?? "";

  const candidates = useMemo(() => {
    const minimal = {
      id: pid,
      product_id: pid,
      productId: pid,
      product_name: name,
      name,
      category: cat,
      product_category: cat,
      image_url: imageUrl,
      imageUrl: imageUrl,
      image_filename: imageUrl,
      imageFileName: imageUrl,
      imageSrc: snap,
      image_src: snap,
      image_cache_bust: bust,
      imageCacheBust: bust,
    };
    return resolveProductImageCandidates(minimal);
  }, [pid, name, cat, imageUrl, snap, bust]);

  const signature = useMemo(() => candidates.join("|"), [candidates]);
  const [idx, setIdx] = useState(0);

  useEffect(() => {
    setIdx(0);
  }, [signature]);

  const src = candidates[idx] || PLACEHOLDER_IMG;

  return (
    <img
      src={src}
      alt={alt}
      loading="lazy"
      decoding="async"
      className="h-full w-full object-cover"
      onError={() => {
        if (idx < candidates.length - 1) setIdx((i) => i + 1);
      }}
    />
  );
}

// ----------------------------------------------------------------------------
// Rating stars
// ----------------------------------------------------------------------------
function Stars({ value }) {
  const v = Math.max(0, Math.min(5, Number(value) || 0));
  const full = Math.round(v);

  return (
    <div className="flex items-center gap-1">
      {Array.from({ length: 5 }).map((_, i) => (
        <Star
          key={i}
          size={14}
          className={i < full ? "fill-green-600 text-green-600" : "text-slate-300"}
        />
      ))}
    </div>
  );
}

// ----------------------------------------------------------------------------
// Tabs
// ----------------------------------------------------------------------------
const TABS = [
  { key: "manage", label: "Manage Products" },
  { key: "top", label: "Top Products" },
  { key: "trends", label: "AI Trends" },
  { key: "alerts", label: "AI Stock Alerts" },
];

export default function FarmerProductsPage() {
  const { user } = useAuth();
  const [searchParams, setSearchParams] = useSearchParams();
  const farmerId = resolveFarmerId(user);

  const { helpers: settingsHelpers, loading: settingsLoading } = usePublicSystemSettings();

  const aiInsightsEnabled = settingsHelpers?.aiInsightsEnabled ?? true;
  const marketTrendsEnabled = settingsHelpers?.marketTrendsEnabled ?? true;
  const lowStockAlertsEnabled = settingsHelpers?.lowStockAlertsEnabled ?? true;
  const rankingWidgetsEnabled = settingsHelpers?.rankingWidgetsEnabled ?? true;

  const canShowTrendTab = aiInsightsEnabled && marketTrendsEnabled;
  const canShowAlertTab = aiInsightsEnabled && lowStockAlertsEnabled;
  const canShowRankingWidgets = rankingWidgetsEnabled;

  const visibleTabs = useMemo(
    () =>
      TABS.filter((item) => {
        if (item.key === "trends") return canShowTrendTab;
        if (item.key === "alerts") return canShowAlertTab;
        return true;
      }),
    [canShowAlertTab, canShowTrendTab]
  );

  const productsPageIntro = aiInsightsEnabled
    ? "Inventory management, performance, and AI insights."
    : "Inventory management and performance.";

  const [tab, setTab] = useState("manage");
  const [showAddForm, setShowAddForm] = useState(false);
  const [snapshotDays, setSnapshotDays] = useState(60);

  const [query, setQuery] = useState("");
  const [status, setStatus] = useState("all");
  const [category, setCategory] = useState("all");
  const [lowOnly, setLowOnly] = useState(false);

  const [adding, setAdding] = useState(false);
  const [addError, setAddError] = useState("");
  const [addSuccess, setAddSuccess] = useState("");
  const [newP, setNewP] = useState({
    product_name: "",
    category: "Fresh Produce",
    price: "",
    quantity: "",
    unit: "each",
    pack_size: "",
    pack_unit: "g",
    description: "",
    image_url: "",
  });

  const localImageOptions = useMemo(() => getBundledProductImageNames?.() || [], []);

  const [newImageFile, setNewImageFile] = useState(null);
  const [newImagePreview, setNewImagePreview] = useState("");

  /**
   * Support cross-page "Add Product" actions from the farmer overview.
   * Visiting /dashboard/farmer/products?create=1 opens the same structured
   * listing form used on this page, then removes the query flag so refreshes
   * do not keep reopening it.
   */
  useEffect(() => {
    if (searchParams.get("create") !== "1") return;

    setTab("manage");
    setShowAddForm(true);

    const nextParams = new URLSearchParams(searchParams);
    nextParams.delete("create");
    setSearchParams(nextParams, { replace: true });

    window.requestAnimationFrame(() => {
      window.scrollTo({ top: 0, behavior: "smooth" });
    });
  }, [searchParams, setSearchParams]);

  useEffect(() => {
    if (!newImageFile) {
      setNewImagePreview("");
      return undefined;
    }

    const url = URL.createObjectURL(newImageFile);
    setNewImagePreview(url);

    return () => URL.revokeObjectURL(url);
  }, [newImageFile]);

  const addFormIsPack = isPackUnit(newP.unit);
  const addDescriptionCount = safeStr(newP.description).trim().length;
  const addImageStatus = imageReadinessLabel(newImageFile, newP.image_url);
  const addSellingBasis = addFormIsPack
    ? `Price is captured per pack. One pack contains ${packDescription(newP.pack_size, newP.pack_unit)}.`
    : `Price is captured per ${unitLabelForPreview(newP.unit)}.`;
  const addStockMeaning = quantityHelpForUnit(newP.unit);

  const [editOpen, setEditOpen] = useState(false);
  const [editProduct, setEditProduct] = useState(null);
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [deleteProduct, setDeleteProduct] = useState(null);

  const [stockEdit, setStockEdit] = useState({});
  const [savingStock, setSavingStock] = useState(null);
  const [stockError, setStockError] = useState("");
  const [stockSuccess, setStockSuccess] = useState("");

  const [catMigrationMsg, setCatMigrationMsg] = useState("");
  const [imageBustById, setImageBustById] = useState({});

  // --------------------------------------------------------------------------
  // Data sources
  // --------------------------------------------------------------------------
  const productsRes = useApi(
    uniqEndpoints(["/api/products/mine", "/products/mine", "/api/products", "/products"]),
    {
      enabled: Boolean(farmerId),
      params: {
        farmer_id: farmerId,
        farmerId,
        owner_id: farmerId,
        user_id: farmerId,
      },
      initialData: undefined,
      deps: [farmerId],
    }
  );

  const ratingsRes = useApi(
    uniqEndpoints([
      farmerId ? `/api/ratings/farmer/${farmerId}` : null,
      farmerId ? `/ratings/farmer/${farmerId}` : null,
      "/api/ratings",
      "/ratings",
    ]),
    {
      enabled: Boolean(farmerId),
      params: {
        days: snapshotDays,
        farmer_id: farmerId,
        farmerId,
        user_id: farmerId,
      },
      initialData: undefined,
      deps: [farmerId, snapshotDays],
    }
  );

  const ordersRes = useApi(
    uniqEndpoints([
      farmerId ? `/api/orders/farmer/${farmerId}` : null,
      farmerId ? `/orders/farmer/${farmerId}` : null,
      "/api/orders",
      "/orders",
    ]),
    {
      enabled: Boolean(farmerId),
      params: {
        days: snapshotDays,
        include_items: 1,
        includeItems: 1,
        farmer_id: farmerId,
        farmerId,
        seller_id: farmerId,
        user_id: farmerId,
      },
      initialData: undefined,
      deps: [farmerId, snapshotDays],
    }
  );

  const trendsRes = useApi(
    uniqEndpoints([
      "/api/ai/market-trends",
      "/ai/market-trends",
      "/api/ai/trends",
      "/ai/trends",
    ]),
    {
      enabled: tab === "trends" && canShowTrendTab && Boolean(farmerId),
      params: {
        farmer_id: farmerId,
        farmerId,
        days: snapshotDays,
      },
      initialData: undefined,
      deps: [tab, farmerId, snapshotDays],
    }
  );

  const alertsRes = useApi(
    uniqEndpoints([
      "/api/ai/stock-alerts",
      "/ai/stock-alerts",
    ]),
    {
      enabled: tab === "alerts" && canShowAlertTab && Boolean(farmerId),
      params: {
        farmer_id: farmerId,
        farmerId,
        days: snapshotDays,
      },
      initialData: undefined,
      deps: [tab, farmerId, snapshotDays],
    }
  );

  const rankingRes = useApi(
    uniqEndpoints([
      "/api/ai/farmer-ranking",
      "/ai/farmer-ranking",
      "/api/farmers/leaderboard",
      "/farmers/leaderboard",
      "/api/farmers/rankings",
      "/farmers/rankings",
    ]),
    {
      enabled: tab === "top" && canShowRankingWidgets && Boolean(farmerId),
      params: {
        days: snapshotDays,
        farmer_id: farmerId,
        farmerId,
      },
      initialData: undefined,
      deps: [tab, farmerId, snapshotDays],
    }
  );

  const topFarmersRes = useApi(
    uniqEndpoints([
      "/api/ai/weekly-top-farmers",
      "/ai/weekly-top-farmers",
      "/api/farmers/leaderboard",
      "/farmers/leaderboard",
      "/api/farmers/rankings",
      "/farmers/rankings",
    ]),
    {
      enabled: tab === "top" && canShowRankingWidgets && Boolean(farmerId),
      params: {
        days: snapshotDays,
        limit: 3,
      },
      initialData: undefined,
      deps: [tab, farmerId, snapshotDays],
    }
  );

  const globalOrdersRankingRes = useApi(
    uniqEndpoints([
      "/api/orders",
      "/orders",
      "/api/orders/all",
      "/orders/all",
      "/api/admin/orders",
      "/admin/orders",
    ]),
    {
      enabled: tab === "top" && canShowRankingWidgets && Boolean(farmerId),
      params: {
        days: snapshotDays,
        include_items: 1,
        includeItems: 1,
        all: 1,
        scope: "all",
        market: 1,
        page_size: 2000,
        per_page: 2000,
        limit: 2000,
      },
      initialData: undefined,
      deps: [tab, farmerId, snapshotDays],
    }
  );

  const productsPainted = useFirstLoadGate(productsRes.loading, productsRes.data, productsRes.error);
  const ordersPainted = useFirstLoadGate(ordersRes.loading, ordersRes.data, ordersRes.error);
  const trendsPainted = useFirstLoadGate(trendsRes.loading, trendsRes.data, trendsRes.error);
  const alertsPainted = useFirstLoadGate(alertsRes.loading, alertsRes.data, alertsRes.error);
  const rankingPainted = useFirstLoadGate(rankingRes.loading, rankingRes.data, rankingRes.error);
  const topFarmersPainted = useFirstLoadGate(topFarmersRes.loading, topFarmersRes.data, topFarmersRes.error);
  const fallbackRankingPainted = useFirstLoadGate(
    globalOrdersRankingRes.loading,
    globalOrdersRankingRes.data,
    globalOrdersRankingRes.error
  );

  // --------------------------------------------------------------------------
  // Stale-while-revalidate for products
  // --------------------------------------------------------------------------
  const [lastProductsData, setLastProductsData] = useState(undefined);

  useEffect(() => {
    if (!productsRes.loading && !productsRes.error && productsRes.data !== undefined) {
      setLastProductsData(productsRes.data);
    }
  }, [productsRes.loading, productsRes.error, productsRes.data]);

  const productsData = productsRes.data !== undefined ? productsRes.data : lastProductsData;

  // --------------------------------------------------------------------------
  // Normalize payloads
  // --------------------------------------------------------------------------
  const allProducts = useMemo(
    () => pickArrayFromPayload(productsData, ["items", "products", "results", "data"]),
    [productsData]
  );

  const allRatings = useMemo(
    () => pickArrayFromPayload(ratingsRes.data, ["items", "ratings", "results", "data"]),
    [ratingsRes.data]
  );

  const allOrders = useMemo(
    () => pickArrayFromPayload(ordersRes.data, ["items", "orders", "results", "data"]),
    [ordersRes.data]
  );

  const trendRows = useMemo(
    () => pickArrayFromPayload(trendsRes.data, ["series", "rows", "trends", "items", "data"]),
    [trendsRes.data]
  );

  const stockAlertRows = useMemo(
    () => pickArrayFromPayload(alertsRes.data, ["alerts", "items", "results", "data"]),
    [alertsRes.data]
  );

  const apiLeaderboardRows = useMemo(
    () => normalizeFarmerLeaderboardRows(rankingRes.data),
    [rankingRes.data]
  );

  const apiTopFarmersRows = useMemo(
    () => normalizeFarmerLeaderboardRows(topFarmersRes.data),
    [topFarmersRes.data]
  );

  const globalOrdersForRanking = useMemo(
    () => pickArrayFromPayload(globalOrdersRankingRes.data, ["items", "orders", "results", "data"]),
    [globalOrdersRankingRes.data]
  );

  const derivedLeaderboardRows = useMemo(
    () => buildFarmerLeaderboardFromOrders(globalOrdersForRanking),
    [globalOrdersForRanking]
  );

  const canUseDerivedLeaderboard = derivedLeaderboardRows.length >= MIN_ROWS_FOR_MARKET_RANKING_FALLBACK;

  const leaderboardRows = useMemo(() => {
    if (apiLeaderboardRows.length) return apiLeaderboardRows;
    if (canUseDerivedLeaderboard) return derivedLeaderboardRows;
    return [];
  }, [apiLeaderboardRows, canUseDerivedLeaderboard, derivedLeaderboardRows]);

  const topFarmersRows = useMemo(() => {
    if (apiTopFarmersRows.length) return apiTopFarmersRows.slice(0, 3);
    if (canUseDerivedLeaderboard) return derivedLeaderboardRows.slice(0, 3);
    return [];
  }, [apiTopFarmersRows, canUseDerivedLeaderboard, derivedLeaderboardRows]);

  const apiTrendSeries = useMemo(
    () => normalizeTrendRowsForChart(trendRows, snapshotDays),
    [trendRows, snapshotDays]
  );

  const derivedTrendSeries = useMemo(
    () => buildDemandIndexFromOrders(allOrders, snapshotDays),
    [allOrders, snapshotDays]
  );

  const effectiveTrendSeries = useMemo(
    () => (apiTrendSeries.length ? apiTrendSeries : derivedTrendSeries),
    [apiTrendSeries, derivedTrendSeries]
  );

  const usingOrderBasedTrendFallback = !apiTrendSeries.length && derivedTrendSeries.length > 0;
  const demandSummary = useMemo(() => buildDemandSummary(effectiveTrendSeries), [effectiveTrendSeries]);

  const myProducts = useMemo(() => {
    if (!farmerId) return [];
    const rows = safeArray(allProducts);

    const withOwner = rows.filter((p) => {
      const owner = getOwnerId(p);
      return owner != null && String(owner).trim() !== "";
    });

    if (withOwner.length === 0) return rows;
    return rows.filter((p) => String(getOwnerId(p)) === String(farmerId));
  }, [allProducts, farmerId]);

  const stockAlerts = useMemo(
    () => normalizeStockAlertsForView(stockAlertRows, myProducts, snapshotDays),
    [stockAlertRows, myProducts, snapshotDays]
  );

  const stockAlertSummary = useMemo(
    () => buildStockAlertSummary(stockAlerts),
    [stockAlerts]
  );

  // --------------------------------------------------------------------------
  // Auto-migrate old categories once
  // --------------------------------------------------------------------------
  const migratingRef = useRef(false);

  useEffect(() => {
    if (!farmerId || !productsPainted || migratingRef.current) return;

    const key = `agroconnect_cat_migrated_v1:${String(farmerId)}`;
    const already = localStorage.getItem(key);
    if (already === "1") return;

    const candidates = myProducts
      .map((p) => {
        const current = safeStr(getCategory(p)).trim();
        const next = normalizeCategory(current, getName(p));
        return { p, current, next };
      })
      .filter(({ current, next }) => current && next && current !== next && !isTopCategory(current));

    if (!candidates.length) {
      localStorage.setItem(key, "1");
      return;
    }

    migratingRef.current = true;

    (async () => {
      let changed = 0;

      for (const item of candidates.slice(0, 50)) {
        const pid = getProductId(item.p);
        if (!pid) continue;

        try {
          try {
            await api.patch(apiPath(`/api/products/${pid}`), { category: item.next });
          } catch {
            await api.put(apiPath(`/api/products/${pid}`), { category: item.next });
          }
          changed += 1;
        } catch {
          // best effort only
        }
      }

      if (changed > 0) {
        setCatMigrationMsg(
          `Updated ${changed} product categor${changed === 1 ? "y" : "ies"} to Namibia top-level categories.`
        );
        setTimeout(() => setCatMigrationMsg(""), 2500);
        await productsRes.refetch?.();
      }

      localStorage.setItem(key, "1");
      migratingRef.current = false;
    })();
  }, [farmerId, productsPainted, myProducts, productsRes]);

  // --------------------------------------------------------------------------
  // Rating summary per product
  // --------------------------------------------------------------------------
  const ratingMap = useMemo(() => {
    const map = new Map();

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

  // --------------------------------------------------------------------------
  // Manage filters
  // --------------------------------------------------------------------------
  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    const wantCat = category === "all" ? "" : category;

    return myProducts.filter((p) => {
      const matchesQuery = !q ? true : getName(p).toLowerCase().includes(q);
      const matchesStatus = status === "all" ? true : getStatus(p) === status;
      const normalizedCat = normalizeCategory(getCategory(p), getName(p));
      const matchesCategory = !wantCat ? true : normalizedCat === wantCat;
      const matchesLow = !lowOnly ? true : isLowStock(p, LOW_STOCK_THRESHOLD);
      return matchesQuery && matchesStatus && matchesCategory && matchesLow;
    });
  }, [myProducts, query, status, category, lowOnly]);

  // --------------------------------------------------------------------------
  // Top products ranked by quantity sold, revenue as tie-breaker
  // --------------------------------------------------------------------------
  const topProducts = useMemo(() => {
    const myIds = new Set(
      myProducts.map((p) => String(getProductId(p) ?? "")).filter(Boolean)
    );

    const agg = new Map();

    for (const order of allOrders) {
      const items = getOrderItems(order);
      if (!items.length) continue;

      const seenInOrder = new Set();

      for (const item of items) {
        const pid = String(item?.product_id ?? item?.productId ?? item?.product?.id ?? "");
        if (!pid || !myIds.has(pid)) continue;

        const qty = Math.max(
          0,
          toNumber(item?.quantity ?? item?.qty ?? item?.ordered_quantity ?? 0, 0)
        );

        const revenue = Math.max(
          0,
          toNumber(
            item?.line_total ??
              item?.lineTotal ??
              item?.total ??
              item?.amount ??
              toNumber(item?.unit_price ?? item?.unitPrice ?? item?.price ?? 0, 0) * qty,
            0
          )
        );

        const prev = agg.get(pid) || { qty: 0, revenue: 0, ordersCount: 0 };
        prev.qty += qty;
        prev.revenue += revenue;

        if (!seenInOrder.has(pid)) {
          prev.ordersCount += 1;
          seenInOrder.add(pid);
        }

        agg.set(pid, prev);
      }
    }

    return [...agg.entries()]
      .map(([pid, v]) => {
        const p = myProducts.find((x) => String(getProductId(x) ?? "") === pid);
        return {
          pid,
          name: getName(p),
          category: normalizeCategory(getCategory(p), getName(p)),
          stock: toNumber(p?.stock ?? p?.quantity ?? 0, 0),
          qty: v.qty,
          revenue: v.revenue,
          ordersCount: v.ordersCount,
          farmerName: getProductFarmerName(p),
          farmerLocation: getProductFarmerLocation(p),
        };
      })
      .sort((a, b) => {
        if (b.qty !== a.qty) return b.qty - a.qty;
        if (b.revenue !== a.revenue) return b.revenue - a.revenue;
        if (b.ordersCount !== a.ordersCount) return b.ordersCount - a.ordersCount;
        return a.name.localeCompare(b.name);
      })
      .slice(0, 10);
  }, [allOrders, myProducts]);

  // --------------------------------------------------------------------------
  // My ranking summary
  // --------------------------------------------------------------------------
  const myRankSummary = useMemo(() => {
    if (!farmerId || !leaderboardRows.length) return null;

    const meId = String(farmerId);
    let mine = leaderboardRows.find((r) => hasValue(r?.id) && String(r.id) === meId);

    if (!mine && user?.email) {
      const em = safeStr(user.email).toLowerCase();
      mine = leaderboardRows.find((r) => safeStr(r?.email).toLowerCase() === em);
    }

    if (!mine && user?.name) {
      const nm = safeStr(user.name).trim().toLowerCase();
      mine = leaderboardRows.find((r) => safeStr(r?.name).trim().toLowerCase() === nm);
    }

    if (!mine) return null;

    const totalFromRows = Math.max(
      leaderboardRows.length,
      ...leaderboardRows.map((r) => toNumber(r?.totalFarmers, 0))
    );

    return {
      ...mine,
      totalFarmers: totalFromRows || leaderboardRows.length,
    };
  }, [farmerId, leaderboardRows, user?.email, user?.name]);

  // --------------------------------------------------------------------------
  // Actions
  // --------------------------------------------------------------------------
  const openEdit = useCallback((p) => {
    setEditProduct(p);
    setEditOpen(true);
  }, []);

  const openDelete = useCallback((p) => {
    setDeleteProduct(p);
    setDeleteOpen(true);
  }, []);

  const onUpdated = useCallback(
    async (updatedProduct = null) => {
      const updatedId = getProductId(updatedProduct) || getProductId(editProduct);
      if (updatedId != null) {
        setImageBustById((s) => ({ ...s, [String(updatedId)]: Date.now() }));
      }

      setEditOpen(false);
      setEditProduct(null);
      await productsRes.refetch?.();
    },
    [editProduct, productsRes]
  );

  const onDeleted = useCallback(async () => {
    const deletedId = getProductId(deleteProduct);
    setDeleteOpen(false);
    setDeleteProduct(null);

    if (deletedId != null) {
      setImageBustById((s) => {
        const next = { ...s };
        delete next[String(deletedId)];
        return next;
      });
    }

    await productsRes.refetch?.();
  }, [deleteProduct, productsRes]);

  const resetAddForm = useCallback(() => {
    setNewP({
      product_name: "",
      category: "Fresh Produce",
      price: "",
      quantity: "",
      unit: "each",
      pack_size: "",
      pack_unit: "g",
      description: "",
      image_url: "",
    });
    setNewImageFile(null);
    setAddError("");
    setAddSuccess("");
  }, []);

  const addProduct = useCallback(
    async (e) => {
      e?.preventDefault?.();
      setAddError("");
      setAddSuccess("");

      const name = safeStr(newP.product_name).trim();
      if (!name) {
        setAddError("Product name is required.");
        return;
      }

      const price = toNumber(newP.price, NaN);
      if (!Number.isFinite(price) || price <= 0) {
        setAddError("Price must be a valid number greater than 0.");
        return;
      }

      const qty = toNumber(newP.quantity, NaN);
      if (!Number.isFinite(qty) || qty < 0) {
        setAddError("Quantity must be a valid non-negative number.");
        return;
      }

      const chosenUnit = safeStr(newP.unit).trim().toLowerCase() || "each";
      const validUnits = new Set(UNIT_OPTIONS.map((u) => u.value));
      if (!validUnits.has(chosenUnit)) {
        setAddError("Unit is invalid.");
        return;
      }

      // Pack-specific validation:
      // unit='pack' means:
      //   - price = price per pack
      //   - quantity = number of packs in stock
      //   - pack_size + pack_unit describe what one pack contains
      let packSizeValue = null;
      let packUnitValue = "";

      if (chosenUnit === "pack") {
        const ps = toNumber(newP.pack_size, NaN);
        if (!Number.isFinite(ps) || ps <= 0) {
          setAddError("Pack size must be a valid number greater than 0 when unit is 'pack'.");
          return;
        }

        const validPackUnits = new Set(PACK_UNIT_OPTIONS.map((u) => u.value));
        packUnitValue = safeStr(newP.pack_unit).trim().toLowerCase() || "g";

        if (!validPackUnits.has(packUnitValue)) {
          setAddError("Pack unit must be one of: each, kg, g, l, ml.");
          return;
        }

        packSizeValue = ps;
      }

      if (newImageFile) {
        const sizeMb = newImageFile.size / (1024 * 1024);
        if (sizeMb > MAX_IMAGE_MB) {
          setAddError(`Image is too large. Max ${MAX_IMAGE_MB}MB.`);
          return;
        }
        if (!String(newImageFile.type || "").startsWith("image/")) {
          setAddError("Please select a valid image file.");
          return;
        }
      }

      setAdding(true);

      try {
        const chosenCategory = normalizeCategory(newP.category, name);

        const basePayload = {
          product_name: name,
          category: chosenCategory,
          price: String(price),
          quantity: String(qty),
          unit: chosenUnit,
          description: safeStr(newP.description).trim() || "",
          farmer_id: farmerId ?? undefined,
          farmerId: farmerId ?? undefined,
        };

        // Only send pack metadata when the product is sold per pack.
        if (chosenUnit === "pack") {
          basePayload.pack_size = String(packSizeValue);
          basePayload.pack_unit = packUnitValue;
        }

        const explicitImageUrl = safeStr(newP.image_url).trim();
        if (explicitImageUrl) {
          basePayload.image_url = explicitImageUrl;
          basePayload.imageUrl = explicitImageUrl;
          basePayload.image_filename = explicitImageUrl;
        }

        let createRes = null;
        let imageSaved = false;

        if (newImageFile) {
          const fd = new FormData();
          Object.entries(basePayload).forEach(([k, v]) => {
            if (v != null) fd.append(k, String(v));
          });
          fd.append("image", newImageFile);
          fd.append("file", newImageFile);
          fd.append("photo", newImageFile);

          try {
            createRes = await api.post(apiPath("/api/products"), fd);
            imageSaved = true;
          } catch {
            createRes = await api.post(apiPath("/api/products"), basePayload);
          }
        } else {
          createRes = await api.post(apiPath("/api/products"), basePayload);
        }

        const createdRoot = unwrapApiDataEnvelope(createRes?.data);
        const created = createdRoot?.item ?? createdRoot?.product ?? createdRoot;
        const createdId = created?.id ?? created?.product_id ?? created?.productId ?? null;

        if (newImageFile && createdId && !imageSaved) {
          const uploadedUrl = await tryUploadImageBestEffort({
            file: newImageFile,
            productId: createdId,
          });

          if (uploadedUrl) {
            try {
              try {
                await api.patch(apiPath(`/api/products/${createdId}`), {
                  image_url: uploadedUrl,
                  imageUrl: uploadedUrl,
                });
              } catch {
                await api.put(apiPath(`/api/products/${createdId}`), {
                  image_url: uploadedUrl,
                  imageUrl: uploadedUrl,
                });
              }
              imageSaved = true;
            } catch {
              imageSaved = false;
            }
          }
        }

        await productsRes.refetch?.();

        if (createdId != null) {
          setImageBustById((s) => ({ ...s, [String(createdId)]: Date.now() }));
        }

        setAddSuccess(
          newImageFile
            ? imageSaved
              ? "Submitted (image saved)."
              : "Submitted (image not saved)."
            : "Submitted for approval."
        );

        setTimeout(() => setAddSuccess(""), 1700);
        resetAddForm();
        setShowAddForm(false);
      } catch (err) {
        console.error("Add product failed", err);
        setAddError(err?.response?.data?.message || "Couldn’t submit product right now. Please try again.");
      } finally {
        setAdding(false);
      }
    },
    [farmerId, newP, newImageFile, productsRes, resetAddForm]
  );

  const saveStock = useCallback(
    async (p) => {
      const pid = getProductId(p);
      if (!pid) return;

      setStockError("");
      setStockSuccess("");
      setSavingStock(pid);

      try {
        const current = toNumber(p?.quantity ?? p?.stock ?? 0, 0);
        const raw = stockEdit[String(pid)];
        const next = toNumber(raw, current);

        if (!Number.isFinite(next) || next < 0) {
          setStockError("Stock must be a valid non-negative number.");
          return;
        }

        const payload = {
          quantity: String(next),
          stock: String(next),
          qty: String(next),
        };

        try {
          await api.patch(apiPath(`/api/products/${pid}`), payload);
        } catch {
          await api.put(apiPath(`/api/products/${pid}`), payload);
        }

        await productsRes.refetch?.();
        setStockEdit((s) => ({ ...s, [String(pid)]: String(next) }));
        setStockSuccess("Stock updated.");
        setTimeout(() => setStockSuccess(""), 1500);
      } catch (e) {
        console.error("Stock update failed", e);
        setStockError("Couldn’t update stock right now. Please try again.");
      } finally {
        setSavingStock(null);
      }
    },
    [productsRes, stockEdit]
  );

  const handleRefresh = useCallback(() => {
    productsRes.refetch?.();
    ratingsRes.refetch?.();

    if (tab === "top") {
      ordersRes.refetch?.();

      if (canShowRankingWidgets) {
        rankingRes.refetch?.();
        topFarmersRes.refetch?.();
        globalOrdersRankingRes.refetch?.();
      }
    }

    if (tab === "trends" && canShowTrendTab) {
      trendsRes.refetch?.();
      ordersRes.refetch?.();
    }

    if (tab === "alerts" && canShowAlertTab) {
      alertsRes.refetch?.();
    }
  }, [
    alertsRes,
    canShowAlertTab,
    canShowRankingWidgets,
    canShowTrendTab,
    globalOrdersRankingRes,
    ordersRes,
    productsRes,
    ratingsRes,
    rankingRes,
    topFarmersRes,
    trendsRes,
    tab,
  ]);

  const snapshotLabel =
    FARMER_TIME_WINDOWS.find((w) => w.value === snapshotDays)?.label || `Last ${snapshotDays} days`;

  useEffect(() => {
    if (settingsLoading) return;

    const visibleKeys = new Set(visibleTabs.map((item) => item.key));
    if (!visibleKeys.has(tab)) {
      setTab("manage");
    }
  }, [settingsLoading, tab, visibleTabs]);

  // --------------------------------------------------------------------------
  // Render
  // --------------------------------------------------------------------------
  return (
    <FarmerLayout>
      <div className="space-y-6">
        <Card>
          <CardHeader className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <CardTitle>Products</CardTitle>
              <p className="mt-1 text-sm text-slate-600">
                {productsPageIntro}
              </p>
            </div>

            <div className="flex items-center gap-2">
              <div className="inline-flex h-9 items-center gap-2 rounded-xl border border-slate-200 bg-white px-3">
                <CalendarDays className="h-4 w-4 text-slate-500" />
                <select
                  value={snapshotDays}
                  onChange={(e) => setSnapshotDays(Number(e.target.value))}
                  className="bg-transparent text-sm font-semibold text-slate-800 outline-none"
                >
                  {FARMER_TIME_WINDOWS.map((w) => (
                    <option key={w.value} value={w.value}>
                      {w.label}
                    </option>
                  ))}
                </select>
              </div>

              <button
                type="button"
                onClick={handleRefresh}
                className="inline-flex h-9 items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-800 hover:bg-slate-50"
              >
                <RefreshCcw className="h-4 w-4" />
                Refresh
              </button>
            </div>
          </CardHeader>

          <CardContent>
            <div className="flex flex-wrap gap-2">
              {visibleTabs.map((t) => (
                <button
                  key={t.key}
                  type="button"
                  onClick={() => setTab(t.key)}
                  className={[
                    "h-9 rounded-xl border px-3 text-sm font-semibold",
                    tab === t.key
                      ? "border-green-200 bg-green-50 text-green-700"
                      : "border-slate-200 bg-white text-slate-800 hover:bg-slate-50",
                  ].join(" ")}
                >
                  {t.label}
                </button>
              ))}
            </div>
          </CardContent>
        </Card>

        {catMigrationMsg ? (
          <div className="rounded-xl border border-green-200 bg-green-50 p-3 text-sm text-green-700">
            {catMigrationMsg}
          </div>
        ) : null}

        {!settingsLoading && (!aiInsightsEnabled || !canShowRankingWidgets) ? (
          <div className="rounded-xl border border-slate-200 bg-slate-50 p-3 text-sm text-slate-700">
            {!aiInsightsEnabled && !canShowRankingWidgets
              ? "AI insights and ranking widgets are turned off in system settings. Product management and order-based performance remain available."
              : !aiInsightsEnabled
                ? "AI insights are turned off in system settings. Product management and order-based performance remain available."
                : "Farmer ranking widgets are turned off in system settings. Product performance based on orders remains available."}
          </div>
        ) : null}

        {/* ------------------------------------------------------------------ */}
        {/* Manage Products */}
        {/* ------------------------------------------------------------------ */}
        {tab === "manage" && (
          <Card>
            <CardHeader>
              <div className="flex items-center gap-2">
                <Package size={18} className="text-green-700" />
                <div>
                  <CardTitle>Manage Products</CardTitle>
                  <p className="mt-1 text-xs text-slate-500">
                    Showing {filtered.length} of {myProducts.length} • Snapshot: {snapshotLabel}
                  </p>
                </div>
              </div>
            </CardHeader>

            <CardContent>
              <div className="mb-4 flex flex-col gap-3 xl:flex-row xl:items-center xl:justify-between">
                <div className="max-w-3xl">
                  <div className="text-sm font-semibold text-slate-800">
                    Maintain a clear, audit-ready product catalogue.
                  </div>
                  <div className="mt-1 text-sm text-slate-600">
                    New listings are submitted for admin review, so enter market-ready product details,
                    accurate stock values, and a professional description.
                  </div>
                </div>

                <button
                  type="button"
                  onClick={() => {
                    setAddError("");
                    setAddSuccess("");
                    setShowAddForm((v) => !v);
                  }}
                  className="inline-flex h-11 items-center gap-2 self-start rounded-2xl bg-green-600 px-4 font-extrabold text-white shadow-sm transition hover:bg-green-700 hover:shadow xl:self-auto"
                >
                  <Plus size={16} />
                  {showAddForm ? "Close form" : "Add Product"}
                </button>
              </div>

              {showAddForm ? (
                <div className="mb-5 overflow-hidden rounded-[28px] border border-slate-200 bg-white shadow-sm">
                  <div className="border-b border-slate-200 bg-gradient-to-r from-emerald-50 via-white to-slate-50 px-5 py-5">
                    <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                      <div className="max-w-3xl">
                        <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-[0.18em] text-emerald-700">
                          <ShieldCheck className="h-4 w-4" />
                          Listing submission workspace
                        </div>
                        <div className="mt-2 text-xl font-extrabold text-slate-900">
                          Add a professional product record
                        </div>
                        <div className="mt-2 text-sm leading-6 text-slate-600">
                          Complete the commercial, stock, and media details below. The product will be
                          submitted for admin approval before it becomes visible to customers.
                        </div>
                      </div>

                      <div className="flex flex-wrap gap-2">
                        <div className="inline-flex items-center gap-2 rounded-full border border-emerald-200 bg-emerald-50 px-3 py-1 text-xs font-bold text-emerald-700">
                          <CheckCircle2 className="h-3.5 w-3.5" />
                          Structured data entry
                        </div>
                        <div className="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white px-3 py-1 text-xs font-bold text-slate-700">
                          <ShieldCheck className="h-3.5 w-3.5" />
                          Admin-reviewed publishing
                        </div>
                        <div className="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white px-3 py-1 text-xs font-bold text-slate-700">
                          <FileText className="h-3.5 w-3.5" />
                          Catalogue quality focus
                        </div>
                      </div>
                    </div>
                  </div>

                  <div className="p-5">
                    <div className="mb-4 flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
                      <div className="grid gap-2 text-sm text-slate-600">
                        <div className="flex items-start gap-2">
                          <CheckCircle2 className="mt-0.5 h-4 w-4 text-emerald-600" />
                          Use a specific, customer-facing product name and accurate category.
                        </div>
                        <div className="flex items-start gap-2">
                          <CheckCircle2 className="mt-0.5 h-4 w-4 text-emerald-600" />
                          Capture price and stock in the same commercial unit used for selling.
                        </div>
                        <div className="flex items-start gap-2">
                          <CheckCircle2 className="mt-0.5 h-4 w-4 text-emerald-600" />
                          Provide clear packaging and image information when available.
                        </div>
                      </div>

                      <button
                        type="button"
                        onClick={() => setShowAddForm(false)}
                        className="inline-flex h-10 items-center justify-center rounded-2xl border border-slate-200 bg-white px-4 text-sm font-semibold text-slate-800 hover:bg-slate-50"
                      >
                        Cancel
                      </button>
                    </div>

                    {addError ? (
                      <div className="mb-4 rounded-2xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
                        {addError}
                      </div>
                    ) : null}

                    {addSuccess ? (
                      <div className="mb-4 rounded-2xl border border-green-200 bg-green-50 px-4 py-3 text-sm text-green-700">
                        {addSuccess}
                      </div>
                    ) : null}

                    <form onSubmit={addProduct} className="grid grid-cols-1 gap-4 xl:grid-cols-12">
                      <div className="space-y-4 xl:col-span-8">
                        <div className="rounded-3xl border border-slate-200 bg-slate-50/60 p-4">
                          <div className="mb-4 flex items-center gap-2 text-sm font-extrabold text-slate-900">
                            <Package className="h-4 w-4 text-emerald-700" />
                            Product identity and classification
                          </div>

                          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
                            <div className="md:col-span-2">
                              <label className="mb-1.5 block text-xs font-bold uppercase tracking-wide text-slate-600">
                                Product name <span className="text-red-500">*</span>
                              </label>
                              <input
                                className="h-11 w-full rounded-2xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-900 outline-none transition focus:border-emerald-300 focus:ring-2 focus:ring-emerald-100"
                                placeholder="e.g. Fresh cream cheese"
                                value={newP.product_name}
                                onChange={(e) => setNewP((s) => ({ ...s, product_name: e.target.value }))}
                              />
                              <div className="mt-1.5 text-xs text-slate-500">
                                Use a concise market-facing name that customers can recognize immediately.
                              </div>
                            </div>

                            <div>
                              <label className="mb-1.5 block text-xs font-bold uppercase tracking-wide text-slate-600">
                                Category <span className="text-red-500">*</span>
                              </label>
                              <select
                                className="h-11 w-full rounded-2xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-900 outline-none transition focus:border-emerald-300 focus:ring-2 focus:ring-emerald-100"
                                value={newP.category}
                                onChange={(e) => setNewP((s) => ({ ...s, category: e.target.value }))}
                              >
                                {NAMIBIA_TOP_CATEGORIES.map((c) => (
                                  <option key={c} value={c}>
                                    {c}
                                  </option>
                                ))}
                              </select>
                            </div>

                            <div>
                              <label className="mb-1.5 block text-xs font-bold uppercase tracking-wide text-slate-600">
                                Selling unit <span className="text-red-500">*</span>
                              </label>
                              <select
                                className="h-11 w-full rounded-2xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-900 outline-none transition focus:border-emerald-300 focus:ring-2 focus:ring-emerald-100"
                                value={newP.unit}
                                onChange={(e) => {
                                  const nextUnit = e.target.value;
                                  setNewP((s) => ({
                                    ...s,
                                    unit: nextUnit,
                                    ...(nextUnit === "pack"
                                      ? {}
                                      : {
                                          pack_size: "",
                                          pack_unit: "g",
                                        }),
                                  }));
                                }}
                              >
                                {UNIT_OPTIONS.map((u) => (
                                  <option key={u.value} value={u.value}>
                                    {u.label}
                                  </option>
                                ))}
                              </select>
                            </div>
                          </div>
                        </div>

                        <div className="rounded-3xl border border-slate-200 bg-slate-50/60 p-4">
                          <div className="mb-4 flex items-center gap-2 text-sm font-extrabold text-slate-900">
                            <CircleDollarSign className="h-4 w-4 text-emerald-700" />
                            Commercial setup and stock position
                          </div>

                          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
                            <div>
                              <label className="mb-1.5 block text-xs font-bold uppercase tracking-wide text-slate-600">
                                Price (N$) <span className="text-red-500">*</span>
                              </label>
                              <input
                                className="h-11 w-full rounded-2xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-900 outline-none transition focus:border-emerald-300 focus:ring-2 focus:ring-emerald-100"
                                placeholder="e.g. 35.00"
                                inputMode="decimal"
                                value={newP.price}
                                onChange={(e) => setNewP((s) => ({ ...s, price: e.target.value }))}
                              />
                              <div className="mt-1.5 text-xs text-slate-500">{addSellingBasis}</div>
                            </div>

                            <div>
                              <label className="mb-1.5 block text-xs font-bold uppercase tracking-wide text-slate-600">
                                {quantityLabelForUnit(newP.unit)} <span className="text-red-500">*</span>
                              </label>
                              <input
                                className="h-11 w-full rounded-2xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-900 outline-none transition focus:border-emerald-300 focus:ring-2 focus:ring-emerald-100"
                                placeholder={quantityPlaceholderForUnit(newP.unit)}
                                inputMode="decimal"
                                value={newP.quantity}
                                onChange={(e) => setNewP((s) => ({ ...s, quantity: e.target.value }))}
                              />
                              <div className="mt-1.5 text-xs text-slate-500">{addStockMeaning}</div>
                            </div>
                          </div>

                          {addFormIsPack ? (
                            <div className="mt-4 rounded-2xl border border-sky-200 bg-sky-50 p-4">
                              <div className="mb-3 flex items-center gap-2 text-sm font-extrabold text-sky-900">
                                <Boxes className="h-4 w-4" />
                                Pack configuration
                              </div>

                              <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
                                <div>
                                  <label className="mb-1.5 block text-xs font-bold uppercase tracking-wide text-sky-800">
                                    Pack size <span className="text-red-500">*</span>
                                  </label>
                                  <input
                                    className="h-11 w-full rounded-2xl border border-sky-200 bg-white px-3 text-sm font-semibold text-slate-900 outline-none transition focus:border-sky-300 focus:ring-2 focus:ring-sky-100"
                                    placeholder="e.g. 250"
                                    inputMode="decimal"
                                    value={newP.pack_size}
                                    onChange={(e) => setNewP((s) => ({ ...s, pack_size: e.target.value }))}
                                  />
                                </div>

                                <div>
                                  <label className="mb-1.5 block text-xs font-bold uppercase tracking-wide text-sky-800">
                                    Pack content unit <span className="text-red-500">*</span>
                                  </label>
                                  <select
                                    className="h-11 w-full rounded-2xl border border-sky-200 bg-white px-3 text-sm font-semibold text-slate-900 outline-none transition focus:border-sky-300 focus:ring-2 focus:ring-sky-100"
                                    value={newP.pack_unit}
                                    onChange={(e) => setNewP((s) => ({ ...s, pack_unit: e.target.value }))}
                                  >
                                    {PACK_UNIT_OPTIONS.map((u) => (
                                      <option key={u.value} value={u.value}>
                                        {u.label}
                                      </option>
                                    ))}
                                  </select>
                                </div>
                              </div>

                              <div className="mt-3 text-xs leading-6 text-sky-800">
                                Example: price = N$35, quantity = 34, unit = pack, pack size = 250, pack content unit = g
                                means N$35 per pack, 34 packs in stock, and each pack contains 250 g.
                              </div>
                            </div>
                          ) : null}
                        </div>

                        <div className="rounded-3xl border border-slate-200 bg-slate-50/60 p-4">
                          <div className="mb-4 flex items-center gap-2 text-sm font-extrabold text-slate-900">
                            <ImageIcon className="h-4 w-4 text-emerald-700" />
                            Media and listing narrative
                          </div>

                          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
                            <div className="rounded-2xl border border-slate-200 bg-white p-4">
                              <div className="mb-2 flex items-center gap-2 text-xs font-bold uppercase tracking-wide text-slate-600">
                                <ImageIcon className="h-4 w-4 text-slate-500" />
                                Product image upload
                              </div>

                              <input
                                type="file"
                                accept="image/*"
                                onChange={(e) => setNewImageFile(e.target.files?.[0] || null)}
                                className="block w-full text-sm text-slate-700"
                              />

                              {newImagePreview ? (
                                <div className="mt-3 overflow-hidden rounded-2xl border border-slate-200 bg-slate-50">
                                  <img src={newImagePreview} alt="Preview" className="h-44 w-full object-cover" />
                                </div>
                              ) : (
                                <div className="mt-3 rounded-2xl border border-dashed border-slate-200 bg-slate-50 px-4 py-6 text-center text-xs leading-5 text-slate-500">
                                  Upload a clean product image. If the backend upload route is unavailable, the
                                  listing will still be created without blocking submission.
                                </div>
                              )}
                            </div>

                            <div className="rounded-2xl border border-slate-200 bg-white p-4">
                              <div className="mb-2 flex items-center gap-2 text-xs font-bold uppercase tracking-wide text-slate-600">
                                <Link2 className="h-4 w-4 text-slate-500" />
                                Image URL or local filename
                              </div>

                              <input
                                className="h-11 w-full rounded-2xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-900 outline-none transition focus:border-emerald-300 focus:ring-2 focus:ring-emerald-100"
                                placeholder="https://... or sweet_melon.jpg"
                                value={newP.image_url}
                                onChange={(e) => setNewP((s) => ({ ...s, image_url: e.target.value }))}
                                list={localImageOptions.length ? "agroconnect_local_images" : undefined}
                              />

                              {localImageOptions.length ? (
                                <datalist id="agroconnect_local_images">
                                  {localImageOptions.slice(0, 250).map((f) => (
                                    <option key={f} value={f} />
                                  ))}
                                </datalist>
                              ) : null}

                              <div className="mt-2 text-xs leading-5 text-slate-500">
                                Use this when the image already exists online or in your frontend image folders.
                              </div>

                              <div className="mt-4 flex items-center gap-2 rounded-2xl border border-slate-200 bg-slate-50 px-3 py-3 text-xs font-semibold text-slate-700">
                                <CheckCircle2 className="h-4 w-4 text-emerald-600" />
                                {addImageStatus}
                              </div>
                            </div>
                          </div>

                          <div className="mt-4">
                            <label className="mb-1.5 block text-xs font-bold uppercase tracking-wide text-slate-600">
                              Product description
                            </label>
                            <textarea
                              className="min-h-[120px] w-full rounded-2xl border border-slate-200 bg-white px-3 py-3 text-sm leading-6 text-slate-900 outline-none transition focus:border-emerald-300 focus:ring-2 focus:ring-emerald-100"
                              placeholder="Describe the product quality, packaging, intended use, and any buyer-relevant details."
                              value={newP.description}
                              onChange={(e) => setNewP((s) => ({ ...s, description: e.target.value }))}
                            />
                            <div className="mt-1.5 flex items-center justify-between text-xs text-slate-500">
                              <span>Write a clear, evidence-oriented description suitable for a professional catalogue.</span>
                              <span>{addDescriptionCount} characters</span>
                            </div>
                          </div>
                        </div>
                      </div>

                      <div className="xl:col-span-4">
                        <div className="sticky top-4 space-y-4">
                          <div className="rounded-3xl border border-slate-200 bg-slate-900 p-5 text-white shadow-sm">
                            <div className="flex items-center gap-2 text-sm font-extrabold">
                              <FileText className="h-4 w-4 text-emerald-300" />
                              Submission preview
                            </div>

                            <div className="mt-4 grid gap-3 text-sm">
                              <div className="rounded-2xl border border-white/10 bg-white/5 px-4 py-3">
                                <div className="text-[11px] font-bold uppercase tracking-wide text-slate-300">
                                  Product
                                </div>
                                <div className="mt-1 font-semibold text-white">
                                  {safeStr(newP.product_name).trim() || "Product name not yet entered"}
                                </div>
                              </div>

                              <div className="grid grid-cols-2 gap-3">
                                <div className="rounded-2xl border border-white/10 bg-white/5 px-4 py-3">
                                  <div className="text-[11px] font-bold uppercase tracking-wide text-slate-300">Category</div>
                                  <div className="mt-1 font-semibold text-white">{newP.category || "—"}</div>
                                </div>
                                <div className="rounded-2xl border border-white/10 bg-white/5 px-4 py-3">
                                  <div className="text-[11px] font-bold uppercase tracking-wide text-slate-300">Unit</div>
                                  <div className="mt-1 font-semibold text-white">{safeStr(newP.unit).toUpperCase() || "—"}</div>
                                </div>
                              </div>

                              <div className="grid grid-cols-2 gap-3">
                                <div className="rounded-2xl border border-white/10 bg-white/5 px-4 py-3">
                                  <div className="text-[11px] font-bold uppercase tracking-wide text-slate-300">Price</div>
                                  <div className="mt-1 font-semibold text-white">{hasValue(newP.price) ? `N$ ${newP.price}` : "Not yet entered"}</div>
                                </div>
                                <div className="rounded-2xl border border-white/10 bg-white/5 px-4 py-3">
                                  <div className="text-[11px] font-bold uppercase tracking-wide text-slate-300">Stock</div>
                                  <div className="mt-1 font-semibold text-white">{hasValue(newP.quantity) ? newP.quantity : "Not yet entered"}</div>
                                </div>
                              </div>

                              {addFormIsPack ? (
                                <div className="rounded-2xl border border-emerald-400/20 bg-emerald-400/10 px-4 py-3 text-emerald-50">
                                  <div className="text-[11px] font-bold uppercase tracking-wide text-emerald-200">Pack definition</div>
                                  <div className="mt-1 font-semibold">{packDescription(newP.pack_size, newP.pack_unit)} per pack</div>
                                </div>
                              ) : null}
                            </div>

                            <button
                              type="submit"
                              disabled={adding}
                              className="mt-5 inline-flex h-12 w-full items-center justify-center gap-2 rounded-2xl bg-emerald-500 text-sm font-extrabold text-white transition hover:bg-emerald-400 disabled:cursor-not-allowed disabled:opacity-60"
                            >
                              <Plus size={16} />
                              {adding ? "Submitting…" : "Submit for approval"}
                            </button>

                            <div className="mt-3 text-xs leading-5 text-slate-300">
                              Submission creates a pending listing and preserves an auditable commercial record for admin review.
                            </div>
                          </div>

                          <div className="rounded-3xl border border-slate-200 bg-slate-50 p-5">
                            <div className="flex items-center gap-2 text-sm font-extrabold text-slate-900">
                              <CheckCircle2 className="h-4 w-4 text-emerald-600" />
                              Quality checklist
                            </div>

                            <div className="mt-4 space-y-3 text-sm text-slate-700">
                              <div className="flex items-start gap-3">
                                <CheckCircle2 className="mt-0.5 h-4 w-4 text-emerald-600" />
                                <div>
                                  <div className="font-semibold text-slate-900">Commercial consistency</div>
                                  <div className="text-slate-600">Ensure price, stock quantity, and selling unit describe the same basis.</div>
                                </div>
                              </div>

                              <div className="flex items-start gap-3">
                                <CheckCircle2 className="mt-0.5 h-4 w-4 text-emerald-600" />
                                <div>
                                  <div className="font-semibold text-slate-900">Catalogue readability</div>
                                  <div className="text-slate-600">Use a clean title and a short description that supports buyer confidence.</div>
                                </div>
                              </div>

                              <div className="flex items-start gap-3">
                                <CheckCircle2 className="mt-0.5 h-4 w-4 text-emerald-600" />
                                <div>
                                  <div className="font-semibold text-slate-900">Pack traceability</div>
                                  <div className="text-slate-600">When selling by pack, define the exact contents of one pack.</div>
                                </div>
                              </div>
                            </div>
                          </div>
                        </div>
                      </div>
                    </form>
                  </div>
                </div>
              ) : null}

              <div className="mb-4 flex flex-col gap-3 lg:flex-row lg:items-center">
                <div className="flex-1">
                  <div className="flex items-center gap-2 rounded-2xl border border-slate-200 bg-white px-3 py-2 shadow-sm">
                    <Search size={18} className="text-slate-400" />
                    <input
                      value={query}
                      onChange={(e) => setQuery(e.target.value)}
                      placeholder="Search by product name…"
                      className="w-full text-sm text-slate-700 outline-none"
                    />
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <span className="text-sm text-slate-600">Status:</span>
                  <select
                    value={status}
                    onChange={(e) => setStatus(e.target.value)}
                    className="rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm text-slate-800 shadow-sm outline-none"
                  >
                    <option value="all">All</option>
                    <option value="available">available</option>
                    <option value="unavailable">unavailable</option>
                    <option value="pending">pending</option>
                    <option value="approved">approved</option>
                    <option value="rejected">rejected</option>
                    <option value="active">active</option>
                    <option value="published">published</option>
                  </select>
                </div>

                <div className="flex items-center gap-2">
                  <span className="text-sm text-slate-600">Category:</span>
                  <select
                    value={category}
                    onChange={(e) => setCategory(e.target.value)}
                    className="rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm text-slate-800 shadow-sm outline-none"
                  >
                    <option value="all">All</option>
                    {NAMIBIA_TOP_CATEGORIES.map((c) => (
                      <option key={c} value={c}>
                        {c}
                      </option>
                    ))}
                  </select>
                </div>

                <label className="inline-flex items-center gap-2 text-sm font-semibold text-slate-700">
                  <input
                    type="checkbox"
                    checked={lowOnly}
                    onChange={(e) => setLowOnly(e.target.checked)}
                  />
                  Low stock only (≤ {LOW_STOCK_THRESHOLD})
                </label>
              </div>

              {productsRes.error ? (
                <div className="mb-4 flex items-center justify-between gap-3 rounded-xl border border-red-200 bg-red-50 p-3 text-sm text-red-700">
                  <div>Couldn’t load products.</div>
                  <button
                    type="button"
                    onClick={() => productsRes.refetch?.()}
                    className="h-9 rounded-xl border border-red-200 bg-white px-3 font-semibold text-red-700"
                  >
                    Retry
                  </button>
                </div>
              ) : null}

              {stockError ? (
                <div className="mb-4 rounded-xl border border-orange-200 bg-orange-50 p-3 text-sm text-orange-700">
                  {stockError}
                </div>
              ) : null}

              {stockSuccess ? (
                <div className="mb-4 rounded-xl border border-green-200 bg-green-50 p-3 text-sm text-green-700">
                  {stockSuccess}
                </div>
              ) : null}

              {!productsPainted && productsRes.loading ? (
                <p className="text-sm text-slate-500">Loading…</p>
              ) : filtered.length === 0 ? (
                <EmptyState message="No products found. Use '+ Add Product' to create one." />
              ) : (
                <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
                  {filtered.map((p) => {
                    const pid = getProductId(p);
                    const name = getName(p);
                    const cat = normalizeCategory(getCategory(p), name);
                    const price = toNumber(p?.price ?? 0, 0).toFixed(2);
                    const qty = toNumber(p?.quantity ?? p?.stock ?? 0, 0);
                    const pStatus = getStatus(p);
                    const badge = statusBadgeClasses(pStatus);
                    const rs = ratingMap.get(String(pid)) || { avg: 0, count: 0 };

                    return (
                      <div
                        key={String(pid)}
                        className="overflow-hidden rounded-3xl border border-slate-200 bg-white shadow-sm transition hover:shadow-md"
                      >
                        <div className="h-36 bg-slate-100">
                          <ProductImage product={p} alt={name} cacheBust={imageBustById[String(pid)]} />
                        </div>

                        <div className="space-y-3 p-4">
                          <div className="flex items-start justify-between gap-3">
                            <div className="min-w-0">
                              <div className="truncate font-semibold text-slate-900">{name}</div>

                              <div className="mt-1 flex items-center gap-2 text-xs text-slate-500">
                                <span>N$ {price}</span>
                                <span>•</span>
                                <span>Stock: {qty}</span>
                              </div>

                              <div className="mt-2 inline-flex items-center gap-2 rounded-full border border-slate-200 bg-slate-50 px-2.5 py-1 text-xs font-semibold text-slate-700">
                                <Tag className="h-3.5 w-3.5 text-slate-500" />
                                {cat || "—"}
                              </div>

                              <div className="mt-2 flex items-center gap-2">
                                <Stars value={rs.avg} />
                                <span className="text-xs text-slate-500">
                                  {rs.count ? `${rs.avg.toFixed(1)} (${rs.count})` : "No reviews"}
                                </span>
                              </div>
                            </div>

                            <span className={`rounded-full border px-3 py-1 text-xs font-semibold ${badge}`}>
                              {statusLabel(pStatus)}
                            </span>
                          </div>

                          <div className="rounded-xl border border-slate-200 bg-slate-50/50 p-3">
                            <div className="mb-2 text-xs font-semibold text-slate-700">
                              Quick Stock Update
                            </div>
                            <div className="flex items-center gap-2">
                              <input
                                type="number"
                                step="0.001"
                                value={stockEdit[String(pid)] ?? qty}
                                onChange={(e) =>
                                  setStockEdit((s) => ({ ...s, [String(pid)]: e.target.value }))
                                }
                                className="h-9 w-28 rounded-lg border border-slate-200 bg-white px-2 text-sm"
                              />
                              <button
                                type="button"
                                onClick={() => saveStock(p)}
                                disabled={savingStock === pid}
                                className="h-9 rounded-xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-800 hover:bg-slate-50 disabled:opacity-60"
                              >
                                {savingStock === pid ? "Saving…" : "Save"}
                              </button>

                              {isLowStock(p, LOW_STOCK_THRESHOLD) ? (
                                <span className="ml-auto inline-flex items-center gap-1 rounded-full border border-orange-200 bg-orange-50 px-2 py-1 text-xs font-semibold text-orange-700">
                                  <AlertTriangle className="h-3.5 w-3.5" />
                                  Low stock
                                </span>
                              ) : null}
                            </div>
                          </div>

                          {p?.description ? (
                            <p className="line-clamp-2 text-sm text-slate-600">
                              {String(p.description)}
                            </p>
                          ) : (
                            <p className="text-sm text-slate-400">No description</p>
                          )}

                          <div className="flex items-center justify-end gap-2 pt-1">
                            <button
                              type="button"
                              onClick={() => openEdit(p)}
                              className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm text-slate-800 hover:bg-slate-50"
                            >
                              <Pencil size={16} />
                              Edit
                            </button>

                            <button
                              type="button"
                              onClick={() => openDelete(p)}
                              className="inline-flex items-center gap-2 rounded-xl bg-red-600 px-3 py-2 text-sm text-white hover:bg-red-500"
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

        {/* ------------------------------------------------------------------ */}
        {/* Top Products */}
        {/* ------------------------------------------------------------------ */}
        {tab === "top" && (
          <Card>
            <CardHeader>
              <div className="flex items-center gap-2">
                <BarChart3 size={18} className="text-green-700" />
                <div>
                  <CardTitle>Top Products</CardTitle>
                  <p className="mt-1 text-xs text-slate-500">
                    Ranked by quantity sold • Revenue breaks ties • Snapshot:{" "}
                    <span className="font-semibold">{snapshotLabel}</span>
                  </p>
                </div>
              </div>
            </CardHeader>

            <CardContent>
              <div className="mb-4 flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => {
                    ordersRes.refetch?.();

                    if (canShowRankingWidgets) {
                      rankingRes.refetch?.();
                      topFarmersRes.refetch?.();
                      globalOrdersRankingRes.refetch?.();
                    }
                  }}
                  className="ml-auto inline-flex h-10 items-center gap-2 rounded-2xl border border-slate-200 bg-white px-4 text-sm font-semibold text-slate-800 hover:bg-slate-50"
                >
                  <RefreshCcw className="h-4 w-4" />
                  {canShowRankingWidgets ? "Refresh rankings" : "Refresh product performance"}
                </button>
              </div>

              {canShowRankingWidgets ? (
                <div className="mb-4 grid grid-cols-1 gap-4 xl:grid-cols-3">
                  <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                    <div className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                      Farmer market ranking
                    </div>
                    <div className="mt-1 text-[11px] text-slate-500">
                      Rank based on available market leaderboard data.
                    </div>

                    {!rankingPainted && !fallbackRankingPainted ? (
                      <div className="mt-3 text-sm text-slate-600">Loading your rank…</div>
                    ) : myRankSummary ? (
                      <div className="mt-3">
                        <div className="text-2xl font-extrabold text-green-700">
                          {formatRankOutOf(myRankSummary.rank, myRankSummary.totalFarmers)}
                        </div>
                        <div className="mt-2 text-xs text-slate-600">
                          Revenue:{" "}
                          <span className="font-semibold text-slate-800">
                            N$ {fmtMoneyNAD(myRankSummary.revenue)}
                          </span>{" "}
                          • Orders:{" "}
                          <span className="font-semibold text-slate-800">
                            {fmtQty(myRankSummary.orders)}
                          </span>
                        </div>
                      </div>
                    ) : (
                      <div className="mt-3 text-sm text-slate-600">Ranking coming soon.</div>
                    )}
                  </div>

                  <div className="rounded-2xl border border-slate-200 bg-white p-4 xl:col-span-2">
                    <div className="text-sm font-extrabold text-slate-900">Top 3 Farmers</div>
                    <div className="mt-1 text-xs text-slate-500">
                      Market-wide view for the selected window: {snapshotLabel}
                    </div>

                    {!topFarmersPainted ? (
                      <div className="mt-3 text-sm text-slate-600">Loading top farmers…</div>
                    ) : topFarmersRows.length === 0 ? (
                      <div className="mt-3 text-sm text-slate-600">Top farmers not available yet.</div>
                    ) : (
                      <ul className="mt-3 space-y-2">
                        {topFarmersRows.map((f, idx) => {
                          const total = Math.max(
                            topFarmersRows.length,
                            ...topFarmersRows.map((x) => toNumber(x?.totalFarmers, 0))
                          );

                          return (
                            <li
                              key={`${f.id ?? f.key ?? idx}`}
                              className="flex items-center justify-between gap-3 rounded-xl border border-slate-200 bg-slate-50 p-3"
                            >
                              <div className="flex min-w-0 items-center gap-3">
                                <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-slate-200 bg-white text-xs font-extrabold text-slate-700">
                                  {idx + 1}
                                </div>

                                <div className="min-w-0">
                                  <div className="truncate text-sm font-semibold text-slate-900">
                                    {f.name}
                                  </div>
                                  <div className="mt-0.5 flex items-center gap-1 text-[11px] text-slate-500">
                                    <MapPin className="h-3 w-3" />
                                    {safeStr(f.location, "Location not set")}
                                  </div>
                                  <div className="text-[11px] text-slate-500">
                                    {formatRankOutOf(f.rank, total)}
                                  </div>
                                </div>
                              </div>

                              <div className="text-right text-xs text-slate-600">
                                <div>
                                  Revenue:{" "}
                                  <span className="font-semibold text-slate-800">
                                    N$ {fmtMoneyNAD(f.revenue)}
                                  </span>
                                </div>
                                <div>
                                  Orders:{" "}
                                  <span className="font-semibold text-slate-800">
                                    {fmtQty(f.orders)}
                                  </span>
                                </div>
                              </div>
                            </li>
                          );
                        })}
                      </ul>
                    )}
                  </div>
                </div>
              ) : (
                <div className="mb-4 rounded-2xl border border-slate-200 bg-slate-50 p-4 text-sm text-slate-700">
                  Farmer ranking widgets are turned off in system settings. Your product performance below still uses your real order history for the selected window.
                </div>
              )}
              {ordersRes.error ? (
                <div className="flex items-center justify-between gap-3 rounded-xl border border-red-200 bg-red-50 p-3 text-sm text-red-700">
                  <div>Couldn’t load orders to compute rankings.</div>
                  <button
                    type="button"
                    onClick={() => ordersRes.refetch?.()}
                    className="h-9 rounded-xl border border-red-200 bg-white px-3 font-semibold text-red-700"
                  >
                    Retry
                  </button>
                </div>
              ) : !ordersPainted && ordersRes.loading ? (
                <div className="text-sm text-slate-600">Loading rankings…</div>
              ) : topProducts.length === 0 ? (
                <EmptyState message="No rankings yet. Orders will appear here once customers purchase." />
              ) : (
                <ul className="space-y-2">
                  {topProducts.map((r, idx) => (
                    <li
                      key={r.pid}
                      className="flex items-center gap-4 rounded-2xl border border-slate-200 bg-white p-4"
                    >
                      <div className="flex min-w-0 flex-1 items-center gap-3">
                        <div className="flex h-9 w-9 items-center justify-center rounded-xl border border-slate-200 bg-slate-50 text-xs font-extrabold text-slate-700">
                          {idx + 1}
                        </div>

                        <div className="min-w-0">
                          <div className="truncate text-sm font-extrabold text-slate-900">
                            {r.name}
                          </div>
                          <div className="mt-0.5 text-xs text-slate-500">
                            Category:{" "}
                            <span className="font-semibold text-slate-700">{r.category}</span>{" "}
                            • Orders:{" "}
                            <span className="font-semibold text-slate-700">{r.ordersCount}</span>{" "}
                            • Stock:{" "}
                            <span className="font-semibold text-slate-700">{r.stock}</span>
                          </div>
                          <div className="mt-0.5 flex items-center gap-1 text-xs text-slate-500">
                            <span className="font-semibold text-slate-700">{r.farmerName}</span>
                            {r.farmerLocation ? (
                              <>
                                <span>•</span>
                                <MapPin className="h-3 w-3" />
                                <span>{r.farmerLocation}</span>
                              </>
                            ) : null}
                          </div>
                        </div>
                      </div>

                      <div className="flex items-center gap-3">
                        <div className="text-right">
                          <div className="text-[11px] text-slate-500">Qty sold</div>
                          <div className="text-sm font-extrabold text-slate-900">
                            {fmtQty(r.qty)}
                          </div>
                        </div>

                        <div className="h-8 w-px bg-slate-200" />

                        <div className="text-right">
                          <div className="text-[11px] text-slate-500">Revenue</div>
                          <div className="text-sm font-extrabold text-slate-900">
                            N$ {fmtMoneyNAD(r.revenue)}
                          </div>
                        </div>
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>
        )}

        {/* ------------------------------------------------------------------ */}
        {/* AI Trends */}
        {/* ------------------------------------------------------------------ */}
        {tab === "trends" && (
          <Card>
            <CardHeader>
              <div className="flex items-center gap-2">
                <BarChart3 size={18} className="text-green-700" />
                <div>
                  <CardTitle>AI Trends (Demand Index)</CardTitle>
                  <p className="mt-1 text-xs text-slate-500">
                    Demand signal analytics for the selected time window.
                  </p>
                </div>
              </div>
            </CardHeader>

            <CardContent>
              {trendsRes.error && effectiveTrendSeries.length === 0 ? (
                <div className="rounded-xl border border-orange-200 bg-orange-50 p-3 text-sm text-orange-700">
                  Demand trends are not available right now.
                </div>
              ) : !trendsPainted && trendsRes.loading && effectiveTrendSeries.length === 0 ? (
                <div className="text-sm text-slate-600">Loading trends…</div>
              ) : effectiveTrendSeries.length === 0 ? (
                <EmptyState message="Demand trends coming soon." />
              ) : (
                <>
                  {usingOrderBasedTrendFallback ? (
                    <div className="mb-4 rounded-xl border border-blue-200 bg-blue-50 p-3 text-xs text-blue-800">
                      Showing a simple demand trend from your real sales history. Higher points mean stronger customer demand during that period.
                    </div>
                  ) : null}

                  <div className="mb-4 grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
                    <DemandStatCard
                      label="Latest index"
                      value={demandSummary.latest.toFixed(1)}
                      sub={`${demandSummary.directionLabel} vs previous point`}
                    />
                    <DemandStatCard
                      label="Average index"
                      value={demandSummary.average.toFixed(1)}
                      sub="Average demand in this period"
                    />
                    <DemandStatCard
                      label="Peak index"
                      value={demandSummary.peak.toFixed(1)}
                      sub={`Highest point on ${demandSummary.peakLabel}`}
                    />
                    <DemandStatCard
                      label="Active points"
                      value={String(demandSummary.activePoints)}
                      sub="Periods with visible demand"
                    />
                  </div>

                  <DemandIndexChart rows={effectiveTrendSeries} height={320} />
                </>
              )}
            </CardContent>
          </Card>
        )}

        {/* ------------------------------------------------------------------ */}
        {/* AI Stock Alerts */}
        {/* ------------------------------------------------------------------ */}
        {tab === "alerts" && (
          <Card>
            <CardHeader>
              <div className="flex items-center gap-2">
                <AlertTriangle size={18} className="text-green-700" />
                <div>
                  <CardTitle>AI Stock Alerts</CardTitle>
                  <p className="mt-1 text-xs text-slate-500">
                    Simple stock warnings for the selected period.
                  </p>
                </div>
              </div>
            </CardHeader>

            <CardContent>
              {alertsRes.error ? (
                <div className="flex items-center justify-between gap-3 rounded-xl border border-red-200 bg-red-50 p-3 text-sm text-red-700">
                  <div>Couldn’t load stock alerts.</div>
                  <button
                    type="button"
                    onClick={() => alertsRes.refetch?.()}
                    className="h-9 rounded-xl border border-red-200 bg-white px-3 font-semibold text-red-700"
                  >
                    Retry
                  </button>
                </div>
              ) : !alertsPainted && alertsRes.loading ? (
                <div className="text-sm text-slate-600">Loading stock alerts…</div>
              ) : (() => {
                  if (!stockAlerts.length) {
                    return <EmptyState message="No stock alerts right now." />;
                  }

                  const avgCoverPercent = getAverageCoverPercent(stockAlertSummary);
                  const coverTone = getCoverTone(avgCoverPercent);

                  return (
                    <>
                      <div className="mb-4 rounded-2xl border border-slate-200 bg-slate-50 p-3 text-sm text-slate-700">
                        <div className="font-semibold text-slate-900">How to read this:</div>
                        <div className="mt-1">
                          <span className="font-semibold text-red-700">Red</span> = restock now,{" "}
                          <span className="font-semibold text-orange-700">Orange</span> = plan soon,{" "}
                          <span className="font-semibold text-green-700">Green</span> = stock is okay.
                        </div>
                      </div>

                      <div className="mb-4 grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
                        <SimpleAlertSummaryCard
                          tone="red"
                          label="Restock now"
                          value={String(stockAlertSummary.high)}
                          sub="Products that may run short"
                        />
                        <SimpleAlertSummaryCard
                          tone="orange"
                          label="Plan soon"
                          value={String(stockAlertSummary.medium)}
                          sub="Products that may become low"
                        />
                        <SimpleAlertSummaryCard
                          tone="green"
                          label="Stock okay"
                          value={String(stockAlertSummary.low)}
                          sub="Products with enough stock"
                        />
                        <div className={`rounded-2xl border p-4 ${coverTone.card}`}>
                          <div className="text-[11px] font-semibold uppercase tracking-wide opacity-80">
                            Average stock cover
                          </div>
                          <div className={`mt-1 text-2xl font-black ${coverTone.text}`}>
                            {avgCoverPercent == null ? "—" : formatCoverValueSimple(avgCoverPercent)}
                          </div>
                          <div className="mt-1 text-xs opacity-90">
                            {avgCoverPercent == null
                              ? "No stock cover data"
                              : `${coverSubtitleSimple(avgCoverPercent)} • ${coverMeaningSimple(avgCoverPercent)}`}
                          </div>
                        </div>
                      </div>

                      <ul className="space-y-4">
                        {stockAlerts.map((a) => {
                          const risk = a.risk;
                          const coverBar = Math.max(0, Math.min(100, a.coverage_percent));
                          const generatedAt = formatAlertTime(a.generated_at);

                          return (
                            <li
                              key={a.id}
                              className={`rounded-2xl border p-4 shadow-sm ${getAlertRowSurfaceClasses(a.risk_level)}`}
                            >
                              <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
                                <div className="min-w-0 flex-1">
                                  <div className="flex flex-wrap items-center gap-2">
                                    <div className="truncate text-base font-extrabold text-slate-900">
                                      {a.product_name}
                                    </div>

                                    <span
                                      className={`inline-flex items-center rounded-full border px-2.5 py-1 text-xs font-semibold ${risk.badge}`}
                                    >
                                      {risk.label}
                                    </span>

                                    {a.category ? (
                                      <span className="inline-flex items-center rounded-full border border-slate-200 bg-slate-50 px-2.5 py-1 text-xs font-semibold text-slate-600">
                                        {a.category}
                                      </span>
                                    ) : null}
                                  </div>

                                  <div className={`mt-2 text-sm font-semibold ${risk.tone}`}>
                                    {risk.meaning}
                                  </div>

                                  <div className="mt-3">
                                    <div className="mb-1 flex items-center justify-between text-[11px] text-slate-500">
                                      <span>Stock compared to expected sales</span>
                                      <span>
                                        {formatCoverValueSimple(a.coverage_percent)} {coverSubtitleSimple(a.coverage_percent)}
                                      </span>
                                    </div>

                                    <div className="h-3 overflow-hidden rounded-full bg-slate-100">
                                      <div
                                        className={`h-full rounded-full ${risk.bar}`}
                                        style={{ width: `${coverBar}%` }}
                                      />
                                    </div>
                                  </div>
                                </div>

                                <div className="grid grid-cols-2 gap-2 xl:min-w-[330px]">
                                  <div className="rounded-xl border border-slate-200 bg-slate-50 p-3">
                                    <div className="text-[11px] text-slate-500">Expected sales</div>
                                    <div className="mt-1 text-sm font-extrabold text-slate-900">
                                      {fmtQty(a.forecast_demand)} {a.unit}
                                    </div>
                                  </div>

                                  <div className="rounded-xl border border-slate-200 bg-slate-50 p-3">
                                    <div className="text-[11px] text-slate-500">Stock on hand</div>
                                    <div className="mt-1 text-sm font-extrabold text-slate-900">
                                      {fmtQty(a.current_stock)} {a.unit}
                                    </div>
                                  </div>

                                  <div className="rounded-xl border border-slate-200 bg-slate-50 p-3">
                                    <div className="text-[11px] text-slate-500">Short by</div>
                                    <div className={`mt-1 text-sm font-extrabold ${a.stock_gap > 0 ? "text-red-700" : "text-slate-900"}`}>
                                      {fmtQty(a.stock_gap)} {a.unit}
                                    </div>
                                  </div>

                                  <div className="rounded-xl border border-slate-200 bg-slate-50 p-3">
                                    <div className="text-[11px] text-slate-500">Add more stock</div>
                                    <div className={`mt-1 text-sm font-extrabold ${a.recommended_restock > 0 ? "text-orange-700" : "text-slate-900"}`}>
                                      {fmtQty(a.recommended_restock)} {a.unit}
                                    </div>
                                  </div>
                                </div>
                              </div>

                              <div className="mt-4 grid grid-cols-1 gap-3 xl:grid-cols-[1.2fr_0.9fr]">
                                <div className={`rounded-xl border p-3 ${risk.softPanel}`}>
                                  <div className="text-[11px] font-semibold uppercase tracking-wide text-slate-600">
                                    What you should do
                                  </div>
                                  <div className="mt-1 text-sm text-slate-800">
                                    {a.recommendation || risk.defaultAction}
                                  </div>
                                </div>

                                <div className="rounded-xl border border-slate-200 bg-slate-50 p-3">
                                  <div className="text-[11px] font-semibold uppercase tracking-wide text-slate-500">
                                    Quick notes
                                  </div>
                                  <div className="mt-1 space-y-1 text-sm text-slate-700">
                                    <div>
                                      Days covered: {a.days_of_cover != null ? `${a.days_of_cover} day(s)` : "—"}
                                    </div>
                                    <div>Generated: {generatedAt || "—"}</div>
                                    <div>Model: {a.model_version || "—"}</div>
                                  </div>
                                </div>
                              </div>
                            </li>
                          );
                        })}
                      </ul>
                    </>
                  );
                })()}
            </CardContent>
          </Card>
        )}
      </div>

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