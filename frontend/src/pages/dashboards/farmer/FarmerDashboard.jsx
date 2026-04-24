// ============================================================================
// frontend/src/pages/dashboards/farmer/FarmerDashboard.jsx
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Farmer overview page (route: /dashboard/farmer/overview)
//
// RESPONSIBILITIES:
//   • Header controls: KPI range + refresh + manage products + add product
//   • KPI tiles:
//       - New orders
//       - Revenue total (paid)
//       - Items sold (paid)
//       - Stock status
//       - Farmer ranking
//       - Comments
//   • Main content:
//       - Revenue trend (paid only) — full width
//       - Recent orders (paid only) — below trend
//       - Top products (quantity-first ranking) — below trend
//   • Moderation banner:
//       - Pending products
//       - Rejected products + reasons
//
// THIS UPDATE:
//   ✅ Revenue Trend remains full width
//   ✅ Recent Orders + Top Products stay below trend
//   ✅ Weekly Top Farmers card removed
//   ✅ AI Trends card removed
//   ✅ Recent Comments card removed
//   ✅ Farmer ranking tile hardened to show concrete farmer position
//   ✅ Top Products rank by quantity sold, revenue used only as tie-breaker
//   ✅ Top Products show farmer name + location fallback from session user
//   ✅ Added stronger null-safety, response normalization, and inline comments
//   ✅ Kept the page monolithic but organized into clear sections for maintainability
// ============================================================================

import React, { useCallback, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  RefreshCcw,
  ArrowRight,
  AlertTriangle,
  XCircle,
  Package,
  TrendingUp,
  ShoppingBag,
  Star,
  MessageSquare,
  MapPin,
  CreditCard,
  Truck,
  Lock,
} from "lucide-react";

import FarmerLayout from "../../../components/FarmerLayout";
import { useAuth } from "../../../components/auth/AuthProvider";
import useApi from "../../../hooks/useApi";

import Card from "../../../components/ui/Card";
import RevenueTrendChart from "../../../components/ui/RevenueTrendChart";

// ----------------------------------------------------------------------------
// Null-safe / formatting helpers
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

function clamp(n, min, max) {
  return Math.max(min, Math.min(max, n));
}

function pad2(n) {
  return String(n).padStart(2, "0");
}

function fmtDDMMYYYY(isoLike) {
  try {
    const d = new Date(isoLike);
    if (Number.isNaN(d.getTime())) return "";
    return `${pad2(d.getUTCDate())}-${pad2(d.getUTCMonth() + 1)}-${d.getUTCFullYear()}`;
  } catch {
    return "";
  }
}

function stripTrailingZeros(num, decimals = 3) {
  const x = safeNumber(num, 0);
  if (Math.abs(x - Math.round(x)) < 1e-9) return String(Math.round(x));
  const s = x.toFixed(decimals).replace(/0+$/, "").replace(/\.$/, "");
  return s || "0";
}

// ----------------------------------------------------------------------------
// API response helpers
// ----------------------------------------------------------------------------
function unwrapApiDataEnvelope(raw) {
  if (raw == null) return raw;
  if (Array.isArray(raw)) return raw;
  if (typeof raw !== "object") return raw;

  let cur = raw;
  let guard = 0;

  while (
    cur &&
    typeof cur === "object" &&
    !Array.isArray(cur) &&
    cur.data != null &&
    guard < 5
  ) {
    cur = cur.data;
    guard += 1;
  }

  return cur;
}

function safeJsonParse(v) {
  try {
    return JSON.parse(String(v));
  } catch {
    return null;
  }
}

function normalizeId(v) {
  const s = safeStr(v, "").trim();
  return s ? s.toLowerCase() : "";
}

function uniqueStrings(list) {
  const out = [];
  const seen = new Set();

  for (const item of list || []) {
    const s = safeStr(item, "").trim();
    if (!s) continue;

    const key = s.toLowerCase();
    if (seen.has(key)) continue;

    seen.add(key);
    out.push(s);
  }

  return out;
}

function firstFinite(...vals) {
  for (const v of vals.flat()) {
    const n = Number(v);
    if (Number.isFinite(n)) return n;
  }
  return NaN;
}

// ----------------------------------------------------------------------------
// Identity / ranking helpers
// ----------------------------------------------------------------------------
function pickEntityIds(entity) {
  if (!entity || typeof entity !== "object") return [];

  return uniqueStrings([
    entity?.farmer_id,
    entity?.farmerId,
    entity?.id,
    entity?.user_id,
    entity?.userId,
    entity?.owner_id,
    entity?.ownerId,
    entity?.farmer?.id,
    entity?.farmer?.farmer_id,
    entity?.farmer?.farmerId,
    entity?.farmer?.user_id,
    entity?.farmer?.userId,
    entity?.user?.id,
    entity?.user?.user_id,
    entity?.user?.userId,
    entity?.owner?.id,
    entity?.owner?.owner_id,
    entity?.owner?.ownerId,
  ]);
}

function parseRankFromText(label) {
  const s = safeStr(label, "");
  if (!s) return { rank: NaN, total: NaN };

  let m = s.match(/(\d+)\s*(?:of|\/)\s*(\d+)/i);
  if (m) {
    return {
      rank: safeNumber(m[1], NaN),
      total: safeNumber(m[2], NaN),
    };
  }

  m = s.match(/(?:rank|#)\s*#?\s*(\d+)/i);
  if (m) {
    return {
      rank: safeNumber(m[1], NaN),
      total: NaN,
    };
  }

  return { rank: NaN, total: NaN };
}

function getFarmerIdCandidatesFromUserAndStorage(user) {
  const direct = [
    user?.id,
    user?.user_id,
    user?.userId,
    user?.farmer_id,
    user?.farmerId,
    user?.sub,
    user?.profile?.id,
    user?.profile?.user_id,
    user?.profile?.userId,
    user?.profile?.farmer_id,
    user?.profile?.farmerId,
  ];

  const fromStorage = [];

  if (typeof window !== "undefined" && window?.localStorage) {
    const keys = [
      "user",
      "auth_user",
      "authUser",
      "currentUser",
      "profile",
      "agroconnect_user",
      "agroconnectUser",
      "session_user",
      "sessionUser",
      "me",
    ];

    for (const key of keys) {
      const raw = window.localStorage.getItem(key);
      if (!raw) continue;

      const parsed = safeJsonParse(raw);
      if (!parsed || typeof parsed !== "object") continue;

      fromStorage.push(
        parsed?.id,
        parsed?.user_id,
        parsed?.userId,
        parsed?.farmer_id,
        parsed?.farmerId,
        parsed?.sub,
        parsed?.profile?.id,
        parsed?.profile?.user_id,
        parsed?.profile?.userId,
        parsed?.profile?.farmer_id,
        parsed?.profile?.farmerId,
        parsed?.user?.id,
        parsed?.user?.user_id,
        parsed?.user?.userId,
        parsed?.user?.farmer_id,
        parsed?.user?.farmerId
      );
    }
  }

  return uniqueStrings([...direct, ...fromStorage]);
}

function resolveFarmerRank({ rankingRaw, overviewRaw, farmerIdCandidates = [] }) {
  const payload = unwrapApiDataEnvelope(rankingRaw);
  const overview = overviewRaw && typeof overviewRaw === "object" ? overviewRaw : null;

  // Some endpoints already return a preformatted rank label.
  const overviewRankText = safeStr(
    overview?.farmer_rank_label ??
      overview?.farmerRankLabel ??
      overview?.rank_label ??
      overview?.rankLabel ??
      "",
    ""
  );
  const overviewParsed = parseRankFromText(overviewRankText);

  const rootObj = payload && typeof payload === "object" && !Array.isArray(payload) ? payload : null;

  let rows = [];
  if (Array.isArray(payload)) {
    rows = payload;
  } else {
    rows = safeArray(
      rootObj?.leaderboard ??
        rootObj?.rows ??
        rootObj?.items ??
        rootObj?.results ??
        rootObj?.farmers ??
        rootObj?.rankings ??
        rootObj?.ranking
    );

    if (!rows.length && Array.isArray(rootObj?.data)) {
      rows = rootObj.data;
    }
  }

  // Candidate objects that may describe "me" or current farmer rank.
  const mineCandidates = [];
  if (rootObj) {
    mineCandidates.push(
      rootObj?.mine,
      rootObj?.me,
      rootObj?.current_farmer,
      rootObj?.currentFarmer,
      rootObj?.my_rank,
      rootObj?.myRank,
      rootObj?.farmer,
      rootObj?.current,
      rootObj?.self
    );

    if (rootObj.data && typeof rootObj.data === "object" && !Array.isArray(rootObj.data)) {
      mineCandidates.push(
        rootObj.data?.mine,
        rootObj.data?.me,
        rootObj.data?.current_farmer,
        rootObj.data?.currentFarmer,
        rootObj.data?.my_rank,
        rootObj.data?.myRank
      );
    }
  }

  const mineObj = mineCandidates.find((x) => x && typeof x === "object") || null;

  const idSet = new Set(
    safeArray(farmerIdCandidates)
      .map(normalizeId)
      .filter(Boolean)
  );

  const rowByFlag =
    rows.find((r) =>
      Boolean(r?.is_me ?? r?.isMe ?? r?.mine ?? r?.current ?? r?.is_current ?? r?.isCurrent)
    ) || null;

  let rowById = null;
  if (idSet.size > 0) {
    rowById =
      rows.find((r) =>
        pickEntityIds(r)
          .map(normalizeId)
          .some((rid) => idSet.has(rid))
      ) || null;
  }

  if (!rowById && mineObj) {
    const mineIds = new Set(pickEntityIds(mineObj).map(normalizeId).filter(Boolean));
    if (mineIds.size > 0) {
      rowById =
        rows.find((r) =>
          pickEntityIds(r)
            .map(normalizeId)
            .some((rid) => mineIds.has(rid))
        ) || null;
    }
  }

  const mineRow = rowByFlag || rowById || (rows.length === 1 ? rows[0] : null);

  const extractRank = (x) =>
    firstFinite(
      x?.rank,
      x?.position,
      x?.rank_position,
      x?.rankPosition,
      x?.overall_rank,
      x?.overallRank,
      x?.ranking,
      x?.rank_no,
      x?.rankNo,
      x?.metrics?.rank,
      x?.metrics?.position
    );

  const extractTotal = (x) =>
    firstFinite(
      x?.total_farmers,
      x?.totalFarmers,
      x?.farmer_count,
      x?.farmerCount,
      x?.participants,
      x?.participant_count,
      x?.participantCount,
      x?.total,
      x?.count,
      x?.metrics?.total_farmers,
      x?.metrics?.totalFarmers
    );

  let rankPos = firstFinite(
    extractRank(mineObj),
    extractRank(mineRow),
    extractRank(rootObj),
    rootObj?.current_rank,
    rootObj?.currentRank,
    rootObj?.my_rank,
    rootObj?.myRank,
    rootObj?.my_position,
    rootObj?.myPosition
  );

  if (!Number.isFinite(rankPos) && mineRow) {
    const idx = rows.findIndex((r) => r === mineRow);
    if (idx >= 0) rankPos = idx + 1;
  }

  if (!Number.isFinite(rankPos) && Number.isFinite(overviewParsed.rank)) {
    rankPos = overviewParsed.rank;
  }

  let rankTotal = firstFinite(
    extractTotal(mineObj),
    extractTotal(mineRow),
    extractTotal(rootObj),
    rootObj?.total_farmers,
    rootObj?.totalFarmers,
    rootObj?.farmer_count,
    rootObj?.farmerCount,
    rootObj?.participant_count,
    rootObj?.participantCount,
    rootObj?.total,
    rootObj?.count
  );

  if (!Number.isFinite(rankTotal) && rows.length > 0) {
    rankTotal = rows.length;
  }

  if (!Number.isFinite(rankTotal) && Number.isFinite(overviewParsed.total)) {
    rankTotal = overviewParsed.total;
  }

  if (Number.isFinite(rankPos)) rankPos = Math.max(1, Math.round(rankPos));
  if (Number.isFinite(rankTotal)) rankTotal = Math.max(1, Math.round(rankTotal));

  if (Number.isFinite(rankPos) && Number.isFinite(rankTotal) && rankPos > rankTotal) {
    rankTotal = rankPos;
  }

  const hasConcrete = Number.isFinite(rankPos) && Number.isFinite(rankTotal);

  if (hasConcrete) {
    return {
      label: `${rankPos} out of ${rankTotal}`,
      sub: "Market-wide farmer rank",
      rankPos,
      rankTotal,
    };
  }

  if (Number.isFinite(rankPos)) {
    return {
      label: `Rank ${rankPos}`,
      sub: "Total farmers still loading",
      rankPos,
      rankTotal: NaN,
    };
  }

  return {
    label: "—",
    sub: "Waiting for leaderboard data",
    rankPos: NaN,
    rankTotal: NaN,
  };
}

// ----------------------------------------------------------------------------
// API endpoint safety
// ----------------------------------------------------------------------------
function stripApiPrefix(path) {
  const p = String(path || "");
  return p.startsWith("/api/") ? p.slice(4) : p;
}

function uniqEndpoints(list) {
  const out = [];
  const seen = new Set();

  for (const value of list || []) {
    const cleaned = stripApiPrefix(value);
    if (!cleaned) continue;
    if (seen.has(cleaned)) continue;

    seen.add(cleaned);
    out.push(cleaned);
  }

  return out;
}

// ----------------------------------------------------------------------------
// KPI date range options
// ----------------------------------------------------------------------------
const TIME_WINDOWS = [
  { label: "Last 7 days", value: 7 },
  { label: "Last 14 days", value: 14 },
  { label: "Last 28 days", value: 28 },
  { label: "Last 60 days", value: 60 },
  { label: "Last 90 days", value: 90 },
  { label: "Last 120 days", value: 120 },
  { label: "Last 180 days", value: 180 },
  { label: "Last 365 days", value: 365 },
  { label: "Last 730 days", value: 730 },
  { label: "Last 1095 days", value: 1095 },
];

const MAX_RANGE_DAYS = TIME_WINDOWS.reduce((m, x) => Math.max(m, safeNumber(x.value, 0)), 365);
const LOW_STOCK_THRESHOLD_DEFAULT = 5;

// ----------------------------------------------------------------------------
// Trend controls
// ----------------------------------------------------------------------------
const TREND_MODES = [
  { label: "Range", value: "range" },
  { label: "Quarterly", value: "quarterly" },
  { label: "Bi-monthly", value: "bimonthly" },
  { label: "Annual", value: "annual" },
];

const QUARTERS = [
  { label: "Q1 (Jan–Mar)", value: "Q1" },
  { label: "Q2 (Apr–Jun)", value: "Q2" },
  { label: "Q3 (Jul–Sep)", value: "Q3" },
  { label: "Q4 (Oct–Dec)", value: "Q4" },
];

const BIMONTHS = [
  { label: "Jan–Feb", value: "01-02" },
  { label: "Mar–Apr", value: "03-04" },
  { label: "May–Jun", value: "05-06" },
  { label: "Jul–Aug", value: "07-08" },
  { label: "Sep–Oct", value: "09-10" },
  { label: "Nov–Dec", value: "11-12" },
];

const TREND_BUCKETS = [
  { label: "Weekly", value: "week" },
  { label: "Bi-monthly", value: "bimonth" },
  { label: "Quarterly", value: "quarter" },
  { label: "Annually", value: "year" },
];

function lastDayOfMonth(year, month1to12) {
  return new Date(Date.UTC(year, month1to12, 0)).getUTCDate();
}

function computeTrendWindow(mode, year, quarter, bimonth, rangeLabel) {
  if (mode === "range") {
    return { start: null, end: null, label: rangeLabel };
  }

  if (mode === "annual") {
    return {
      start: `${year}-01-01`,
      end: `${year}-12-31`,
      label: `${year}`,
    };
  }

  if (mode === "quarterly") {
    const q = quarter || "Q1";
    const map = {
      Q1: { sm: 1, em: 3 },
      Q2: { sm: 4, em: 6 },
      Q3: { sm: 7, em: 9 },
      Q4: { sm: 10, em: 12 },
    };

    const { sm, em } = map[q] || map.Q1;
    const endDay = lastDayOfMonth(year, em);

    return {
      start: `${year}-${pad2(sm)}-01`,
      end: `${year}-${pad2(em)}-${pad2(endDay)}`,
      label: `${q} ${year}`,
    };
  }

  const pair = bimonth || "01-02";
  const [smS, emS] = pair.split("-");
  const sm = Number(smS || 1);
  const em = Number(emS || 2);
  const endDay = lastDayOfMonth(year, em);
  const labelText = (BIMONTHS.find((x) => x.value === pair)?.label || "Jan–Feb") + ` ${year}`;

  return {
    start: `${year}-${pad2(sm)}-01`,
    end: `${year}-${pad2(em)}-${pad2(endDay)}`,
    label: labelText,
  };
}

// ----------------------------------------------------------------------------
// Endpoint builders
// ----------------------------------------------------------------------------
const epProductsMineOrList = (farmerId) =>
  uniqEndpoints(
    [
      "/products/mine",
      "/products",
      farmerId ? `/farmer/${farmerId}/products` : null,
      "/farmer/products",
    ].filter(Boolean)
  );

const epOrdersForFarmer = (farmerId) =>
  uniqEndpoints(
    [
      farmerId ? `/orders/farmer/${farmerId}` : null,
      "/orders/farmer",
      "/orders",
    ].filter(Boolean)
  );

const epTopProducts = (farmerId) =>
  uniqEndpoints(
    [
      farmerId ? `/orders/farmer/${farmerId}/top-products` : null,
      "/orders/top-products",
      "/analytics/top-products",
    ].filter(Boolean)
  );

const epRatings = (farmerId) =>
  uniqEndpoints(
    [
      farmerId ? `/ratings/farmer/${farmerId}` : null,
      "/ratings/farmer",
      "/feedback/farmer",
    ].filter(Boolean)
  );

const epFarmersOverview = () => uniqEndpoints(["/farmers/overview", "/farmer/overview"]);

const epFarmerRanking = () =>
  uniqEndpoints([
    "/ai/farmer-ranking",
    "/ai/farmer-ranking/me",
    "/farmers/ranking",
    "/analytics/farmer-ranking",
    "/leaderboard/farmers",
    "/api/ai/farmer-ranking",
  ]);

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
  return (
    s === "paid" ||
    s === "success" ||
    s === "completed" ||
    s === "true" ||
    s === "1" ||
    s === "yes"
  );
}

function orderTotal(order) {
  return (
    safeNumber(order?.order_total) ||
    safeNumber(order?.total) ||
    safeNumber(order?.amount) ||
    safeNumber(order?.total_amount) ||
    safeNumber(order?.totalAmount) ||
    safeNumber(order?.farmer_total) ||
    safeNumber(order?.farmerTotal) ||
    0
  );
}

function parseOrderDate(order) {
  const raw =
    order?.order_date ??
    order?.orderDate ??
    order?.created_at ??
    order?.createdAt ??
    order?.date;

  const dt = raw ? new Date(raw) : null;
  if (!dt || Number.isNaN(dt.getTime())) return null;
  return dt;
}

function normalizeProductsPayload(raw) {
  const payload = unwrapApiDataEnvelope(raw);
  if (!payload) return [];
  if (Array.isArray(payload)) return payload;
  return safeArray(payload.items ?? payload.products ?? payload.data ?? payload.results);
}

function normalizeOrdersPayload(raw) {
  const payload = unwrapApiDataEnvelope(raw);
  const list = Array.isArray(payload)
    ? payload
    : safeArray(payload?.orders ?? payload?.items ?? payload?.data ?? payload?.results);

  return list.map((order) => {
    const items = Array.isArray(order?.items)
      ? order.items
      : Array.isArray(order?.order_items)
        ? order.order_items
        : Array.isArray(order?.orderItems)
          ? order.orderItems
          : [];

    return { ...order, items };
  });
}

function normalizeRatings(raw) {
  const payload = unwrapApiDataEnvelope(raw);
  const rollup = payload && !Array.isArray(payload) ? payload : null;

  const list = Array.isArray(payload)
    ? payload
    : safeArray(
        payload?.ratings ??
          payload?.items ??
          payload?.data ??
          payload?.recent ??
          payload?.recent_ratings ??
          payload?.recentRatings
      );

  const avg =
    safeNumber(rollup?.avg_rating, NaN) ||
    safeNumber(rollup?.averageRating, NaN) ||
    safeNumber(rollup?.average_rating, NaN) ||
    safeNumber(rollup?.average, NaN) ||
    safeNumber(rollup?.avg, NaN) ||
    0;

  const count =
    safeNumber(rollup?.rating_count, NaN) ||
    safeNumber(rollup?.totalRatings, NaN) ||
    safeNumber(rollup?.count, NaN) ||
    safeNumber(rollup?.total, NaN) ||
    list.length;

  return { list, avg, count, rollup };
}

function normalizeTopProducts(raw) {
  const payload = unwrapApiDataEnvelope(raw);
  if (!payload) return [];
  if (Array.isArray(payload)) return payload;

  return safeArray(
    payload.items ?? payload.products ?? payload.data ?? payload.results ?? payload.top_products
  );
}

function computeItemsProgressFromOrderItems(order) {
  const items = Array.isArray(order?.items) ? order.items : [];
  if (!items.length) return null;

  let total = 0;
  let delivered = 0;
  let anyProgress = false;

  for (const item of items) {
    total += 1;

    const qty = safeNumber(item?.quantity ?? item?.qty ?? 0, 0);
    const deliveredQty = safeNumber(
      item?.delivered_qty ??
        item?.deliveredQty ??
        item?.delivered_quantity ??
        item?.deliveredQuantity ??
        0,
      0
    );

    const st = safeStr(
      item?.delivery_status ??
        item?.deliveryStatus ??
        item?.item_delivery_status ??
        item?.itemDeliveryStatus ??
        "",
      ""
    )
      .trim()
      .toLowerCase();

    const isDelivered = st === "delivered" || (qty > 0 && deliveredQty >= qty);

    if (isDelivered) {
      delivered += 1;
      anyProgress = true;
      continue;
    }

    if (deliveredQty > 0 || st === "partial" || st === "in_transit") {
      anyProgress = true;
    }
  }

  const pct = total > 0 ? Math.round((delivered / total) * 100) : 0;
  const status =
    delivered >= total && total > 0 ? "delivered" : anyProgress ? "partial" : "pending";

  return {
    total_items: total,
    delivered_items: delivered,
    progress_pct: pct,
    status,
  };
}

// ----------------------------------------------------------------------------
// Revenue trend fallback helpers
// ----------------------------------------------------------------------------
function toUtcDateOnly(dt) {
  return new Date(Date.UTC(dt.getUTCFullYear(), dt.getUTCMonth(), dt.getUTCDate()));
}

function startOfWeekUtc(dt) {
  const d = toUtcDateOnly(dt);
  const dow = d.getUTCDay();
  const offset = (dow + 6) % 7;
  d.setUTCDate(d.getUTCDate() - offset);
  return d;
}

function startOfBiMonthUtc(dt) {
  const y = dt.getUTCFullYear();
  const m = dt.getUTCMonth();
  const startM = m % 2 === 0 ? m : m - 1;
  return new Date(Date.UTC(y, startM, 1));
}

function startOfQuarterUtc(dt) {
  const y = dt.getUTCFullYear();
  const m = Math.floor(dt.getUTCMonth() / 3) * 3;
  return new Date(Date.UTC(y, m, 1));
}

function startOfYearUtc(dt) {
  return new Date(Date.UTC(dt.getUTCFullYear(), 0, 1));
}

function bucketStartUtc(dt, bucket) {
  const d = toUtcDateOnly(dt);

  if (bucket === "week") return startOfWeekUtc(d);
  if (bucket === "bimonth") return startOfBiMonthUtc(d);
  if (bucket === "quarter") return startOfQuarterUtc(d);
  if (bucket === "year") return startOfYearUtc(d);

  return d;
}

function addBucketUtc(dt, bucket) {
  const d = new Date(dt.getTime());

  if (bucket === "week") {
    d.setUTCDate(d.getUTCDate() + 7);
    return d;
  }

  if (bucket === "bimonth") {
    return new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + 2, 1));
  }

  if (bucket === "quarter") {
    return new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + 3, 1));
  }

  if (bucket === "year") {
    return new Date(Date.UTC(d.getUTCFullYear() + 1, 0, 1));
  }

  return new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate() + 1));
}

function dateKey(d) {
  return d.toISOString().slice(0, 10);
}

function buildRevenueTrendFromOrders({
  orders = [],
  bucket = "week",
  windowStart = null,
  windowEnd = null,
}) {
  if (!Array.isArray(orders) || !orders.length || !windowStart || !windowEnd) return [];

  const start = toUtcDateOnly(windowStart);
  const end = toUtcDateOnly(windowEnd);
  if (start > end) return [];

  const sums = new Map();

  for (const order of orders) {
    const dt = parseOrderDate(order);
    if (!dt) continue;

    const d = toUtcDateOnly(dt);
    if (d < start || d > end) continue;

    const b = bucketStartUtc(d, bucket);
    const k = dateKey(b);
    sums.set(k, (sums.get(k) || 0) + orderTotal(order));
  }

  const points = [];
  let cur = bucketStartUtc(start, bucket);
  const last = bucketStartUtc(end, bucket);
  let guard = 0;

  while (cur <= last && guard < 500) {
    const k = dateKey(cur);

    points.push({
      date: k,
      label: fmtDDMMYYYY(k) || k,
      value: Number((sums.get(k) || 0).toFixed(2)),
      compare: 0,
    });

    cur = addBucketUtc(cur, bucket);
    guard += 1;
  }

  return points;
}

// ----------------------------------------------------------------------------
// UI atoms
// ----------------------------------------------------------------------------
function Pill({ tone = "neutral", children }) {
  const cls =
    tone === "danger"
      ? "border-rose-200 bg-rose-50 text-rose-800"
      : tone === "warn"
        ? "border-amber-200 bg-amber-50 text-amber-900"
        : "border-slate-200 bg-slate-50 text-slate-700";

  return (
    <span
      className={`inline-flex items-center gap-2 rounded-full border px-3 py-1.5 text-xs font-bold ${cls}`}
    >
      {children}
    </span>
  );
}

function StatTile({ icon: Icon, title, value, sub }) {
  return (
    <div className="rounded-2xl border border-slate-200 bg-white p-4">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="text-xs font-semibold text-slate-500">{title}</div>
          <div className="mt-1 text-xl font-extrabold text-slate-900">{value}</div>
          {sub ? <div className="mt-1 text-xs text-slate-500">{sub}</div> : null}
        </div>

        {Icon ? (
          <div className="flex h-10 w-10 items-center justify-center rounded-2xl border border-slate-200 bg-slate-50">
            <Icon className="h-5 w-5 text-slate-700" />
          </div>
        ) : null}
      </div>
    </div>
  );
}

export default function FarmerDashboard() {
  const nav = useNavigate();
  const { user } = useAuth();

  // Resolve the best possible farmer identity from auth + storage so ranking,
  // products, and orders stay stable even when payload shapes vary.
  const farmerIdCandidates = useMemo(
    () => getFarmerIdCandidatesFromUserAndStorage(user),
    [user]
  );
  const farmerId = farmerIdCandidates[0] ?? null;

  // Session-based identity fallbacks for display on product summaries.
  const farmerDisplayName = safeStr(
    user?.full_name ?? user?.fullName ?? user?.name ?? user?.display_name ?? "You"
  );

  const farmerLocation = safeStr(
    user?.location ?? user?.profile?.location ?? user?.region ?? "Location not set"
  );
  const goToMessageCustomer = useCallback(
    (orderLike) => {
      const customerId = safeStr(
        orderLike?.customerId ??
          orderLike?.buyerId ??
          orderLike?.customer_id ??
          orderLike?.buyer_id ??
          ""
      );

      // Keep the farmer in the order workflow when the summary payload does not
      // expose the buyer identity required to seed a secure one-to-one thread.
      if (!customerId) {
        nav("/dashboard/farmer/orders");
        return;
      }

      const orderId = safeStr(orderLike?.oid ?? orderLike?.orderId ?? orderLike?.id ?? "");
      const params = new URLSearchParams();
      params.set("customerId", customerId);
      if (orderId) {
        params.set("orderId", orderId);
        params.set("subject", `Order ${orderId}`);
      }

      nav(`/dashboard/farmer/messages?${params.toString()}`);
    },
    [nav]
  );

  // --------------------------------------------------------------------------
  // UI state
  // --------------------------------------------------------------------------
  const [days, setDays] = useState(90);

  // Revenue trend / recent orders controls
  const now = new Date();
  const currentYear = now.getFullYear();

  const [trendMode, setTrendMode] = useState("range");
  const [trendYear, setTrendYear] = useState(currentYear);
  const [trendQuarter, setTrendQuarter] = useState("Q1");
  const [trendBimonth, setTrendBimonth] = useState("01-02");
  const [trendBucket, setTrendBucket] = useState("week");

  const yearOptions = useMemo(() => {
    const base = currentYear;
    return [base - 2, base - 1, base, base + 1, base + 2];
  }, [currentYear]);

  // --------------------------------------------------------------------------
  // Endpoint lists
  // --------------------------------------------------------------------------
  const productsEndpoints = useMemo(() => epProductsMineOrList(farmerId), [farmerId]);
  const ordersEndpoints = useMemo(() => epOrdersForFarmer(farmerId), [farmerId]);
  const topEndpoints = useMemo(() => epTopProducts(farmerId), [farmerId]);
  const ratingsEndpoints = useMemo(() => epRatings(farmerId), [farmerId]);
  const overviewEndpoints = useMemo(() => epFarmersOverview(), []);
  const rankingEndpoints = useMemo(() => epFarmerRanking(), []);

  // --------------------------------------------------------------------------
  // Derived controls
  // --------------------------------------------------------------------------
  const rangeDays = clamp(days, 1, MAX_RANGE_DAYS);
  const rangeLabel =
    TIME_WINDOWS.find((t) => t.value === days)?.label || `Last ${days} days`;

  const trendWindow = useMemo(
    () => computeTrendWindow(trendMode, trendYear, trendQuarter, trendBimonth, rangeLabel),
    [trendMode, trendYear, trendQuarter, trendBimonth, rangeLabel]
  );

  const paidOnlyLabel = useMemo(() => {
    const bucketText = TREND_BUCKETS.find((b) => b.value === trendBucket)?.label || "Weekly";
    return `Paid orders only • ${trendWindow.label} • ${bucketText}`;
  }, [trendWindow.label, trendBucket]);

  const overviewParams = useMemo(() => {
    const params = {
      days: rangeDays,
      bucket: trendBucket,
      include_compare: 1,
    };

    if (trendWindow.start && trendWindow.end) {
      params.trend_start_date = trendWindow.start;
      params.trend_end_date = trendWindow.end;
    }

    return params;
  }, [rangeDays, trendBucket, trendWindow.start, trendWindow.end]);

  // --------------------------------------------------------------------------
  // API hooks
  // --------------------------------------------------------------------------
  const overviewRes = useApi(overviewEndpoints, {
    enabled: true,
    params: overviewParams,
    initialData: undefined,
    deps: [JSON.stringify(overviewParams)],
  });

  const productsRes = useApi(productsEndpoints, {
    enabled: true,
    params: farmerId ? { farmerId, farmer_id: farmerId } : undefined,
    initialData: undefined,
    deps: [farmerId],
  });

  const ordersRes = useApi(ordersEndpoints, {
    enabled: true,
    params: {
      include_items: 1,
      days: rangeDays,
      ...(farmerId ? { farmerId, farmer_id: farmerId } : {}),
    },
    initialData: undefined,
    deps: [farmerId, rangeDays],
  });

  const topRes = useApi(topEndpoints, {
    enabled: true,
    params: {
      days: rangeDays,
      limit: 8,
      ...(farmerId ? { farmerId, farmer_id: farmerId } : {}),
    },
    initialData: undefined,
    deps: [farmerId, rangeDays],
  });

  const ratingsRes = useApi(ratingsEndpoints, {
    enabled: true,
    params: {
      days: rangeDays,
      limit: 20,
      period: "month",
      ...(farmerId ? { farmerId, farmer_id: farmerId } : {}),
    },
    initialData: undefined,
    deps: [farmerId, rangeDays],
  });

  const rankingRes = useApi(rankingEndpoints, {
    enabled: true,
    params: {
      days: rangeDays,
      window_days: rangeDays,
      limit: 500,
      include_me: 1,
      include_totals: 1,
      with_totals: 1,
      ...(farmerId
        ? {
            farmer_id: farmerId,
            farmerId,
            user_id: farmerId,
            userId: farmerId,
            id: farmerId,
          }
        : {}),
    },
    initialData: undefined,
    deps: [farmerId, rangeDays, JSON.stringify(farmerIdCandidates)],
  });

  const onRefresh = () => {
    overviewRes.refetch?.();
    productsRes.refetch?.();
    ordersRes.refetch?.();
    topRes.refetch?.();
    ratingsRes.refetch?.();
    rankingRes.refetch?.();
  };

  // --------------------------------------------------------------------------
  // Computed dashboard state
  // ----------------------------------------------------------------------------
  // This is the heart of the dashboard. It:
  //   • normalizes mixed endpoint payloads
  //   • prefers overview endpoint data when present
  //   • falls back to orders/products/ratings payloads when needed
  //   • keeps the UI stable even if one backend source is missing
  // --------------------------------------------------------------------------
  const computed = useMemo(() => {
    const overview = overviewRes.data && typeof overviewRes.data === "object" ? overviewRes.data : null;

    const overviewOk =
      Boolean(overview?.success) &&
      Boolean(
        overview?.revenue_trend ||
          overview?.recent_orders ||
          overview?.top_products ||
          overview?.new_orders ||
          overview?.revenue_paid_total ||
          overview?.items_sold_paid
      );

    const products = normalizeProductsPayload(productsRes.data);
    const orders = normalizeOrdersPayload(ordersRes.data);
    const topFromApi = normalizeTopProducts(topRes.data);
    const { list: ratingsList, avg: ratingsAvg, count: ratingsCount } = normalizeRatings(ratingsRes.data);

    // Narrow products to the current signed-in farmer when mixed/global payloads are returned.
    const ownerIdSet = new Set(farmerIdCandidates.map(normalizeId).filter(Boolean));
    const myProducts = products.filter((product) => {
      const ownerCandidates = [
        product?.farmer_id,
        product?.farmerId,
        product?.owner_id,
        product?.ownerId,
        product?.user_id,
        product?.userId,
        product?.created_by_id,
        product?.createdById,
      ]
        .map(normalizeId)
        .filter(Boolean);

      if (!ownerCandidates.length) return false;
      return ownerCandidates.some((id) => ownerIdSet.has(id));
    });

    // Stock status fallback when overview values are missing.
    const lowStockThreshold =
      safeNumber(overview?.low_stock_threshold) ||
      safeNumber(overview?.lowStockThreshold) ||
      LOW_STOCK_THRESHOLD_DEFAULT;

    const lowStockCountFallback = myProducts.filter((product) => {
      const qty = safeNumber(
        product?.quantity ?? product?.qty ?? product?.stock ?? product?.units,
        0
      );
      return qty > 0 && qty <= lowStockThreshold;
    }).length;

    const outOfStockCountFallback = myProducts.filter((product) => {
      const qty = safeNumber(
        product?.quantity ?? product?.qty ?? product?.stock ?? product?.units,
        0
      );
      return qty <= 0;
    }).length;

    // KPI-window order filters.
    const now2 = new Date();
    const sinceRange = new Date(now2.getTime() - rangeDays * 24 * 60 * 60 * 1000);

    const ordersInRange = orders.filter((order) => {
      const dt = parseOrderDate(order);
      return dt && dt >= sinceRange;
    });

    const paidOrdersInRange = ordersInRange.filter(isPaid);

    const revenuePaidTotalFallback = paidOrdersInRange.reduce(
      (sum, order) => sum + orderTotal(order),
      0
    );

    const monthKey = `${now2.getFullYear()}-${now2.getMonth()}`;
    const revenueThisMonthFallback = paidOrdersInRange.reduce((sum, order) => {
      const dt = parseOrderDate(order);
      if (!dt) return sum;
      const key = `${dt.getFullYear()}-${dt.getMonth()}`;
      return key === monthKey ? sum + orderTotal(order) : sum;
    }, 0);

    // Trend-window orders power the revenue chart and recent orders fallback.
    const trendWindowStart = trendWindow.start
      ? new Date(`${trendWindow.start}T00:00:00Z`)
      : new Date(now2.getTime() - (rangeDays - 1) * 24 * 60 * 60 * 1000);

    const trendWindowEnd = trendWindow.end
      ? new Date(`${trendWindow.end}T23:59:59.999Z`)
      : now2;

    const paidOrdersInTrendWindow = orders.filter((order) => {
      if (!isPaid(order)) return false;
      const dt = parseOrderDate(order);
      if (!dt) return false;
      return dt >= trendWindowStart && dt <= trendWindowEnd;
    });

    // Items sold summary fallback: derive a readable unit summary from paid order items.
    const unitQty = new Map();
    for (const order of paidOrdersInRange) {
      const items = Array.isArray(order?.items) ? order.items : [];

      if (items.length) {
        for (const item of items) {
          const qty = safeNumber(item?.quantity ?? item?.qty ?? item?.count ?? item?.amount, 0);
          if (!Number.isFinite(qty) || qty <= 0) continue;

          const unit = safeStr(
            item?.unit ??
              item?.pack_unit ??
              item?.packUnit ??
              item?.measure_unit ??
              item?.measureUnit,
            "unit"
          )
            .toLowerCase()
            .trim();

          unitQty.set(unit, (unitQty.get(unit) || 0) + qty);
        }
      } else {
        unitQty.set("orders", (unitQty.get("orders") || 0) + 1);
      }
    }

    const itemsSoldSummaryFallback =
      [...unitQty.entries()]
        .sort((a, b) => b[1] - a[1])
        .slice(0, 3)
        .map(([u, v]) => `${stripTrailingZeros(v, 3)} ${u}`)
        .join(" • ") || "—";

    // Comments: keep tile summary, but no dedicated Recent Comments card.
    const commentsFromOverview = safeArray(overview?.recent_comments)
      .map((row) => {
        const score = safeNumber(row?.score ?? row?.rating_score ?? row?.rating, 0);
        const text = safeStr(row?.comments ?? row?.comment ?? row?.feedback ?? "", "").trim();
        const product = safeStr(row?.product_name ?? row?.product ?? "Product");
        const when = safeStr(row?.created_at ?? row?.createdAt ?? "", "") || null;
        const buyer =
          safeStr(
            row?.buyer_name ?? row?.buyer?.name ?? row?.customer_name ?? row?.customer ?? "",
            "Customer"
          ) || "Customer";

        return text ? { score, text, buyer, product, when } : null;
      })
      .filter(Boolean);

    const commentsFallback = ratingsList
      .map((row) => {
        const score = safeNumber(row?.rating_score ?? row?.rating ?? row?.score, 0);
        const text = safeStr(
          row?.comment ?? row?.comments ?? row?.feedback ?? row?.message ?? "",
          ""
        ).trim();

        const buyer =
          safeStr(
            row?.buyer_name ?? row?.buyerName ?? row?.customer_name ?? row?.customer ?? "",
            "Customer"
          ).trim() || "Customer";

        const product =
          safeStr(row?.product_name ?? row?.productName ?? row?.product?.name ?? "", "Product").trim() ||
          "Product";

        const when = safeStr(row?.created_at ?? row?.createdAt ?? row?.date ?? "", "") || null;
        return text ? { score, text, buyer, product, when } : null;
      })
      .filter(Boolean);

    const comments =
      overviewOk && commentsFromOverview.length ? commentsFromOverview : commentsFallback;

    // Recent paid orders: prefer overview endpoint, fallback to orders endpoint.
    const recentOrders =
      overviewOk && Array.isArray(overview?.recent_orders)
        ? safeArray(overview.recent_orders)
            .filter((order) => isPaid(order))
            .slice(0, 8)
            .map((order) => ({
              oid: safeStr(order?.order_id ?? order?.id ?? "—"),
              customerId: safeStr(
                order?.buyer?.id ??
                  order?.buyer_id ??
                  order?.buyerId ??
                  order?.customer_id ??
                  order?.customerId ??
                  order?.user_id ??
                  order?.userId ??
                  ""
              ),
              buyer: safeStr(
                order?.buyer?.name ??
                  order?.buyer_name ??
                  order?.customer_name ??
                  order?.customer ??
                  "Customer"
              ),
              addr: safeStr(
                order?.delivery_address ?? order?.deliveryAddress ?? order?.address ?? "—"
              ),
              payment: safeStr(
                order?.payment_status ?? order?.paymentStatus ?? order?.payment ?? "—"
              ),
              delivery: safeStr(
                order?.delivery_status ?? order?.deliveryStatus ?? order?.delivery ?? "—"
              ),
              total: safeNumber(
                order?.farmer_subtotal ??
                  order?.total ??
                  order?.order_total ??
                  order?.total_amount ??
                  0
              ),
              dateISO: safeStr(order?.order_date ?? order?.created_at ?? order?.date ?? "") || null,
              dateDisplay: safeStr(order?.order_date_display ?? "", "") || null,
              itemsProgress: order?.items_progress ?? order?.itemsProgress ?? null,
              paymentLocked: Boolean(order?.payment_locked ?? order?.paymentLocked),
            }))
        : [...paidOrdersInTrendWindow]
            .sort((a, b) => (parseOrderDate(b)?.getTime() || 0) - (parseOrderDate(a)?.getTime() || 0))
            .slice(0, 8)
            .map((order) => {
              const dt = parseOrderDate(order);

              return {
                oid: safeStr(order?.order_id ?? order?.id ?? "—"),
                customerId: safeStr(
                  order?.buyer?.id ??
                    order?.buyer_id ??
                    order?.buyerId ??
                    order?.customer_id ??
                    order?.customerId ??
                    order?.user_id ??
                    order?.userId ??
                    ""
                ),
                buyer: safeStr(
                  order?.buyer_name ??
                    order?.buyerName ??
                    order?.customer_name ??
                    order?.customer ??
                    order?.buyer ??
                    "",
                  "Customer"
                ),
                addr: safeStr(
                  order?.delivery_address ?? order?.deliveryAddress ?? order?.address ?? "—"
                ),
                payment: safeStr(
                  order?.payment_status ?? order?.paymentStatus ?? order?.payment ?? "paid"
                ),
                delivery: safeStr(
                  order?.delivery_status ?? order?.deliveryStatus ?? order?.delivery ?? "—"
                ),
                total: orderTotal(order),
                dateISO: dt ? dt.toISOString() : null,
                dateDisplay: dt ? fmtDDMMYYYY(dt.toISOString()) : null,
                itemsProgress: computeItemsProgressFromOrderItems(order),
                paymentLocked: Boolean(order?.payment_locked ?? order?.paymentLocked),
              };
            });

    // Revenue trend: prefer overview chart series, fallback to order-derived trend.
    const overviewTrend =
      overviewOk && Array.isArray(overview?.revenue_trend)
        ? safeArray(overview.revenue_trend)
            .map((point) => {
              const iso = safeStr(point?.date ?? point?.bucket ?? "");
              return {
                date: iso,
                label: safeStr(point?.date_display ?? "", "") || fmtDDMMYYYY(iso) || iso,
                value: safeNumber(point?.value ?? point?.revenue ?? point?.amount ?? point?.total ?? 0),
                compare: safeNumber(
                  point?.compare_value ??
                    point?.previous_value ??
                    point?.previous ??
                    point?.last_year ??
                    point?.compare ??
                    0
                ),
              };
            })
            .filter((point) => safeStr(point.date).length > 0)
        : [];

    const fallbackTrend = buildRevenueTrendFromOrders({
      orders: paidOrdersInTrendWindow,
      bucket: trendBucket,
      windowStart: trendWindowStart,
      windowEnd: trendWindowEnd,
    });

    const overviewHasValue = overviewTrend.some((point) => safeNumber(point.value) > 0);
    const fallbackHasValue = fallbackTrend.some((point) => safeNumber(point.value) > 0);

    const revenuePoints = overviewHasValue || !fallbackHasValue ? overviewTrend : fallbackTrend;

    const explicitPrevYearSeries =
      overviewOk && Array.isArray(overview?.revenue_trend_prev_year)
        ? safeArray(overview.revenue_trend_prev_year).map((point) =>
            safeNumber(point?.value ?? point?.revenue ?? point?.amount ?? point?.total ?? 0)
          )
        : [];

    const embeddedCompareSeries = revenuePoints.map((point) => safeNumber(point?.compare, 0));
    const hasExplicitSeries = explicitPrevYearSeries.some((v) => v > 0);
    const hasEmbeddedSeries = embeddedCompareSeries.some((v) => v > 0);

    const revenueCompareValues = hasExplicitSeries
      ? explicitPrevYearSeries
      : hasEmbeddedSeries
        ? embeddedCompareSeries
        : [];

    const revenueAllZero = revenuePoints.length
      ? revenuePoints.every((point) => safeNumber(point.value) <= 0)
      : true;

    // Top Products: quantity sold is primary rank metric; revenue breaks ties.
    const topProducts =
      overviewOk && Array.isArray(overview?.top_products) && overview.top_products.length
        ? safeArray(overview.top_products)
            .map((item) => ({
              id: safeStr(item?.product_id ?? item?.id ?? ""),
              name: safeStr(item?.name ?? item?.product_name ?? "Product"),
              revenue: safeNumber(item?.revenue, 0),
              qty: safeNumber(item?.qty_sold ?? item?.qty ?? item?.quantity_sold ?? 0),
              orders: safeNumber(item?.order_count ?? item?.orders ?? 0),
              farmerName: safeStr(
                item?.farmer_name ?? item?.owner_name ?? item?.seller_name ?? farmerDisplayName,
                farmerDisplayName
              ),
              farmerLocation: safeStr(
                item?.farmer_location ?? item?.location ?? item?.region ?? farmerLocation,
                farmerLocation
              ),
            }))
            .sort((a, b) => {
              const byQty = safeNumber(b.qty) - safeNumber(a.qty);
              if (byQty !== 0) return byQty;

              const byRevenue = safeNumber(b.revenue) - safeNumber(a.revenue);
              if (byRevenue !== 0) return byRevenue;

              return safeStr(a.name).localeCompare(safeStr(b.name));
            })
        : topFromApi.length
          ? topFromApi
              .map((item) => ({
                id: safeStr(item?.product_id ?? item?.id ?? ""),
                name: safeStr(item?.product_name ?? item?.name ?? "Product"),
                revenue: safeNumber(item?.revenue, 0),
                qty: safeNumber(item?.qty_sold ?? item?.qty ?? item?.quantity_sold ?? 0),
                orders: safeNumber(item?.order_count ?? item?.orders ?? 0),
                farmerName: safeStr(
                  item?.farmer_name ?? item?.owner_name ?? item?.seller_name ?? farmerDisplayName,
                  farmerDisplayName
                ),
                farmerLocation: safeStr(
                  item?.farmer_location ?? item?.location ?? item?.region ?? farmerLocation,
                  farmerLocation
                ),
              }))
              .sort((a, b) => {
                const byQty = safeNumber(b.qty) - safeNumber(a.qty);
                if (byQty !== 0) return byQty;

                const byRevenue = safeNumber(b.revenue) - safeNumber(a.revenue);
                if (byRevenue !== 0) return byRevenue;

                return safeStr(a.name).localeCompare(safeStr(b.name));
              })
          : [];

    // Moderation info comes from the farmer's products payload.
    const rejectedProducts = myProducts
      .filter((product) => String(product?.status || "").toLowerCase() === "rejected")
      .map((product) => ({
        id: product?.id || product?.product_id,
        name: product?.product_name || product?.name || "Product",
        reason: product?.rejection_reason || product?.rejectionReason || "No reason provided.",
      }));

    const pendingProductsCount = myProducts.filter(
      (product) => String(product?.status || "").toLowerCase() === "pending"
    ).length;

    const newOrders = safeNumber(overview?.new_orders, NaN);
    const revenuePaidTotal = safeNumber(overview?.revenue_paid_total, NaN);
    const revenueThisMonth = safeNumber(overview?.revenue_paid_this_month, NaN);
    const itemsSoldPaid = safeNumber(overview?.items_sold_paid, NaN);

    const lowStockCount = safeNumber(overview?.low_stock_count, NaN);
    const outOfStockCount = safeNumber(overview?.out_of_stock_count, NaN);

    const rankResolved = resolveFarmerRank({
      rankingRaw: rankingRes.data,
      overviewRaw: overview,
      farmerIdCandidates,
    });

    const avgRating = safeNumber(overview?.avg_rating, ratingsAvg);
    const feedbackCount = safeNumber(overview?.feedback_count, ratingsCount);

    return {
      overviewOk,

      newOrders: Number.isFinite(newOrders) ? newOrders : ordersInRange.length,
      revenuePaidTotal: Number.isFinite(revenuePaidTotal)
        ? revenuePaidTotal
        : revenuePaidTotalFallback,
      revenueThisMonth: Number.isFinite(revenueThisMonth)
        ? revenueThisMonth
        : revenueThisMonthFallback,

      itemsSoldSummary: Number.isFinite(itemsSoldPaid)
        ? `${safeStr(
            overview?.items_sold_paid_display ?? stripTrailingZeros(itemsSoldPaid, 3)
          )} items`
        : itemsSoldSummaryFallback,

      lowStockCount: Number.isFinite(lowStockCount) ? lowStockCount : lowStockCountFallback,
      outOfStockCount: Number.isFinite(outOfStockCount)
        ? outOfStockCount
        : outOfStockCountFallback,

      farmerRankLabel: rankResolved.label,
      farmerRankSub: rankResolved.sub,

      commentCount: comments.length,
      ratingsAvg: avgRating,
      ratingsCount: feedbackCount,

      revenuePoints,
      revenueCompareValues,
      revenueAllZero,
      trendFallbackUsed: !overviewHasValue && fallbackHasValue,

      recentOrders,
      topProducts,

      pendingProductsCount,
      rejectedProducts,
      lowStockThreshold,
    };
  }, [
    overviewRes.data,
    productsRes.data,
    ordersRes.data,
    topRes.data,
    ratingsRes.data,
    rankingRes.data,
    farmerIdCandidates,
    rangeDays,
    trendBucket,
    trendWindow.start,
    trendWindow.end,
    farmerDisplayName,
    farmerLocation,
  ]);

  const loading =
    overviewRes.loading ||
    (!computed.overviewOk &&
      (productsRes.loading || ordersRes.loading || topRes.loading || ratingsRes.loading));

  const goToProducts = () => nav("/dashboard/farmer/products");

  /**
   * Keep the add-product experience consistent across the farmer workspace.
   * Instead of opening the older overview modal, route the farmer to the
   * richer Products page form and auto-open it there.
   */

  return (
    <FarmerLayout>
      <div className="space-y-6">
        {/* ------------------------------------------------------------------ */}
        {/* Header                                                             */}
        {/* ------------------------------------------------------------------ */}
        <Card className="border border-slate-200 bg-white p-6">
          <div className="flex flex-col gap-4 xl:flex-row xl:items-center xl:justify-between">
            <div className="min-w-0">
              <div className="text-xs font-semibold text-slate-500">AgroConnect Namibia</div>
              <h1 className="text-2xl font-extrabold text-slate-900">Farmer Overview</h1>
              <p className="mt-1 text-sm text-slate-600">
                Performance snapshot • <span className="font-semibold">{rangeLabel}</span>
              </p>

              {/* Best-effort warning when multiple sources have issues */}
              {overviewRes.error && (ordersRes.error || productsRes.error || ratingsRes.error) ? (
                <div className="mt-3 flex flex-wrap items-center gap-2">
                  <Pill tone="warn">
                    <AlertTriangle className="h-4 w-4" />
                    Some dashboard sources returned an error — showing best-effort data
                  </Pill>
                </div>
              ) : null}
            </div>

            <div className="flex flex-wrap items-center justify-start gap-2 xl:justify-end">
              <select
                value={days}
                onChange={(e) => setDays(Number(e.target.value))}
                className="h-10 rounded-2xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-800"
                aria-label="Select KPI date range"
              >
                {TIME_WINDOWS.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>

              <button type="button" onClick={onRefresh} className="btn-secondary">
                <RefreshCcw className="h-4 w-4" />
                Refresh
              </button>

              <button type="button" onClick={goToProducts} className="btn-secondary">
                Manage Products <ArrowRight className="h-4 w-4" />
              </button>

            </div>
          </div>
        </Card>

        {/* ------------------------------------------------------------------ */}
        {/* KPI tiles                                                          */}
        {/* ------------------------------------------------------------------ */}
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4 2xl:grid-cols-6">
          <StatTile
            icon={ShoppingBag}
            title="New orders"
            value={loading ? "…" : `${safeNumber(computed.newOrders)}`}
            sub={rangeLabel}
          />

          <StatTile
            icon={TrendingUp}
            title="Revenue total (paid)"
            value={loading ? "…" : `N$ ${safeNumber(computed.revenuePaidTotal).toFixed(2)}`}
            sub={`This month: N$ ${safeNumber(computed.revenueThisMonth).toFixed(2)}`}
          />

          <StatTile
            icon={Package}
            title="Items sold (paid)"
            value={loading ? "…" : computed.itemsSoldSummary}
            sub={`No trailing .00 • ${rangeLabel}`}
          />

          <StatTile
            icon={AlertTriangle}
            title="Stock status"
            value={
              loading
                ? "…"
                : `${computed.lowStockCount} low • ${computed.outOfStockCount} out`
            }
            sub={`Low ≤ ${safeNumber(computed.lowStockThreshold, LOW_STOCK_THRESHOLD_DEFAULT)}`}
          />

          <StatTile
            icon={Star}
            title="Farmer ranking"
            value={
              rankingRes.loading && computed.farmerRankLabel === "—"
                ? "…"
                : computed.farmerRankLabel
            }
            sub={computed.farmerRankSub}
          />

          <StatTile
            icon={MessageSquare}
            title="Comments"
            value={loading ? "…" : `${computed.commentCount}`}
            sub={`Avg rating: ${safeNumber(computed.ratingsAvg).toFixed(1)} (${computed.ratingsCount})`}
          />
        </div>

        {/* ------------------------------------------------------------------ */}
        {/* Moderation banner                                                  */}
        {/* ------------------------------------------------------------------ */}
        {computed.pendingProductsCount > 0 || safeArray(computed.rejectedProducts).length > 0 ? (
          <Card className="border border-slate-200 bg-white p-4">
            <div className="flex items-start gap-3">
              <div className="mt-0.5">
                <XCircle className="h-5 w-5 text-rose-600" />
              </div>

              <div className="min-w-0 flex-1">
                <div className="text-sm font-extrabold text-slate-900">
                  Product moderation updates
                </div>

                {computed.pendingProductsCount > 0 ? (
                  <div className="mt-1 text-sm text-slate-700">
                    You have{" "}
                    <span className="font-extrabold">{computed.pendingProductsCount}</span> product(s)
                    awaiting admin approval.
                  </div>
                ) : null}

                {safeArray(computed.rejectedProducts).length > 0 ? (
                  <div className="mt-3 space-y-2">
                    <div className="text-sm font-extrabold text-rose-700">Rejected products</div>

                    <ul className="space-y-2">
                      {safeArray(computed.rejectedProducts).map((product) => (
                        <li
                          key={product.id}
                          className="rounded-2xl border border-rose-200 bg-rose-50 p-3"
                        >
                          <div className="text-sm font-extrabold text-slate-900">
                            {product.name}
                          </div>

                          <div className="mt-1 text-xs text-rose-700">
                            Reason: <span className="font-semibold">{product.reason}</span>
                          </div>

                          <div className="mt-2 text-xs text-slate-600">
                            Edit the product and save changes to resubmit for approval.
                          </div>
                        </li>
                      ))}
                    </ul>
                  </div>
                ) : null}
              </div>

              <button
                type="button"
                onClick={() => nav("/dashboard/farmer/products")}
                className="h-10 rounded-2xl border border-slate-200 bg-white px-3 font-bold text-slate-800 hover:bg-slate-50"
              >
                Open Products
              </button>
            </div>
          </Card>
        ) : null}

        {/* ------------------------------------------------------------------ */}
        {/* Revenue trend — full width                                         */}
        {/* ------------------------------------------------------------------ */}
        <div className="grid grid-cols-1 gap-6 xl:grid-cols-12">
          <Card className="border border-slate-200 bg-white p-4 xl:col-span-12">
            <div className="mb-2 flex items-center justify-between gap-3">
              <div>
                <div className="text-sm font-extrabold text-slate-900">Revenue Trend</div>
                <div className="text-xs text-slate-500">{paidOnlyLabel}</div>
              </div>

              <button type="button" onClick={onRefresh} className="btn-secondary">
                Refresh
              </button>
            </div>

            {/* Power BI-style filter bar for the chart + recent orders window */}
            <div className="mb-3 rounded-2xl bg-slate-900 p-3 text-white">
              <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
                <div className="flex flex-wrap items-center gap-2">
                  <div className="text-xs font-bold opacity-90">Mode</div>

                  <select
                    value={trendMode}
                    onChange={(e) => setTrendMode(e.target.value)}
                    className="h-9 rounded-full border border-slate-700 bg-slate-800 px-3 text-sm font-semibold"
                  >
                    {TREND_MODES.map((mode) => (
                      <option key={mode.value} value={mode.value}>
                        {mode.label}
                      </option>
                    ))}
                  </select>

                  <div className="ml-1 text-xs font-bold opacity-90">Year</div>

                  <select
                    value={trendYear}
                    onChange={(e) => setTrendYear(Number(e.target.value))}
                    className="h-9 rounded-full border border-slate-700 bg-slate-800 px-3 text-sm font-semibold"
                  >
                    {yearOptions.map((year) => (
                      <option key={year} value={year}>
                        {year}
                      </option>
                    ))}
                  </select>

                  {trendMode === "quarterly" ? (
                    <>
                      <div className="ml-1 text-xs font-bold opacity-90">Quarter</div>
                      <select
                        value={trendQuarter}
                        onChange={(e) => setTrendQuarter(e.target.value)}
                        className="h-9 rounded-full border border-slate-700 bg-slate-800 px-3 text-sm font-semibold"
                      >
                        {QUARTERS.map((quarter) => (
                          <option key={quarter.value} value={quarter.value}>
                            {quarter.label}
                          </option>
                        ))}
                      </select>
                    </>
                  ) : null}

                  {trendMode === "bimonthly" ? (
                    <>
                      <div className="ml-1 text-xs font-bold opacity-90">Bi-month</div>
                      <select
                        value={trendBimonth}
                        onChange={(e) => setTrendBimonth(e.target.value)}
                        className="h-9 rounded-full border border-slate-700 bg-slate-800 px-3 text-sm font-semibold"
                      >
                        {BIMONTHS.map((bimonth) => (
                          <option key={bimonth.value} value={bimonth.value}>
                            {bimonth.label}
                          </option>
                        ))}
                      </select>
                    </>
                  ) : null}

                  <span className="ml-2 inline-flex items-center gap-2 rounded-full bg-emerald-600 px-3 py-1.5 text-xs font-extrabold text-white">
                    <CreditCard className="h-4 w-4" />
                    Paid only
                  </span>
                </div>

                <div className="flex flex-wrap items-center gap-2">
                  <div className="text-xs font-bold opacity-90">Bucket</div>

                  <div className="inline-flex rounded-full border border-slate-700 bg-slate-800 p-1">
                    {TREND_BUCKETS.map((bucket) => (
                      <button
                        key={bucket.value}
                        type="button"
                        onClick={() => setTrendBucket(bucket.value)}
                        className={`rounded-full px-3 py-1 text-xs font-extrabold ${
                          trendBucket === bucket.value
                            ? "bg-white text-slate-900"
                            : "text-white/90 hover:bg-slate-700"
                        }`}
                        aria-pressed={trendBucket === bucket.value}
                      >
                        {bucket.label}
                      </button>
                    ))}
                  </div>
                </div>
              </div>

              {trendWindow.start && trendWindow.end ? (
                <div className="mt-2 text-xs text-white/80">
                  Window: <span className="font-bold">{trendWindow.start}</span> →{" "}
                  <span className="font-bold">{trendWindow.end}</span>
                </div>
              ) : null}
            </div>

            {computed.revenueAllZero ? (
              <div className="flex h-[300px] items-center justify-center rounded-2xl border border-slate-200 bg-slate-50">
                <div className="text-sm text-slate-600">
                  No paid revenue yet for this period.
                </div>
              </div>
            ) : (
              <RevenueTrendChart
                labels={safeArray(computed.revenuePoints).map((r) => safeStr(r?.label))}
                values={safeArray(computed.revenuePoints).map((r) => safeNumber(r?.value))}
                compareValues={safeArray(computed.revenueCompareValues).map((v) => safeNumber(v))}
                height={320}
                valuePrefix="N$ "
              />
            )}

            {computed.trendFallbackUsed ? (
              <div className="mt-2 text-[11px] text-slate-500">
                Trend is using paid-order fallback data for this window.
              </div>
            ) : null}
          </Card>
        </div>

        {/* ------------------------------------------------------------------ */}
        {/* Below trend: Recent Orders + Top Products                          */}
        {/* ------------------------------------------------------------------ */}
        <div className="grid grid-cols-1 gap-6 xl:grid-cols-12">
          {/* Recent Orders */}
          <Card className="border border-slate-200 bg-white p-4 xl:col-span-6">
            <div className="mb-3 flex items-center justify-between gap-3">
              <div>
                <div className="text-sm font-extrabold text-slate-900">Recent Orders</div>
                <div className="text-xs text-slate-500">{paidOnlyLabel}</div>
              </div>

              <button
                type="button"
                onClick={() => nav("/dashboard/farmer/orders")}
                className="text-sm font-semibold text-emerald-700 hover:text-emerald-800"
              >
                View
              </button>
            </div>

            {overviewRes.error && ordersRes.error ? (
              <div className="flex items-center justify-between gap-3 rounded-2xl border border-rose-200 bg-rose-50 p-3 text-sm text-rose-700">
                <div>Couldn’t load orders.</div>
                <button type="button" onClick={onRefresh} className="btn-secondary">
                  Retry
                </button>
              </div>
            ) : safeArray(computed.recentOrders).length === 0 ? (
              <div className="text-sm text-slate-500">No paid orders found for this period.</div>
            ) : (
              <ul className="max-h-[620px] space-y-2 overflow-auto pr-1">
                {safeArray(computed.recentOrders).slice(0, 8).map((order, idx) => {
                  const pr =
                    order?.itemsProgress && typeof order.itemsProgress === "object"
                      ? order.itemsProgress
                      : null;

                  const pct = clamp(safeNumber(pr?.progress_pct, 0), 0, 100);
                  const deliveredItems = safeNumber(pr?.delivered_items, 0);
                  const totalItems = safeNumber(pr?.total_items, 0);
                  const paymentLocked = Boolean(order?.paymentLocked);

                  const placed = order?.dateDisplay || (order?.dateISO ? fmtDDMMYYYY(order.dateISO) : null);

                  return (
                    <li
                      key={`${order.oid}-${idx}`}
                      className="rounded-2xl border border-slate-200 p-3"
                    >
                      <div className="flex items-start justify-between gap-3">
                        <div className="min-w-0">
                          <div className="truncate text-sm font-extrabold text-slate-900">
                            {order.oid}
                          </div>

                          {placed ? (
                            <div className="mt-1 text-[11px] text-slate-500">
                              Placed: <span className="font-semibold">{placed}</span>
                            </div>
                          ) : null}

                          <div className="mt-2 flex items-center gap-2 truncate text-xs text-slate-600">
                            <ShoppingBag className="h-3.5 w-3.5 text-slate-400" />
                            <span className="font-semibold">{order.buyer}</span>
                          </div>

                          <div className="mt-1 flex items-center gap-2 truncate text-xs text-slate-600">
                            <MapPin className="h-3.5 w-3.5 text-slate-400" />
                            <span className="truncate">{order.addr}</span>
                          </div>

                          <div className="mt-2 flex flex-wrap items-center gap-2">
                            <span className="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-slate-50 px-2 py-1 text-xs font-bold text-slate-700">
                              <CreditCard className="h-3.5 w-3.5" />
                              {safeStr(order.payment, "paid")}
                              {paymentLocked ? (
                                <span className="ml-1 inline-flex items-center gap-1 text-slate-700">
                                  <Lock className="h-3.5 w-3.5" />
                                  locked
                                </span>
                              ) : null}
                            </span>

                            <span className="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-slate-50 px-2 py-1 text-xs font-bold text-slate-700">
                              <Truck className="h-3.5 w-3.5" />
                              {safeStr(order.delivery, "—")}
                            </span>
                          </div>

                          {pr && totalItems > 0 ? (
                            <div className="mt-3">
                              <div className="flex items-center justify-between text-xs text-slate-600">
                                <div className="font-semibold">
                                  Items delivered: {deliveredItems}/{totalItems}
                                </div>
                                <div className="font-extrabold text-slate-900">{pct}%</div>
                              </div>

                              <div className="mt-1 h-2 overflow-hidden rounded-full bg-slate-100">
                                <div
                                  className="h-full bg-slate-900"
                                  style={{ width: `${pct}%` }}
                                />
                              </div>

                              <div className="mt-1 text-[11px] text-slate-500">
                                Status:{" "}
                                <span className="font-semibold">
                                  {safeStr(pr?.status, "pending")}
                                </span>
                              </div>
                            </div>
                          ) : null}
                        </div>

                        <div className="flex shrink-0 flex-col items-end gap-3">
                          <div className="text-sm font-extrabold text-slate-900">
                            N$ {safeNumber(order.total).toFixed(2)}
                          </div>

                          <button
                            type="button"
                            onClick={() => goToMessageCustomer(order)}
                            className="inline-flex items-center gap-2 rounded-full border border-emerald-200 bg-emerald-50 px-3 py-1.5 text-xs font-bold text-emerald-700 transition hover:bg-emerald-100 disabled:cursor-not-allowed disabled:border-slate-200 disabled:bg-slate-100 disabled:text-slate-400"
                            disabled={!safeStr(order?.customerId)}
                            title={
                              safeStr(order?.customerId)
                                ? "Open a buyer conversation for this order"
                                : "Customer identity is not available on this summary. Open the full order to continue."
                            }
                          >
                            <MessageSquare className="h-3.5 w-3.5" />
                            Message customer
                          </button>
                        </div>
                      </div>
                    </li>
                  );
                })}
              </ul>
            )}
          </Card>

          {/* Top Products */}
          <Card className="border border-slate-200 bg-white p-4 xl:col-span-6">
            <div className="mb-3 flex items-center justify-between gap-3">
              <div>
                <div className="text-sm font-extrabold text-slate-900">Top Products</div>
                <div className="text-xs text-slate-500">
                  Ranked by quantity sold • revenue is used only when quantities are tied
                </div>
              </div>

              <button
                type="button"
                onClick={goToProducts}
                className="text-sm font-semibold text-emerald-700 hover:text-emerald-800"
              >
                View
              </button>
            </div>

            {overviewRes.error && topRes.error ? (
              <div className="flex items-center justify-between gap-3 rounded-2xl border border-rose-200 bg-rose-50 p-3 text-sm text-rose-700">
                <div>Couldn’t load top products.</div>
                <button type="button" onClick={onRefresh} className="btn-secondary">
                  Retry
                </button>
              </div>
            ) : safeArray(computed.topProducts).length === 0 ? (
              <div className="text-sm text-slate-500">
                No product rankings yet for this period.
              </div>
            ) : (
              <ul className="space-y-2">
                {safeArray(computed.topProducts)
                  .slice(0, 8)
                  .map((product, idx) => (
                    <li
                      key={`${product.id || idx}`}
                      className="rounded-2xl border border-slate-200 p-3"
                    >
                      <div className="flex items-center justify-between gap-3">
                        <div className="min-w-0">
                          <div className="truncate text-sm font-extrabold text-slate-900">
                            #{idx + 1} {safeStr(product.name)}
                          </div>

                          <div className="mt-1 text-xs text-slate-500">
                            Farmer:{" "}
                            <span className="font-semibold text-slate-700">
                              {safeStr(product.farmerName)}
                            </span>
                            {" • "}
                            Location:{" "}
                            <span className="font-semibold text-slate-700">
                              {safeStr(product.farmerLocation)}
                            </span>
                          </div>

                          <div className="mt-1 text-xs text-slate-500">
                            Qty sold:{" "}
                            <span className="font-semibold">
                              {stripTrailingZeros(product.qty, 3)}
                            </span>
                            {" • "}
                            Revenue:{" "}
                            <span className="font-semibold">
                              N$ {safeNumber(product.revenue).toFixed(2)}
                            </span>
                            {" • "}
                            Orders:{" "}
                            <span className="font-semibold">
                              {safeNumber(product.orders)}
                            </span>
                          </div>
                        </div>

                        <div className="text-right">
                          <div className="text-[11px] text-slate-500">Qty sold</div>
                          <div className="text-sm font-extrabold text-slate-900">
                            {stripTrailingZeros(product.qty, 3)}
                          </div>
                        </div>
                      </div>
                    </li>
                  ))}
              </ul>
            )}
          </Card>
        </div>
      </div>
    </FarmerLayout>
  );
}