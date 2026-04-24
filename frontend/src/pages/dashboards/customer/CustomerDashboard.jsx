// ============================================================================
// frontend/src/pages/dashboards/customer/CustomerDashboard.jsx
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Customer marketplace dashboard.
//   • Loads marketplace products and customer profile
//   • Supports feed-based browsing (All / New / Liked / Rated)
//   • Supports filtering, search, quick view, likes, ratings, and cart actions
//   • Keeps checkout/cart behavior stable with customer location fallback
//
// MASTER'S-LEVEL CLEANUP UPDATE:
//   ✅ Keeps one primary search input in the command bar
//   ✅ Disables duplicate sidebar search via showSearch={false}
//   ✅ Uses explicit customer feed tabs:
//        - All Products
//        - New Products
//        - Liked Products
//        - Rated Products
//   ✅ Keeps a feed summary strip above the catalog
//   ✅ Moves "Weekly Top 3 Farmers" below the product grid
//   ✅ Keeps one page-level refresh action in the main command bar
//   ✅ Replaces heavy inline product-card rendering with ProductGrid
//   ✅ Removes full rating interaction from the grid cards
//   ✅ Wires full rating interaction through ProductQuickViewModal
//   ✅ Keeps "Your rating" state visible through the shared product-card layer
//   ✅ Keeps API-prefix resilient fallbacks and cart integration stable
//   ✅ Uses backend-backed fetchNewProducts() for the New Products feed
//      with graceful local fallback when needed
//
// NEW PRODUCTS FIX:
//   ✅ "New Products" now means ONLY products created in the last 7 days
//   ✅ Even if /products/new returns older rows, the frontend filters them out
//   ✅ Fallback local filtering also uses the same 7-day rule
//
// PAGINATION UPDATE:
//   ✅ Splits product listing into pages to reduce long customer scrolling
//   ✅ Uses responsive per-page sizes based on screen width
//   ✅ Keeps product browsing cleaner on phone, tablet, and desktop
//   ✅ Resets page automatically when feed/filter context changes
//   ✅ Smooth-scrolls back to catalog top when customer changes page
//
// QUICK VIEW POSITIONING UPDATE:
//   ✅ Stores clicked-card screen context
//   ✅ Passes triggerContext into ProductQuickViewModal
//   ✅ Clears context when quick view closes
// ============================================================================

import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Search,
  ShoppingCart,
  RefreshCw,
  SlidersHorizontal,
  Crown,
  Trophy,
  ChevronLeft,
  ChevronRight,
} from "lucide-react";
import toast from "react-hot-toast";

import DashboardLayout from "../../../components/layout/DashboardLayout";
import Card, { CardContent } from "../../../components/ui/Card";
import ProductQuickViewModal from "../../../components/customer/marketplace/ProductQuickViewModal";
import CartDrawer from "../../../components/customer/marketplace/CartDrawer";
import CustomerFiltersSidebar from "../../../components/customer/CustomerFiltersSidebar";
import ProductGrid from "../../../components/customer/ProductGrid";
import CustomerTopbarNotifications from "../../../components/customer/CustomerTopbarNotifications";
import useCart from "../../../hooks/useCart";
import api from "../../../api";
import * as customerApi from "../../../services/customerApi";
import {
  DEFAULT_PRODUCT_IMG,
  resolveProductImageCandidates,
} from "../../../utils/productImage";

// ----------------------------------------------------------------------------
// Marketplace constants
// ----------------------------------------------------------------------------
// IMPORTANT:
// "New Products" is now strictly defined as products added within the last 7 days.
const NEW_PRODUCT_WINDOW_DAYS = 7;

const CUSTOMER_FEEDS = [
  { value: "all", label: "All Products" },
  { value: "new", label: "New Products" },
  { value: "liked", label: "Liked Products" },
  { value: "rated", label: "Rated Products" },
];

// ----------------------------------------------------------------------------
// Envelope / parsing helpers
// ----------------------------------------------------------------------------
function unwrapEnvelope(v) {
  let cur = v;
  let guard = 0;

  while (
    cur &&
    typeof cur === "object" &&
    !Array.isArray(cur) &&
    Object.prototype.hasOwnProperty.call(cur, "data") &&
    cur.data != null &&
    guard < 4
  ) {
    cur = cur.data;
    guard += 1;
  }

  return cur;
}

function asArray(v) {
  const u = unwrapEnvelope(v);

  if (Array.isArray(u)) return u;
  if (Array.isArray(u?.items)) return u.items;
  if (Array.isArray(u?.data)) return u.data;
  if (Array.isArray(u?.results)) return u.results;
  if (Array.isArray(u?.products)) return u.products;
  if (Array.isArray(u?.ratings)) return u.ratings;
  if (Array.isArray(u?.likes)) return u.likes;
  if (Array.isArray(u?.farmers)) return u.farmers;
  if (Array.isArray(u?.leaderboard)) return u.leaderboard;
  if (Array.isArray(u?.rows)) return u.rows;
  if (Array.isArray(u?.top_farmers)) return u.top_farmers;
  if (Array.isArray(u?.topFarmers)) return u.topFarmers;
  if (Array.isArray(u?.top_three)) return u.top_three;
  if (Array.isArray(u?.topThree)) return u.topThree;
  if (Array.isArray(u?.farmer_ranking)) return u.farmer_ranking;

  return [];
}

function safeParseJson(raw, fallback) {
  if (!raw) return fallback;
  try {
    return JSON.parse(raw);
  } catch {
    return fallback;
  }
}

function asNumber(v, fallback = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

function toNullableNumber(v) {
  if (v === null || v === undefined || v === "") return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

function clampRating(value) {
  const n = Math.round(asNumber(value, 0));
  if (!Number.isFinite(n)) return 0;
  return Math.max(0, Math.min(5, n));
}

function normalizeText(v) {
  return String(v || "").trim().toLowerCase();
}

function money(v) {
  return `N$ ${asNumber(v, 0).toFixed(2)}`;
}

// ----------------------------------------------------------------------------
// Responsive pagination helpers
// ----------------------------------------------------------------------------
// KEY IDEA:
// Smaller screens should show fewer products per page to reduce long scrolling
// and keep each page visually comfortable.
function getProductsPerPageForWidth(width) {
  const w = Number(width);

  if (!Number.isFinite(w)) return 12;
  if (w < 640) return 4;
  if (w < 768) return 6;
  if (w < 1024) return 8;
  return 12;
}

function getVisiblePageNumbers(currentPage, totalPages, maxVisible = 5) {
  const current = Math.max(1, Math.round(asNumber(currentPage, 1)));
  const total = Math.max(1, Math.round(asNumber(totalPages, 1)));

  if (total <= maxVisible) {
    return Array.from({ length: total }, (_, i) => i + 1);
  }

  const half = Math.floor(maxVisible / 2);
  let start = Math.max(1, current - half);
  let end = start + maxVisible - 1;

  if (end > total) {
    end = total;
    start = Math.max(1, end - maxVisible + 1);
  }

  return Array.from({ length: end - start + 1 }, (_, i) => start + i);
}

// ----------------------------------------------------------------------------
// API prefix helpers
// ----------------------------------------------------------------------------
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

// ----------------------------------------------------------------------------
// Product / customer helpers
// ----------------------------------------------------------------------------
function getProductId(p) {
  return p?.product_id ?? p?.id ?? p?.uuid ?? null;
}

function getProductName(p) {
  return p?.name ?? p?.product_name ?? p?.title ?? "Unnamed Product";
}

function getProductPrice(p) {
  return asNumber(p?.price ?? p?.unit_price ?? 0, 0);
}

function getProductCategory(p) {
  return p?.category ?? p?.product_category ?? "Other";
}

function getFarmerName(p) {
  return p?.farmer_name ?? p?.farmer?.name ?? p?.seller_name ?? "Farmer";
}

function getLocation(p) {
  return (
    p?.location ??
    p?.region ??
    p?.town ??
    p?.city ??
    p?.farmer_location ??
    p?.farmer?.location ??
    p?.farmer?.region ??
    ""
  );
}

function getStableCustomerKey(profile) {
  return String(
    profile?.customer_id ??
      profile?.user_id ??
      profile?.id ??
      profile?.email ??
      profile?.username ??
      "guest"
  );
}

function getSeedRatingSnapshot(product) {
  const average = asNumber(
    product?.rating_avg ??
      product?.rating_average ??
      product?.average_rating ??
      product?.rating ??
      0,
    0
  );

  const count = Math.max(
    0,
    Math.round(
      asNumber(product?.rating_count ?? product?.ratings_count ?? product?.total_ratings ?? 0, 0)
    )
  );

  return { average, count };
}

function getCreatedAtMs(product) {
  const raw =
    product?.created_at ??
    product?.createdAt ??
    product?.posted_at ??
    product?.published_at ??
    product?.date_created ??
    null;

  if (!raw) return null;
  const ms = new Date(raw).getTime();
  return Number.isFinite(ms) ? ms : null;
}

function isRecentProduct(product, days = NEW_PRODUCT_WINDOW_DAYS) {
  const createdAtMs = getCreatedAtMs(product);
  if (!createdAtMs) return false;
  const windowMs = days * 24 * 60 * 60 * 1000;
  return Date.now() - createdAtMs <= windowMs;
}

// ----------------------------------------------------------------------------
// Farmer ranking helpers
// ----------------------------------------------------------------------------
function toPercentLabel(value) {
  const n = Math.round(asNumber(value, 0));
  if (!Number.isFinite(n) || n <= 0) return "";
  return `Top ${n}%`;
}

function formatRankOutOfTotal(rank, total) {
  const r = Math.round(asNumber(rank, 0));
  const t = Math.round(asNumber(total, 0));
  if (!r || !t) return "";
  return `${r} out of ${t} farmers`;
}

function normalizeFarmerRankingRow(row, idx, rootMeta = {}) {
  const rank = Math.max(
    1,
    Math.round(
      asNumber(row?.rank ?? row?.position ?? row?.leaderboard_rank ?? idx + 1, idx + 1)
    )
  );

  const totalFarmers = Math.max(
    0,
    Math.round(
      asNumber(
        row?.total_farmers ??
          row?.totalFarmers ??
          rootMeta?.total_farmers ??
          rootMeta?.totalFarmers ??
          0,
        0
      )
    )
  );

  const explicitPercent = toNullableNumber(
    row?.rank_percent ?? row?.rankPercent ?? row?.top_percent ?? row?.topPercent ?? row?.percentile
  );

  const computedPercent =
    explicitPercent != null
      ? Math.max(1, Math.round(explicitPercent))
      : totalFarmers > 0
        ? Math.max(1, Math.round((rank / totalFarmers) * 100))
        : null;

  const revenue = asNumber(
    row?.revenue ??
      row?.total_revenue ??
      row?.revenue_nad ??
      row?.sales_value ??
      row?.gross_revenue ??
      0,
    0
  );

  const orders = Math.max(
    0,
    Math.round(
      asNumber(row?.orders ?? row?.order_count ?? row?.orders_count ?? row?.total_orders ?? 0, 0)
    )
  );

  const avgRating = asNumber(
    row?.avg_rating ?? row?.rating_avg ?? row?.rating_average ?? row?.average_rating ?? 0,
    0
  );

  const ratingCount = Math.max(
    0,
    Math.round(
      asNumber(row?.rating_count ?? row?.ratings_count ?? row?.total_ratings ?? 0, 0)
    )
  );

  const name =
    row?.farmer_name ??
    row?.name ??
    row?.display_name ??
    row?.farmer?.name ??
    row?.seller_name ??
    "Farmer";

  const location =
    row?.farmer_location ??
    row?.location ??
    row?.region ??
    row?.town ??
    row?.city ??
    row?.farmer?.location ??
    "Location not set";

  const id = String(
    row?.farmer_id ?? row?.farmerId ?? row?.user_id ?? row?.id ?? `${idx + 1}`
  );

  const updatedAt =
    row?.updated_at ?? row?.generated_at ?? row?.created_at ?? row?.computed_at ?? null;

  return {
    id,
    rank,
    totalFarmers,
    topPercent: computedPercent,
    name: String(name || "Farmer"),
    location: String(location || "Location not set"),
    revenue,
    orders,
    avgRating,
    ratingCount,
    updatedAt,
  };
}

function sortFarmerRanking(rows) {
  const list = Array.isArray(rows) ? rows : [];

  const hasExplicitRank = list.some(
    (r) => r?.rank != null || r?.position != null || r?.leaderboard_rank != null
  );

  if (hasExplicitRank) {
    return [...list].sort((a, b) => asNumber(a.rank, 9999) - asNumber(b.rank, 9999));
  }

  const hasRevenueOrOrders = list.some(
    (r) => asNumber(r.revenue, 0) > 0 || asNumber(r.orders, 0) > 0
  );

  if (hasRevenueOrOrders) {
    return [...list].sort((a, b) => {
      const byRevenue = asNumber(b.revenue, 0) - asNumber(a.revenue, 0);
      if (byRevenue !== 0) return byRevenue;

      const byOrders = asNumber(b.orders, 0) - asNumber(a.orders, 0);
      if (byOrders !== 0) return byOrders;

      const byRating = asNumber(b.avgRating, 0) - asNumber(a.avgRating, 0);
      if (byRating !== 0) return byRating;

      return asNumber(b.ratingCount, 0) - asNumber(a.ratingCount, 0);
    });
  }

  return [...list].sort((a, b) => {
    const byRating = asNumber(b.avgRating, 0) - asNumber(a.avgRating, 0);
    if (byRating !== 0) return byRating;
    return asNumber(b.ratingCount, 0) - asNumber(a.ratingCount, 0);
  });
}

// ----------------------------------------------------------------------------
// Generic async fallback helper
// ----------------------------------------------------------------------------
async function tryCall(...fns) {
  for (const fn of fns) {
    if (typeof fn !== "function") continue;
    try {
      const res = await fn();
      return res;
    } catch {
      // keep trying next candidate
    }
  }
  return null;
}

// ----------------------------------------------------------------------------
// Ratings / likes helpers
// ----------------------------------------------------------------------------
function computeAverageFromRatings(rows) {
  const list = asArray(rows);
  if (!list.length) return { average: 0, count: 0 };

  let sum = 0;
  let count = 0;

  list.forEach((r) => {
    const score = clampRating(r?.rating_score ?? r?.score ?? r?.rating);
    if (score > 0) {
      sum += score;
      count += 1;
    }
  });

  return {
    average: count > 0 ? sum / count : 0,
    count,
  };
}

function mapLikesToState(rows = []) {
  const out = {};

  rows.forEach((row) => {
    const pid = String(row?.product_id ?? row?.productId ?? "").trim();
    if (!pid) return;

    const likedAtRaw = row?.liked_at ?? row?.created_at ?? row?.likedAt ?? null;
    const likedAtMs = likedAtRaw ? new Date(likedAtRaw).getTime() : Date.now();

    out[pid] = {
      likedAt: Number.isFinite(likedAtMs) ? likedAtMs : Date.now(),
      source: "server",
    };
  });

  return out;
}

export default function CustomerDashboard() {
  const navigate = useNavigate();

  // --------------------------------------------------------------------------
  // Primary page state
  // --------------------------------------------------------------------------
  const [loading, setLoading] = useState(true);
  const [reloading, setReloading] = useState(false);
  const [error, setError] = useState("");

  const [products, setProducts] = useState([]);

  // Dedicated new-products feed returned by backend helper.
  // This feed is still filtered again on the frontend to enforce the 7-day rule.
  const [newProductsFeed, setNewProductsFeed] = useState([]);
  const [newProductsHydrated, setNewProductsHydrated] = useState(false);

  const [customerProfile, setCustomerProfile] = useState(null);

  // Explicit feed mode replaces hidden personalization behavior.
  const [activeFeed, setActiveFeed] = useState("all");

  // Central filter state used by the command bar + sidebar.
  const [filters, setFilters] = useState({
    query: "",
    category: "All",
    location: "All",
    minPrice: "",
    maxPrice: "",
    inStockOnly: true,
    sort: "relevance",
  });

  const [filtersOpen, setFiltersOpen] = useState(false);
  const [animateCartBadge, setAnimateCartBadge] = useState(false);

  // --------------------------------------------------------------------------
  // Responsive pagination state
  // --------------------------------------------------------------------------
  const catalogTopRef = useRef(null);

  const [currentPage, setCurrentPage] = useState(1);
  const [productsPerPage, setProductsPerPage] = useState(() =>
    getProductsPerPageForWidth(
      typeof window !== "undefined" ? window.innerWidth : 1280
    )
  );

  const [quickViewOpen, setQuickViewOpen] = useState(false);
  const [quickViewProduct, setQuickViewProduct] = useState(null);

  // KEY FIX:
  // Store clicked-card viewport context so the quick-view modal can choose
  // a clearer vertical placement based on where the customer clicked.
  const [quickViewContext, setQuickViewContext] = useState(null);

  const [cartOpen, setCartOpen] = useState(false);

  // Likes / favorites
  const [likedByProduct, setLikedByProduct] = useState({});
  const [likesLoading, setLikesLoading] = useState(false);
  const [likesHydrated, setLikesHydrated] = useState(false);
  const [likeBusyByProduct, setLikeBusyByProduct] = useState({});

  // Ratings
  const [myRatingsByProduct, setMyRatingsByProduct] = useState({});
  const [ratingSummaryByProduct, setRatingSummaryByProduct] = useState({});
  const [ratingBusyByProduct, setRatingBusyByProduct] = useState({});
  const [preferencesHydrated, setPreferencesHydrated] = useState(false);

  // Weekly / rolling top farmers
  const [weeklyTopFarmers, setWeeklyTopFarmers] = useState([]);
  const [topFarmersLoading, setTopFarmersLoading] = useState(false);
  const [topFarmersHydrated, setTopFarmersHydrated] = useState(false);
  const [topFarmersError, setTopFarmersError] = useState("");
  const [topFarmersSource, setTopFarmersSource] = useState("coming_soon");
  const [topFarmersDays, setTopFarmersDays] = useState(7);

  // --------------------------------------------------------------------------
  // Cart hook compatibility layer
  // --------------------------------------------------------------------------
  const cart = useCart();
  const cartState = cart?.cartState ?? cart;
  const actions = cart?.actions ?? cartState?.actions ?? {};

  const customerIdentityKey = useMemo(
    () => getStableCustomerKey(customerProfile),
    [customerProfile]
  );

  const preferenceStorageKey = useMemo(
    () => `agroconnect.customer.marketplace.preferences.v3.${customerIdentityKey}`,
    [customerIdentityKey]
  );

  const likesBootstrapRef = useRef("");
  const likedByProductRef = useRef({});

  useEffect(() => {
    likedByProductRef.current = likedByProduct || {};
  }, [likedByProduct]);

  // --------------------------------------------------------------------------
  // Keep products-per-page responsive to screen size
  // --------------------------------------------------------------------------
  useEffect(() => {
    if (typeof window === "undefined") return undefined;

    const handleResize = () => {
      setProductsPerPage((prev) => {
        const next = getProductsPerPageForWidth(window.innerWidth);
        return prev === next ? prev : next;
      });
    };

    handleResize();
    window.addEventListener("resize", handleResize);
    return () => window.removeEventListener("resize", handleResize);
  }, []);

  // --------------------------------------------------------------------------
  // Safe filter setter
  // --------------------------------------------------------------------------
  const setFiltersSafe = useCallback((updaterOrKey, maybeValue) => {
    if (typeof updaterOrKey === "function") {
      setFilters((prev) => {
        const next = updaterOrKey(prev);
        return next && typeof next === "object" ? next : prev;
      });
      return;
    }

    if (typeof updaterOrKey === "string") {
      setFilters((prev) => ({ ...prev, [updaterOrKey]: maybeValue }));
      return;
    }

    if (updaterOrKey && typeof updaterOrKey === "object") {
      setFilters((prev) => ({ ...prev, ...updaterOrKey }));
    }
  }, []);

  // --------------------------------------------------------------------------
  // Load marketplace products + customer profile + backend-backed new products
  // --------------------------------------------------------------------------
  const loadData = useCallback(async (isReload = false) => {
    if (isReload) setReloading(true);
    else setLoading(true);

    setError("");

    try {
      const [productsResp, profileResp, newProductsResp] = await Promise.all([
        tryCall(
          () => customerApi.getProducts?.(),
          () => customerApi.fetchProducts?.(),
          () => customerApi.listProducts?.(),
          () => customerApi.getMarketplaceProducts?.(),
          () => customerApi.getAvailableProducts?.()
        ),
        tryCall(
          () => customerApi.getCustomerProfile?.(),
          () => customerApi.getMyProfile?.(),
          () => customerApi.getCustomerMe?.(),
          () => customerApi.getMe?.(),
          () => customerApi.fetchMyProfile?.()
        ),
        tryCall(
          () => customerApi.fetchNewProducts?.({ limit: 48 }),
          () => customerApi.getNewProducts?.({ limit: 48 })
        ),
      ]);

      const nextProducts = asArray(productsResp);
      const nextProfile = profileResp?.data ?? profileResp?.customer ?? profileResp ?? null;

      const nextNewProductsRaw = asArray(newProductsResp);
      const nextNewProducts = nextNewProductsRaw.filter((p) =>
        isRecentProduct(p, NEW_PRODUCT_WINDOW_DAYS)
      );

      const hasBackendNewProducts = newProductsResp !== null;

      setProducts(nextProducts);
      setCustomerProfile(nextProfile);
      setNewProductsFeed(nextNewProducts);
      setNewProductsHydrated(hasBackendNewProducts);

      const seeded = {};
      [...nextProducts, ...nextNewProducts].forEach((p) => {
        const id = String(getProductId(p) ?? "").trim();
        if (!id) return;
        seeded[id] = getSeedRatingSnapshot(p);
      });

      setRatingSummaryByProduct((prev) => ({ ...seeded, ...prev }));
    } catch (e) {
      console.error(e);
      setNewProductsFeed([]);
      setNewProductsHydrated(false);
      setError("Failed to load marketplace data. Please refresh.");
    } finally {
      setLoading(false);
      setReloading(false);
    }
  }, []);

  // --------------------------------------------------------------------------
  // Load top farmers
  // --------------------------------------------------------------------------
  const loadWeeklyTopFarmers = useCallback(async () => {
    setTopFarmersLoading(true);
    setTopFarmersError("");

    const params = {
      limit: 12,
      days: topFarmersDays,
      window_days: topFarmersDays,
      timeframe_days: topFarmersDays,
      snapshot_days: topFarmersDays,
    };

    try {
      const response = await tryCall(
        () => customerApi.getWeeklyTopFarmers?.(params),
        () => customerApi.getFarmerLeaderboard?.(params),
        () => customerApi.fetchFarmerLeaderboard?.(params),

        () => api.get(apiPath("/api/ai/weekly-top-farmers"), { params }),
        () => api.get(apiPath("/ai/weekly-top-farmers"), { params }),
        () => api.get(apiPath("/api/farmers/leaderboard"), { params }),
        () => api.get(apiPath("/farmers/leaderboard"), { params }),
        () => api.get(apiPath("/api/ai/farmer-ranking"), { params }),
        () => api.get(apiPath("/ai/farmer-ranking"), { params })
      );

      const root = unwrapEnvelope(response?.data ?? response);
      const rows = asArray(root?.top_farmers ?? root?.top_three ?? root);

      if (!rows.length) {
        setWeeklyTopFarmers([]);
        setTopFarmersSource("coming_soon");
        return;
      }

      const normalized = rows
        .map((row, idx) => normalizeFarmerRankingRow(row, idx, root))
        .filter((row) => String(row.name || "").trim().length > 0);

      const sorted = sortFarmerRanking(normalized)
        .map((row, idx) => ({
          ...row,
          rank: row.rank ?? idx + 1,
          totalFarmers: Math.max(
            row.totalFarmers || 0,
            asNumber(root?.total_farmers ?? root?.totalFarmers ?? 0, 0),
            normalized.length
          ),
        }))
        .slice(0, 3);

      const hasRevenueOrOrders = sorted.some(
        (r) => asNumber(r.revenue, 0) > 0 || asNumber(r.orders, 0) > 0
      );

      setWeeklyTopFarmers(sorted);
      setTopFarmersSource(hasRevenueOrOrders ? "orders_revenue" : "ratings_best_effort");
    } catch (e) {
      console.error("weekly top farmers load failed", e);
      setTopFarmersError("Could not load top farmers right now.");
      setWeeklyTopFarmers([]);
      setTopFarmersSource("coming_soon");
    } finally {
      setTopFarmersLoading(false);
      setTopFarmersHydrated(true);
    }
  }, [topFarmersDays]);

  useEffect(() => {
    loadData(false);
  }, [loadData]);

  useEffect(() => {
    loadWeeklyTopFarmers();
  }, [loadWeeklyTopFarmers]);

  // --------------------------------------------------------------------------
  // Hydrate local preferences
  // --------------------------------------------------------------------------
  useEffect(() => {
    if (typeof window === "undefined") return;

    setPreferencesHydrated(false);

    const saved = safeParseJson(window.localStorage.getItem(preferenceStorageKey), null);

    if (saved && typeof saved === "object") {
      setLikedByProduct(saved.likes && typeof saved.likes === "object" ? saved.likes : {});
      setMyRatingsByProduct(saved.ratings && typeof saved.ratings === "object" ? saved.ratings : {});
    } else {
      setLikedByProduct({});
      setMyRatingsByProduct({});
    }

    setPreferencesHydrated(true);
  }, [preferenceStorageKey]);

  useEffect(() => {
    if (!preferencesHydrated || typeof window === "undefined") return;

    const payload = {
      version: 3,
      updated_at: new Date().toISOString(),
      likes: likedByProduct,
      ratings: myRatingsByProduct,
    };

    window.localStorage.setItem(preferenceStorageKey, JSON.stringify(payload));
  }, [preferencesHydrated, preferenceStorageKey, likedByProduct, myRatingsByProduct]);

  // --------------------------------------------------------------------------
  // Hydrate likes from server
  // --------------------------------------------------------------------------
  useEffect(() => {
    if (!preferencesHydrated) return;

    const customerId =
      customerProfile?.customer_id ?? customerProfile?.id ?? customerProfile?.user_id ?? null;

    if (!customerId) {
      setLikesHydrated(true);
      return;
    }

    if (likesBootstrapRef.current === customerIdentityKey) {
      setLikesHydrated(true);
      return;
    }

    let cancelled = false;

    async function hydrateLikesFromServer() {
      setLikesLoading(true);

      try {
        if (typeof customerApi.fetchMyProductLikes !== "function") {
          if (!cancelled) {
            setLikesHydrated(true);
            setLikesLoading(false);
          }
          return;
        }

        const serverRows = asArray(await customerApi.fetchMyProductLikes({ limit: 2000 }));
        const serverMap = mapLikesToState(serverRows);

        const localSaved =
          typeof window !== "undefined"
            ? safeParseJson(window.localStorage.getItem(preferenceStorageKey), null)
            : null;

        const localLikes =
          localSaved && typeof localSaved.likes === "object" ? localSaved.likes : {};

        const localIds = Object.keys(localLikes || {}).filter((pid) => localLikes?.[pid]);
        const missingOnServer = localIds.filter((pid) => !serverMap[pid]);

        let merged = { ...serverMap };

        if (missingOnServer.length && typeof customerApi.syncProductLikes === "function") {
          try {
            const syncedRows = await customerApi.syncProductLikes(missingOnServer, {
              replace: false,
            });
            const syncedMap = mapLikesToState(asArray(syncedRows));
            merged = { ...merged, ...syncedMap };
          } catch {
            missingOnServer.forEach((pid) => {
              merged[pid] =
                merged[pid] ||
                localLikes[pid] || {
                  likedAt: Date.now(),
                  source: "local-fallback",
                };
            });
          }
        }

        if (!cancelled) {
          setLikedByProduct(merged);
          likesBootstrapRef.current = customerIdentityKey;
        }
      } catch {
        // Keep local fallback
      } finally {
        if (!cancelled) {
          setLikesLoading(false);
          setLikesHydrated(true);
        }
      }
    }

    hydrateLikesFromServer();

    return () => {
      cancelled = true;
    };
  }, [
    preferencesHydrated,
    preferenceStorageKey,
    customerIdentityKey,
    customerProfile?.customer_id,
    customerProfile?.id,
    customerProfile?.user_id,
  ]);

  // --------------------------------------------------------------------------
  // Hydrate authenticated customer's prior ratings if backend endpoint exists
  // --------------------------------------------------------------------------
  useEffect(() => {
    let isCancelled = false;

    async function loadMyRatings() {
      const customerId =
        customerProfile?.customer_id ?? customerProfile?.id ?? customerProfile?.user_id ?? null;

      if (!customerId) return;

      const fetchMine =
        typeof customerApi.fetchMyRatings === "function"
          ? customerApi.fetchMyRatings
          : customerApi.fetchRatings;

      if (typeof fetchMine !== "function") return;

      try {
        const response = await fetchMine({
          customer_id: customerId,
          limit: 300,
        });

        const rows = asArray(response?.ratings ?? response?.items ?? response);
        if (!rows.length || isCancelled) return;

        const serverMap = {};
        rows.forEach((row) => {
          const pid = String(row?.product_id ?? row?.product?.product_id ?? "").trim();
          const score = clampRating(row?.rating_score ?? row?.score ?? row?.rating);
          if (!pid || score <= 0) return;
          serverMap[pid] = score;
        });

        if (!Object.keys(serverMap).length || isCancelled) return;
        setMyRatingsByProduct((prev) => ({ ...prev, ...serverMap }));
      } catch {
        // Non-blocking fallback
      }
    }

    loadMyRatings();

    return () => {
      isCancelled = true;
    };
  }, [customerProfile?.customer_id, customerProfile?.id, customerProfile?.user_id]);

  // --------------------------------------------------------------------------
  // Derived lists used by the explicit feed switcher
  // --------------------------------------------------------------------------
  const allProducts = useMemo(() => products, [products]);

  const newProducts = useMemo(() => {
    if (newProductsHydrated) {
      const strictBackendFeed = (Array.isArray(newProductsFeed) ? newProductsFeed : []).filter((p) =>
        isRecentProduct(p, NEW_PRODUCT_WINDOW_DAYS)
      );
      return strictBackendFeed;
    }

    return products.filter((p) => isRecentProduct(p, NEW_PRODUCT_WINDOW_DAYS));
  }, [newProductsFeed, newProductsHydrated, products]);

  const likedProducts = useMemo(
    () =>
      products.filter((p) => {
        const id = String(getProductId(p) ?? "").trim();
        return !!id && !!likedByProduct[id];
      }),
    [products, likedByProduct]
  );

  const ratedProducts = useMemo(
    () =>
      products.filter((p) => {
        const id = String(getProductId(p) ?? "").trim();
        return !!id && clampRating(myRatingsByProduct[id]) > 0;
      }),
    [products, myRatingsByProduct]
  );

  const feedCounts = useMemo(
    () => ({
      all: allProducts.length,
      new: newProducts.length,
      liked: likedProducts.length,
      rated: ratedProducts.length,
    }),
    [allProducts.length, newProducts.length, likedProducts.length, ratedProducts.length]
  );

  const feedBaseProducts = useMemo(() => {
    if (activeFeed === "new") return newProducts;
    if (activeFeed === "liked") return likedProducts;
    if (activeFeed === "rated") return ratedProducts;
    return allProducts;
  }, [activeFeed, allProducts, newProducts, likedProducts, ratedProducts]);

  const feedMeta = useMemo(() => {
    const map = {
      all: {
        title: "All Products",
        description: "Browse the full marketplace catalog.",
      },
      new: {
        title: "New Products",
        description: `Products added within the last ${NEW_PRODUCT_WINDOW_DAYS} days only.`,
      },
      liked: {
        title: "Liked Products",
        description: "Products you saved for quick access and later review.",
      },
      rated: {
        title: "Rated Products",
        description: "Products you have already reviewed or scored.",
      },
    };

    return map[activeFeed] || map.all;
  }, [activeFeed]);

  const categories = useMemo(() => {
    const set = new Set(["All"]);
    feedBaseProducts.forEach((p) => {
      const c = String(getProductCategory(p) || "").trim();
      if (c) set.add(c);
    });
    return [...set];
  }, [feedBaseProducts]);

  const locations = useMemo(() => {
    const set = new Set(["All"]);
    feedBaseProducts.forEach((p) => {
      const loc = String(getLocation(p) || "").trim();
      if (loc) set.add(loc);
    });
    return [...set];
  }, [feedBaseProducts]);

  const filteredProducts = useMemo(() => {
    const q = normalizeText(filters.query);
    const selectedCategory = String(filters.category || "All");
    const selectedLocation = String(filters.location || "All");
    const minPrice = toNullableNumber(filters.minPrice);
    const maxPrice = toNullableNumber(filters.maxPrice);
    const inStockOnly = !!filters.inStockOnly;
    const sortBy = String(filters.sort || "relevance");

    let out = feedBaseProducts.filter((p) => {
      const stock = asNumber(p?.stock_quantity ?? p?.stock ?? p?.quantity ?? 0, 0);
      const price = getProductPrice(p);
      const category = String(getProductCategory(p) || "Other");
      const location = String(getLocation(p) || "");

      if (inStockOnly && stock <= 0) return false;
      if (selectedCategory !== "All" && category !== selectedCategory) return false;

      if (selectedLocation !== "All") {
        if (normalizeText(location) !== normalizeText(selectedLocation)) return false;
      }

      if (minPrice !== null && price < minPrice) return false;
      if (maxPrice !== null && price > maxPrice) return false;

      if (!q) return true;

      const hay = [getProductName(p), category, getFarmerName(p), location]
        .join(" ")
        .toLowerCase();

      return hay.includes(q);
    });

    if (sortBy === "price_asc") {
      out = [...out].sort((a, b) => getProductPrice(a) - getProductPrice(b));
    } else if (sortBy === "price_desc") {
      out = [...out].sort((a, b) => getProductPrice(b) - getProductPrice(a));
    } else if (sortBy === "name_asc") {
      out = [...out].sort((a, b) =>
        getProductName(a).localeCompare(getProductName(b), undefined, { sensitivity: "base" })
      );
    } else if (sortBy === "name_desc") {
      out = [...out].sort((a, b) =>
        getProductName(b).localeCompare(getProductName(a), undefined, { sensitivity: "base" })
      );
    } else if (sortBy === "stock_desc") {
      out = [...out].sort(
        (a, b) =>
          asNumber(b?.stock_quantity ?? b?.stock ?? b?.quantity ?? 0, 0) -
          asNumber(a?.stock_quantity ?? a?.stock ?? a?.quantity ?? 0, 0)
      );
    }

    return out;
  }, [feedBaseProducts, filters]);

  // --------------------------------------------------------------------------
  // Reset to page 1 whenever the visible result context changes
  // --------------------------------------------------------------------------
  useEffect(() => {
    setCurrentPage(1);
  }, [
    activeFeed,
    filters.query,
    filters.category,
    filters.location,
    filters.minPrice,
    filters.maxPrice,
    filters.inStockOnly,
    filters.sort,
  ]);

  // --------------------------------------------------------------------------
  // Pagination derived state
  // --------------------------------------------------------------------------
  const totalFilteredProducts = filteredProducts.length;

  const totalPages = useMemo(() => {
    return Math.max(1, Math.ceil(totalFilteredProducts / productsPerPage));
  }, [totalFilteredProducts, productsPerPage]);

  useEffect(() => {
    setCurrentPage((prev) => Math.min(prev, totalPages));
  }, [totalPages]);

  const currentPageSafe = Math.min(currentPage, totalPages);

  const paginatedProducts = useMemo(() => {
    const start = (currentPageSafe - 1) * productsPerPage;
    const end = start + productsPerPage;
    return filteredProducts.slice(start, end);
  }, [filteredProducts, currentPageSafe, productsPerPage]);

  const currentPageStart =
    totalFilteredProducts === 0 ? 0 : (currentPageSafe - 1) * productsPerPage + 1;

  const currentPageEnd = Math.min(
    currentPageSafe * productsPerPage,
    totalFilteredProducts
  );

  const visiblePageNumbers = useMemo(() => {
    return getVisiblePageNumbers(currentPageSafe, totalPages, 5);
  }, [currentPageSafe, totalPages]);

  const goToPage = useCallback(
    (nextPage) => {
      const clamped = Math.max(1, Math.min(nextPage, totalPages));
      setCurrentPage(clamped);

      if (catalogTopRef.current?.scrollIntoView) {
        catalogTopRef.current.scrollIntoView({
          behavior: "smooth",
          block: "start",
        });
      }
    },
    [totalPages]
  );

  const cartCount = useMemo(() => {
    const items = Array.isArray(cartState?.items) ? cartState.items : [];
    if (typeof cartState?.totalItems === "number") return cartState.totalItems;
    return items.reduce((sum, it) => sum + asNumber(it?.quantity ?? it?.qty ?? 1, 1), 0);
  }, [cartState]);

  const feedResultsLabel = useMemo(() => {
    if (totalFilteredProducts === 0) return "0 products";
    return `Showing ${currentPageStart}-${currentPageEnd} of ${totalFilteredProducts} products`;
  }, [currentPageStart, currentPageEnd, totalFilteredProducts]);

  // Quick-view derived state keeps the modal fully connected to page state.
  const quickViewProductId = useMemo(
    () => String(getProductId(quickViewProduct) ?? "").trim(),
    [quickViewProduct]
  );

  const quickViewLiked = !!likedByProduct[quickViewProductId];

  const quickViewMyRating = useMemo(
    () => clampRating(myRatingsByProduct[quickViewProductId] ?? quickViewProduct?.my_rating ?? 0),
    [myRatingsByProduct, quickViewProductId, quickViewProduct]
  );

  const quickViewRatingSummary = useMemo(
    () =>
      ratingSummaryByProduct[quickViewProductId] ??
      getSeedRatingSnapshot(quickViewProduct || {}) ?? {
        average: 0,
        count: 0,
      },
    [ratingSummaryByProduct, quickViewProductId, quickViewProduct]
  );

  const quickViewRatingBusy = !!ratingBusyByProduct[quickViewProductId];

  const prevCartCountRef = useRef(cartCount);
  useEffect(() => {
    if (prevCartCountRef.current === cartCount) return;
    prevCartCountRef.current = cartCount;
    setAnimateCartBadge(true);
    const timer = window.setTimeout(() => setAnimateCartBadge(false), 220);
    return () => window.clearTimeout(timer);
  }, [cartCount]);

  const defaultCustomerLocation =
    customerProfile?.delivery_location ||
    customerProfile?.address ||
    customerProfile?.location ||
    customerProfile?.current_location ||
    "";

  // --------------------------------------------------------------------------
  // Cart actions
  // --------------------------------------------------------------------------
  function addToCart(product, quantity = 1, options = {}) {
    const productId = getProductId(product);
    const imageCandidates = resolveProductImageCandidates(product);
    const firstImage = imageCandidates[0] || DEFAULT_PRODUCT_IMG;

    const normalizedQty = Number(quantity);
    const safeQty = Number.isFinite(normalizedQty) && normalizedQty > 0 ? normalizedQty : 1;

    // ------------------------------------------------------------------------
    // UX FIX:
    // Opening the cart drawer from the quick-view modal makes the page feel
    // "frozen" because the drawer intentionally locks background scrolling.
    //
    // Therefore this helper now supports a caller option:
    //   openCart: true  -> normal catalogue/card add behaviour
    //   openCart: false -> silent add, keep dashboard scrollable
    //
    // Quick View uses openCart:false so the product is added, the modal closes,
    // the cart badge updates, and the customer can continue browsing normally.
    // ------------------------------------------------------------------------
    const { openCart = true } = options || {};

    const payload = {
      product_id: productId,
      productId: productId,
      id: productId,
      name: getProductName(product),
      price: getProductPrice(product),
      unit_price: getProductPrice(product),
      image_url: firstImage,
      image: firstImage,
      farmer_id: product?.farmer_id ?? product?.farmer?.id ?? null,
      farmer_name: getFarmerName(product),
      quantity: safeQty,
      stock_quantity: product?.stock_quantity ?? product?.stock ?? null,
      category: getProductCategory(product),
      location: getLocation(product),
      image_candidates: imageCandidates,
    };

    const ok =
      (typeof actions?.addItem === "function" && (actions.addItem(payload), true)) ||
      (typeof actions?.addToCart === "function" && (actions.addToCart(payload), true));

    if (!ok) {
      console.warn("No compatible add-to-cart action found in useCart.");
      return;
    }

    if (openCart) {
      setCartOpen(true);
    }
  }

  // KEY FIX:
  // Quick view now accepts screen-position metadata from the clicked card.
  function openQuickView(product, triggerContext = null) {
    setQuickViewProduct(product);
    setQuickViewContext(triggerContext || null);
    setQuickViewOpen(true);
  }

  function closeQuickView() {
    setQuickViewOpen(false);
    setQuickViewContext(null);
  }

  function clearFilters() {
    setFilters({
      query: "",
      category: "All",
      location: "All",
      minPrice: "",
      maxPrice: "",
      inStockOnly: true,
      sort: "relevance",
    });
  }

  // --------------------------------------------------------------------------
  // Likes
  // --------------------------------------------------------------------------
  const toggleLikeProduct = useCallback(
    async (product) => {
      const productId = String(getProductId(product) ?? "").trim();
      if (!productId) return;
      if (likeBusyByProduct?.[productId]) return;

      const currentMap = likedByProductRef.current || {};
      const previousEntry = currentMap[productId] || null;
      const previouslyLiked = !!previousEntry;

      setLikedByProduct((prev) => {
        const next = { ...(prev || {}) };
        if (previouslyLiked) {
          delete next[productId];
        } else {
          next[productId] = {
            likedAt: Date.now(),
            productName: getProductName(product),
            source: "optimistic",
          };
        }
        return next;
      });

      setLikeBusyByProduct((prev) => ({ ...prev, [productId]: true }));

      try {
        const response = await customerApi.setProductLike(productId, !previouslyLiked);

        if (!previouslyLiked) {
          const serverLikedAt =
            response?.like?.liked_at ?? response?.like?.created_at ?? response?.liked_at ?? null;

          const likedAtMs = serverLikedAt ? new Date(serverLikedAt).getTime() : Date.now();

          setLikedByProduct((prev) => ({
            ...prev,
            [productId]: {
              ...(prev?.[productId] || {}),
              likedAt: Number.isFinite(likedAtMs) ? likedAtMs : Date.now(),
              productName: getProductName(product),
              source: "server",
            },
          }));
        }
      } catch (err) {
        setLikedByProduct((prev) => {
          const next = { ...(prev || {}) };
          if (previouslyLiked) next[productId] = previousEntry;
          else delete next[productId];
          return next;
        });

        const msg =
          err?.response?.data?.message ||
          err?.message ||
          "Could not update liked products right now.";
        toast.error(msg);
      } finally {
        setLikeBusyByProduct((prev) => ({ ...prev, [productId]: false }));
      }
    },
    [likeBusyByProduct]
  );

  // --------------------------------------------------------------------------
  // Ratings
  // --------------------------------------------------------------------------
  const refreshProductRatingSummary = useCallback(async (productId) => {
    const id = String(productId || "").trim();
    if (!id || typeof customerApi.fetchProductRatings !== "function") return;

    try {
      const rows = await customerApi.fetchProductRatings(id, { limit: 250 });
      const summary = computeAverageFromRatings(rows);

      setRatingSummaryByProduct((prev) => ({
        ...prev,
        [id]: summary,
      }));
    } catch {
      // Keep seeded summary if endpoint is not available
    }
  }, []);

  const rateProduct = useCallback(
    async (product, score) => {
      const productId = String(getProductId(product) ?? "").trim();
      const nextScore = clampRating(score);

      if (!productId || nextScore < 1 || nextScore > 5) return;

      const previousScore = clampRating(myRatingsByProduct[productId]);
      const currentSummary =
        ratingSummaryByProduct[productId] ??
        getSeedRatingSnapshot(product) ?? { average: 0, count: 0 };

      const currentCount = Math.max(0, Math.round(asNumber(currentSummary?.count, 0)));
      const currentAverage = asNumber(currentSummary?.average, 0);

      let optimisticSummary;
      if (previousScore > 0 && currentCount > 0) {
        optimisticSummary = {
          count: currentCount,
          average: (currentAverage * currentCount - previousScore + nextScore) / currentCount,
        };
      } else {
        const nextCount = currentCount + 1;
        optimisticSummary = {
          count: nextCount,
          average: (currentAverage * currentCount + nextScore) / nextCount,
        };
      }

      setMyRatingsByProduct((prev) => ({ ...prev, [productId]: nextScore }));
      setRatingSummaryByProduct((prev) => ({ ...prev, [productId]: optimisticSummary }));
      setRatingBusyByProduct((prev) => ({ ...prev, [productId]: true }));

      try {
        if (typeof customerApi.submitProductRating === "function") {
          // Phase 1:
          // Ratings must be tied to a delivered/completed order item.
          // For the quick-star shortcut, we auto-link the newest eligible
          // reviewable item for this product. The full explicit workflow lives
          // in the RatingsPanel.
          const reviewableItems =
            typeof customerApi.fetchReviewableOrderItems === "function"
              ? await customerApi.fetchReviewableOrderItems({
                  product_id: productId,
                  include_reviewed: 0,
                })
              : [];

          const targetItem = Array.isArray(reviewableItems) ? reviewableItems[0] : null;
          if (!targetItem?.order_item_id) {
            throw new Error(
              "Verified purchase review required. Open the product review panel after delivery to rate this item."
            );
          }

          await customerApi.submitProductRating({
            product_id: productId,
            order_id: targetItem.order_id,
            order_item_id: targetItem.order_item_id,
            rating_score: nextScore,
          });

          toast.success(`Verified review saved for ${getProductName(product)} (${nextScore}★)`);
        }

        await refreshProductRatingSummary(productId);
      } catch (err) {
        const message =
          err?.response?.data?.message ||
          err?.message ||
          "Could not sync rating right now. Your rating is saved locally.";

        toast.error(message);
      } finally {
        setRatingBusyByProduct((prev) => ({ ...prev, [productId]: false }));
      }
    },
    [myRatingsByProduct, ratingSummaryByProduct, refreshProductRatingSummary]
  );

  // --------------------------------------------------------------------------
  // Topbar actions:
  //   • Customer notification bell for payment-ready alerts
  //   • Cart button
  // --------------------------------------------------------------------------
  const topbarActions = (
    <div className="flex flex-wrap items-center gap-2">
      <CustomerTopbarNotifications />

      <button
        type="button"
        onClick={() => setCartOpen(true)}
        className="inline-flex h-11 min-w-[98px] shrink-0 items-center justify-center gap-2 rounded-xl border border-[#D8F3DC] bg-white px-3 text-sm font-semibold text-slate-700 shadow-sm transition duration-200 hover:-translate-y-[1px] hover:bg-slate-50 hover:shadow"
        aria-label="Open cart"
        title="Open cart"
      >
        <ShoppingCart className="h-4 w-4" />
        <span>Cart</span>
        <span className="inline-flex h-5 min-w-5 items-center justify-center rounded-full bg-[#0F172A] px-1.5 text-[11px] font-bold leading-none text-white">
          <span
            className={`inline-flex transition-transform duration-200 ${
              animateCartBadge ? "scale-110" : "scale-100"
            }`}
          >
            {cartCount > 99 ? "99+" : cartCount}
          </span>
        </span>
      </button>
    </div>
  );

  // --------------------------------------------------------------------------
  // Render
  // --------------------------------------------------------------------------
  return (
    <DashboardLayout title="Customer Dashboard" topbarActions={topbarActions}>
      <div className="space-y-4 sm:space-y-5">
        {/* ------------------------------------------------------------------ */}
        {/* Row 1: Command bar                                                  */}
        {/* ------------------------------------------------------------------ */}
        <Card className="shadow-sm">
          <CardContent className="p-4 sm:p-5">
            <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
              <div className="relative w-full lg:max-w-xl">
                <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-400" />
                <input
                  value={filters.query}
                  onChange={(e) => setFiltersSafe({ query: e.target.value })}
                  placeholder="Search products, farmers, categories..."
                  className="h-11 w-full rounded-xl border bg-white py-2.5 pl-9 pr-3 text-sm outline-none ring-0 transition focus:border-gray-400"
                />
              </div>

              <div className="flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  onClick={() => setFiltersOpen((s) => !s)}
                  className="inline-flex h-11 items-center gap-2 rounded-xl border px-3 text-sm shadow-sm transition duration-200 hover:-translate-y-[1px] hover:bg-gray-50"
                >
                  <SlidersHorizontal className="h-4 w-4" />
                  Filters
                </button>

                <button
                  type="button"
                  onClick={() => {
                    loadData(true);
                    loadWeeklyTopFarmers();
                  }}
                  className="inline-flex h-11 items-center gap-2 rounded-xl border px-3 text-sm shadow-sm transition duration-200 hover:-translate-y-[1px] hover:bg-gray-50"
                  disabled={reloading || topFarmersLoading}
                >
                  <RefreshCw
                    className={`h-4 w-4 ${
                      reloading || topFarmersLoading ? "animate-spin" : ""
                    }`}
                  />
                  Refresh
                </button>
              </div>
            </div>

            {(likesLoading && !likesHydrated) || error ? (
              <div className="mt-3 space-y-2">
                {likesLoading && !likesHydrated ? (
                  <p className="text-xs text-gray-500">Loading your marketplace preferences…</p>
                ) : null}

                {error ? (
                  <p className="rounded-lg bg-red-50 px-3 py-2 text-sm text-red-700">{error}</p>
                ) : null}
              </div>
            ) : null}
          </CardContent>
        </Card>

        {/* ------------------------------------------------------------------ */}
        {/* Row 2: Explicit personalized feed tabs                             */}
        {/* ------------------------------------------------------------------ */}
        <Card className="shadow-sm">
          <CardContent className="p-3 sm:p-4">
            <div className="flex flex-wrap items-center gap-2">
              {CUSTOMER_FEEDS.map((feed) => {
                const active = activeFeed === feed.value;
                const count = feedCounts[feed.value] ?? 0;

                return (
                  <button
                    key={feed.value}
                    type="button"
                    onClick={() => setActiveFeed(feed.value)}
                    className={`inline-flex items-center gap-2 rounded-xl border px-3 py-2 text-sm font-semibold transition ${
                      active
                        ? "border-[#95D5B2] bg-[#F1FBF5] text-emerald-800 shadow-sm"
                        : "border-slate-200 bg-white text-slate-700 hover:bg-slate-50"
                    }`}
                    aria-pressed={active}
                  >
                    {feed.value === "liked" ? (
                      <span className="inline-flex h-4 min-w-4 items-center justify-center rounded-full bg-rose-50 px-1 text-[10px] font-bold text-rose-600">
                        ♥
                      </span>
                    ) : feed.value === "rated" ? (
                      <span className="inline-flex h-4 min-w-4 items-center justify-center rounded-full bg-amber-50 px-1 text-[10px] font-bold text-amber-600">
                        ★
                      </span>
                    ) : feed.value === "new" ? (
                      <span className="inline-flex h-4 min-w-4 items-center justify-center rounded-full bg-emerald-100 px-1 text-[10px] font-bold text-emerald-700">
                        N
                      </span>
                    ) : null}

                    <span>{feed.label}</span>

                    <span
                      className={`inline-flex min-w-6 items-center justify-center rounded-full px-1.5 py-0.5 text-[11px] font-bold ${
                        active
                          ? "bg-emerald-800 text-white"
                          : "bg-slate-100 text-slate-600"
                      }`}
                    >
                      {count}
                    </span>
                  </button>
                );
              })}
            </div>
          </CardContent>
        </Card>

        {/* ------------------------------------------------------------------ */}
        {/* Row 3: Feed summary                                                 */}
        {/* ------------------------------------------------------------------ */}
        <Card className="border border-slate-200 bg-gradient-to-r from-white to-slate-50 shadow-sm">
          <CardContent className="p-4 sm:p-5">
            <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <p className="text-base font-semibold text-slate-900">{feedMeta.title}</p>
                <p className="mt-1 text-sm text-slate-600">{feedMeta.description}</p>
              </div>

              <div className="inline-flex items-center rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm font-semibold text-slate-700 shadow-sm">
                {feedResultsLabel}
              </div>
            </div>
          </CardContent>
        </Card>

        {/* ------------------------------------------------------------------ */}
        {/* Row 4: Filters + product grid                                      */}
        {/* ------------------------------------------------------------------ */}
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-[280px,1fr]">
          <div className={`${filtersOpen ? "block" : "hidden"} lg:block`}>
            <CustomerFiltersSidebar
              showSearch={false}
              filters={filters}
              setFilters={setFiltersSafe}
              categories={categories}
              locations={locations}
              locationOptions={locations}
              selectedCategory={filters.category}
              onCategoryChange={(v) => setFiltersSafe({ category: v })}
              selectedLocation={filters.location}
              onLocationChange={(v) => setFiltersSafe({ location: v })}
              minPrice={filters.minPrice}
              maxPrice={filters.maxPrice}
              onMinPriceChange={(v) => setFiltersSafe({ minPrice: v })}
              onMaxPriceChange={(v) => setFiltersSafe({ maxPrice: v })}
              inStockOnly={filters.inStockOnly}
              onInStockOnlyChange={(v) => setFiltersSafe({ inStockOnly: !!v })}
              sortBy={filters.sort}
              onSortChange={(v) => setFiltersSafe({ sort: v })}
              onClear={clearFilters}
            />
          </div>

          {/* Product grid now renders only the current page slice, not the full
              filtered list. This keeps customer browsing shorter and cleaner. */}
          <div ref={catalogTopRef}>
            <ProductGrid
              products={paginatedProducts}
              loading={loading}
              activeFeed={activeFeed}
              onOpenQuickView={openQuickView}
              likedMap={likedByProduct}
              likeBusyByProduct={likeBusyByProduct}
              onToggleLike={toggleLikeProduct}
              myRatingsByProduct={myRatingsByProduct}
              ratingSummaryByProduct={ratingSummaryByProduct}
              isRecentProduct={isRecentProduct}
              onAddToCart={addToCart}
            />

            {!loading && totalFilteredProducts > 0 ? (
              <div className="mt-4 rounded-2xl border border-slate-200 bg-white px-4 py-3 shadow-sm">
                <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                  <div className="text-sm text-slate-600">
                    <span className="font-semibold text-slate-900">
                      Page {currentPageSafe}
                    </span>{" "}
                    of{" "}
                    <span className="font-semibold text-slate-900">
                      {totalPages}
                    </span>
                    <span className="mx-2 text-slate-300">•</span>
                    <span>{productsPerPage} per page on this screen</span>
                  </div>

                  <div className="flex flex-wrap items-center gap-2">
                    <button
                      type="button"
                      onClick={() => goToPage(currentPageSafe - 1)}
                      disabled={currentPageSafe <= 1}
                      className="inline-flex h-10 items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-700 transition hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-50"
                    >
                      <ChevronLeft className="h-4 w-4" />
                      Prev
                    </button>

                    {visiblePageNumbers.map((pageNum) => {
                      const active = pageNum === currentPageSafe;

                      return (
                        <button
                          key={pageNum}
                          type="button"
                          onClick={() => goToPage(pageNum)}
                          className={`inline-flex h-10 min-w-[40px] items-center justify-center rounded-xl border px-3 text-sm font-bold transition ${
                            active
                              ? "border-emerald-200 bg-emerald-50 text-emerald-800"
                              : "border-slate-200 bg-white text-slate-700 hover:bg-slate-50"
                          }`}
                          aria-current={active ? "page" : undefined}
                        >
                          {pageNum}
                        </button>
                      );
                    })}

                    <button
                      type="button"
                      onClick={() => goToPage(currentPageSafe + 1)}
                      disabled={currentPageSafe >= totalPages}
                      className="inline-flex h-10 items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-700 transition hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-50"
                    >
                      Next
                      <ChevronRight className="h-4 w-4" />
                    </button>
                  </div>
                </div>
              </div>
            ) : null}
          </div>
        </div>

        {/* ------------------------------------------------------------------ */}
        {/* Row 5: Marketplace insights                                        */}
        {/* ------------------------------------------------------------------ */}
        <Card className="border border-emerald-100 bg-gradient-to-br from-emerald-50/70 via-white to-sky-50/40 shadow-sm">
          <CardContent className="p-4 sm:p-5">
            <div className="mb-4 flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
              <div>
                <p className="inline-flex items-center gap-2 text-sm font-semibold text-emerald-800">
                  <Crown className="h-4 w-4" />
                  Marketplace Insights
                </p>
                <p className="mt-1 text-xs text-slate-600">
                  Weekly Top 3 Farmers for the last {topFarmersDays} days.
                </p>
              </div>

              <select
                value={topFarmersDays}
                onChange={(e) => setTopFarmersDays(Number(e.target.value))}
                className="h-9 rounded-lg border border-emerald-200 bg-white px-2.5 text-xs font-semibold text-emerald-800 shadow-sm outline-none"
                title="Select leaderboard time window"
              >
                <option value={7}>Last 7 days</option>
                <option value={30}>Last 30 days</option>
                <option value={90}>Last 90 days</option>
              </select>
            </div>

            {topFarmersError ? (
              <div className="rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-800">
                {topFarmersError}
              </div>
            ) : topFarmersLoading && !topFarmersHydrated ? (
              <div className="text-xs text-slate-500">Loading farmer rankings…</div>
            ) : weeklyTopFarmers.length === 0 ? (
              <div className="rounded-lg border border-slate-200 bg-white px-3 py-3 text-xs text-slate-600">
                Weekly top farmers coming soon.
              </div>
            ) : (
              <ul className="space-y-2.5">
                {weeklyTopFarmers.map((farmer, idx) => {
                  const topLabel = toPercentLabel(farmer.topPercent);
                  const isTop17 =
                    Number.isFinite(farmer.topPercent) &&
                    farmer.topPercent > 0 &&
                    farmer.topPercent <= 17;

                  const metricTextParts = [];
                  if (asNumber(farmer.orders, 0) > 0) {
                    metricTextParts.push(`${Math.round(farmer.orders)} orders`);
                  }
                  if (asNumber(farmer.revenue, 0) > 0) {
                    metricTextParts.push(`${money(farmer.revenue)} revenue`);
                  }

                  const updatedAtRaw = farmer.updatedAt ? new Date(farmer.updatedAt) : null;
                  const updatedLabel =
                    updatedAtRaw && !Number.isNaN(updatedAtRaw.getTime())
                      ? updatedAtRaw.toLocaleDateString()
                      : "";

                  return (
                    <li
                      key={`${farmer.id}-${idx}`}
                      className="rounded-xl border border-slate-200 bg-white p-3 shadow-[0_1px_0_rgba(15,23,42,0.03)]"
                    >
                      <div className="flex items-center justify-between gap-3">
                        <div className="min-w-0">
                          <p className="line-clamp-1 text-sm font-semibold text-slate-900">
                            #{idx + 1} {farmer.name}
                          </p>

                          <p className="mt-0.5 text-xs text-slate-600">
                            {farmer.location || "Location not set"} •{" "}
                            {formatRankOutOfTotal(
                              farmer.rank,
                              farmer.totalFarmers || weeklyTopFarmers.length
                            ) || `Rank #${farmer.rank}`}
                          </p>

                          <p className="mt-1 text-xs text-slate-500">
                            {metricTextParts.length
                              ? metricTextParts.join(" • ")
                              : "Performance snapshot updating…"}
                          </p>
                        </div>

                        <div className="flex flex-col items-end gap-1">
                          {topLabel ? (
                            <span
                              className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11px] font-semibold ${
                                isTop17
                                  ? "border-violet-200 bg-violet-50 text-violet-700"
                                  : "border-slate-200 bg-slate-50 text-slate-700"
                              }`}
                              title={isTop17 ? "Top 17% or better" : "Global rank percentile"}
                            >
                              <Trophy className="h-3 w-3" />
                              {topLabel}
                            </span>
                          ) : (
                            <span className="inline-flex items-center rounded-full border border-slate-200 bg-slate-50 px-2 py-0.5 text-[11px] font-semibold text-slate-700">
                              Rank #{farmer.rank}
                            </span>
                          )}
                        </div>
                      </div>

                      {updatedLabel ? (
                        <p className="mt-2 text-[10px] uppercase tracking-wide text-slate-400">
                          Updated: {updatedLabel}
                        </p>
                      ) : null}
                    </li>
                  );
                })}
              </ul>
            )}

            <div className="mt-3 text-[11px] text-slate-500">
              {topFarmersSource === "orders_revenue"
                ? "Source: orders + revenue signals."
                : topFarmersSource === "ratings_best_effort"
                  ? "Source: ratings-based best-effort fallback."
                  : "Source: coming soon."}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Full product interaction now happens in the quick-view layer */}
      <ProductQuickViewModal
        isOpen={quickViewOpen}
        product={quickViewProduct}
        triggerContext={quickViewContext}
        onClose={closeQuickView}
        liked={quickViewLiked}
        onToggleLike={toggleLikeProduct}
        myRating={quickViewMyRating}
        ratingSummary={quickViewRatingSummary}
        ratingBusy={quickViewRatingBusy}
        onRate={rateProduct}
        onAddToCart={(product, qty = 1) => {
          if (!product) return;

          // ------------------------------------------------------------------
          // QUICK VIEW FIX:
          // Add silently so the modal can close without immediately opening the
          // cart drawer. This avoids the "page froze / can't scroll" feeling.
          // ------------------------------------------------------------------
          addToCart(product, qty, { openCart: false });
        }}
        onViewFarmer={() => {
          const farmerId = quickViewProduct?.farmer_id ?? quickViewProduct?.farmer?.id;
          if (farmerId) navigate(`/dashboard/customer/farmers/${farmerId}`);
        }}
        onMessageFarmer={(product) => {
          const farmerId = product?.farmer_id ?? product?.farmer?.id;
          const productId = getProductId(product);
          const productName = getProductName(product);
          if (!farmerId) return;

          const params = new URLSearchParams();
          params.set("farmerId", String(farmerId));
          if (productId) params.set("productId", String(productId));
          if (productName) params.set("productName", String(productName));
          navigate(`/dashboard/customer/messages?${params.toString()}`);
        }}
      />

      {/* Cart drawer */}
      <CartDrawer
        isOpen={cartOpen}
        onClose={() => setCartOpen(false)}
        cartState={cartState}
        actions={actions}
        customerProfile={customerProfile}
        customerLocation={defaultCustomerLocation}
        onCheckoutSuccess={() => {
          loadData(true);
          loadWeeklyTopFarmers();
        }}
      />
    </DashboardLayout>
  );
}
