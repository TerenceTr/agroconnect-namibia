// ============================================================================
// frontend/src/pages/dashboards/farmer/dashboard/useFarmerDashboardData.js
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Data fetching + derived computations for FarmerDashboard.
//
// RESPONSIBILITIES:
//   • Fetch products, orders, ratings (best-effort)
//   • Filter products by farmer ownership (multiple schema support)
//   • Derive salesOrders, KPIs, pipeline counts, top lists
//   • Expose a single refetchAll() for the UI
// ============================================================================

import { useMemo } from "react";
import { subDays, isAfter } from "date-fns";

// IMPORTANT: this file is inside .../farmer/dashboard/, so we go up 4 levels to /src
import useApi from "../../../../hooks/useApi";

import {
  getOrderProductId,
  getOrderTotal,
  getProductId,
  getProductName,
  getProductOwnerId,
  normalizeFulfillmentStatus,
  normalizePaymentStatus,
  pickDate,
  toNumber,
} from "./utils";

export function useFarmerDashboardData({
  farmerId,
  days,
  query,
  statusFocus,
  paymentFocus,
  lowStockThreshold = 5,
}) {
  // ----------------------------
  // Fetching (best-effort)
  // ----------------------------
  const productsReq = useApi("/products");
  const ordersReq = useApi("/orders");
  const ratingsReq = useApi("/ratings"); // if 404, UI explains how to add endpoint

  const { data: productsData, loading: productsLoading, error: productsError, refetch: refetchProducts } =
    productsReq;

  const { data: ordersData, loading: ordersLoading, error: ordersError, refetch: refetchOrders } =
    ordersReq;

  const { data: ratingsData, loading: ratingsLoading, error: ratingsError, refetch: refetchRatings } =
    ratingsReq;

  // ----------------------------
  // Normalize arrays
  // ----------------------------
  const allProducts = useMemo(() => {
    const raw = productsData?.items ?? productsData ?? [];
    return Array.isArray(raw) ? raw : [];
  }, [productsData]);

  const allOrders = useMemo(() => {
    const raw = ordersData?.items ?? ordersData ?? [];
    return Array.isArray(raw) ? raw : [];
  }, [ordersData]);

  const allRatings = useMemo(() => {
    const raw = ratingsData?.items ?? ratingsData ?? [];
    return Array.isArray(raw) ? raw : [];
  }, [ratingsData]);

  // ----------------------------
  // Farmer products
  // ----------------------------
  const farmerProducts = useMemo(() => {
    if (!farmerId) return [];
    return allProducts.filter((p) => String(getProductOwnerId(p)) === String(farmerId));
  }, [allProducts, farmerId]);

  const farmerProductIds = useMemo(() => {
    const ids = farmerProducts.map(getProductId).filter(Boolean).map(String);
    return new Set(ids);
  }, [farmerProducts]);

  // ----------------------------
  // Search query
  // ----------------------------
  const q = String(query || "").trim().toLowerCase();

  const products = useMemo(() => {
    if (!q) return farmerProducts;
    return farmerProducts.filter((p) => getProductName(p).toLowerCase().includes(q));
  }, [farmerProducts, q]);

  // ----------------------------
  // Sales orders (best-effort)
  // ----------------------------
  const salesOrders = useMemo(() => {
    if (!allOrders.length) return [];

    // 1) If backend returns seller/farmer fields on the order, use them
    const direct = allOrders.filter((o) => {
      const seller =
        o?.farmer_id ||
        o?.seller_id ||
        o?.user_id ||
        o?.owner_id ||
        o?.product?.user_id ||
        null;
      return seller != null && String(seller) === String(farmerId);
    });

    if (direct.length) return direct;

    // 2) Otherwise, filter by product ids owned by farmer
    if (farmerProductIds.size) {
      const byProduct = allOrders.filter((o) => {
        const pid = getOrderProductId(o);
        return pid != null && farmerProductIds.has(String(pid));
      });
      if (byProduct.length) return byProduct;
    }

    // 3) Fallback: show whatever /orders returned (better than empty)
    return allOrders;
  }, [allOrders, farmerId, farmerProductIds]);

  // If /orders seems to be buyer-only orders, show a warning in UI
  const looksLikeBuyerOrders =
    allOrders.length > 0 && farmerProductIds.size > 0 && salesOrders === allOrders;

  // Apply search on orders (name/buyer)
  const searchedOrders = useMemo(() => {
    if (!q) return salesOrders;
    return salesOrders.filter((o) => {
      const pn = String(o?.product_name || o?.product?.product_name || "").toLowerCase();
      const bn = String(o?.buyer_name || o?.buyer?.full_name || "").toLowerCase();
      return pn.includes(q) || bn.includes(q);
    });
  }, [salesOrders, q]);

  // Time window filter
  const timeFilteredOrders = useMemo(() => {
    if (!searchedOrders.length) return [];
    const cutoff = subDays(new Date(), days);
    return searchedOrders.filter((o) => {
      const d = pickDate(o);
      return d ? isAfter(d, cutoff) : false;
    });
  }, [searchedOrders, days]);

  // Status + payment filters (interactive)
  const filteredOrders = useMemo(() => {
    return timeFilteredOrders.filter((o) => {
      const f = normalizeFulfillmentStatus(o);
      const p = normalizePaymentStatus(o);
      const okStatus = statusFocus === "all" ? true : f === statusFocus;
      const okPay = paymentFocus === "all" ? true : p === paymentFocus;
      return okStatus && okPay;
    });
  }, [timeFilteredOrders, statusFocus, paymentFocus]);

  // ----------------------------
  // KPIs
  // ----------------------------
  const revenue = useMemo(() => {
    return filteredOrders.reduce((sum, o) => sum + getOrderTotal(o), 0);
  }, [filteredOrders]);

  const avgOrder = useMemo(() => {
    if (!filteredOrders.length) return 0;
    return revenue / filteredOrders.length;
  }, [revenue, filteredOrders.length]);

  const pendingCount = useMemo(() => {
    return timeFilteredOrders.filter((o) => normalizeFulfillmentStatus(o) === "pending").length;
  }, [timeFilteredOrders]);

  const lowStockCount = useMemo(() => {
    return products.filter((p) => toNumber(p?.quantity ?? 0, 0) <= lowStockThreshold).length;
  }, [products, lowStockThreshold]);

  // Pipeline counts (use timeFilteredOrders so totals remain visible)
  const pipeline = useMemo(() => {
    const base = timeFilteredOrders;
    const counts = { pending: 0, in_progress: 0, delivered: 0, cancelled: 0 };
    const pays = { paid: 0, unpaid: 0, unknown: 0 };

    for (const o of base) {
      counts[normalizeFulfillmentStatus(o)] += 1;
      pays[normalizePaymentStatus(o)] += 1;
    }

    return { counts, pays, total: base.length };
  }, [timeFilteredOrders]);

  // Top products (demo-friendly: by stock)
  const topProducts = useMemo(() => {
    const copy = [...products];
    copy.sort((a, b) => {
      const aq = toNumber(a?.quantity ?? 0, 0);
      const bq = toNumber(b?.quantity ?? 0, 0);
      if (bq !== aq) return bq - aq;
      const ad = pickDate(a) || new Date(0);
      const bd = pickDate(b) || new Date(0);
      return bd.getTime() - ad.getTime();
    });
    return copy.slice(0, 5);
  }, [products]);

  const recentOrders = useMemo(() => {
    const copy = [...filteredOrders];
    copy.sort((a, b) => (pickDate(b)?.getTime() ?? 0) - (pickDate(a)?.getTime() ?? 0));
    return copy.slice(0, 8);
  }, [filteredOrders]);

  // ----------------------------
  // Ratings for farmer products
  // ----------------------------
  const myRatings = useMemo(() => {
    if (!allRatings.length || !farmerProductIds.size) return [];
    return allRatings.filter((r) => farmerProductIds.has(String(r?.product_id)));
  }, [allRatings, farmerProductIds]);

  const avgRating = useMemo(() => {
    if (!myRatings.length) return 0;
    const sum = myRatings.reduce(
      (acc, r) => acc + toNumber(r?.rating_score ?? r?.rating ?? 0, 0),
      0
    );
    return sum / myRatings.length;
  }, [myRatings]);

  const ratingDistribution = useMemo(() => {
    const dist = { 5: 0, 4: 0, 3: 0, 2: 0, 1: 0 };
    for (const r of myRatings) {
      const v = Math.round(toNumber(r?.rating_score ?? r?.rating ?? 0, 0));
      if (v >= 1 && v <= 5) dist[v] += 1;
    }
    return dist;
  }, [myRatings]);

  const recentFeedback = useMemo(() => {
    const copy = [...myRatings];
    copy.sort((a, b) => (pickDate(b)?.getTime() ?? 0) - (pickDate(a)?.getTime() ?? 0));
    // Prefer comments first
    copy.sort(
      (a, b) => String(b?.comment || "").trim().length - String(a?.comment || "").trim().length
    );
    return copy.slice(0, 6);
  }, [myRatings]);

  const refetchAll = async () => {
    await Promise.allSettled([refetchProducts(), refetchOrders(), refetchRatings()]);
  };

  return {
    // request states
    productsLoading,
    ordersLoading,
    ratingsLoading,
    productsError,
    ordersError,
    ratingsError,
    refetchAll,

    // derived lists
    products,
    timeFilteredOrders,
    filteredOrders,
    pipeline,
    topProducts,
    recentOrders,

    // KPIs
    revenue,
    avgOrder,
    pendingCount,
    lowStockCount,

    // feedback
    myRatings,
    avgRating,
    ratingDistribution,
    recentFeedback,

    // warnings
    looksLikeBuyerOrders,
  };
}
