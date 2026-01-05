// ============================================================================
// useCustomerAnalytics.js
// ----------------------------------------------------------------------------
// ROLE:
// • Tracks customer behavior
// • Provides simple analytics for dashboard insights
// ============================================================================

import { useMemo } from 'react';

export default function useCustomerAnalytics({ orders = [], lastViewed = [] }) {
  // --------------------------------------------------
  // Top viewed products
  // --------------------------------------------------
  const topViewed = useMemo(() => {
    const map = {};

    lastViewed.forEach((p) => {
      if (!p?.id) return;
      map[p.id] = (map[p.id] || 0) + 1;
    });

    return Object.entries(map)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([id, count]) => ({ id, views: count }));
  }, [lastViewed]);

  // --------------------------------------------------
  // Repeat purchases
  // --------------------------------------------------
  const repeatPurchases = useMemo(() => {
    const map = {};

    orders.forEach((o) => {
      if (!o?.product_id) return;
      map[o.product_id] = (map[o.product_id] || 0) + 1;
    });

    return Object.entries(map)
      .filter(([, count]) => count > 1)
      .map(([product_id, count]) => ({
        product_id,
        times: count,
      }));
  }, [orders]);

  return {
    topViewed,
    repeatPurchases,
  };
}
