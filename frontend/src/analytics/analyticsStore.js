// ============================================================================
// src/analytics/analyticsStore.js
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Lightweight client-side analytics (no backend required).
//   • Tracks: product views, last viewed timestamp, purchases per product
//   • Stores to localStorage so it survives reloads
//   • Can be mirrored to backend later (see analyticsApi.js)
// ============================================================================

const KEY = "agroconnect_analytics_v1";

/** Safe JSON parse with fallback (prevents app break if storage is corrupted). */
function safeParse(json, fallback) {
  try {
    const v = JSON.parse(json);
    return v && typeof v === "object" ? v : fallback;
  } catch {
    return fallback;
  }
}

function nowISO() {
  return new Date().toISOString();
}

export function readAnalytics() {
  const base = {
    views: {}, // { [productId]: number }
    lastViewed: {}, // { [productId]: ISOString }
    purchases: {}, // { [productId]: number }
    orders: [], // [{ id, created_at, items:[{product_id, qty}]}]
  };

  const raw = localStorage.getItem(KEY);
  return raw ? safeParse(raw, base) : base;
}

export function writeAnalytics(next) {
  localStorage.setItem(KEY, JSON.stringify(next));
}

export function trackProductView(product) {
  if (!product || product.id == null) return;

  const a = readAnalytics();
  const id = String(product.id);

  a.views[id] = (a.views[id] || 0) + 1;
  a.lastViewed[id] = nowISO();

  writeAnalytics(a);
}

export function trackOrderCreated(order) {
  // Expected: { id, created_at, items: [{ product_id, qty }] }
  if (!order) return;

  const a = readAnalytics();

  const items = Array.isArray(order.items) ? order.items : [];
  items.forEach((it) => {
    const pid = String(it.product_id);
    a.purchases[pid] = (a.purchases[pid] || 0) + 1;
  });

  a.orders.unshift({
    id: order.id || order.order_id || `local-${Date.now()}`,
    created_at: order.created_at || nowISO(),
    items: items.map((it) => ({ product_id: it.product_id, qty: it.qty })),
  });

  // Keep last 100 only
  a.orders = a.orders.slice(0, 100);

  writeAnalytics(a);
}

export function computeCustomerAnalytics(products = []) {
  const a = readAnalytics();

  const rows = products.map((p) => {
    const id = String(p.id);
    return {
      product_id: id,
      name: p.name || `Product ${id}`,
      views: a.views[id] || 0,
      lastViewedAt: a.lastViewed[id] || null,
      purchases: a.purchases[id] || 0,
    };
  });

  const topViewed = [...rows]
    .sort((x, y) => (y.views || 0) - (x.views || 0))
    .slice(0, 10);

  const repeatPurchases = rows
    .filter((x) => (x.purchases || 0) >= 2)
    .sort((x, y) => (y.purchases || 0) - (x.purchases || 0))
    .slice(0, 10);

  return { topViewed, repeatPurchases, raw: rows };
}
