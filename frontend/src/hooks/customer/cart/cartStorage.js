// ============================================================================
// frontend/src/hooks/customer/cart/cartStorage.js
// ----------------------------------------------------------------------------
// FILE ROLE:
//   LocalStorage persistence + small utilities.
// ============================================================================

const KEY = "agroconnect_cart_v1";

export function safeArray(x) {
  return Array.isArray(x) ? x : [];
}

export function clampQty(qty) {
  const n = Number(qty);
  if (!Number.isFinite(n)) return 1;
  return Math.max(1, Math.round(n * 100) / 100);
}

export function loadLocalCart() {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return [];
    const arr = JSON.parse(raw);
    return safeArray(arr)
      .map((it) => ({
        productId: it?.productId ?? it?.product_id ?? it?.id ?? null,
        itemId: it?.itemId ?? it?.item_id ?? null,
        qty: clampQty(it?.qty ?? it?.quantity ?? 1),
        product: it?.product ?? null,
      }))
      .filter((x) => x.productId != null);
  } catch {
    return [];
  }
}

export function saveLocalCart(items) {
  try {
    const safe = safeArray(items);
    localStorage.setItem(KEY, JSON.stringify(safe));
  } catch {
    // ignore
  }
}
