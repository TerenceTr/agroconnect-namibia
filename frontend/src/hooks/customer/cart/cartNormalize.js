// ============================================================================
// frontend/src/hooks/customer/cart/cartNormalize.js
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Normalize backend cart item responses into the local cart shape.
// ============================================================================

import { clampQty } from "./cartStorage";

export function normalizeBackendCartItem(it) {
  if (!it || typeof it !== "object") return null;

  const productId =
    it.productId ??
    it.product_id ??
    it.product?.id ??
    it.product?.product_id ??
    it.id?.product_id ?? // rare
    null;

  const itemId = it.itemId ?? it.item_id ?? it.id ?? null;

  const qty = clampQty(it.qty ?? it.quantity ?? 1);

  const product = it.product ?? it.product_snapshot ?? null;

  return { productId, itemId, qty, product };
}
