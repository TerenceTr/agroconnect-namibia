// ============================================================================
// frontend/src/hooks/customer/cart/cartMath.js
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Totals computation.
//   Matches your UI screenshot:
//   • VAT = 15% of subtotal ONLY
//   • Delivery fee = fixed N$30 if cart not empty
// ============================================================================

import { safeArray } from "./cartStorage";

const VAT_RATE = 0.15;
const DELIVERY_FEE = 30;

function toNum(x) {
  const n = Number(x);
  return Number.isFinite(n) ? n : 0;
}

export function computeTotals(items) {
  const list = safeArray(items);

  const subtotal = list.reduce((sum, it) => {
    const p = it?.product || it;
    const price = toNum(p?.price ?? it?.price ?? it?.unit_price ?? 0);
    const qty = toNum(it?.qty ?? it?.quantity ?? 1);
    return sum + price * qty;
  }, 0);

  const deliveryFee = subtotal > 0 ? DELIVERY_FEE : 0;
  const vat = subtotal * VAT_RATE;
  const total = subtotal + deliveryFee + vat;

  return {
    subtotal,
    deliveryFee,
    vat,
    total,
  };
}
