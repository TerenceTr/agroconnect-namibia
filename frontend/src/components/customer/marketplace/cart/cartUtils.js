// ============================================================================
// frontend/src/components/customer/marketplace/cart/cartUtils.js
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Shared cart utilities (formatting + payload building + quantity policy).
//
// THIS UPDATE:
//   ✅ Adds clampQty() export (required by CartItemRow in some versions)
//   ✅ Keeps existing exports: money, qtyPolicyFromUnit, extractCartDisplayFields,
//      buildBaseOrderPayload.
// ============================================================================

export function money(v) {
  const n = Number(v);
  if (Number.isNaN(n) || !Number.isFinite(n)) return "0.00";
  return n.toFixed(2);
}

/**
 * Quantity policy by unit:
 *  - "kg", "g", "l", "ml" allow decimals
 *  - "each", "pack", etc default to integers
 */
export function qtyPolicyFromUnit(unitRaw) {
  const unit = String(unitRaw || "").toLowerCase().trim();

  if (["kg", "kilogram", "kilograms"].includes(unit)) return { min: 0.25, step: 0.25 };
  if (["g", "gram", "grams"].includes(unit)) return { min: 100, step: 50 };
  if (["l", "litre", "liter", "litres", "liters"].includes(unit)) return { min: 0.5, step: 0.5 };
  if (["ml"].includes(unit)) return { min: 250, step: 50 };

  // default: integer-style
  return { min: 1, step: 1 };
}

// ---------------------------------------------------------------------------
// clampQty — sanitize + snap quantity input to the unit policy
// ---------------------------------------------------------------------------
// Supports two common calling styles:
//
//   clampQty(rawQty, unitString, maxStock?)
//   clampQty(rawQty, {min, step}, maxStock?)
//
// Returns a number that is:
//   • >= policy.min
//   • aligned to policy.step
//   • <= maxStock (if provided)
// ---------------------------------------------------------------------------
export function clampQty(rawQty, unitOrPolicy, maxStock) {
  const policy =
    unitOrPolicy && typeof unitOrPolicy === "object"
      ? unitOrPolicy
      : qtyPolicyFromUnit(unitOrPolicy);

  const min = Number(policy?.min ?? 1);
  const step = Number(policy?.step ?? 1);

  let q = Number(rawQty);
  if (!Number.isFinite(q)) q = min;

  // Enforce min
  q = Math.max(q, min);

  // Snap to step
  const snapped = Math.round((q - min) / step) * step + min;

  // Fix floating artifacts
  let fixed = Number(snapped.toFixed(6));

  // Enforce maxStock if provided
  const max = Number(maxStock);
  if (Number.isFinite(max) && max >= 0) fixed = Math.min(fixed, max);

  if (!Number.isFinite(fixed)) fixed = min;
  return fixed;
}

export function extractCartDisplayFields(item) {
  const it = item || {};
  const p = it.product || it;

  const productId = it.product_id ?? it.productId ?? p.product_id ?? p.id;
  const name = p.name ?? it.name ?? "Product";
  const unit = p.unit ?? it.unit ?? "each";
  const price = Number(it.price ?? p.price ?? 0);
  const qty = Number(it.quantity ?? it.qty ?? 1);

  const farmerName =
    it.farmer_name ??
    p.farmer_name ??
    p.farmerName ??
    it.farmerName ??
    "";

  const stock = Number(p.quantity ?? p.stock ?? p.available_qty ?? NaN);

  return { productId, name, unit, price, qty, farmerName, stock };
}

export function buildBaseOrderPayload(items, totals) {
  // Keep payload minimal: backend splits by farmer as needed.
  const safeItems = Array.isArray(items) ? items : [];
  const safeTotals = totals || {};

  return {
    items: safeItems.map((it) => {
      const { productId, qty } = extractCartDisplayFields(it);
      return { product_id: productId, quantity: qty };
    }),
    totals: {
      subtotal: Number(safeTotals.subtotal ?? 0),
      deliveryFee: Number(safeTotals.deliveryFee ?? 0),
      vat: Number(safeTotals.vat ?? 0),
      total: Number(safeTotals.total ?? 0),
    },
  };
}
