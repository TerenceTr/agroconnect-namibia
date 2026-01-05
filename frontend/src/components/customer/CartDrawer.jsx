// ============================================================================
// components/customer/CartDrawer.jsx
// ----------------------------------------------------------------------------
// ROLE:
// • Cart panel (drawer-style card)
// • Displays cart items, quantity controls, subtotal
//
// FIXES:
// • Added PropTypes to resolve ESLint validation errors
// • Defensive defaults for cart + totals
//
// MSc VALUE:
// • Explicit interface contracts
// • Safer component boundaries
// ============================================================================

import React from 'react';
import PropTypes from 'prop-types';
import { Minus, Plus, Trash2 } from 'lucide-react';

export default function CartDrawer({
  cart,
  totals,
  onInc,
  onDec,
  onRemove,
  onClear,
}) {
  // --------------------------------------------------------------------------
  // Defensive defaults (prevents runtime crashes)
  // --------------------------------------------------------------------------
  const items = Array.isArray(cart?.items) ? cart.items : [];
  const subtotal =
    typeof totals?.subtotal === 'number' ? totals.subtotal : 0;

  return (
    <div className="glass-card p-6 rounded-2xl">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h3 className="font-semibold">Cart</h3>

        <button
          type="button"
          onClick={onClear}
          disabled={!items.length}
          className="text-sm text-white/70 hover:text-white disabled:opacity-40"
        >
          Clear
        </button>
      </div>

      {/* Empty state */}
      {items.length === 0 ? (
        <div className="py-8 text-center text-white/70">
          Your cart is empty.
        </div>
      ) : (
        <>
          {/* Items */}
          <div className="mt-4 space-y-3">
            {items.map((it) => (
              <div
                key={it.id}
                className="p-3 rounded-xl bg-white/5 border border-white/10 flex items-center justify-between gap-3"
              >
                {/* Product info */}
                <div>
                  <div className="font-medium">
                    {it.product_name || 'Product'}
                  </div>
                  <div className="text-xs text-white/60">
                    {Number(it.unit_price || 0).toFixed(2)} N$ each
                  </div>
                </div>

                {/* Quantity controls */}
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    className="p-2 rounded-lg bg-white/10 hover:bg-white/15"
                    onClick={() => onDec(it)}
                    aria-label="Decrease quantity"
                  >
                    <Minus size={16} />
                  </button>

                  <div className="w-8 text-center">{it.qty}</div>

                  <button
                    type="button"
                    className="p-2 rounded-lg bg-white/10 hover:bg-white/15"
                    onClick={() => onInc(it)}
                    aria-label="Increase quantity"
                  >
                    <Plus size={16} />
                  </button>

                  <button
                    type="button"
                    className="p-2 rounded-lg bg-red-500/15 hover:bg-red-500/25 text-red-200"
                    onClick={() => onRemove(it)}
                    aria-label="Remove item"
                  >
                    <Trash2 size={16} />
                  </button>
                </div>
              </div>
            ))}
          </div>

          {/* Subtotal */}
          <div className="pt-3 mt-3 border-t border-white/10 flex items-center justify-between">
            <span className="text-white/70">Subtotal</span>
            <span className="font-semibold">
              {subtotal.toFixed(2)} N$
            </span>
          </div>
        </>
      )}
    </div>
  );
}

// ============================================================================
// PropTypes — fixes ESLint validation errors
// ============================================================================
CartDrawer.propTypes = {
  cart: PropTypes.shape({
    items: PropTypes.arrayOf(
      PropTypes.shape({
        id: PropTypes.oneOfType([PropTypes.string, PropTypes.number])
          .isRequired,
        product_name: PropTypes.string,
        unit_price: PropTypes.number,
        qty: PropTypes.number.isRequired,
      })
    ),
  }).isRequired,

  totals: PropTypes.shape({
    subtotal: PropTypes.number.isRequired,
  }).isRequired,

  onInc: PropTypes.func.isRequired,
  onDec: PropTypes.func.isRequired,
  onRemove: PropTypes.func.isRequired,
  onClear: PropTypes.func.isRequired,
};
