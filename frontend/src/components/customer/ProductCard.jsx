// ============================================================================
// components/customer/ProductCard.jsx
// ----------------------------------------------------------------------------
// ROLE:
// • Small reusable product tile (used in grids)
// ============================================================================

import React from 'react';

export default function ProductCard({ product, active, onClick }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={[
        'text-left rounded-xl p-4 transition border',
        'bg-white/5 hover:bg-white/10 border-white/10',
        active ? 'ring-2 ring-emerald-400/60' : '',
      ].join(' ')}
    >
      <div className="flex items-start justify-between gap-3">
        <div>
          <h4 className="font-semibold">{product?.name || 'Unnamed product'}</h4>
          <p className="text-sm text-white/70">{product?.location || '—'}</p>
          {!!product?.type && (
            <p className="text-xs text-white/60 mt-1">{product.type}</p>
          )}
        </div>

        <div className="text-right">
          <div className="font-bold">{Number(product?.price || 0).toFixed(2)} N$</div>
          {!!product?.stock && (
            <div className="text-xs text-white/60 mt-1">Stock: {product.stock}</div>
          )}
        </div>
      </div>
    </button>
  );
}
