// ============================================================================
// components/customer/ProductHighlights.jsx
// ----------------------------------------------------------------------------
// ROLE:
// • Shows "New products" and "Top-selling products"
// • Helps customers discover items quickly
// ============================================================================

import React from 'react';

export default function ProductHighlights({ title, items, onPick }) {
  return (
    <div className="glass-card p-6 rounded-2xl">
      <div className="flex items-center justify-between">
        <h3 className="font-semibold">{title}</h3>
      </div>

      {!items?.length ? (
        <div className="py-8 text-center text-white/70">Nothing to show yet.</div>
      ) : (
        <div className="mt-4 grid grid-cols-1 md:grid-cols-3 gap-3">
          {items.map((p) => (
            <button
              key={p.id}
              type="button"
              onClick={() => onPick?.(p)}
              className="p-3 rounded-xl bg-white/5 border border-white/10 hover:bg-white/10 text-left"
            >
              <div className="font-medium">{p.name}</div>
              <div className="text-xs text-white/60">{p.location || '—'}</div>
              <div className="mt-1 font-semibold">
                {Number(p.price || 0).toFixed(2)} N$
              </div>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
