// ============================================================================
// components/customer/ProductGrid.jsx
// ----------------------------------------------------------------------------
// ROLE:
// • Renders the filtered products list
// ============================================================================

import React from 'react';
import ProductCard from './ProductCard';

export default function ProductGrid({ products, selectedId, onSelect }) {
  if (!products?.length) {
    return <div className="text-white/70 py-8 text-center">No products found.</div>;
  }

  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-5">
      {products.map((p) => (
        <ProductCard
          key={p.id}
          product={p}
          active={String(selectedId) === String(p.id)}
          onClick={() => onSelect(p)}
        />
      ))}
    </div>
  );
}
