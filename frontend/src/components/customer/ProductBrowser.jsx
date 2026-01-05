// ============================================================================
// components/customer/ProductBrowser.jsx
// ----------------------------------------------------------------------------
// ROLE:
// • Search + filter products
// • Keeps CustomerDashboard clean and focused
// ============================================================================

import React, { useMemo, useState } from 'react';
import PropTypes from 'prop-types';
import { Search } from 'lucide-react';
import ProductGrid from './ProductGrid';

export default function ProductBrowser({
  products,
  loading,
  onSelect,
  selectedId,
  initialFilters,
}) {
  const [q, setQ] = useState(initialFilters.q || '');
  const [region, setRegion] = useState(initialFilters.region || 'all');
  const [type, setType] = useState(initialFilters.type || 'all');

  const filtered = useMemo(() => {
    const query = q.trim().toLowerCase();

    return products.filter((p) => {
      const okQ =
        !query ||
        p.name?.toLowerCase().includes(query) ||
        p.location?.toLowerCase().includes(query);

      const okRegion =
        region === 'all' ||
        String(p.region || '').toLowerCase() === region;

      const okType =
        type === 'all' ||
        String(p.type || '').toLowerCase() === type;

      return okQ && okRegion && okType;
    });
  }, [products, q, region, type]);

  return (
    <div className="glass-card p-6 rounded-2xl">
      <div className="flex flex-col md:flex-row justify-between gap-4">
        <div className="flex items-center gap-2">
          <Search />
          <h3 className="font-semibold">Browse Products</h3>
        </div>

        <div className="flex gap-3 flex-wrap">
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search by name or location"
            className="px-3 py-2 rounded-lg bg-white/10 border border-white/10 text-white"
          />

          <select
            value={region}
            onChange={(e) => setRegion(e.target.value)}
            className="px-3 py-2 rounded-lg bg-white/10 border border-white/10 text-white"
          >
            <option value="all">All regions</option>
            <option value="north">North</option>
            <option value="central">Central</option>
            <option value="south">South</option>
          </select>

          <select
            value={type}
            onChange={(e) => setType(e.target.value)}
            className="px-3 py-2 rounded-lg bg-white/10 border border-white/10 text-white"
          >
            <option value="all">All types</option>
            <option value="vegetable">Vegetables</option>
            <option value="fruit">Fruits</option>
            <option value="grain">Grains</option>
            <option value="livestock">Livestock</option>
          </select>
        </div>
      </div>

      {loading ? (
        <div className="py-10 text-center text-white/70">
          Loading products…
        </div>
      ) : (
        <ProductGrid
          products={filtered}
          selectedId={selectedId}
          onSelect={onSelect}
        />
      )}
    </div>
  );
}

ProductBrowser.propTypes = {
  products: PropTypes.array.isRequired,
  loading: PropTypes.bool.isRequired,
  onSelect: PropTypes.func.isRequired,
  selectedId: PropTypes.oneOfType([PropTypes.string, PropTypes.number]),
  initialFilters: PropTypes.shape({
    q: PropTypes.string,
    region: PropTypes.string,
    type: PropTypes.string,
  }),
};

ProductBrowser.defaultProps = {
  initialFilters: {},
};
