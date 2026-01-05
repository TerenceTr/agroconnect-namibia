// ============================================================================
// components/customer/ProductDetailsPanel.jsx
// ----------------------------------------------------------------------------
// ROLE:
// • Product details + follow/unfollow + add-to-cart
// • Read-only AI insights (customers consume AI outputs, don't trigger models)
// • SMS alerts opt-in UI can remain here if you want later
// ============================================================================

import React, { useMemo, useState } from 'react';
import { Star, StarOff, ShoppingCart } from 'lucide-react';

// AI components (existing in your project)
import ForecastChart from '../../components/ai/ForecastChart';
import RecommendationList from '../../components/ai/RecommendationList';
import SmsSender from '../../components/ai/SmsSender';

export default function ProductDetailsPanel({
  product,
  isFollowed,
  onFollow,
  onUnfollow,
  onAddToCart,
  customerId,
}) {
  const [qty, setQty] = useState(1);

  const safeQty = useMemo(() => {
    const n = Number(qty);
    if (!Number.isFinite(n) || n <= 0) return 1;
    return Math.min(999, Math.floor(n));
  }, [qty]);

  if (!product) {
    return (
      <div className="glass-card p-6 rounded-2xl">
        <div className="text-white/70 text-center py-10">
          Select a product to view details and AI insights.
        </div>
      </div>
    );
  }

  return (
    <div className="glass-card p-6 rounded-2xl space-y-6">
      {/* Title */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold">{product.name}</h2>
          <p className="text-white/70 text-sm">
            {product.location || '—'} {product.region ? `• ${product.region}` : ''}
          </p>
        </div>

        <div className="text-right">
          <div className="text-2xl font-extrabold">
            {Number(product.price || 0).toFixed(2)} N$
          </div>
          {product.stock != null && (
            <div className="text-xs text-white/60 mt-1">Stock: {product.stock}</div>
          )}
        </div>
      </div>

      {/* Actions */}
      <div className="flex flex-col md:flex-row gap-3 md:items-center md:justify-between">
        <div className="flex gap-3">
          {!isFollowed ? (
            <button
              type="button"
              onClick={onFollow}
              className="px-4 py-2 rounded-lg bg-white/10 hover:bg-white/15 border border-white/10 inline-flex items-center gap-2"
            >
              <Star size={18} /> Follow
            </button>
          ) : (
            <button
              type="button"
              onClick={onUnfollow}
              className="px-4 py-2 rounded-lg bg-red-500/15 hover:bg-red-500/25 border border-red-500/20 inline-flex items-center gap-2 text-red-200"
            >
              <StarOff size={18} /> Unfollow
            </button>
          )}
        </div>

        <div className="flex gap-2 items-center">
          <input
            type="number"
            min={1}
            value={qty}
            onChange={(e) => setQty(e.target.value)}
            className="w-24 px-3 py-2 rounded-lg bg-white/10 border border-white/10 text-white outline-none"
          />
          <button
            type="button"
            onClick={() => onAddToCart(product.id, safeQty)}
            className="px-4 py-2 rounded-lg bg-emerald-500 hover:bg-emerald-600 font-semibold inline-flex items-center gap-2"
          >
            <ShoppingCart size={18} />
            Add to cart
          </button>
        </div>
      </div>

      {/* Read-only AI forecast */}
      <div className="rounded-2xl bg-white/5 border border-white/10 p-4">
        <h3 className="font-semibold mb-3">AI Price Forecast (Read-only)</h3>
        <ForecastChart product={product} readOnly />
      </div>

      {/* Recommendations based on searches/orders (AI optional in backend) */}
      <div className="rounded-2xl bg-white/5 border border-white/10 p-4">
        <h3 className="font-semibold mb-3">Recommendations</h3>
        <RecommendationList customerId={customerId} productId={product.id} />
      </div>

      {/* SMS / email market alerts (subscription UI) */}
      <div className="rounded-2xl bg-white/5 border border-white/10 p-4">
        <h3 className="font-semibold mb-3">Market Alerts</h3>
        <SmsSender productName={product.name} />
      </div>
    </div>
  );
}
