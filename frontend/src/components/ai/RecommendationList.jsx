// ============================================================================
// frontend/src/components/ai/RecommendationList.jsx
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Display AI recommended products as a lightweight, non-clutter list.
//   • Safe across backend shapes (IDs only vs {product_id, score})
//   • No heavy UI: this is usually nested inside a section already
//
// FIX:
//   ✅ Adds getRecommendations to useEffect dependency list.
// ============================================================================

import React, { useEffect, useMemo } from "react";
import { Loader2, Sparkles } from "lucide-react";
import { useAiRecommend } from "../../hooks/ai/useAiRecommend";

function safeArray(x) {
  return Array.isArray(x) ? x : [];
}

export default function RecommendationList({
  customerId = null,
  productId = null,
  recentProductIds = [],
  limit = 5,
}) {
  const { getRecommendations, recommendations, loading, error } = useAiRecommend();

  const recent = useMemo(() => {
    const base = safeArray(recentProductIds);
    if (productId != null && !base.includes(productId)) {
      return [productId, ...base].slice(0, 10);
    }
    return base.slice(0, 10);
  }, [recentProductIds, productId]);

  useEffect(() => {
    if (!customerId) return;

    getRecommendations({
      buyer_id: customerId,
      recent_product_ids: recent,
      k: limit,
    });
  }, [customerId, recent, limit, getRecommendations]);

  const list = useMemo(() => {
    // shapes:
    // { recommendations: [...] }
    // [...] directly
    if (!recommendations) return [];
    return safeArray(recommendations?.recommendations || recommendations);
  }, [recommendations]);

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <Sparkles className="h-4 w-4 text-emerald-700" />
        <div className="text-sm font-extrabold text-slate-900">Recommended Products</div>
        <div className="text-xs text-slate-500 font-semibold">Top {limit}</div>
      </div>

      <div className="rounded-2xl border border-slate-200 bg-white p-3">
        {loading && (
          <div className="flex justify-center py-8">
            <Loader2 className="h-6 w-6 animate-spin text-emerald-600" />
          </div>
        )}

        {!loading && error && (
          <div className="text-rose-700 text-sm py-4 text-center">{String(error)}</div>
        )}

        {!loading && !error && list.length === 0 && (
          <div className="text-slate-500 text-sm py-4 text-center">
            No recommendations yet.
          </div>
        )}

        {!loading && !error && list.length > 0 && (
          <ul className="space-y-2">
            {list.map((rec, idx) => {
              const pid = rec?.product_id ?? rec?.id ?? rec ?? `rec-${idx}`;
              const score = rec?.score ?? rec?.confidence ?? null;

              return (
                <li
                  key={String(pid)}
                  className="flex items-center justify-between rounded-2xl border border-slate-200 bg-slate-50 px-3 py-2"
                >
                  <div className="text-sm font-semibold text-slate-900">Product #{pid}</div>
                  {score != null && Number.isFinite(Number(score)) && (
                    <div className="text-xs font-semibold text-slate-600">
                      Score: {Number(score).toFixed(3)}
                    </div>
                  )}
                </li>
              );
            })}
          </ul>
        )}
      </div>
    </div>
  );
}
