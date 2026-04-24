// ============================================================================
// frontend/src/hooks/ai/useAiRecommend.js
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Hook to fetch AI product recommendations.
//   • getRecommendations({ buyer_id, recent_product_ids, k })
//   • Normalizes response shape into: { recommendations: [...] }
// ============================================================================

import { useState, useCallback } from "react";
import API from "./aiClient";

export function useAiRecommend() {
  const [loading, setLoading] = useState(false);
  const [recommendations, setRecommendations] = useState(null);
  const [error, setError] = useState(null);

  const getRecommendations = useCallback(
    async ({ buyer_id, recent_product_ids = [], k = 5 }) => {
      setLoading(true);
      setError(null);

      try {
        const { data } = await API.post("/recommend", {
          buyer_id,
          recent_product_ids,
          k,
        });

        // Normalize:
        // if backend returns { recommendations: [...] } keep it
        // else wrap array into the expected object
        const out =
          data?.recommendations != null ? data : { recommendations: data || [] };

        setRecommendations(out);
        return out;
      } catch (err) {
        const msg =
          err?.response?.data?.error ||
          err?.response?.data?.message ||
          err?.message ||
          "Recommendation failed";
        setError(msg);
        return null;
      } finally {
        setLoading(false);
      }
    },
    []
  );

  return { getRecommendations, recommendations, loading, error };
}
