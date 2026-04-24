// ============================================================================
// frontend/src/hooks/ai/useAiForecast.js
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Hook to fetch AI forecast data from the backend.
//   • Exposes getForecast({ product_type, region, horizon_days })
//   • Returns { forecast, loading, error }
//   • Null-safe error extraction
// ============================================================================

import { useState, useCallback } from "react";
import API from "./aiClient";

export function useAiForecast() {
  const [loading, setLoading] = useState(false);
  const [forecast, setForecast] = useState(null);
  const [error, setError] = useState(null);

  const getForecast = useCallback(
    async ({ product_type, region, horizon_days = 14 }) => {
      setLoading(true);
      setError(null);

      try {
        const { data } = await API.post("/forecast", {
          product_type,
          region,
          horizon_days,
        });

        setForecast(data);
        return data;
      } catch (err) {
        const msg =
          err?.response?.data?.error ||
          err?.response?.data?.message ||
          err?.message ||
          "Forecast failed";
        setError(msg);
        return null;
      } finally {
        setLoading(false);
      }
    },
    []
  );

  return { getForecast, forecast, loading, error };
}
