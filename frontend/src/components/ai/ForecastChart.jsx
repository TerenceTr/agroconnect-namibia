// ============================================================================
// frontend/src/components/ai/ForecastChart.jsx
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Customer-facing AI forecast visualization.
//   • Calls AI forecast hook with (product_type, region, horizon_days)
//   • Renders a simple line chart using recharts
//   • Fully null-safe (won't crash if backend returns unexpected shape)
//
// UI NOTE:
//   This component is commonly rendered inside a parent <Card> already.
//   So we support a "readOnly" + "embed" style by keeping visuals minimal.
// ============================================================================

import React, { useEffect, useMemo } from "react";
import { Loader2, TrendingUp } from "lucide-react";

import { useAiForecast } from "../../hooks/ai/useAiForecast";

import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
} from "recharts";

function safeArray(x) {
  return Array.isArray(x) ? x : [];
}

export default function ForecastChart({
  product,
  region = null,
  horizon = 14,
  readOnly = false,
}) {
  const { getForecast, forecast, loading, error } = useAiForecast();

  // Accept product as string or object
  const productName = useMemo(() => {
    if (!product) return null;
    if (typeof product === "string") return product.trim() || null;
    return (product?.name || product?.title || "").trim() || null;
  }, [product]);

  useEffect(() => {
    if (!productName) return;

    getForecast({
      product_type: productName,
      region,
      horizon_days: horizon,
    });
  }, [productName, region, horizon, getForecast]);

  const points = useMemo(() => {
    // Common shapes:
    //   { daily_predictions: [{date, price}] }
    //   { predictions: [...] }
    //   [...] directly
    return safeArray(
      forecast?.daily_predictions || forecast?.predictions || forecast
    );
  }, [forecast]);

  return (
    <div className="space-y-3">
      {!readOnly && (
        <div className="flex items-center justify-between">
          <div className="inline-flex items-center gap-2">
            <TrendingUp className="h-4 w-4 text-emerald-700" />
            <div className="text-sm font-extrabold text-slate-900">
              {productName ? `${productName} Price Forecast` : "Forecast"}
            </div>
          </div>
          <div className="text-xs font-semibold text-slate-500">
            {horizon} days
          </div>
        </div>
      )}

      <div className="rounded-2xl border border-slate-200 bg-white p-3">
        {loading && (
          <div className="flex items-center justify-center py-10">
            <Loader2 className="h-6 w-6 animate-spin text-emerald-600" />
          </div>
        )}

        {!loading && error && (
          <div className="text-rose-700 text-sm py-4 text-center">
            {String(error)}
          </div>
        )}

        {!loading && !error && points.length === 0 && (
          <div className="text-slate-500 text-sm py-6 text-center">
            No forecast available — select a product to generate a forecast.
          </div>
        )}

        {!loading && !error && points.length > 0 && (
          <div className="w-full h-64">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={points}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="date" tick={{ fontSize: 12 }} />
                <YAxis tick={{ fontSize: 12 }} />
                <Tooltip />
                <Line
                  type="monotone"
                  dataKey="price"
                  stroke="#10B981"
                  strokeWidth={3}
                  dot={false}
                />
              </LineChart>
            </ResponsiveContainer>

            <div className="text-xs text-slate-500 mt-2 text-right">
              {forecast?.from_cache ? "Loaded from cache" : "Generated fresh"}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
