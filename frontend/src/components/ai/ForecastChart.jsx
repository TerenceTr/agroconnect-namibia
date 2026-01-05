// src/components/ai/ForecastChart.jsx
import React, { useEffect } from "react";

// Correct path: src/components/ui/Card.jsx
import { Card, CardHeader, CardTitle, CardContent } from "../ui/Card";

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

export default function ForecastChart({ product, region = null, horizon = 14 }) {
  const { getForecast, forecast, loading, error } = useAiForecast();

  // Accept product as string or object
  const productName = product
    ? typeof product === "string"
      ? product
      : product.name || product.title || ""
    : null;

  useEffect(() => {
    if (productName) {
      getForecast({
        product_type: productName,
        region,
        horizon_days: horizon,
      });
    }
  }, [productName, region, horizon, getForecast]);

  return (
    <Card className="rounded-2xl shadow-md">
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle className="flex items-center gap-2">
          <TrendingUp className="h-5 w-5 text-primary" />
          {productName
            ? `${productName} Price Forecast`
            : "Forecast"}
        </CardTitle>
      </CardHeader>

      <CardContent>
        {loading && (
          <div className="flex items-center justify-center py-10">
            <Loader2 className="h-6 w-6 animate-spin text-primary" />
          </div>
        )}

        {error && (
          <div className="text-red-600 text-sm py-4 text-center">
            Error: {error}
          </div>
        )}

        {!loading && !forecast && !error && (
          <div className="text-gray-500 text-sm py-6 text-center">
            No forecast available — select a product to generate a forecast.
          </div>
        )}

        {forecast &&
          Array.isArray(forecast.daily_predictions) && (
            <div className="w-full h-72">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={forecast.daily_predictions}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="date" />
                  <YAxis />
                  <Tooltip />
                  <Line
                    type="monotone"
                    dataKey="price"
                    stroke="#10B981"
                    strokeWidth={3}
                  />
                </LineChart>
              </ResponsiveContainer>

              <p className="text-xs text-gray-500 mt-3 text-right">
                {forecast.from_cache
                  ? "Loaded from cache"
                  : "Generated fresh"}
              </p>
            </div>
          )}
      </CardContent>
    </Card>
  );
}
