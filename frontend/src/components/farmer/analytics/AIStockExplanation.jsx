// ============================================================================
// frontend/src/components/farmer/analytics/AIStockExplanation.jsx
// ============================================================================
// FILE ROLE:
//   Explainability card: "Why recommended?"
//   • Turns an AI stock alert into human-readable bullet reasons.
//   • Uses alert fields + optional alert.meta.
// ============================================================================

import React, { useMemo } from "react";
import Card, { CardHeader, CardTitle, CardContent } from "../../ui/Card";

function toNumber(v, fallback = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

function severityStyle(sev) {
  const s = String(sev || "low").toLowerCase();
  if (s === "high") return "bg-red-50 text-red-700 border border-red-200";
  if (s === "medium") return "bg-yellow-50 text-yellow-700 border border-yellow-200";
  return "bg-emerald-50 text-emerald-700 border border-emerald-200";
}

export default function AIStockExplanation({ alert }) {
  const modelVersion = alert?.model_version || alert?.modelVersion || "—";
  const productName = alert?.product_name || alert?.name || "Product";
  const severity = alert?.severity || "low";

  const demand = toNumber(alert?.predicted_demand ?? alert?.demand ?? 0, 0);
  const stock = toNumber(alert?.available_stock ?? alert?.stock ?? 0, 0);
  const restock = toNumber(alert?.recommended_restock ?? 0, 0);

  const meta = alert?.meta || {};
  const recentSales = meta?.recent_sales ?? meta?.sales_last_7d ?? meta?.sales_last_30d;
  const trend = meta?.market_trend ?? meta?.trend ?? null;
  const seasonality = meta?.seasonality ?? meta?.season ?? null;

  const reasons = useMemo(() => {
    const list = [];

    if (demand > 0 && stock >= 0) {
      if (stock < demand) {
        list.push(
          `Predicted demand (${demand.toFixed(1)}) is higher than available stock (${stock.toFixed(
            1
          )}), which can cause stockouts.`
        );
      } else {
        list.push(
          `Stock (${stock.toFixed(1)}) currently covers predicted demand (${demand.toFixed(
            1
          )}), but risk may increase soon based on the model window.`
        );
      }
    }

    if (restock > 0) {
      list.push(`Recommended restock is ${restock.toFixed(1)} units to reduce shortage risk.`);
    } else {
      list.push(`No additional restock is required based on current signal strength.`);
    }

    if (recentSales != null) list.push(`Recent sales signal: ${toNumber(recentSales, 0)} (AI meta).`);
    if (trend) list.push(`Market trend indicator: ${String(trend)}.`);
    if (seasonality) list.push(`Seasonality factor: ${String(seasonality)}.`);

    list.push(`Model: ${modelVersion}. Recommendation compares predicted demand vs stock.`);
    return list;
  }, [demand, stock, restock, recentSales, trend, seasonality, modelVersion]);

  return (
    <Card>
      <CardHeader>
        <div className="min-w-0">
          <CardTitle className="text-base">Why recommended?</CardTitle>
          <p className="text-gray-500 text-sm mt-1 truncate">
            {productName} • AI explainability summary
          </p>
        </div>

        <span className={`px-3 py-1 rounded-full text-xs font-medium ${severityStyle(severity)}`}>
          {String(severity).toLowerCase()}
        </span>
      </CardHeader>

      <CardContent>
        <ul className="list-disc pl-5 space-y-2 text-sm text-gray-700">
          {reasons.map((r, i) => (
            <li key={i}>{r}</li>
          ))}
        </ul>
      </CardContent>
    </Card>
  );
}
