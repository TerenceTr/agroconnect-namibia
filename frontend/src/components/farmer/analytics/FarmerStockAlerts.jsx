// ============================================================================
// frontend/src/components/farmer/analytics/FarmerStockAlerts.jsx
// ============================================================================
// FILE ROLE:
//   Farmer AI Stock Alerts panel (Chart + List + Explainability cards)
// ============================================================================

import React, { useEffect, useMemo, useState } from "react";
import { toast } from "react-hot-toast";

import api from "../../../api";

import Card, { CardHeader, CardTitle, CardContent } from "../../ui/Card";
import EmptyState from "../../ui/EmptyState";
import SkeletonChart from "../../ui/SkeletonChart";
import BarChart from "../../charts/BarChart";
import AIStockExplanation from "./AIStockExplanation";

function toNumber(v, fallback = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

export default function FarmerStockAlerts({
  farmerId,
  thresholdDays = 7,
  topN = 8,
  explainTopN = 2,
  onCountChange,
  // IMPORTANT: no "/api" prefix (api.js baseURL already includes "/api")
  endpoint = "/ai/stock-alerts",
  wrapInCard = true, // allows dashboard to control outer layout
}) {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!farmerId) return;

    let mounted = true;
    setLoading(true);

    api
      .get(endpoint, { params: { farmer_id: farmerId, threshold_days: thresholdDays } })
      .then((res) => {
        const list = res?.data?.alerts ?? res?.data?.items ?? res?.data ?? [];
        const normalized = Array.isArray(list) ? list : [];
        if (mounted) setAlerts(normalized);
        onCountChange && onCountChange(normalized.length);
      })
      .catch((err) => {
        console.warn("AI alerts fetch failed:", err?.message || err);
        toast.error("Failed to load AI stock alerts");
      })
      .finally(() => mounted && setLoading(false));

    return () => {
      mounted = false;
    };
  }, [farmerId, thresholdDays, endpoint, onCountChange]);

  const chart = useMemo(() => {
    if (!alerts.length) return null;
    const top = alerts.slice(0, topN);

    return {
      labels: top.map((a) => a?.product_name || a?.name || "Product"),
      datasets: [
        { label: "Predicted Demand", data: top.map((a) => toNumber(a?.predicted_demand ?? a?.demand ?? 0, 0)) },
        { label: "Available Stock", data: top.map((a) => toNumber(a?.available_stock ?? a?.stock ?? 0, 0)) },
      ],
    };
  }, [alerts, topN]);

  const body = (
    <div className="space-y-6">
      {/* Chart */}
      <Card variant="surface">
        <CardHeader>
          <div>
            <CardTitle>AI Insight: Demand vs Stock</CardTitle>
            <p className="text-xs text-slate-500 mt-1">Top alerts (model output)</p>
          </div>
          <span className="text-xs text-slate-500">Top alerts</span>
        </CardHeader>

        <CardContent>
          <div className="h-72">
            {loading ? (
              <SkeletonChart className="h-full" />
            ) : chart ? (
              <BarChart data={chart} height={288} options={{ scales: { y: { beginAtZero: true } } }} />
            ) : (
              <EmptyState message="No AI alerts to visualise yet." />
            )}
          </div>
        </CardContent>
      </Card>

      {/* List */}
      <Card variant="surface">
        <CardHeader>
          <div>
            <CardTitle>AI Stock Alerts</CardTitle>
            <p className="text-xs text-slate-500 mt-1">{`Threshold: ${thresholdDays} days`}</p>
          </div>
        </CardHeader>

        <CardContent>
          {loading ? (
            <p className="text-slate-500 text-sm">Loading alerts…</p>
          ) : alerts.length === 0 ? (
            <EmptyState message="No stock risks detected. ✅" />
          ) : (
            <ul className="space-y-3">
              {alerts.slice(0, 10).map((a, idx) => {
                const severity = String(a?.severity || "low").toLowerCase();
                const badge =
                  severity === "high"
                    ? "bg-rose-50 text-rose-700 border-rose-200"
                    : severity === "medium"
                    ? "bg-amber-50 text-amber-800 border-amber-200"
                    : "bg-emerald-50 text-emerald-800 border-emerald-200";

                return (
                  <li
                    key={a?.alert_id || a?.product_id || `${idx}-${a?.product_name || "alert"}`}
                    className="p-4 bg-slate-50 rounded-xl border border-slate-200/70 flex flex-col md:flex-row md:items-center md:justify-between gap-3"
                  >
                    <div>
                      <p className="font-semibold text-slate-900">
                        {a?.product_name || "Product"}{" "}
                        <span className="text-slate-500 font-normal">
                          {a?.product_id ? `(${a.product_id})` : ""}
                        </span>
                      </p>
                      <p className="text-sm text-slate-600 mt-1">
                        Demand: <b>{toNumber(a?.predicted_demand ?? 0, 0).toFixed(1)}</b> • Stock:{" "}
                        <b>{toNumber(a?.available_stock ?? 0, 0).toFixed(1)}</b> • Restock:{" "}
                        <b>{toNumber(a?.recommended_restock ?? 0, 0).toFixed(1)}</b>
                      </p>
                    </div>

                    <span className={`px-3 py-1 rounded-full text-xs font-semibold border ${badge}`}>
                      {severity}
                    </span>
                  </li>
                );
              })}
            </ul>
          )}
        </CardContent>
      </Card>

      {/* Explainability */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {(alerts || []).slice(0, explainTopN).map((a, i) => (
          <AIStockExplanation key={a?.alert_id || a?.product_id || i} alert={a} />
        ))}
      </div>
    </div>
  );

  // Backward compatibility: some pages expect it wrapped already
  return wrapInCard ? body : <div>{body}</div>;
}
