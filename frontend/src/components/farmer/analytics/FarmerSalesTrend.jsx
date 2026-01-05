// ============================================================================
// frontend/src/components/farmer/analytics/FarmerSalesTrend.jsx
// ============================================================================
// FILE ROLE:
//   Revenue trend line chart for a farmer over the last N days.
//   • Aggregates orders by day
//   • Optional moving average smoothing
// ============================================================================

import React, { useMemo } from "react";
import Card, { CardHeader, CardTitle, CardContent } from "../../ui/Card";
import EmptyState from "../../ui/EmptyState";
import SkeletonChart from "../../ui/SkeletonChart";
import LineChart from "../../charts/LineChart";

import { parseISO, format } from "date-fns";

function toNumber(v, fallback = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

function pickDate(o) {
  const raw =
    o?.created_at || o?.createdAt || o?.order_date || o?.ordered_at || o?.timestamp || null;
  if (!raw) return null;
  if (raw instanceof Date) return raw;
  try {
    return parseISO(String(raw));
  } catch {
    const d = new Date(String(raw));
    return Number.isNaN(d.getTime()) ? null : d;
  }
}

function movingAverage(values, windowSize) {
  if (!Array.isArray(values) || windowSize <= 1) return values.slice();
  const out = [];
  let sum = 0;
  const q = [];
  for (let i = 0; i < values.length; i++) {
    const v = toNumber(values[i], 0);
    q.push(v);
    sum += v;
    if (q.length > windowSize) sum -= q.shift();
    out.push(q.length < windowSize ? null : sum / windowSize);
  }
  return out;
}

export default function FarmerSalesTrend({
  orders = [],
  loading = false,
  days = 7,
  maWindow = 3,
  title = "Revenue Trend + Moving Average",
}) {
  const chart = useMemo(() => {
    if (!Array.isArray(orders) || orders.length === 0) return null;

    const byDay = new Map();

    for (const o of orders) {
      const d = pickDate(o);
      if (!d) continue;
      const key = format(d, "yyyy-MM-dd");
      const revenue = toNumber(o?.total_amount ?? o?.total ?? o?.amount ?? 0, 0);
      byDay.set(key, (byDay.get(key) || 0) + revenue);
    }

    const labels = Array.from(byDay.keys()).sort();
    if (labels.length === 0) return null;

    const values = labels.map((k) => byDay.get(k) || 0);
    const ma = movingAverage(values, Math.max(2, toNumber(maWindow, 3)));

    return {
      labels,
      datasets: [
        { label: "Revenue (N$)", data: values, tension: 0.25 },
        { label: `Moving Avg (${maWindow})`, data: ma, tension: 0.25 },
      ],
    };
  }, [orders, maWindow]);

  return (
    <Card className="lg:col-span-2">
      <CardHeader>
        <div>
          <CardTitle>{title}</CardTitle>
          <p className="text-xs text-gray-500 mt-1">{`Last ${days} days`}</p>
        </div>
      </CardHeader>
      <CardContent>
        <div className="h-80">
          {loading ? (
            <SkeletonChart className="h-full" />
          ) : chart ? (
            <LineChart data={chart} height={320} />
          ) : (
            <EmptyState message="No revenue trend data available yet." />
          )}
        </div>
      </CardContent>
    </Card>
  );
}
