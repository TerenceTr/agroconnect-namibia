// ============================================================================
// frontend/src/components/farmer/analytics/FarmerRevenueBreakdown.jsx
// ============================================================================
// FILE ROLE:
//   Financial summary chart for a selected window:
//     • Revenue vs Cost vs Profit
//   Demo-safe:
//     • If cost is missing, derives cost using order items or fallback ratio.
// ============================================================================

import React, { useMemo } from "react";
import Card, { CardHeader, CardTitle, CardContent } from "../../ui/Card";
import EmptyState from "../../ui/EmptyState";
import SkeletonChart from "../../ui/SkeletonChart";
import BarChart from "../../charts/BarChart";

function toNumber(v, fallback = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

const COST_RATIO_FALLBACK = 0.65;

function computeFinancialsFromOrders(orders) {
  let revenue = 0;
  let cost = 0;

  for (const o of orders) {
    const orderRevenue = toNumber(o?.total_amount ?? o?.total ?? o?.amount ?? 0, 0);
    revenue += orderRevenue;

    // Best: explicit cost on order
    if (o?.cost != null) {
      cost += toNumber(o.cost, 0);
      continue;
    }

    // Next best: compute from items if present
    const items = o?.items || o?.order_items || o?.lines || null;
    if (Array.isArray(items) && items.length > 0) {
      let orderCost = 0;
      for (const it of items) {
        const qty = toNumber(it?.quantity ?? it?.qty ?? 1, 1);
        const unitCost = toNumber(
          it?.unit_cost ?? it?.cost_price ?? it?.buy_price ?? it?.cost ?? null,
          null
        );
        if (unitCost == null) continue;
        orderCost += unitCost * qty;
      }
      cost += orderCost;
      continue;
    }

    // Fallback ratio (demo stability)
    cost += orderRevenue * COST_RATIO_FALLBACK;
  }

  const profit = revenue - cost;
  return { revenue, cost, profit };
}

export default function FarmerRevenueBreakdown({
  orders = [],
  loading = false,
  days = 7,
  title = "Financial Overview: Revenue vs Cost vs Profit",
}) {
  const chart = useMemo(() => {
    if (!Array.isArray(orders) || orders.length === 0) return null;

    const { revenue, cost, profit } = computeFinancialsFromOrders(orders);

    return {
      labels: ["Revenue", "Cost", "Profit"],
      datasets: [
        {
          label: `N$ (last ${days} days)`,
          data: [revenue, cost, profit],
        },
      ],
    };
  }, [orders, days]);

  return (
    <Card>
      <CardHeader>
        <div>
          <CardTitle>{title}</CardTitle>
          <p className="text-xs text-gray-500 mt-1">{`Last ${days} days`}</p>
        </div>
      </CardHeader>
      <CardContent>
        <div className="h-72">
          {loading ? (
            <SkeletonChart className="h-full" />
          ) : chart ? (
            <BarChart data={chart} height={288} options={{ scales: { y: { beginAtZero: true } } }} />
          ) : (
            <EmptyState message="No orders in this time window." />
          )}
        </div>

        <p className="text-xs text-gray-500 mt-3">
          Cost is computed from order-level cost if provided; otherwise from order items (unit_cost /
          cost_price) if present; otherwise a fallback ratio is used for demo stability.
        </p>
      </CardContent>
    </Card>
  );
}
