// ============================================================================
// frontend/src/pages/dashboards/farmer/dashboard/TopProductsCard.jsx
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Top products panel for FarmerDashboard.
//
// RESPONSIBILITIES:
//   • Show a small ranked list (currently by stock quantity)
// ============================================================================

import React from "react";

// IMPORTANT: this file is inside .../farmer/dashboard/, so go up 4 levels to /src
import Card, { CardHeader, CardTitle, CardContent } from "../../../../components/ui/Card";
import EmptyState from "../../../../components/ui/EmptyState";

import { getProductId, getProductName, toNumber } from "./utils";

export default function TopProductsCard({ loading, products, lowStockThreshold = 5 }) {
  return (
    <Card variant="surface">
      <CardHeader>
        <div>
          <CardTitle>Top Products</CardTitle>
          <p className="text-xs text-slate-500 mt-1">
            Based on stock quantity (change to “most ordered” later)
          </p>
        </div>
      </CardHeader>

      <CardContent>
        {loading ? (
          <p className="text-sm text-slate-500">Loading…</p>
        ) : products.length === 0 ? (
          <EmptyState message="No products yet. Add your first product." />
        ) : (
          <ul className="space-y-3">
            {products.map((p, idx) => {
              const pid = getProductId(p) || idx;
              const qty = toNumber(p?.quantity ?? 0, 0);

              return (
                <li
                  key={pid}
                  className="flex items-center justify-between gap-3 p-3 rounded-2xl bg-white border border-slate-200 shadow-sm hover:shadow-md transition"
                >
                  <div className="min-w-0">
                    <div className="font-semibold text-slate-900 truncate">{getProductName(p)}</div>
                    <div className="text-xs text-slate-500 mt-1">
                      Price: N$ {toNumber(p?.price ?? 0, 0).toFixed(2)}
                    </div>
                  </div>

                  <span
                    className={[
                      "text-xs font-semibold px-3 py-1 rounded-full border",
                      qty <= lowStockThreshold
                        ? "bg-amber-50 text-amber-800 border-amber-200"
                        : "bg-emerald-50 text-emerald-800 border-emerald-200",
                    ].join(" ")}
                  >
                    Stock: {qty}
                  </span>
                </li>
              );
            })}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}
