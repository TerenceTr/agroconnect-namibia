// ============================================================================
// frontend/src/pages/dashboards/farmer/dashboard/RecentOrdersCard.jsx
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Recent orders panel for FarmerDashboard.
//
// UX FIX (THIS UPDATE):
//   • First-load-only loading:
//       - show “Loading…” only before first resolved fetch
//       - during refetch keep existing orders visible (no flicker)
// ============================================================================

import React, { useEffect, useState } from "react";
import { Wallet } from "lucide-react";
import { format, formatDistanceToNow } from "date-fns";

// IMPORTANT: this file is inside .../farmer/dashboard/, so go up 4 levels to /src
import Card, { CardHeader, CardTitle, CardContent } from "../../../../components/ui/Card";
import EmptyState from "../../../../components/ui/EmptyState";

import {
  badgeForFulfillment,
  badgeForPayment,
  fulfillmentLabel,
  getOrderBuyerLabel,
  getOrderId,
  getOrderProductName,
  getOrderTotal,
  normalizeFulfillmentStatus,
  normalizePaymentStatus,
  pickDate,
  titleCase,
} from "./utils";

/**
 * Local first-load gate:
 * - once loading turns false once, we never show the loader again
 * - parent should keep previous data during refetch; this prevents “Loading…” flicker
 */
function useFirstLoadOnly(loading) {
  const [painted, setPainted] = useState(false);

  useEffect(() => {
    if (!painted && !loading) setPainted(true);
  }, [loading, painted]);

  return painted;
}

export default function RecentOrdersCard({ loading, orders, days }) {
  const painted = useFirstLoadOnly(loading);
  const showLoading = loading && !painted;

  return (
    <Card variant="surface">
      <CardHeader>
        <div className="flex items-center justify-between gap-3">
          <div>
            <CardTitle>Recent Orders</CardTitle>
            <p className="text-xs text-slate-500 mt-1">
              Last {days} days • newest first • status + payment included
            </p>
          </div>
          <div className="flex items-center gap-2 text-xs text-slate-600">
            <Wallet size={14} />
            <span>Payment</span>
          </div>
        </div>
      </CardHeader>

      <CardContent>
        {showLoading ? (
          <p className="text-sm text-slate-500">Loading…</p>
        ) : orders.length === 0 ? (
          <EmptyState message="No recent orders in this time window." />
        ) : (
          <div className="space-y-3">
            {orders.map((o, idx) => {
              const oid = getOrderId(o) || idx;
              const when = pickDate(o);
              const f = normalizeFulfillmentStatus(o);
              const p = normalizePaymentStatus(o);

              return (
                <div
                  key={oid}
                  className="p-3 rounded-2xl bg-white border border-slate-200/80 shadow-sm hover:shadow-md transition flex items-start justify-between gap-3"
                >
                  <div className="min-w-0">
                    <div className="font-semibold text-slate-900 truncate">{getOrderProductName(o)}</div>

                    <div className="text-xs text-slate-500 mt-1">
                      {getOrderBuyerLabel(o)} • {when ? format(when, "dd MMM yyyy") : "—"}
                      {when ? ` • ${formatDistanceToNow(when, { addSuffix: true })}` : ""}
                    </div>

                    <div className="text-xs text-slate-600 mt-2">
                      Total: <b>N$ {getOrderTotal(o).toFixed(2)}</b>
                    </div>
                  </div>

                  <div className="flex flex-col items-end gap-2">
                    <span
                      className={[
                        "px-3 py-1 rounded-full text-xs font-semibold border",
                        badgeForFulfillment(f),
                      ].join(" ")}
                    >
                      {fulfillmentLabel(f)}
                    </span>

                    <span
                      className={[
                        "px-3 py-1 rounded-full text-xs font-semibold border",
                        badgeForPayment(p),
                      ].join(" ")}
                    >
                      {p === "unknown" ? "Payment: —" : `Payment: ${titleCase(p)}`}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
