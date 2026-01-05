// ============================================================================
// CustomerAnalyticsPanel.jsx
// ----------------------------------------------------------------------------
// ROLE:
// • Displays customer behavior insights
// • MSc value: explainability + transparency
// ============================================================================

import React from 'react';

export default function CustomerAnalyticsPanel({ topViewed, repeatPurchases }) {
  return (
    <div className="glass-card p-6 rounded-2xl space-y-6">
      <h3 className="font-semibold">Your Activity Insights</h3>

      {/* Top Viewed */}
      <div>
        <h4 className="text-sm text-white/80 mb-2">Top Viewed Products</h4>
        {topViewed.length === 0 ? (
          <p className="text-white/60">No viewing data yet.</p>
        ) : (
          <ul className="space-y-1 text-sm">
            {topViewed.map((p) => (
              <li key={p.id}>
                Product #{p.id} — {p.views} views
              </li>
            ))}
          </ul>
        )}
      </div>

      {/* Repeat Purchases */}
      <div>
        <h4 className="text-sm text-white/80 mb-2">Repeat Purchases</h4>
        {repeatPurchases.length === 0 ? (
          <p className="text-white/60">No repeat purchases yet.</p>
        ) : (
          <ul className="space-y-1 text-sm">
            {repeatPurchases.map((p) => (
              <li key={p.product_id}>
                Product #{p.product_id} — purchased {p.times} times
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
