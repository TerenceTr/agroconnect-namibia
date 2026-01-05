// ============================================================================
// src/pages/dashboards/customer/CustomerAnalyticsSection.jsx
// ----------------------------------------------------------------------------
// ROLE:
// • Customer-facing analytics section (read-only)
// • Visualizes: top viewed + repeat purchases using Chart.js
// • Data source: local analyticsStore (works without backend)
// ============================================================================

import React, { useMemo } from 'react';
import PropTypes from 'prop-types';
import CustomerAnalyticsCharts from '../../../components/analytics/CustomerAnalyticsCharts';
import { computeCustomerAnalytics } from '../../../analytics/analyticsStore';

export default function CustomerAnalyticsSection({ products }) {
  const analytics = useMemo(() => computeCustomerAnalytics(products || []), [products]);

  return (
    <div className="space-y-4">
      <div className="glass-card p-6 rounded-2xl">
        <h2 className="text-xl font-bold">Your Activity</h2>
        <p className="text-white/70 text-sm mt-1">
          Shows your most viewed products and repeat purchases (stored locally).
        </p>
      </div>

      <CustomerAnalyticsCharts
        topViewed={analytics.topViewed}
        repeatPurchases={analytics.repeatPurchases}
      />
    </div>
  );
}

CustomerAnalyticsSection.propTypes = {
  products: PropTypes.array,
};
