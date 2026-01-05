// ============================================================================
// CustomerAnalyticsCharts.jsx
// ----------------------------------------------------------------------------
// ROLE:
// • Visualize customer behavior
// • Makes activity diagram measurable
//
// MSc VALUE:
// • Converts logs → insight → decision support
// ============================================================================

import React, { useEffect, useState, useMemo } from 'react';
import { Bar, Line } from 'react-chartjs-2';
import { fetchCustomerAnalytics } from '../../services/analyticsApi';
import SkeletonChart from '../ui/SkeletonChart';

export default function CustomerAnalyticsCharts() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchCustomerAnalytics()
      .then(setData)
      .finally(() => setLoading(false));
  }, []);

  // -----------------------------
  // Top viewed products
  // -----------------------------
  const topViewed = useMemo(() => {
    if (!data) return null;
    return {
      labels: data.topViewed.map(p => p.name),
      datasets: [{
        label: 'Views',
        data: data.topViewed.map(p => p.views),
      }],
    };
  }, [data]);

  // -----------------------------
  // Repeat purchases
  // -----------------------------
  const repeatPurchases = useMemo(() => {
    if (!data) return null;
    return {
      labels: data.repeatPurchases.map(p => p.name),
      datasets: [{
        label: 'Orders',
        data: data.repeatPurchases.map(p => p.count),
      }],
    };
  }, [data]);

  if (loading) return <SkeletonChart />;

  return (
    <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
      <div className="glass-card p-6">
        <h3 className="font-semibold mb-3">Top Viewed Products</h3>
        <Bar data={topViewed} />
      </div>

      <div className="glass-card p-6">
        <h3 className="font-semibold mb-3">Repeat Purchases</h3>
        <Line data={repeatPurchases} />
      </div>
    </div>
  );
}
