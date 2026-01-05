// ============================================================================
// AdminAnalyticsComparison.jsx
// ----------------------------------------------------------------------------
// ROLE:
// • Compare customer behavior vs sales outcomes
// • Supports governance & moderation decisions
//
// MSc VALUE:
// • Evidence-based administration
// ============================================================================

import React, { useEffect, useState } from 'react';
import { Bar } from 'react-chartjs-2';
import { fetchAdminAnalytics } from '../../services/analyticsApi';

export default function AdminAnalyticsComparison() {
  const [data, setData] = useState(null);

  useEffect(() => {
    fetchAdminAnalytics().then(setData);
  }, []);

  if (!data) return null;

  const comparison = {
    labels: data.topViewed.map(p => p.name),
    datasets: [
      {
        label: 'Views',
        data: data.topViewed.map(p => p.views),
      },
      {
        label: 'Sales',
        data: data.topSelling.map(p => p.sales),
      },
    ],
  };

  return (
    <div className="glass-card p-6">
      <h3 className="font-semibold mb-3">Interest vs Sales Comparison</h3>
      <Bar data={comparison} />
    </div>
  );
}
