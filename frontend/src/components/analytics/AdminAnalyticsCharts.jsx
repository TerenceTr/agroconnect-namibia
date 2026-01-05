// ============================================================================
// src/components/analytics/AdminAnalyticsCharts.jsx
// ----------------------------------------------------------------------------
// ROLE:
// • Admin comparison dashboard visuals (Chart.js)
// • Designed for backend-fed summaries (but renders safely with missing data)
// • Examples:
//   - Total orders vs delivered vs rejected
//   - Top products by orders
// ============================================================================

import React, { useMemo } from 'react';
import PropTypes from 'prop-types';
import { Bar } from 'react-chartjs-2';

import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  Tooltip,
  Legend,
} from 'chart.js';

ChartJS.register(CategoryScale, LinearScale, BarElement, Tooltip, Legend);

export default function AdminAnalyticsCharts({ summary }) {
  const statusData = useMemo(() => {
    const s = summary?.ordersByStatus || {};
    const labels = ['pending', 'confirmed', 'in_transit', 'delivered', 'rejected'];
    const values = labels.map((k) => Number(s[k] || 0));

    return {
      labels,
      datasets: [{ label: 'Orders', data: values }],
    };
  }, [summary]);

  const topProductsData = useMemo(() => {
    const rows = Array.isArray(summary?.topProducts) ? summary.topProducts : [];
    return {
      labels: rows.map((r) => r.name || `#${r.product_id}`),
      datasets: [{ label: 'Orders', data: rows.map((r) => Number(r.orders || 0)) }],
    };
  }, [summary]);

  const options = useMemo(
    () => ({
      responsive: true,
      plugins: { legend: { display: true } },
    }),
    []
  );

  return (
    <div className="space-y-6">
      <div className="glass-card p-6 rounded-2xl">
        <h3 className="font-semibold mb-3">Orders by Status</h3>
        <Bar data={statusData} options={options} />
      </div>

      <div className="glass-card p-6 rounded-2xl">
        <h3 className="font-semibold mb-3">Top Products (by Orders)</h3>
        {(summary?.topProducts?.length || 0) > 0 ? (
          <Bar data={topProductsData} options={options} />
        ) : (
          <div className="text-white/70">No top-products data yet.</div>
        )}
      </div>
    </div>
  );
}

AdminAnalyticsCharts.propTypes = {
  summary: PropTypes.shape({
    ordersByStatus: PropTypes.object,
    topProducts: PropTypes.array,
  }),
};
