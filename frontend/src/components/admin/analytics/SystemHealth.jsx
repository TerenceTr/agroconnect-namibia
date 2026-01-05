// ============================================================================
// FarmerPerformance.jsx
// ----------------------------------------------------------------------------
// ROLE:
// • Admin comparison of farmer revenue performance
// • Governance & fairness insight
//
// DEPENDS ON:
// • components/ui/Card
// • components/ui/EmptyState
// • components/charts/BarChart
// ============================================================================

import React, { useMemo } from 'react';
import Card from '../../ui/Card';
import EmptyState from '../../ui/EmptyState';
import BarChart from '../../charts/BarChart';

export default function FarmerPerformance({ data = [] }) {
  const chartData = useMemo(() => {
    if (!data.length) return null;

    return {
      labels: data.map((f) => f.farmer_name),
      datasets: [
        {
          label: 'Total Revenue (N$)',
          data: data.map((f) => f.revenue),
          backgroundColor: 'rgba(59,130,246,0.7)',
        },
      ],
    };
  }, [data]);

  return (
    <Card>
      <h3 className="font-semibold mb-3">Farmer Performance</h3>

      {!chartData ? (
        <EmptyState message="No farmer performance data available." />
      ) : (
        <BarChart data={chartData} height={300} />
      )}
    </Card>
  );
}
