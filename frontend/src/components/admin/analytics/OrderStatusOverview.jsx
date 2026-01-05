// ============================================================================
// OrderStatusOverview.jsx
// ----------------------------------------------------------------------------
// ROLE:
// • Visualizes order statuses across platform
// ============================================================================

import React from 'react';
import Card, { CardHeader, CardTitle, CardContent } from '../../ui/Card';
import DoughnutChart from '../../charts/DoughnutChart';
import EmptyState from '../../ui/EmptyState';

export default function OrderStatusOverview({ data }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Orders by Status</CardTitle>
      </CardHeader>

      <CardContent>
        {data ? (
          <DoughnutChart data={data} height={260} />
        ) : (
          <EmptyState message="No order status data." />
        )}
      </CardContent>
    </Card>
  );
}
