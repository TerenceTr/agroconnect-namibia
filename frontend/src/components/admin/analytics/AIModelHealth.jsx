// ============================================================================
// AIModelHealth.jsx
// ----------------------------------------------------------------------------
// ROLE:
// • Tracks AI model error trends
// • Explainable governance view
// ============================================================================

import React from 'react';
import Card, { CardHeader, CardTitle, CardContent } from '../../ui/Card';
import LineChart from '../../charts/LineChart';
import EmptyState from '../../ui/EmptyState';

export default function AIModelHealth({ chartData }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>AI Model Health</CardTitle>
      </CardHeader>

      <CardContent>
        {chartData ? (
          <LineChart data={chartData} height={280} />
        ) : (
          <EmptyState message="No AI evaluation data available." />
        )}
      </CardContent>
    </Card>
  );
}
