// ============================================================================
// LineChart.jsx — Reusable Line Chart Wrapper
// ROLE:
// • Centralizes Chart.js config
// • Prevents repeated registrations
// ============================================================================

import React from 'react';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  LineElement,
  PointElement,
  Tooltip,
  Legend,
} from 'chart.js';
import { Line } from 'react-chartjs-2';

ChartJS.register(
  CategoryScale,
  LinearScale,
  LineElement,
  PointElement,
  Tooltip,
  Legend
);

export default function LineChart({ data, options, height = 300 }) {
  if (!data) return null;

  return (
    <div style={{ height }}>
      <Line
        data={data}
        options={{
          responsive: true,
          maintainAspectRatio: false,
          ...options,
        }}
      />
    </div>
  );
}
