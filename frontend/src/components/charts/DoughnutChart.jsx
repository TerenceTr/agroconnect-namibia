// ============================================================================
// DoughnutChart.jsx — Reusable Doughnut Chart Wrapper (FIXED)
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Reusable Doughnut chart wrapper for react-chartjs-2.
//   (Previously duplicated from BarChart.jsx, so it could not render correctly.)
// ============================================================================

import React from "react";
import {
  Chart as ChartJS,
  ArcElement,
  Tooltip,
  Legend,
} from "chart.js";
import { Doughnut } from "react-chartjs-2";

ChartJS.register(ArcElement, Tooltip, Legend);

export default function DoughnutChart({ data, options }) {
  if (!data) return null;
  return <Doughnut data={data} options={options} />;
}
