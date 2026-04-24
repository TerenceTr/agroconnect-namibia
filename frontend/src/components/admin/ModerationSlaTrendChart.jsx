// ============================================================================
// src/components/admin/ModerationSlaTrendChart.jsx
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Clean, modern moderation SLA trend chart.
//   Uses Recharts (already used in this project for AI charts).
//
// INPUT DATA SHAPE:
//   trend = [{ bucket, reviewed, breached, breach_rate, avg_hours }, ...]
// ============================================================================

import React, { useMemo } from "react";
import {
  ResponsiveContainer,
  ComposedChart,
  Bar,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  Legend,
} from "recharts";

const safeArray = (v) => (Array.isArray(v) ? v : []);

function pct(v) {
  const n = Number(v);
  if (!Number.isFinite(n)) return "0%";
  return `${Math.round(n * 100)}%`;
}

export default function ModerationSlaTrendChart({ trend = [] }) {
  const rows = useMemo(() => safeArray(trend), [trend]);

  if (!rows.length) {
    return (
      <div className="h-[240px] grid place-items-center text-sm text-slate-500">
        No SLA trend data available yet.
      </div>
    );
  }

  return (
    <div className="h-[260px] w-full">
      <ResponsiveContainer width="100%" height="100%">
        <ComposedChart data={rows}>
          <CartesianGrid strokeDasharray="3 3" stroke="rgba(148, 163, 184, 0.35)" />
          <XAxis dataKey="bucket" tick={{ fill: "rgba(71,85,105,0.9)", fontSize: 12 }} />
          <YAxis
            yAxisId="left"
            tick={{ fill: "rgba(71,85,105,0.9)", fontSize: 12 }}
            allowDecimals={false}
          />
          <YAxis
            yAxisId="right"
            orientation="right"
            tick={{ fill: "rgba(71,85,105,0.9)", fontSize: 12 }}
            tickFormatter={(v) => pct(v)}
          />

          <Tooltip
            formatter={(value, name) => {
              if (name === "Breach Rate") return pct(value);
              return value;
            }}
          />
          <Legend />

          {/* Reviewed volume */}
          <Bar
            yAxisId="left"
            dataKey="reviewed"
            name="Reviewed"
            fill="rgba(15, 23, 42, 0.65)"
            radius={[8, 8, 0, 0]}
          />

          {/* Breached count */}
          <Bar
            yAxisId="left"
            dataKey="breached"
            name="Breached"
            fill="rgba(244, 63, 94, 0.75)"
            radius={[8, 8, 0, 0]}
          />

          {/* Breach rate line */}
          <Line
            yAxisId="right"
            type="monotone"
            dataKey="breach_rate"
            name="Breach Rate"
            stroke="rgba(2, 132, 199, 0.95)"
            strokeWidth={2}
            dot={{ r: 3 }}
          />
        </ComposedChart>
      </ResponsiveContainer>
    </div>
  );
}
