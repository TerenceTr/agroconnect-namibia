// ============================================================================
// src/components/ui/RevenueTrendChart.jsx — Farmer Revenue Trend (Power BI-like)
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Purpose-built line/area chart for Farmer Overview revenue trend.
//   • Power BI-like look (clean line + soft area + optional compare series)
//   • Keeps AgroConnect green palette
//   • Supports optional previous-year compare series (dashed)
// ============================================================================
import React, { useMemo } from "react";
import {
  ResponsiveContainer,
  ComposedChart,
  CartesianGrid,
  XAxis,
  YAxis,
  Tooltip,
  Area,
  Line,
} from "recharts";

function safeNumber(v, fallback = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

function safeArray(v) {
  return Array.isArray(v) ? v : [];
}

function toMoney(v, prefix = "N$ ") {
  const n = safeNumber(v, 0);
  return `${prefix}${n.toLocaleString(undefined, {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  })}`;
}

function formatAxisMoney(v) {
  const n = safeNumber(v, 0);
  if (Math.abs(n) >= 1_000_000) return `N$ ${(n / 1_000_000).toFixed(1)}M`;
  if (Math.abs(n) >= 1_000) return `N$ ${(n / 1_000).toFixed(1)}K`;
  return `N$ ${n.toFixed(0)}`;
}

function CustomTooltip({ active, payload, label, prefix }) {
  if (!active || !Array.isArray(payload) || payload.length === 0) return null;

  const current = payload.find((p) => p?.dataKey === "current")?.value;
  const previous = payload.find((p) => p?.dataKey === "previous")?.value;

  return (
    <div className="rounded-xl border border-slate-200 bg-white/95 shadow-md px-3 py-2">
      <div className="text-xs font-bold text-slate-700 mb-1">{label}</div>
      <div className="text-xs text-slate-800">
        This period: <span className="font-extrabold">{toMoney(current, prefix)}</span>
      </div>
      {safeNumber(previous, 0) > 0 ? (
        <div className="text-xs text-slate-600 mt-0.5">
          Prev year: <span className="font-bold">{toMoney(previous, prefix)}</span>
        </div>
      ) : null}
    </div>
  );
}

export default function RevenueTrendChart({
  labels = [],
  values = [],
  compareValues = [],
  height = 280,
  valuePrefix = "N$ ",
}) {
  const rows = useMemo(() => {
    const l = safeArray(labels);
    const v = safeArray(values);
    const c = safeArray(compareValues);

    const len = Math.max(l.length, v.length, c.length);
    const out = [];

    for (let i = 0; i < len; i += 1) {
      out.push({
        label: String(l[i] ?? ""),
        current: safeNumber(v[i], 0),
        previous: safeNumber(c[i], 0),
      });
    }

    return out;
  }, [labels, values, compareValues]);

  const hasCurrent = rows.some((r) => safeNumber(r.current, 0) > 0);
  const hasCompare = rows.some((r) => safeNumber(r.previous, 0) > 0);

  const yMax = useMemo(() => {
    const maxVal = rows.reduce((m, r) => {
      const c = safeNumber(r.current, 0);
      const p = safeNumber(r.previous, 0);
      return Math.max(m, c, p);
    }, 0);

    if (maxVal <= 0) return 10;
    return Math.ceil(maxVal * 1.12);
  }, [rows]);

  if (!rows.length || !hasCurrent) {
    return (
      <div className="h-full rounded-2xl border border-slate-200 bg-slate-50 flex items-center justify-center">
        <div className="text-sm text-slate-600">No paid revenue yet for this period.</div>
      </div>
    );
  }

  return (
    <div className="h-full rounded-2xl border border-slate-200 bg-white p-2">
      <ResponsiveContainer width="100%" height={height - 16}>
        <ComposedChart data={rows} margin={{ top: 12, right: 10, left: 4, bottom: 2 }}>
          <defs>
            <linearGradient id="revenueAreaGreen" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#52B788" stopOpacity={0.34} />
              <stop offset="65%" stopColor="#95D5B2" stopOpacity={0.14} />
              <stop offset="100%" stopColor="#D8F3DC" stopOpacity={0.04} />
            </linearGradient>
          </defs>

          <CartesianGrid strokeDasharray="3 3" stroke="#D8F3DC" vertical={false} />

          <XAxis
            dataKey="label"
            tick={{ fontSize: 11, fill: "#64748B" }}
            axisLine={{ stroke: "#E2E8F0" }}
            tickLine={false}
            minTickGap={14}
          />

          <YAxis
            domain={[0, yMax]}
            tick={{ fontSize: 11, fill: "#64748B" }}
            tickLine={false}
            axisLine={{ stroke: "#E2E8F0" }}
            width={76}
            tickFormatter={formatAxisMoney}
          />

          <Tooltip
            cursor={{ stroke: "#74C69D", strokeDasharray: "3 3" }}
            content={<CustomTooltip prefix={valuePrefix} />}
          />

          <Area type="monotone" dataKey="current" stroke="none" fill="url(#revenueAreaGreen)" />

          {hasCompare ? (
            <Line
              type="monotone"
              dataKey="previous"
              connectNulls
              stroke="#40916C"
              strokeWidth={2}
              strokeDasharray="6 6"
              dot={false}
              activeDot={false}
            />
          ) : null}

          <Line
            type="monotone"
            dataKey="current"
            connectNulls
            stroke="#2D6A4F"
            strokeWidth={3}
            dot={{ r: 3, fill: "#FFFFFF", stroke: "#2D6A4F", strokeWidth: 2 }}
            activeDot={{ r: 5, fill: "#2D6A4F", stroke: "#FFFFFF", strokeWidth: 2 }}
          />
        </ComposedChart>
      </ResponsiveContainer>
    </div>
  );
}
