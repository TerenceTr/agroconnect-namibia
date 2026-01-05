// ============================================================================
// src/components/ui/SimpleBarChart.jsx — Lightweight Chart (No dependencies)
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Safe “good enough” bar chart for dashboards without Chart.js runtime issues.
//
// WHY IT EXISTS:
//   Some builds throw chart-runtime errors (ex: "_s is not a function").
//   This avoids external chart libs entirely while still giving readable trends.
//
// DESIGN RULE:
//   Neutral surfaces + subtle emerald accent (no “green wall”).
// ============================================================================

import React, { useMemo } from "react";

function safeNumber(v, fallback = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

export default function SimpleBarChart({
  title = "",
  labels = [],
  values = [],
  height = 260,
  valuePrefix = "",
}) {
  const data = useMemo(() => {
    const len = Math.min(labels.length, values.length);
    const rows = [];
    for (let i = 0; i < len; i++) {
      rows.push({ label: String(labels[i] ?? ""), value: safeNumber(values[i]) });
    }
    return rows;
  }, [labels, values]);

  const maxV = useMemo(() => {
    let m = 0;
    for (const r of data) m = Math.max(m, r.value);
    return m || 1;
  }, [data]);

  return (
    <div className="w-full" style={{ height }}>
      {title ? <div className="text-sm font-semibold text-slate-800 mb-2">{title}</div> : null}

      <div className="h-full rounded-2xl border border-slate-200 bg-white p-3">
        {data.length === 0 ? (
          <div className="h-full grid place-items-center text-sm text-slate-500">
            No trend data available.
          </div>
        ) : (
          <div className="h-full flex items-end gap-2">
            {data.map((r, idx) => {
              const pct = Math.max(2, Math.round((r.value / maxV) * 100));
              return (
                <div key={`${r.label}-${idx}`} className="flex-1 min-w-[10px]">
                  <div
                    className="w-full rounded-xl bg-emerald-500/20 border border-emerald-500/20"
                    style={{ height: `${pct}%` }}
                    title={`${r.label}: ${valuePrefix}${r.value}`}
                  />
                  <div className="mt-2 text-[10px] text-slate-500 truncate" title={r.label}>
                    {r.label}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
