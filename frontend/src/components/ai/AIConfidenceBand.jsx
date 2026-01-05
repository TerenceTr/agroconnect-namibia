// ============================================================================
// AIConfidenceBand.jsx — AgroConnect Namibia
// ----------------------------------------------------------------------------
// ROLE:
// • Visual certainty indicator for AI outputs
// • Used in analytics dashboards (Admin / Farmer)
// ============================================================================

import React from "react";

function clamp01(x) {
  const n = Number(x);
  return Number.isNaN(n) ? 0.65 : Math.max(0, Math.min(1, n));
}

function bandMeta(c) {
  if (c >= 0.8) return { label: "High", cls: "bg-emerald-500/20 text-emerald-200 border-emerald-400/40" };
  if (c >= 0.6) return { label: "Medium", cls: "bg-amber-500/20 text-amber-200 border-amber-400/40" };
  return { label: "Low", cls: "bg-red-500/20 text-red-200 border-red-400/40" };
}

export default function AIConfidenceBand({ confidence }) {
  const c = clamp01(confidence);
  const { label, cls } = bandMeta(c);

  return (
    <div className={`inline-flex items-center gap-2 px-3 py-1 rounded-full border text-xs font-semibold ${cls}`}>
      <span>{label} Confidence</span>
      <span className="opacity-80">{Math.round(c * 100)}%</span>
    </div>
  );
}
