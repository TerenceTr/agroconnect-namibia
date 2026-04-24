// ============================================================================
// frontend/src/components/reviews/RepeatIssueRiskPanel.jsx
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Risk panel and alert-card renderer for repeat issue detection.
//
// PHASE 4C:
//   ✅ Risk band summary cards
//   ✅ Alert threshold display
//   ✅ Top alert cards with recommendations
// ============================================================================

import React from "react";
import { AlertTriangle, Flame, ShieldAlert, TrendingUp } from "lucide-react";

function safeArray(value) {
  return Array.isArray(value) ? value : [];
}
function safeObj(value) {
  return value && typeof value === "object" ? value : {};
}
function safeStr(value, fallback = "") {
  if (typeof value === "string") return value;
  if (value == null) return fallback;
  return String(value);
}
function safeNumber(value, fallback = 0) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function RiskCard({ title, value, subtitle, icon: Icon, tone = "slate" }) {
  const toneMap = {
    slate: "border-slate-200 bg-white",
    amber: "border-amber-200 bg-amber-50/70",
    rose: "border-rose-200 bg-rose-50/70",
    red: "border-red-200 bg-red-50/70",
  };

  return (
    <div className={`rounded-2xl border p-4 shadow-sm ${toneMap[tone] || toneMap.slate}`}>
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="text-xs font-bold uppercase tracking-wide text-slate-500">{title}</div>
          <div className="mt-2 text-2xl font-black text-slate-900">{value}</div>
          <div className="mt-1 text-xs font-semibold text-slate-600">{subtitle}</div>
        </div>
        <div className="rounded-xl border border-slate-200 bg-white p-2 text-slate-700 shadow-sm">
          <Icon className="h-5 w-5" />
        </div>
      </div>
    </div>
  );
}

function bandTone(band) {
  const b = safeStr(band).toLowerCase();
  if (b === "critical") return "red";
  if (b === "high") return "rose";
  if (b === "medium") return "amber";
  return "slate";
}

export default function RepeatIssueRiskPanel({ payload = {}, title = "Repeat issue risk panel" }) {
  const summary = safeObj(payload?.summary);
  const alerts = safeArray(payload?.alerts);
  const riskPanels = safeObj(payload?.risk_panels);
  const critical = safeArray(riskPanels?.critical);
  const high = safeArray(riskPanels?.high);

  return (
    <div className="space-y-4 rounded-3xl border border-[#D8F3DC] bg-white p-5 shadow-sm">
      <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
        <div>
          <div className="text-sm font-extrabold text-slate-900">{title}</div>
          <div className="mt-1 text-xs font-semibold text-slate-500">
            Threshold: {safeNumber(summary?.threshold, 2)} occurrences before a repeat issue becomes an alert.
          </div>
        </div>
        <div className="rounded-2xl border border-slate-200 bg-slate-50 px-3 py-2 text-xs font-semibold text-slate-600">
          Highest risk score: {safeNumber(summary?.highest_score, 0).toFixed(2)}
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <RiskCard
          title="Critical"
          value={safeNumber(summary?.critical_count, 0)}
          subtitle="Immediate corrective action needed"
          icon={ShieldAlert}
          tone="red"
        />
        <RiskCard
          title="High"
          value={safeNumber(summary?.high_count, 0)}
          subtitle="Active hotspot requiring close attention"
          icon={Flame}
          tone="rose"
        />
        <RiskCard
          title="Medium"
          value={safeNumber(summary?.medium_count, 0)}
          subtitle="Watchlist risk clusters"
          icon={AlertTriangle}
          tone="amber"
        />
        <RiskCard
          title="Average score"
          value={safeNumber(summary?.avg_score, 0).toFixed(2)}
          subtitle="Across detected repeat issue clusters"
          icon={TrendingUp}
        />
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <div className="rounded-2xl border border-red-200 bg-red-50/40 p-4">
          <div className="mb-3 text-sm font-extrabold text-slate-900">Critical alerts</div>
          <div className="space-y-3">
            {critical.length === 0 ? (
              <div className="rounded-2xl border border-red-100 bg-white p-3 text-sm text-slate-500">
                No critical repeat issue alerts under the current filters.
              </div>
            ) : (
              critical.map((alert, index) => (
                <div key={`${alert.entity_id}-${alert.taxonomy_code}-${index}`} className="rounded-2xl border border-red-100 bg-white p-4">
                  <div className="flex flex-col gap-2 md:flex-row md:items-start md:justify-between">
                    <div>
                      <div className="text-sm font-bold text-slate-900">{safeStr(alert.entity_name, "Unknown entity")}</div>
                      <div className="mt-1 text-xs font-semibold uppercase tracking-wide text-slate-500">
                        {safeStr(alert.taxonomy_label || alert.taxonomy_code).replace(/_/g, " ")}
                      </div>
                    </div>
                    <div className="rounded-xl border border-red-200 bg-red-50 px-3 py-1 text-xs font-black text-red-700">
                      Score {safeNumber(alert.repeat_issue_score, 0).toFixed(2)}
                    </div>
                  </div>
                  <div className="mt-3 grid gap-2 text-xs font-medium text-slate-600 md:grid-cols-3">
                    <div>Occurrences: {safeNumber(alert.count)}</div>
                    <div>Unresolved: {safeNumber(alert.unresolved_count)}</div>
                    <div>Average rating: {safeNumber(alert.avg_rating).toFixed(2)}</div>
                  </div>
                  <div className="mt-3 rounded-2xl border border-red-100 bg-red-50/50 px-3 py-2 text-xs font-semibold text-red-800">
                    {safeStr(alert.recommendation)}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        <div className="rounded-2xl border border-amber-200 bg-amber-50/40 p-4">
          <div className="mb-3 text-sm font-extrabold text-slate-900">High-priority watchlist</div>
          <div className="space-y-3">
            {high.length === 0 ? (
              <div className="rounded-2xl border border-amber-100 bg-white p-3 text-sm text-slate-500">
                No high-risk repeat issue alerts under the current filters.
              </div>
            ) : (
              high.map((alert, index) => (
                <div key={`${alert.entity_id}-${alert.taxonomy_code}-${index}`} className="rounded-2xl border border-amber-100 bg-white p-4">
                  <div className="flex flex-col gap-2 md:flex-row md:items-start md:justify-between">
                    <div>
                      <div className="text-sm font-bold text-slate-900">{safeStr(alert.entity_name, "Unknown entity")}</div>
                      <div className="mt-1 text-xs font-semibold uppercase tracking-wide text-slate-500">
                        {safeStr(alert.taxonomy_label || alert.taxonomy_code).replace(/_/g, " ")}
                      </div>
                    </div>
                    <div className="rounded-xl border border-amber-200 bg-amber-50 px-3 py-1 text-xs font-black text-amber-700">
                      Score {safeNumber(alert.repeat_issue_score, 0).toFixed(2)}
                    </div>
                  </div>
                  <div className="mt-3 grid gap-2 text-xs font-medium text-slate-600 md:grid-cols-3">
                    <div>Occurrences: {safeNumber(alert.count)}</div>
                    <div>Unresolved: {safeNumber(alert.unresolved_count)}</div>
                    <div>Average rating: {safeNumber(alert.avg_rating).toFixed(2)}</div>
                  </div>
                  <div className="mt-3 rounded-2xl border border-amber-100 bg-amber-50/50 px-3 py-2 text-xs font-semibold text-amber-800">
                    {safeStr(alert.recommendation)}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {alerts.length > 0 ? (
        <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
          <div className="mb-3 text-sm font-extrabold text-slate-900">Top repeat issue alerts</div>
          <div className="overflow-x-auto">
            <table className="min-w-full text-sm">
              <thead>
                <tr className="border-b border-slate-200 text-left text-slate-500">
                  <th className="px-3 py-2 font-semibold">Entity</th>
                  <th className="px-3 py-2 font-semibold">Issue</th>
                  <th className="px-3 py-2 font-semibold">Band</th>
                  <th className="px-3 py-2 font-semibold">Score</th>
                  <th className="px-3 py-2 font-semibold">Occurrences</th>
                  <th className="px-3 py-2 font-semibold">Unresolved</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((alert, index) => (
                  <tr key={`${alert.entity_id}-${alert.taxonomy_code}-${index}`} className="border-b border-slate-100">
                    <td className="px-3 py-2 font-semibold text-slate-900">{safeStr(alert.entity_name, "Unknown")}</td>
                    <td className="px-3 py-2">{safeStr(alert.taxonomy_label || alert.taxonomy_code).replace(/_/g, " ")}</td>
                    <td className="px-3 py-2">
                      <span className={`inline-flex rounded-full px-2.5 py-1 text-xs font-bold ${bandTone(alert.risk_band) === "red" ? "bg-red-100 text-red-700" : bandTone(alert.risk_band) === "rose" ? "bg-rose-100 text-rose-700" : bandTone(alert.risk_band) === "amber" ? "bg-amber-100 text-amber-700" : "bg-slate-100 text-slate-700"}`}>
                        {safeStr(alert.risk_band, "low")}
                      </span>
                    </td>
                    <td className="px-3 py-2">{safeNumber(alert.repeat_issue_score).toFixed(2)}</td>
                    <td className="px-3 py-2">{safeNumber(alert.count)}</td>
                    <td className="px-3 py-2">{safeNumber(alert.unresolved_count)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : null}
    </div>
  );
}
