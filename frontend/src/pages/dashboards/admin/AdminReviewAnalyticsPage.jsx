// ============================================================================
// frontend/src/pages/dashboards/admin/AdminReviewAnalyticsPage.jsx
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Platform-level complaint analytics dashboard for admins.
//
// PHASE 4C ADDITIONS:
//   ✅ Repeat issue risk panel
//   ✅ Alert threshold visibility
//   ✅ Governance-ready repeat issue watchlists
// ============================================================================

import React, { useEffect, useMemo, useState } from "react";
import { AlertTriangle, Filter, RefreshCw, ShieldCheck, TrendingUp } from "lucide-react";

import AdminLayout from "../../../components/AdminLayout";
import SimpleBarChart from "../../../components/ui/SimpleBarChart";
import RepeatIssueRiskPanel from "../../../components/reviews/RepeatIssueRiskPanel";
import { fetchAdminReviewAnalytics } from "../../../services/reviewAnalyticsApi";
import { fetchAdminRepeatIssueDetection } from "../../../services/repeatIssueApi";

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

function KpiCard({ title, value, subtitle, icon: Icon, tone = "slate" }) {
  const toneMap = {
    slate: "border-slate-200 bg-white",
    amber: "border-amber-200 bg-amber-50/70",
    emerald: "border-emerald-200 bg-emerald-50/70",
    rose: "border-rose-200 bg-rose-50/70",
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

export default function AdminReviewAnalyticsPage() {
  const [filters, setFilters] = useState({
    days: 90,
    bucket: "week",
    parent_group: "",
    taxonomy_code: "",
    resolution_status: "",
    detected_by: "",
    verified_only: true,
    only_negative: false,
    min_severity: 0,
    repeat_threshold: 2,
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [payload, setPayload] = useState({});
  const [riskPayload, setRiskPayload] = useState({});
  const [refreshKey, setRefreshKey] = useState(0);

  useEffect(() => {
    let active = true;

    async function load() {
      setLoading(true);
      setError("");
      try {
        const [analyticsData, repeatData] = await Promise.all([
          fetchAdminReviewAnalytics(filters),
          fetchAdminRepeatIssueDetection(filters),
        ]);
        if (!active) return;
        setPayload(analyticsData || {});
        setRiskPayload(repeatData || {});
      } catch (err) {
        if (!active) return;
        setError(err?.message || "Failed to load admin review analytics.");
      } finally {
        if (active) setLoading(false);
      }
    }

    load();
    return () => {
      active = false;
    };
  }, [filters, refreshKey]);

  const summary = safeObj(payload?.summary);
  const trend = safeArray(payload?.trend);
  const taxonomyBreakdown = safeArray(payload?.taxonomy_breakdown);
  const groupBreakdown = safeArray(payload?.parent_group_breakdown);
  const farmerBreakdown = safeArray(payload?.farmer_breakdown);
  const repeatClusters = safeArray(payload?.repeat_issue_clusters);
  const filterMeta = safeObj(payload?.filters);
  const parentGroups = safeArray(filterMeta?.parent_groups);
  const taxonomyItems = safeArray(filterMeta?.taxonomy_items);

  const trendLabels = useMemo(() => trend.map((row) => safeStr(row?.bucket)), [trend]);
  const trendValues = useMemo(() => trend.map((row) => safeNumber(row?.count)), [trend]);
  const taxonomyLabels = useMemo(
    () => taxonomyBreakdown.slice(0, 8).map((row) => safeStr(row?.taxonomy_label || row?.label)),
    [taxonomyBreakdown]
  );
  const taxonomyValues = useMemo(
    () => taxonomyBreakdown.slice(0, 8).map((row) => safeNumber(row?.count)),
    [taxonomyBreakdown]
  );
  const groupLabels = useMemo(
    () => groupBreakdown.slice(0, 8).map((row) => safeStr(row?.label || row?.parent_group)),
    [groupBreakdown]
  );
  const groupValues = useMemo(
    () => groupBreakdown.slice(0, 8).map((row) => safeNumber(row?.count)),
    [groupBreakdown]
  );

  const setFilter = (key, value) => {
    setFilters((prev) => ({ ...prev, [key]: value }));
  };

  return (
    <AdminLayout>
      <div className="space-y-6">
        <div className="flex flex-col gap-3 rounded-3xl border border-[#D8F3DC] bg-white p-6 shadow-sm lg:flex-row lg:items-center lg:justify-between">
          <div>
            <div className="text-xs font-bold uppercase tracking-[0.22em] text-[#2D6A4F]">
              Review Analytics
            </div>
            <h1 className="mt-2 text-3xl font-black tracking-tight text-slate-900">
              Platform complaint intelligence and hotspot tracking
            </h1>
            <p className="mt-2 max-w-3xl text-sm font-medium leading-6 text-slate-600">
              Aggregate complaint categories across the marketplace, compare farmer issue loads,
              and surface recurring quality risks that need governance or corrective action.
            </p>
          </div>

          <button
            type="button"
            onClick={() => setRefreshKey((value) => value + 1)}
            className="inline-flex items-center gap-2 rounded-2xl border border-[#B7E4C7] bg-[#F4FBF7] px-4 py-2 text-sm font-semibold text-[#1B4332] shadow-sm hover:bg-white"
          >
            <RefreshCw className="h-4 w-4" />
            Refresh analytics
          </button>
        </div>

        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          <KpiCard
            title="Complaint links"
            value={safeNumber(summary?.complaint_count, 0)}
            subtitle="Structured complaint instances"
            icon={AlertTriangle}
            tone="amber"
          />
          <KpiCard
            title="Farmers affected"
            value={safeNumber(summary?.farmer_count, 0)}
            subtitle="Distinct farmers in filtered analytics"
            icon={ShieldCheck}
          />
          <KpiCard
            title="Unresolved"
            value={safeNumber(summary?.unresolved_count, 0)}
            subtitle="Complaint links still not resolved"
            icon={ShieldCheck}
            tone="rose"
          />
          <KpiCard
            title="Repeat clusters"
            value={safeNumber(summary?.repeat_issue_cluster_count, 0)}
            subtitle="Recurring complaint hotspots"
            icon={TrendingUp}
            tone="emerald"
          />
        </div>

        <div className="rounded-3xl border border-[#D8F3DC] bg-white p-5 shadow-sm">
          <div className="mb-4 flex items-center gap-2 text-sm font-extrabold text-slate-900">
            <Filter className="h-4 w-4 text-[#2D6A4F]" />
            Complaint filters
          </div>

          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
            <label className="text-sm font-semibold text-slate-700">
              Days
              <select value={filters.days} onChange={(e) => setFilter("days", Number(e.target.value))} className="mt-1 w-full rounded-2xl border border-slate-200 bg-white px-3 py-2 text-sm">
                <option value={30}>Last 30 days</option>
                <option value={60}>Last 60 days</option>
                <option value={90}>Last 90 days</option>
                <option value={180}>Last 180 days</option>
                <option value={365}>Last 365 days</option>
              </select>
            </label>
            <label className="text-sm font-semibold text-slate-700">
              Trend bucket
              <select value={filters.bucket} onChange={(e) => setFilter("bucket", e.target.value)} className="mt-1 w-full rounded-2xl border border-slate-200 bg-white px-3 py-2 text-sm">
                <option value="day">Daily</option>
                <option value="week">Weekly</option>
                <option value="month">Monthly</option>
              </select>
            </label>
            <label className="text-sm font-semibold text-slate-700">
              Parent group
              <select value={filters.parent_group} onChange={(e) => setFilter("parent_group", e.target.value)} className="mt-1 w-full rounded-2xl border border-slate-200 bg-white px-3 py-2 text-sm">
                <option value="">All groups</option>
                {parentGroups.map((group) => (
                  <option key={group} value={group}>{safeStr(group).replace(/_/g, " ")}</option>
                ))}
              </select>
            </label>
            <label className="text-sm font-semibold text-slate-700">
              Taxonomy item
              <select value={filters.taxonomy_code} onChange={(e) => setFilter("taxonomy_code", e.target.value)} className="mt-1 w-full rounded-2xl border border-slate-200 bg-white px-3 py-2 text-sm">
                <option value="">All complaint types</option>
                {taxonomyItems.map((item) => (
                  <option key={item.taxonomy_id || item.code} value={item.code}>{item.label}</option>
                ))}
              </select>
            </label>
            <label className="text-sm font-semibold text-slate-700">
              Resolution status
              <select value={filters.resolution_status} onChange={(e) => setFilter("resolution_status", e.target.value)} className="mt-1 w-full rounded-2xl border border-slate-200 bg-white px-3 py-2 text-sm">
                <option value="">All statuses</option>
                <option value="open">Open</option>
                <option value="acknowledged">Acknowledged</option>
                <option value="in_progress">In progress</option>
                <option value="resolved">Resolved</option>
              </select>
            </label>
            <label className="text-sm font-semibold text-slate-700">
              Detected by
              <select value={filters.detected_by} onChange={(e) => setFilter("detected_by", e.target.value)} className="mt-1 w-full rounded-2xl border border-slate-200 bg-white px-3 py-2 text-sm">
                <option value="">All sources</option>
                <option value="customer">Customer</option>
                <option value="farmer">Farmer</option>
                <option value="admin">Admin</option>
                <option value="system">System</option>
              </select>
            </label>
            <label className="text-sm font-semibold text-slate-700">
              Minimum severity
              <select value={filters.min_severity} onChange={(e) => setFilter("min_severity", Number(e.target.value))} className="mt-1 w-full rounded-2xl border border-slate-200 bg-white px-3 py-2 text-sm">
                <option value={0}>All severities</option>
                <option value={2}>2 and above</option>
                <option value={3}>3 and above</option>
                <option value={4}>4 and above</option>
              </select>
            </label>
            <label className="text-sm font-semibold text-slate-700">
              Repeat threshold
              <select value={filters.repeat_threshold} onChange={(e) => setFilter("repeat_threshold", Number(e.target.value))} className="mt-1 w-full rounded-2xl border border-slate-200 bg-white px-3 py-2 text-sm">
                <option value={2}>2 occurrences</option>
                <option value={3}>3 occurrences</option>
                <option value={4}>4 occurrences</option>
              </select>
            </label>
          </div>

          <div className="mt-4 flex flex-wrap gap-4">
            <label className="inline-flex items-center gap-2 text-sm font-semibold text-slate-700">
              <input type="checkbox" checked={filters.verified_only} onChange={(e) => setFilter("verified_only", e.target.checked)} />
              Verified reviews only
            </label>
            <label className="inline-flex items-center gap-2 text-sm font-semibold text-slate-700">
              <input type="checkbox" checked={filters.only_negative} onChange={(e) => setFilter("only_negative", e.target.checked)} />
              Only negative reviews (≤ 3 stars)
            </label>
          </div>
        </div>

        {error ? <div className="rounded-2xl border border-rose-200 bg-rose-50 p-4 text-sm font-semibold text-rose-700">{error}</div> : null}

        {loading ? (
          <div className="rounded-2xl border border-slate-200 bg-white p-8 text-center text-sm text-slate-500 shadow-sm">
            Loading admin review analytics…
          </div>
        ) : (
          <>
            <RepeatIssueRiskPanel payload={riskPayload} title="Platform repeat issue risk panel" />

            <div className="grid gap-4 xl:grid-cols-3">
              <SimpleBarChart title="Complaint trend" labels={trendLabels} values={trendValues} height={280} />
              <SimpleBarChart title="Top complaint types" labels={taxonomyLabels} values={taxonomyValues} height={280} />
              <SimpleBarChart title="Parent group mix" labels={groupLabels} values={groupValues} height={280} />
            </div>

            <div className="grid gap-4 xl:grid-cols-2">
              <div className="rounded-3xl border border-[#D8F3DC] bg-white p-5 shadow-sm">
                <div className="mb-4 text-sm font-extrabold text-slate-900">Farmer complaint hotspots</div>
                <div className="overflow-x-auto">
                  <table className="min-w-full text-sm">
                    <thead>
                      <tr className="border-b border-slate-200 text-left text-slate-500">
                        <th className="px-3 py-2 font-semibold">Farmer</th>
                        <th className="px-3 py-2 font-semibold">Complaints</th>
                        <th className="px-3 py-2 font-semibold">Products</th>
                        <th className="px-3 py-2 font-semibold">Top issue</th>
                        <th className="px-3 py-2 font-semibold">Unresolved</th>
                      </tr>
                    </thead>
                    <tbody>
                      {farmerBreakdown.slice(0, 12).map((row) => (
                        <tr key={row.farmer_id} className="border-b border-slate-100">
                          <td className="px-3 py-2 font-semibold text-slate-900">{row.farmer_name}</td>
                          <td className="px-3 py-2">{safeNumber(row.count)}</td>
                          <td className="px-3 py-2">{safeNumber(row.product_count)}</td>
                          <td className="px-3 py-2">{safeStr(row.top_issue_code).replace(/_/g, " ") || "—"}</td>
                          <td className="px-3 py-2">{safeNumber(row.unresolved_count)}</td>
                        </tr>
                      ))}
                      {farmerBreakdown.length === 0 ? (
                        <tr>
                          <td colSpan={5} className="px-3 py-6 text-center text-slate-500">No farmer complaint hotspots found.</td>
                        </tr>
                      ) : null}
                    </tbody>
                  </table>
                </div>
              </div>

              <div className="rounded-3xl border border-[#D8F3DC] bg-white p-5 shadow-sm">
                <div className="mb-4 text-sm font-extrabold text-slate-900">Repeat issue clusters</div>
                <div className="space-y-3">
                  {repeatClusters.slice(0, 12).map((cluster, index) => (
                    <div key={`${cluster.entity_id}-${cluster.taxonomy_code}-${index}`} className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                      <div className="flex flex-col gap-2 md:flex-row md:items-start md:justify-between">
                        <div>
                          <div className="text-sm font-bold text-slate-900">{cluster.entity_name}</div>
                          <div className="mt-1 text-xs font-semibold uppercase tracking-wide text-slate-500">
                            {safeStr(cluster.taxonomy_label || cluster.taxonomy_code).replace(/_/g, " ")}
                          </div>
                        </div>
                        <div className="rounded-xl border border-amber-200 bg-amber-50 px-3 py-1 text-xs font-bold text-amber-700">
                          {safeNumber(cluster.count)} occurrences
                        </div>
                      </div>
                      <div className="mt-3 grid gap-2 text-xs font-medium text-slate-600 md:grid-cols-4">
                        <div>Scope: {cluster.scope}</div>
                        <div>Parent group: {safeStr(cluster.parent_group).replace(/_/g, " ")}</div>
                        <div>Unresolved: {safeNumber(cluster.unresolved_count)}</div>
                        <div>Average rating: {safeNumber(cluster.avg_rating).toFixed(2)}</div>
                      </div>
                    </div>
                  ))}
                  {repeatClusters.length === 0 ? (
                    <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4 text-sm text-slate-500">
                      No repeat issue clusters crossed the selected threshold.
                    </div>
                  ) : null}
                </div>
              </div>
            </div>
          </>
        )}
      </div>
    </AdminLayout>
  );
}
