// ============================================================================
// frontend/src/pages/dashboards/admin/AuditLogPage.jsx
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Admin audit workspace for:
//     • auth/session statistics
//     • governance decisions
//     • user activity evidence
//
// WHAT THIS VERSION IMPROVES:
//   ✅ Unified audit records now use real paging controls.
//   ✅ The page tells the admin where they are in the result set.
//   ✅ Daily auth timeline is easier to read with a mixed chart:
//        - bars for logins and logouts
//        - line for failed logins
//   ✅ Long date windows auto-skip labels instead of crowding the x-axis.
//   ✅ Top actions chart is easier to scan with a horizontal layout.
// ============================================================================

import React, { useCallback, useEffect, useMemo, useState } from "react";
import { motion } from "framer-motion";
import toast from "react-hot-toast";
import { format } from "date-fns";
import {
  ShieldCheck,
  Activity,
  LogIn,
  LogOut,
  RefreshCw,
  Search,
  Filter,
  Clock3,
  Download,
  AlertTriangle,
  UserCircle2,
  Database,
  TrendingUp,
  BarChart3,
  Users,
  CheckCircle2,
  Info,
  ChevronLeft,
  ChevronRight,
} from "lucide-react";
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  Tooltip,
  Legend,
} from "chart.js";
import { Line, Bar } from "react-chartjs-2";

import api from "../../../api";
import AdminLayout from "../../../components/AdminLayout";
import ProtectedRoute from "../../../components/auth/ProtectedRoute";
import Card from "../../../components/ui/Card";
import EmptyState from "../../../components/ui/EmptyState";
import SkeletonChart from "../../../components/ui/SkeletonChart";

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, BarElement, Tooltip, Legend);

const DAY_PRESETS = [7, 30, 90, 180, 365];

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------
function safeArray(value) {
  return Array.isArray(value) ? value : [];
}

function safeNumber(value, fallback = 0) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function safeString(value, fallback = "") {
  return typeof value === "string" && value.trim() ? value.trim() : fallback;
}

function formatDateTime(value) {
  if (!value) return "—";
  try {
    return format(new Date(value), "dd MMM yyyy HH:mm");
  } catch {
    return "—";
  }
}

function formatDateLabel(value) {
  if (!value) return "—";
  try {
    return format(new Date(value), "dd MMM");
  } catch {
    return value;
  }
}

function streamLabel(stream) {
  const raw = safeString(stream, "unknown").toLowerCase();
  if (raw === "auth") return "Auth";
  if (raw === "activity") return "Activity";
  if (raw === "governance") return "Governance";
  return "Unknown";
}

function streamBadgeClasses(stream) {
  const raw = safeString(stream, "unknown").toLowerCase();
  if (raw === "auth") return "border-blue-200 bg-blue-50 text-blue-700";
  if (raw === "activity") return "border-emerald-200 bg-emerald-50 text-emerald-700";
  if (raw === "governance") return "border-violet-200 bg-violet-50 text-violet-700";
  return "border-slate-200 bg-slate-50 text-slate-700";
}

function statusBadgeClasses(status) {
  const raw = safeString(status, "unknown").toLowerCase();
  if (raw === "success") return "border-emerald-200 bg-emerald-50 text-emerald-700";
  if (raw === "failed") return "border-rose-200 bg-rose-50 text-rose-700";
  if (raw === "blocked") return "border-amber-200 bg-amber-50 text-amber-700";
  return "border-slate-200 bg-slate-50 text-slate-700";
}

function compactJson(obj) {
  try {
    return JSON.stringify(obj || {}, null, 2);
  } catch {
    return "{}";
  }
}

function standardChartOptions(overrides = {}) {
  return {
    responsive: true,
    maintainAspectRatio: false,
    interaction: { mode: "index", intersect: false },
    plugins: {
      legend: {
        display: true,
        position: "top",
        align: "end",
        labels: {
          color: "#334155",
          font: { weight: "700" },
          usePointStyle: true,
          boxWidth: 10,
          boxHeight: 10,
        },
      },
      tooltip: {
        enabled: true,
        backgroundColor: "rgba(15,23,42,0.96)",
        titleColor: "#f8fafc",
        bodyColor: "#e2e8f0",
        padding: 10,
        titleFont: { weight: "800" },
        bodyFont: { weight: "700" },
      },
    },
    scales: {
      x: {
        grid: { display: false },
        ticks: {
          color: "#64748b",
          font: { weight: "700", size: 11 },
          autoSkip: true,
          maxRotation: 0,
          minRotation: 0,
        },
      },
      y: {
        beginAtZero: true,
        grace: "12%",
        grid: { color: "rgba(148,163,184,0.12)" },
        ticks: {
          color: "#475569",
          font: { weight: "700" },
          precision: 0,
        },
      },
    },
    ...overrides,
  };
}

function timelineChartOptions(labelCount = 0) {
  const maxTicksLimit = labelCount > 240 ? 16 : labelCount > 180 ? 14 : labelCount > 120 ? 12 : labelCount > 90 ? 10 : labelCount > 45 ? 8 : 7;

  return standardChartOptions({
    plugins: {
      legend: {
        display: true,
        position: "top",
        align: "end",
        labels: {
          color: "#334155",
          font: { weight: "700" },
          usePointStyle: true,
          boxWidth: 10,
          boxHeight: 10,
        },
      },
      tooltip: {
        enabled: true,
        backgroundColor: "rgba(15,23,42,0.96)",
        titleColor: "#f8fafc",
        bodyColor: "#e2e8f0",
        padding: 10,
        titleFont: { weight: "800" },
        bodyFont: { weight: "700" },
      },
    },
    scales: {
      x: {
        grid: { display: false },
        ticks: {
          color: "#64748b",
          font: { weight: "700", size: 11 },
          autoSkip: true,
          maxTicksLimit,
          maxRotation: 0,
          minRotation: 0,
        },
      },
      y: {
        beginAtZero: true,
        grace: "12%",
        grid: { color: "rgba(148,163,184,0.12)" },
        ticks: {
          color: "#475569",
          font: { weight: "700" },
          precision: 0,
        },
      },
    },
  });
}

function horizontalBarOptions() {
  return standardChartOptions({
    indexAxis: "y",
    scales: {
      x: {
        beginAtZero: true,
        grid: { color: "rgba(148,163,184,0.12)" },
        ticks: {
          color: "#475569",
          font: { weight: "700" },
          precision: 0,
        },
      },
      y: {
        grid: { display: false },
        ticks: {
          color: "#475569",
          font: { weight: "700", size: 11 },
        },
      },
    },
  });
}

function buildPageItems(currentPage, totalPages, maxVisible = 7) {
  if (totalPages <= maxVisible) {
    return Array.from({ length: totalPages }, (_, index) => index + 1);
  }

  const pages = [1];
  const siblingCount = 1;
  const left = Math.max(2, currentPage - siblingCount);
  const right = Math.min(totalPages - 1, currentPage + siblingCount);

  if (left > 2) pages.push("left-ellipsis");
  for (let page = left; page <= right; page += 1) pages.push(page);
  if (right < totalPages - 1) pages.push("right-ellipsis");
  pages.push(totalPages);

  return pages;
}

function KpiCard({ icon, title, value, subtitle, tone = "slate" }) {
  const toneMap = {
    slate: "border-slate-200 bg-white",
    emerald: "border-emerald-200 bg-emerald-50/70",
    blue: "border-blue-200 bg-blue-50/70",
    amber: "border-amber-200 bg-amber-50/70",
    rose: "border-rose-200 bg-rose-50/70",
    violet: "border-violet-200 bg-violet-50/70",
  };

  return (
    <Card className={`rounded-2xl border p-4 shadow-sm ${toneMap[tone] || toneMap.slate}`}>
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="text-xs font-bold uppercase tracking-wide text-slate-500">{title}</div>
          <div className="mt-2 text-2xl font-black text-slate-900">{value}</div>
          <div className="mt-1 text-xs font-semibold text-slate-600">{subtitle}</div>
        </div>
        <div className="rounded-xl border border-slate-200 bg-white p-2 text-slate-700 shadow-sm">
          {icon}
        </div>
      </div>
    </Card>
  );
}

function SectionTitle({ icon, title, subtitle }) {
  return (
    <div className="mb-3">
      <div className="flex items-center gap-2 text-sm font-extrabold text-slate-900">
        {icon}
        {title}
      </div>
      <div className="mt-1 text-xs font-semibold text-slate-500">{subtitle}</div>
    </div>
  );
}

function CoverageCard({ title, rows, note, available, primary }) {
  return (
    <div className={`rounded-2xl border p-4 ${available ? "border-slate-200 bg-white" : "border-amber-200 bg-amber-50/70"}`}>
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="text-xs font-bold uppercase tracking-wide text-slate-500">{title}</div>
          <div className="mt-2 text-xl font-black text-slate-900">{safeNumber(rows)}</div>
          <div className="mt-1 text-xs font-semibold text-slate-500">Primary source: {primary || "—"}</div>
        </div>
        <div className={`inline-flex rounded-full border px-2.5 py-1 text-xs font-extrabold ${available ? "border-emerald-200 bg-emerald-50 text-emerald-700" : "border-amber-200 bg-amber-50 text-amber-700"}`}>
          {available ? "Available" : "Fallback / Missing"}
        </div>
      </div>
      <div className="mt-3 text-xs font-semibold leading-5 text-slate-600">{note || "No note provided."}</div>
    </div>
  );
}

function InsightCard({ level, title, description }) {
  const tone = String(level || "info").toLowerCase();
  const classes =
    tone === "warning"
      ? "border-amber-200 bg-amber-50/70"
      : tone === "success"
      ? "border-emerald-200 bg-emerald-50/70"
      : "border-blue-200 bg-blue-50/70";
  const Icon = tone === "warning" ? AlertTriangle : tone === "success" ? CheckCircle2 : Info;

  return (
    <div className={`rounded-2xl border p-4 ${classes}`}>
      <div className="flex items-start gap-3">
        <div className="rounded-xl border border-white/70 bg-white p-2 text-slate-700 shadow-sm">
          <Icon className="h-4 w-4" />
        </div>
        <div>
          <div className="text-sm font-extrabold text-slate-900">{title}</div>
          <div className="mt-1 text-xs font-semibold leading-5 text-slate-600">{description}</div>
        </div>
      </div>
    </div>
  );
}

// ----------------------------------------------------------------------------
// Page
// ----------------------------------------------------------------------------
export default function AuditLogPage() {
  const [summary, setSummary] = useState(null);
  const [logs, setLogs] = useState([]);
  const [loadingSummary, setLoadingSummary] = useState(true);
  const [loadingLogs, setLoadingLogs] = useState(true);
  const [limit, setLimit] = useState(50);
  const [page, setPage] = useState(1);
  const [totalEstimate, setTotalEstimate] = useState(0);
  const [expandedRowId, setExpandedRowId] = useState(null);

  const [filters, setFilters] = useState({
    stream: "all",
    days: "30",
    q: "",
    action: "",
    role: "",
  });

  const offset = Math.max(0, (page - 1) * limit);

  const loadSummary = useCallback(async () => {
    try {
      setLoadingSummary(true);
      const params = {};
      const daysValue = Number(filters.days);
      if (Number.isFinite(daysValue) && daysValue > 0) params.days = daysValue;
      const res = await api.get("/admin/audit-log/summary", { params });
      setSummary(res?.data?.summary || null);
    } catch (error) {
      console.error("Failed to load audit summary:", error);
      toast.error("Failed to load audit summary");
      setSummary(null);
    } finally {
      setLoadingSummary(false);
    }
  }, [filters.days]);

  const loadLogs = useCallback(async () => {
    try {
      setLoadingLogs(true);
      const params = {
        stream: filters.stream || "all",
        limit,
        offset,
      };

      const daysValue = Number(filters.days);
      if (Number.isFinite(daysValue) && daysValue > 0) params.days = daysValue;
      if (safeString(filters.q)) params.q = filters.q.trim();
      if (safeString(filters.action)) params.action = filters.action.trim();
      if (safeString(filters.role)) params.role = filters.role.trim();

      const res = await api.get("/admin/audit-log", { params });
      const nextLogs = safeArray(res?.data?.items || res?.data?.logs);
      const nextTotal = safeNumber(res?.data?.total_estimate, nextLogs.length);

      setLogs(nextLogs);
      setTotalEstimate(nextTotal > 0 ? nextTotal : nextLogs.length);
      setExpandedRowId(null);
    } catch (error) {
      console.error("Failed to load audit logs:", error);
      toast.error("Failed to load audit log");
      setLogs([]);
      setTotalEstimate(0);
    } finally {
      setLoadingLogs(false);
    }
  }, [filters, limit, offset]);

  useEffect(() => {
    loadSummary();
  }, [loadSummary]);

  useEffect(() => {
    loadLogs();
  }, [loadLogs]);

  // Reset paging whenever the filter window changes.
  useEffect(() => {
    setPage(1);
    setExpandedRowId(null);
  }, [filters.stream, filters.days, filters.q, filters.action, filters.role, limit]);

  const onRefresh = async () => {
    const toastId = toast.loading("Refreshing audit data...");
    try {
      await Promise.all([loadSummary(), loadLogs()]);
      toast.success("Audit data refreshed");
    } catch {
      toast.error("Refresh failed");
    } finally {
      toast.dismiss(toastId);
    }
  };

  const onExportCsv = () => {
    if (!logs.length) {
      toast.error("No audit rows to export");
      return;
    }

    const header = [
      "Occurred At",
      "Stream",
      "Actor Name",
      "Actor Email",
      "Actor Role",
      "Action",
      "Target Type",
      "Target ID",
      "Status",
      "Route",
      "IP Address",
      "Source Table",
    ];

    const rows = logs.map((row) => [
      safeString(row?.occurred_at),
      safeString(row?.stream),
      safeString(row?.actor_name),
      safeString(row?.actor_email),
      safeString(row?.actor_role),
      safeString(row?.action),
      safeString(row?.target_type),
      safeString(row?.target_id),
      safeString(row?.status),
      safeString(row?.route),
      safeString(row?.ip_address),
      safeString(row?.source_table),
    ]);

    const csv = [header, ...rows]
      .map((line) =>
        line
          .map((cell) => {
            const value = `${cell ?? ""}`.replace(/"/g, '""');
            return `"${value}"`;
          })
          .join(",")
      )
      .join("\n");

    const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `agroconnect-audit-log-page-${page}-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const healthEntries = useMemo(() => {
    const health = summary?.health || {};
    return [
      { key: "auth", title: "Auth coverage", data: health?.auth || {} },
      { key: "activity", title: "Activity coverage", data: health?.activity || {} },
      { key: "governance", title: "Governance coverage", data: health?.governance || {} },
    ];
  }, [summary]);

  const authCountsChart = useMemo(() => {
    const auth = summary?.auth || {};
    return {
      labels: ["Logins", "Logouts", "Failed", "Refreshes"],
      datasets: [
        {
          label: "Auth events",
          data: [
            safeNumber(auth.logins),
            safeNumber(auth.logouts) + safeNumber(auth.logout_all),
            safeNumber(auth.failed_logins),
            safeNumber(auth.refreshes),
          ],
          backgroundColor: [
            "rgba(16,185,129,0.55)",
            "rgba(59,130,246,0.40)",
            "rgba(245,158,11,0.45)",
            "rgba(168,85,247,0.35)",
          ],
          borderColor: [
            "rgba(5,150,105,1)",
            "rgba(37,99,235,1)",
            "rgba(217,119,6,1)",
            "rgba(147,51,234,1)",
          ],
          borderWidth: 1,
          borderRadius: 10,
          maxBarThickness: 36,
        },
      ],
    };
  }, [summary]);

  const streamChartData = useMemo(() => {
    const streams = summary?.streams || {};
    return {
      labels: ["Governance", "Activity", "Auth"],
      datasets: [
        {
          label: "Evidence rows",
          data: [
            safeNumber(streams.governance),
            safeNumber(streams.activity),
            safeNumber(streams.auth),
          ],
          backgroundColor: [
            "rgba(139,92,246,0.35)",
            "rgba(16,185,129,0.35)",
            "rgba(59,130,246,0.35)",
          ],
          borderColor: [
            "rgba(124,58,237,1)",
            "rgba(5,150,105,1)",
            "rgba(37,99,235,1)",
          ],
          borderWidth: 1,
          borderRadius: 10,
          maxBarThickness: 42,
        },
      ],
    };
  }, [summary]);

  const authTimelineChart = useMemo(() => {
    const timeline = summary?.timeline || {};
    const labels = safeArray(timeline.labels).map((item) => formatDateLabel(item));
    const logins = safeArray(timeline.login).map((value) => safeNumber(value));
    const logouts = safeArray(timeline.logout).map((value) => safeNumber(value));
    const failed = safeArray(timeline.failed_login).map((value) => safeNumber(value));

    return {
      labels,
      datasets: [
        {
          type: "bar",
          label: "Logins",
          data: logins,
          backgroundColor: "rgba(16,185,129,0.38)",
          borderColor: "rgba(5,150,105,1)",
          borderWidth: 1,
          borderRadius: 8,
          maxBarThickness: 18,
          order: 2,
        },
        {
          type: "bar",
          label: "Logouts",
          data: logouts,
          backgroundColor: "rgba(59,130,246,0.24)",
          borderColor: "rgba(37,99,235,0.95)",
          borderWidth: 1,
          borderRadius: 8,
          maxBarThickness: 18,
          order: 3,
        },
        {
          type: "line",
          label: "Failed logins",
          data: failed,
          borderColor: "rgba(245,158,11,1)",
          backgroundColor: "rgba(245,158,11,0.12)",
          borderWidth: 2.5,
          tension: 0.32,
          fill: true,
          spanGaps: true,
          pointRadius: failed.map((value) => (value > 0 ? 3 : 0)),
          pointHoverRadius: failed.map((value) => (value > 0 ? 5 : 3)),
          pointBackgroundColor: "rgba(245,158,11,1)",
          pointBorderColor: "#ffffff",
          pointBorderWidth: 1.5,
          order: 1,
        },
      ],
    };
  }, [summary]);

  const topActionsChart = useMemo(() => {
    const actions = safeArray(summary?.top_actions).slice(0, 7);
    return {
      labels: actions.map((row) => safeString(row?.action, "unknown")),
      datasets: [
        {
          label: "Occurrences",
          data: actions.map((row) => safeNumber(row?.count)),
          backgroundColor: "rgba(99,102,241,0.28)",
          borderColor: "rgba(79,70,229,1)",
          borderWidth: 1,
          borderRadius: 10,
        },
      ],
    };
  }, [summary]);

  const hasTopActions = safeArray(summary?.top_actions).length > 0;
  const insights = safeArray(summary?.insights);
  const topActors = safeArray(summary?.top_actors);

  const totalPages = useMemo(() => {
    const rows = Math.max(totalEstimate, logs.length);
    return Math.max(1, Math.ceil(rows / Math.max(1, limit)));
  }, [limit, logs.length, totalEstimate]);

  const visiblePageItems = useMemo(() => buildPageItems(page, totalPages), [page, totalPages]);
  const pageStart = logs.length ? offset + 1 : 0;
  const pageEnd = logs.length ? offset + logs.length : 0;

  return (
    <ProtectedRoute roles={["admin"]}>
      <AdminLayout>
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.25 }}
          className="space-y-6"
        >
          <div className="flex flex-col gap-4 rounded-3xl border border-emerald-100 bg-white/90 p-5 shadow-sm md:flex-row md:items-start md:justify-between">
            <div>
              <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wide text-emerald-700">
                <ShieldCheck className="h-4 w-4" />
                Audit intelligence workspace
              </div>
              <h1 className="mt-2 text-3xl font-black tracking-tight text-slate-900">
                Audit Log &amp; User Activity
              </h1>
              <p className="mt-2 max-w-3xl text-sm font-semibold leading-6 text-slate-600">
                Designed to answer three questions fast: who accessed the platform, what users did,
                and what privileged admin decisions changed the system state.
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <button
                onClick={onRefresh}
                className="inline-flex items-center gap-2 rounded-2xl border border-slate-200 bg-white px-4 py-2 text-sm font-extrabold text-slate-700 shadow-sm transition hover:bg-slate-50"
              >
                <RefreshCw className="h-4 w-4" />
                Refresh
              </button>
              <button
                onClick={onExportCsv}
                className="inline-flex items-center gap-2 rounded-2xl border border-emerald-200 bg-emerald-50 px-4 py-2 text-sm font-extrabold text-emerald-700 shadow-sm transition hover:bg-emerald-100"
              >
                <Download className="h-4 w-4" />
                Export CSV
              </button>
            </div>
          </div>

          <Card className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
            <SectionTitle
              icon={<Clock3 className="h-4 w-4 text-slate-700" />}
              title="Time range and filters"
              subtitle="Use the day presets first, then narrow by stream, role, action, or free-text search."
            />

            <div className="mb-4 flex flex-wrap gap-2">
              {DAY_PRESETS.map((days) => {
                const active = Number(filters.days) === days;
                return (
                  <button
                    key={days}
                    type="button"
                    onClick={() => setFilters((prev) => ({ ...prev, days: String(days) }))}
                    className={[
                      "rounded-2xl border px-4 py-2 text-sm font-extrabold transition",
                      active
                        ? "border-emerald-500 bg-emerald-50 text-emerald-700"
                        : "border-slate-200 bg-white text-slate-700 hover:bg-slate-50",
                    ].join(" ")}
                  >
                    Last {days} days
                  </button>
                );
              })}
            </div>

            <div className="grid grid-cols-1 gap-3 md:grid-cols-5">
              <label className="block">
                <span className="mb-1 block text-xs font-bold uppercase tracking-wide text-slate-500">
                  Stream
                </span>
                <select
                  value={filters.stream}
                  onChange={(e) => setFilters((prev) => ({ ...prev, stream: e.target.value }))}
                  className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm font-semibold text-slate-700 outline-none focus:border-emerald-400"
                >
                  <option value="all">All streams</option>
                  <option value="auth">Auth</option>
                  <option value="activity">Activity</option>
                  <option value="governance">Governance</option>
                </select>
              </label>

              <label className="block">
                <span className="mb-1 block text-xs font-bold uppercase tracking-wide text-slate-500">
                  Days
                </span>
                <select
                  value={filters.days}
                  onChange={(e) => setFilters((prev) => ({ ...prev, days: e.target.value }))}
                  className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm font-semibold text-slate-700 outline-none focus:border-emerald-400"
                >
                  {DAY_PRESETS.map((days) => (
                    <option key={days} value={String(days)}>
                      Last {days} days
                    </option>
                  ))}
                </select>
              </label>

              <label className="block">
                <span className="mb-1 block text-xs font-bold uppercase tracking-wide text-slate-500">
                  Role
                </span>
                <select
                  value={filters.role}
                  onChange={(e) => setFilters((prev) => ({ ...prev, role: e.target.value }))}
                  className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm font-semibold text-slate-700 outline-none focus:border-emerald-400"
                >
                  <option value="">All roles</option>
                  <option value="admin">Admin</option>
                  <option value="farmer">Farmer</option>
                  <option value="customer">Customer</option>
                </select>
              </label>

              <label className="block">
                <span className="mb-1 block text-xs font-bold uppercase tracking-wide text-slate-500">
                  Action
                </span>
                <input
                  value={filters.action}
                  onChange={(e) => setFilters((prev) => ({ ...prev, action: e.target.value }))}
                  placeholder="e.g. login, approved, search"
                  className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm font-semibold text-slate-700 outline-none transition placeholder:text-slate-400 focus:border-emerald-400"
                />
              </label>

              <label className="block">
                <span className="mb-1 block text-xs font-bold uppercase tracking-wide text-slate-500">
                  Search
                </span>
                <div className="relative">
                  <Search className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-slate-400" />
                  <input
                    value={filters.q}
                    onChange={(e) => setFilters((prev) => ({ ...prev, q: e.target.value }))}
                    placeholder="user, product, query, IP…"
                    className="w-full rounded-xl border border-slate-200 bg-white py-2 pl-9 pr-3 text-sm font-semibold text-slate-700 outline-none transition placeholder:text-slate-400 focus:border-emerald-400"
                  />
                </div>
              </label>
            </div>
          </Card>

          <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
            {healthEntries.map((entry) => (
              <CoverageCard
                key={entry.key}
                title={entry.title}
                rows={entry.data?.rows}
                note={entry.data?.note}
                available={Boolean(entry.data?.available)}
                primary={entry.data?.primary}
              />
            ))}
          </div>

          <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
            <KpiCard
              icon={<LogIn className="h-5 w-5" />}
              title="Logins"
              value={loadingSummary ? "…" : safeNumber(summary?.auth?.logins)}
              subtitle="Successful login events in selected period"
              tone="emerald"
            />
            <KpiCard
              icon={<LogOut className="h-5 w-5" />}
              title="Logouts"
              value={loadingSummary ? "…" : safeNumber(summary?.auth?.logouts) + safeNumber(summary?.auth?.logout_all)}
              subtitle="Explicit session terminations"
              tone="blue"
            />
            <KpiCard
              icon={<AlertTriangle className="h-5 w-5" />}
              title="Failed logins"
              value={loadingSummary ? "…" : safeNumber(summary?.auth?.failed_logins)}
              subtitle="Credential or access failure signal"
              tone="amber"
            />
            <KpiCard
              icon={<Users className="h-5 w-5" />}
              title="Users online now"
              value={loadingSummary ? "…" : safeNumber(summary?.auth?.active_users_now)}
              subtitle="Best-effort recent presence estimate"
              tone="violet"
            />
          </div>

          <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
            <Card className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm xl:col-span-2">
              <SectionTitle
                icon={<TrendingUp className="h-4 w-4 text-slate-700" />}
                title="Key insights"
                subtitle="Interpretive findings derived from the currently selected evidence window."
              />
              {loadingSummary ? (
                <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
                  <SkeletonChart />
                  <SkeletonChart />
                </div>
              ) : insights.length ? (
                <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
                  {insights.map((item, index) => (
                    <InsightCard
                      key={`${safeString(item?.title, "insight")}-${index}`}
                      level={item?.level}
                      title={safeString(item?.title, "Insight")}
                      description={safeString(item?.description, "")}
                    />
                  ))}
                </div>
              ) : (
                <EmptyState message="No insight bullets are available yet for the current filters." />
              )}
            </Card>

            <Card className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm xl:col-span-1">
              <SectionTitle
                icon={<UserCircle2 className="h-4 w-4 text-slate-700" />}
                title="Most visible actors"
                subtitle="Who appears most often across the selected evidence window."
              />
              {loadingSummary ? (
                <SkeletonChart />
              ) : topActors.length ? (
                <div className="space-y-3">
                  {topActors.slice(0, 6).map((actor, index) => (
                    <div key={`${safeString(actor?.actor_name, "actor")}-${index}`} className="flex items-start justify-between gap-3 rounded-2xl border border-slate-200 bg-slate-50/70 px-3 py-3">
                      <div>
                        <div className="text-sm font-extrabold text-slate-900">{safeString(actor?.actor_name, "Unknown user")}</div>
                        <div className="mt-0.5 text-xs font-semibold text-slate-500">{safeString(actor?.actor_email, "—")}</div>
                        <div className="mt-1 inline-flex rounded-full border border-slate-200 bg-white px-2.5 py-1 text-[11px] font-extrabold capitalize text-slate-700">
                          {safeString(actor?.actor_role, "unknown")}
                        </div>
                      </div>
                      <div className="rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm font-black text-slate-900 shadow-sm">
                        {safeNumber(actor?.count)}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <EmptyState message="No actor dominance data is available for this window." />
              )}
            </Card>
          </div>

          <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
            <Card className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
              <SectionTitle
                icon={<BarChart3 className="h-4 w-4 text-slate-700" />}
                title="Auth event mix"
                subtitle="Counts of the core authentication and session events."
              />
              {loadingSummary ? (
                <SkeletonChart />
              ) : (
                <div className="h-72">
                  <Bar data={authCountsChart} options={standardChartOptions()} />
                </div>
              )}
            </Card>

            <Card className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm xl:col-span-2">
              <SectionTitle
                icon={<TrendingUp className="h-4 w-4 text-slate-700" />}
                title="Daily auth timeline"
                subtitle="Bars show login and logout volume. The line isolates failed logins so spikes are easier to spot."
              />
              {loadingSummary ? (
                <SkeletonChart />
              ) : (
                <div className="h-80">
                  <Line data={authTimelineChart} options={timelineChartOptions(safeArray(summary?.timeline?.labels).length)} />
                </div>
              )}
            </Card>
          </div>

          <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
            <Card className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
              <SectionTitle
                icon={<Database className="h-4 w-4 text-slate-700" />}
                title="Stream volume"
                subtitle="How much evidence is currently available by audit stream."
              />
              {loadingSummary ? (
                <SkeletonChart />
              ) : (
                <div className="h-72">
                  <Bar data={streamChartData} options={standardChartOptions()} />
                </div>
              )}
            </Card>

            <Card className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
              <SectionTitle
                icon={<Filter className="h-4 w-4 text-slate-700" />}
                title="Top actions"
                subtitle="Most frequent action labels inside the selected evidence window."
              />
              {loadingSummary ? (
                <SkeletonChart />
              ) : hasTopActions ? (
                <div className="h-72">
                  <Bar data={topActionsChart} options={horizontalBarOptions()} />
                </div>
              ) : (
                <EmptyState message="No action concentration could be derived for the current filters." />
              )}
            </Card>
          </div>

          <Card className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
            <div className="mb-3 flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
              <SectionTitle
                icon={<Activity className="h-4 w-4 text-slate-700" />}
                title="Unified audit records"
                subtitle="Combined evidence stream for auth, activity, and governance."
              />

              <div className="flex flex-wrap items-center gap-2">
                <div className="rounded-xl border border-slate-200 bg-slate-50 px-3 py-2 text-xs font-bold text-slate-600">
                  Page <span className="text-slate-900">{page}</span> of <span className="text-slate-900">{totalPages}</span>
                </div>
                <div className="rounded-xl border border-slate-200 bg-slate-50 px-3 py-2 text-xs font-bold text-slate-600">
                  Showing <span className="text-slate-900">{pageStart || 0}</span>–<span className="text-slate-900">{pageEnd || 0}</span> of about <span className="text-slate-900">{Math.max(totalEstimate, logs.length)}</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-xs font-bold uppercase tracking-wide text-slate-500">Rows</span>
                  <select
                    value={String(limit)}
                    onChange={(e) => setLimit(Number(e.target.value) || 50)}
                    className="rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm font-semibold text-slate-700 outline-none focus:border-emerald-400"
                  >
                    <option value="25">25</option>
                    <option value="50">50</option>
                    <option value="100">100</option>
                    <option value="150">150</option>
                  </select>
                </div>
              </div>
            </div>

            {loadingLogs ? (
              <p className="text-sm font-semibold text-slate-500">Loading audit records…</p>
            ) : logs.length === 0 ? (
              <EmptyState message="No audit records were found for the current filters. If this is unexpected, expand the date range first and then check the coverage cards above." />
            ) : (
              <>
                <div className="overflow-x-auto">
                  <table className="min-w-full text-sm">
                    <thead className="border-b border-slate-200 text-slate-500">
                      <tr>
                        <th className="px-3 py-3 text-left text-xs font-extrabold uppercase tracking-wide">Time</th>
                        <th className="px-3 py-3 text-left text-xs font-extrabold uppercase tracking-wide">Stream</th>
                        <th className="px-3 py-3 text-left text-xs font-extrabold uppercase tracking-wide">Actor</th>
                        <th className="px-3 py-3 text-left text-xs font-extrabold uppercase tracking-wide">Role</th>
                        <th className="px-3 py-3 text-left text-xs font-extrabold uppercase tracking-wide">Action</th>
                        <th className="px-3 py-3 text-left text-xs font-extrabold uppercase tracking-wide">Target</th>
                        <th className="px-3 py-3 text-left text-xs font-extrabold uppercase tracking-wide">Status</th>
                        <th className="px-3 py-3 text-left text-xs font-extrabold uppercase tracking-wide">Details</th>
                      </tr>
                    </thead>
                    <tbody>
                      {logs.map((row, idx) => {
                        const rowId = safeString(row?.id, `row-${idx}`);
                        const isExpanded = expandedRowId === rowId;
                        const actorName = safeString(row?.actor_name, "Unknown user");
                        const actorEmail = safeString(row?.actor_email);
                        const action = safeString(row?.action, "unknown");
                        const targetType = safeString(row?.target_type, "system");
                        const detailsText =
                          safeString(row?.route) ||
                          safeString(row?.ip_address) ||
                          safeString(row?.source_table) ||
                          "View metadata";

                        return (
                          <React.Fragment key={rowId}>
                            <tr className="border-b border-slate-100 align-top transition hover:bg-slate-50/70">
                              <td className="px-3 py-3 font-semibold text-slate-700">
                                {formatDateTime(row?.occurred_at)}
                              </td>
                              <td className="px-3 py-3">
                                <span className={`inline-flex rounded-full border px-2.5 py-1 text-xs font-bold ${streamBadgeClasses(row?.stream)}`}>
                                  {streamLabel(row?.stream)}
                                </span>
                              </td>
                              <td className="px-3 py-3">
                                <div className="font-bold text-slate-900">{actorName}</div>
                                <div className="text-xs font-medium text-slate-500">{actorEmail || "—"}</div>
                              </td>
                              <td className="px-3 py-3">
                                <span className="inline-flex rounded-full border border-slate-200 bg-slate-50 px-2.5 py-1 text-xs font-bold capitalize text-slate-700">
                                  {safeString(row?.actor_role, "unknown")}
                                </span>
                              </td>
                              <td className="px-3 py-3 font-bold text-slate-900">{action}</td>
                              <td className="px-3 py-3">
                                <div className="font-semibold capitalize text-slate-800">{targetType}</div>
                                <div className="text-xs font-medium text-slate-500">{safeString(row?.target_id, "—")}</div>
                              </td>
                              <td className="px-3 py-3">
                                <span className={`inline-flex rounded-full border px-2.5 py-1 text-xs font-bold ${statusBadgeClasses(row?.status)}`}>
                                  {safeString(row?.status, "unknown")}
                                </span>
                              </td>
                              <td className="px-3 py-3">
                                <button
                                  type="button"
                                  onClick={() => setExpandedRowId((prev) => (prev === rowId ? null : rowId))}
                                  className="rounded-xl border border-slate-200 bg-white px-3 py-2 text-left text-xs font-bold text-slate-700 shadow-sm transition hover:bg-slate-50"
                                >
                                  {isExpanded ? "Hide" : "View"} · {detailsText}
                                </button>
                              </td>
                            </tr>

                            {isExpanded && (
                              <tr className="border-b border-slate-100 bg-slate-50/60">
                                <td colSpan={8} className="px-4 py-4">
                                  <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
                                    <div className="rounded-2xl border border-slate-200 bg-white p-3 shadow-sm">
                                      <div className="text-xs font-extrabold uppercase tracking-wide text-slate-500">Context</div>
                                      <div className="mt-2 space-y-1 text-sm text-slate-700">
                                        <div><span className="font-bold">Time:</span> {formatDateTime(row?.occurred_at)}</div>
                                        <div><span className="font-bold">Action:</span> {safeString(row?.action, "—")}</div>
                                        <div><span className="font-bold">Route:</span> {safeString(row?.route, "—")}</div>
                                        <div><span className="font-bold">IP:</span> {safeString(row?.ip_address, "—")}</div>
                                        <div><span className="font-bold">Source:</span> {safeString(row?.source_table, "—")}</div>
                                      </div>
                                    </div>

                                    <div className="rounded-2xl border border-slate-200 bg-white p-3 shadow-sm">
                                      <div className="text-xs font-extrabold uppercase tracking-wide text-slate-500">Identity snapshot</div>
                                      <div className="mt-2 space-y-1 text-sm text-slate-700">
                                        <div><span className="font-bold">Actor ID:</span> {safeString(row?.actor_id, "—")}</div>
                                        <div><span className="font-bold">Role:</span> {safeString(row?.actor_role, "—")}</div>
                                        <div><span className="font-bold">Target ID:</span> {safeString(row?.target_id, "—")}</div>
                                        <div><span className="font-bold">User agent:</span> {safeString(row?.user_agent, "—")}</div>
                                      </div>
                                    </div>

                                    <div className="rounded-2xl border border-slate-200 bg-white p-3 shadow-sm">
                                      <div className="text-xs font-extrabold uppercase tracking-wide text-slate-500">Metadata</div>
                                      <pre className="mt-2 max-h-56 overflow-auto rounded-xl bg-slate-900 p-3 text-xs font-medium text-slate-100">
                                        {compactJson(row?.metadata)}
                                      </pre>
                                    </div>
                                  </div>
                                </td>
                              </tr>
                            )}
                          </React.Fragment>
                        );
                      })}
                    </tbody>
                  </table>
                </div>

                <div className="mt-4 flex flex-col gap-3 border-t border-slate-200 pt-4 md:flex-row md:items-center md:justify-between">
                  <div className="text-sm font-semibold text-slate-600">
                    Showing <span className="font-extrabold text-slate-900">{pageStart || 0}</span>–<span className="font-extrabold text-slate-900">{pageEnd || 0}</span> of about <span className="font-extrabold text-slate-900">{Math.max(totalEstimate, logs.length)}</span> filtered records.
                  </div>

                  <div className="flex flex-wrap items-center gap-2">
                    <button
                      type="button"
                      onClick={() => setPage((prev) => Math.max(1, prev - 1))}
                      disabled={page <= 1}
                      className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm font-extrabold text-slate-700 shadow-sm transition hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-50"
                    >
                      <ChevronLeft className="h-4 w-4" />
                      Previous
                    </button>

                    {visiblePageItems.map((item, index) => {
                      if (typeof item !== "number") {
                        return (
                          <span key={`${item}-${index}`} className="px-2 py-2 text-sm font-bold text-slate-400">
                            …
                          </span>
                        );
                      }

                      const active = item === page;
                      return (
                        <button
                          key={item}
                          type="button"
                          onClick={() => setPage(item)}
                          className={[
                            "rounded-xl border px-3 py-2 text-sm font-extrabold shadow-sm transition",
                            active
                              ? "border-emerald-500 bg-emerald-50 text-emerald-700"
                              : "border-slate-200 bg-white text-slate-700 hover:bg-slate-50",
                          ].join(" ")}
                        >
                          {item}
                        </button>
                      );
                    })}

                    <button
                      type="button"
                      onClick={() => setPage((prev) => Math.min(totalPages, prev + 1))}
                      disabled={page >= totalPages}
                      className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm font-extrabold text-slate-700 shadow-sm transition hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-50"
                    >
                      Next
                      <ChevronRight className="h-4 w-4" />
                    </button>
                  </div>
                </div>
              </>
            )}
          </Card>
        </motion.div>
      </AdminLayout>
    </ProtectedRoute>
  );
}
