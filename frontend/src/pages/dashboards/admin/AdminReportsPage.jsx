// ============================================================================
// frontend/src/pages/dashboards/admin/AdminReportsPage.jsx
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Admin reporting workspace for:
//     • analytics overview
//     • auth + audit reporting
//     • moderation SLA reporting
//     • standard report generation
//     • ad hoc report generation
//     • professional CSV/PDF export
//
// BACKEND CONTRACTS USED:
//   GET  /admin/reports/overview
//   GET  /admin/reports/audit-overview
//   GET  /admin/reports/moderation-sla
//   GET  /admin/reports/catalog
//   POST /admin/reports/generate
//   POST /admin/reports/generate/export
//
// UPDATED DESIGN:
//   ✅ Moves report-builder workflow into ReportBuilderDrawer
//   ✅ Keeps analytics overview widgets
//   ✅ Keeps moderation SLA export shortcuts
//   ✅ Keeps recent activity feed
//   ✅ Cleaner page with reusable report builder component
//   ✅ Auto-opens drawer from ?builder=1
//   ✅ Keeps URL state in sync when opening/closing the drawer
// ============================================================================

import React, { useCallback, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import toast from "react-hot-toast";
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  Tooltip,
  Legend,
} from "chart.js";
import { Line, Bar, Doughnut } from "react-chartjs-2";
import {
  RefreshCw,
  FileDown,
  TrendingUp,
  Users,
  ShoppingCart,
  Package,
  Star,
  ShieldCheck,
  Activity,
  LogIn,
  AlertTriangle,
  Clock3,
  Wand2,
  FileText,
  Eye,
  X,
} from "lucide-react";

import api from "../../../api";
import AdminLayout from "../../../components/AdminLayout";
import ProtectedRoute from "../../../components/auth/ProtectedRoute";
import Card from "../../../components/ui/Card";
import EmptyState from "../../../components/ui/EmptyState";
import SkeletonChart from "../../../components/ui/SkeletonChart";
import ReportBuilderDrawer from "../../../components/admin/ReportBuilderDrawer";

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  ArcElement,
  Tooltip,
  Legend
);

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

function pickSeries(timeSeries, key) {
  return safeArray(timeSeries?.[key]);
}

function extractLabels(rows) {
  return safeArray(rows).map(
    (row, index) => row?.label || row?.bucket || row?.date || `Point ${index + 1}`
  );
}

function extractValues(rows) {
  return safeArray(rows).map((row) => safeNumber(row?.count));
}

function formatDateTime(value) {
  if (!value) return "—";
  try {
    const dt = new Date(value);
    return Number.isNaN(dt.getTime()) ? "—" : dt.toLocaleString();
  } catch {
    return "—";
  }
}

function chartOptions() {
  return {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        labels: {
          color: "#334155",
          font: { weight: "700" },
        },
      },
      tooltip: { enabled: true },
    },
    scales: {
      x: {
        grid: { color: "rgba(148,163,184,0.12)" },
        ticks: { color: "#475569", font: { weight: "600" } },
      },
      y: {
        beginAtZero: true,
        grid: { color: "rgba(148,163,184,0.12)" },
        ticks: { color: "#475569", font: { weight: "600" } },
      },
    },
  };
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

function SectionTitle({ icon, title, subtitle, right }) {
  return (
    <div className="mb-4 flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
      <div>
        <div className="flex items-center gap-2 text-sm font-extrabold text-slate-900">
          {icon}
          {title}
        </div>
        <div className="mt-1 text-xs font-semibold text-slate-500">{subtitle}</div>
      </div>
      {right ? <div>{right}</div> : null}
    </div>
  );
}

function buildReportPayload(form) {
  const payload = {
    report_key: form.report_key,
    preview_limit: safeNumber(form.preview_limit, 25),
  };

  const maybeAssign = (key, value) => {
    if (value !== null && value !== undefined && `${value}`.trim() !== "") {
      payload[key] = value;
    }
  };

  maybeAssign("period", form.period);
  maybeAssign("span", form.span);
  maybeAssign("days", form.days);
  maybeAssign("date_from", form.date_from);
  maybeAssign("date_to", form.date_to);
  maybeAssign("q", form.q);
  maybeAssign("role", form.role);
  maybeAssign("action", form.action);
  maybeAssign("status", form.status);
  maybeAssign("event_type", form.event_type);
  maybeAssign("actor_role", form.actor_role);
  maybeAssign("limit", form.limit);
  maybeAssign("sla_hours", form.sla_hours);

  return payload;
}

function reportTone(reportKey) {
  if (reportKey === "auth_activity") return "blue";
  if (reportKey === "user_activity") return "emerald";
  if (reportKey === "product_lifecycle") return "amber";
  if (reportKey === "product_search_statistics") return "violet";
  if (reportKey === "moderation_sla") return "rose";
  return "slate";
}

function reportToneClasses(reportKey) {
  const tone = reportTone(reportKey);

  if (tone === "blue") return "border-blue-200 bg-blue-50/50";
  if (tone === "emerald") return "border-emerald-200 bg-emerald-50/50";
  if (tone === "amber") return "border-amber-200 bg-amber-50/50";
  if (tone === "violet") return "border-violet-200 bg-violet-50/50";
  if (tone === "rose") return "border-rose-200 bg-rose-50/50";
  return "border-slate-200 bg-slate-50/50";
}

function suggestReportPeriodFromDays(daysValue) {
  const days = safeNumber(daysValue, 30);
  if (days <= 31) return "day";
  if (days <= 120) return "week";
  if (days <= 365) return "month";
  return "year";
}

function filenameFromDisposition(contentDisposition, fallback) {
  const raw = safeString(contentDisposition);
  const utf8Match = raw.match(/filename\*=UTF-8''([^;]+)/i);
  if (utf8Match?.[1]) {
    try {
      return decodeURIComponent(utf8Match[1]);
    } catch {
      return utf8Match[1];
    }
  }

  const plainMatch = raw.match(/filename=([^;]+)/i);
  if (plainMatch?.[1]) return plainMatch[1].replace(/["']/g, "");
  return fallback;
}

async function parseBlobError(blob) {
  if (!(blob instanceof Blob)) return null;
  try {
    const text = await blob.text();
    if (!text) return null;
    const data = JSON.parse(text);
    return safeString(data?.error || data?.message || data?.detail || data?.details, text);
  } catch {
    return null;
  }
}

function isEventLike(value) {
  return !!(
    value &&
    typeof value === "object" &&
    (typeof value.preventDefault === "function" || typeof value.stopPropagation === "function" || value.nativeEvent)
  );
}

function normalizePayloadOverride(value) {
  if (!value || isEventLike(value) || Array.isArray(value)) return null;
  return typeof value === "object" ? value : null;
}

// ----------------------------------------------------------------------------
// Page
// ----------------------------------------------------------------------------
export default function AdminReportsPage() {
  const [searchParams, setSearchParams] = useSearchParams();

  const [period, setPeriod] = useState("week");
  const [span, setSpan] = useState(12);
  const [slaHours, setSlaHours] = useState(48);

  const [overview, setOverview] = useState(null);
  const [auditOverview, setAuditOverview] = useState(null);
  const [moderationSla, setModerationSla] = useState(null);

  const [catalog, setCatalog] = useState([]);
  const [loadingCatalog, setLoadingCatalog] = useState(true);

  const [drawerOpen, setDrawerOpen] = useState(false);
  const [standardDays, setStandardDays] = useState(90);
  const [previewDialogOpen, setPreviewDialogOpen] = useState(false);

  const [reportForm, setReportForm] = useState({
    report_key: "auth_activity",
    period: "month",
    span: 12,
    days: "",
    date_from: "",
    date_to: "",
    q: "",
    role: "",
    action: "",
    status: "",
    event_type: "",
    actor_role: "",
    limit: 500,
    sla_hours: 48,
    preview_limit: 25,
  });

  const [reportPreview, setReportPreview] = useState(null);
  const [previewExportPayload, setPreviewExportPayload] = useState(null);
  const [loadingPreview, setLoadingPreview] = useState(false);
  const [activePreviewKey, setActivePreviewKey] = useState("");
  const [activeExportKey, setActiveExportKey] = useState("");
  const [activeExportFormat, setActiveExportFormat] = useState("");
  const [actionMessage, setActionMessage] = useState("");
  const [actionTone, setActionTone] = useState("slate");

  const [loadingOverview, setLoadingOverview] = useState(true);
  const [loadingAudit, setLoadingAudit] = useState(true);
  const [loadingSla, setLoadingSla] = useState(true);

  const activeReportMeta = useMemo(
    () => safeArray(catalog).find((item) => item?.report_key === reportForm.report_key) || null,
    [catalog, reportForm.report_key]
  );

  const openBuilder = useCallback(() => {
    setDrawerOpen(true);
    const next = new URLSearchParams(searchParams);
    next.set("builder", "1");
    setSearchParams(next, { replace: true });
  }, [searchParams, setSearchParams]);

  const closeBuilder = useCallback(() => {
    setDrawerOpen(false);
    if (searchParams.has("builder")) {
      const next = new URLSearchParams(searchParams);
      next.delete("builder");
      setSearchParams(next, { replace: true });
    }
  }, [searchParams, setSearchParams]);

  const openPreviewDialog = useCallback(() => setPreviewDialogOpen(true), []);
  const closePreviewDialog = useCallback(() => {
    setPreviewDialogOpen(false);
    setPreviewExportPayload(null);
  }, []);

  const openAdHocBuilder = useCallback(
    (reportKey = reportForm.report_key) => {
      setReportForm((prev) => ({ ...prev, report_key: reportKey || prev.report_key }));
      openBuilder();
    },
    [openBuilder, reportForm.report_key]
  );

  const buildStandardPayload = useCallback(
    (reportKey) => ({
      report_key: reportKey,
      preset: "standard",
      days: standardDays,
      period: suggestReportPeriodFromDays(standardDays),
      preview_limit: 25,
      limit: 500,
      sla_hours: reportKey === "moderation_sla" ? slaHours : reportForm.sla_hours,
    }),
    [standardDays, slaHours, reportForm.sla_hours]
  );

  const loadOverview = useCallback(async () => {
    try {
      setLoadingOverview(true);
      const res = await api.get("/admin/reports/overview", {
        params: { period, span, refresh: 1 },
      });
      setOverview(res?.data?.data || null);
    } catch (error) {
      console.error("Failed to load admin overview:", error);
      toast.error("Failed to load overview reports");
      setOverview(null);
    } finally {
      setLoadingOverview(false);
    }
  }, [period, span]);

  const loadAuditOverview = useCallback(async () => {
    try {
      setLoadingAudit(true);
      const res = await api.get("/admin/reports/audit-overview", {
        params: { period, span, refresh: 1 },
      });
      setAuditOverview(res?.data?.data || null);
    } catch (error) {
      console.error("Failed to load audit overview:", error);
      toast.error("Failed to load audit reports");
      setAuditOverview(null);
    } finally {
      setLoadingAudit(false);
    }
  }, [period, span]);

  const loadModerationSla = useCallback(async () => {
    try {
      setLoadingSla(true);
      const res = await api.get("/admin/reports/moderation-sla", {
        params: { period: "month", span: 6, sla_hours: slaHours },
      });
      setModerationSla(res?.data?.data || null);
    } catch (error) {
      console.error("Failed to load moderation SLA:", error);
      toast.error("Failed to load moderation SLA");
      setModerationSla(null);
    } finally {
      setLoadingSla(false);
    }
  }, [slaHours]);

  const loadCatalog = useCallback(async () => {
    try {
      setLoadingCatalog(true);
      const res = await api.get("/admin/reports/catalog");
      setCatalog(safeArray(res?.data?.data?.reports));
    } catch (error) {
      console.error("Failed to load report catalog:", error);
      toast.error("Failed to load report catalog");
      setCatalog([]);
    } finally {
      setLoadingCatalog(false);
    }
  }, []);

  const loadAll = useCallback(async () => {
    await Promise.all([loadOverview(), loadAuditOverview(), loadModerationSla(), loadCatalog()]);
  }, [loadOverview, loadAuditOverview, loadModerationSla, loadCatalog]);

  useEffect(() => {
    loadOverview();
  }, [loadOverview]);

  useEffect(() => {
    loadAuditOverview();
  }, [loadAuditOverview]);

  useEffect(() => {
    loadModerationSla();
  }, [loadModerationSla]);

  useEffect(() => {
    loadCatalog();
  }, [loadCatalog]);

  useEffect(() => {
    const shouldOpenBuilder = (searchParams.get("builder") || "").trim().toLowerCase();
    if (shouldOpenBuilder === "1" || shouldOpenBuilder === "true" || shouldOpenBuilder === "yes") {
      setDrawerOpen(true);
    }
  }, [searchParams]);

  const refreshReports = async () => {
    const toastId = toast.loading("Refreshing reports...");
    try {
      await loadAll();
      toast.success("Reports refreshed");
    } catch {
      toast.error("Failed to refresh reports");
    } finally {
      toast.dismiss(toastId);
    }
  };

  const exportLegacyModerationSla = async (format) => {
    const toastId = toast.loading(`Exporting ${format.toUpperCase()}...`);
    try {
      const res = await api.get(
        `/admin/reports/export?report=moderation_sla&format=${encodeURIComponent(
          format
        )}&span=6&sla_hours=${encodeURIComponent(slaHours)}`,
        { responseType: "blob" }
      );

      const blob = new Blob([res.data]);
      const url = window.URL.createObjectURL(blob);

      const a = document.createElement("a");
      a.href = url;
      a.download = `agroconnect-moderation-sla.${format === "pdf" ? "pdf" : "csv"}`;
      document.body.appendChild(a);
      a.click();
      a.remove();

      window.URL.revokeObjectURL(url);
      toast.success("Export downloaded");
    } catch (error) {
      console.error("Export failed:", error);
      toast.error("Export failed");
    } finally {
      toast.dismiss(toastId);
    }
  };

  const previewReport = async (payloadOverride = null) => {
    const normalizedOverride = normalizePayloadOverride(payloadOverride);
    const payload = normalizedOverride || buildReportPayload(reportForm);
    const workingReportKey = safeString(payload?.report_key || reportForm.report_key, reportForm.report_key);
    const toastId = toast.loading("Generating report preview...");

    try {
      setLoadingPreview(true);
      setActivePreviewKey(workingReportKey);
      setActionTone("slate");
      setActionMessage(`Generating ${workingReportKey.replace(/_/g, " ")} preview...`);

      const res = await api.post("/admin/reports/generate", payload);
      const reportData = res?.data?.data || null;
      if (!reportData) throw new Error("No preview data returned by the server.");

      const effectiveFilters = {
        ...(reportData?.context?.filters || {}),
        report_key: workingReportKey,
        period: safeString(reportData?.context?.period, payload?.period),
        preview_limit: safeNumber(payload?.preview_limit, 25),
      };

      setReportPreview(reportData);
      setPreviewExportPayload(effectiveFilters);
      setReportForm((prev) => ({
        ...prev,
        report_key: workingReportKey,
        period: safeString(reportData?.context?.period, prev.period),
        days:
          effectiveFilters?.days !== undefined && effectiveFilters?.days !== null
            ? effectiveFilters.days
            : prev.days,
        date_from: safeString(reportData?.context?.date_from, prev.date_from),
        date_to: safeString(reportData?.context?.date_to, prev.date_to),
        sla_hours:
          effectiveFilters?.sla_hours !== undefined && effectiveFilters?.sla_hours !== null
            ? effectiveFilters.sla_hours
            : prev.sla_hours,
      }));
      setPreviewDialogOpen(true);
      setActionTone("emerald");
      setActionMessage(
        safeString(reportData?.summary?.window_note) ||
          `${safeString(reportData?.title, "Report")} preview generated.`
      );
      toast.success(
        safeString(reportData?.summary?.window_note) || "Report preview generated"
      );
    } catch (error) {
      console.error("Failed to generate report preview:", error);
      const message =
        safeString(error?.response?.data?.error) ||
        safeString(error?.response?.data?.details) ||
        safeString(error?.message) ||
        "Failed to generate report preview";
      setActionTone("rose");
      setActionMessage(message);
      toast.error(message);
      setReportPreview(null);
      setPreviewExportPayload(null);
    } finally {
      setLoadingPreview(false);
      setActivePreviewKey("");
      toast.dismiss(toastId);
    }
  };

  const exportGeneratedReport = async (format, payloadOverride = null) => {
    const normalizedOverride = normalizePayloadOverride(payloadOverride);
    const payloadBase = normalizedOverride || buildReportPayload(reportForm);
    const workingReportKey = safeString(payloadBase?.report_key || reportForm.report_key, reportForm.report_key);
    const toastId = toast.loading(`Generating ${format.toUpperCase()} export...`);

    try {
      setActiveExportKey(workingReportKey);
      setActiveExportFormat(format);
      setActionTone("slate");
      setActionMessage(`Generating ${format.toUpperCase()} export for ${workingReportKey.replace(/_/g, " ")}...`);

      const payload = {
        ...payloadBase,
        format,
      };

      const res = await api.post("/admin/reports/generate/export", payload, {
        responseType: "blob",
        validateStatus: () => true,
      });

      const blob = new Blob([res.data], {
        type: res?.headers?.["content-type"] || (format === "pdf" ? "application/pdf" : "text/csv"),
      });

      if (res.status < 200 || res.status >= 300) {
        const message =
          (await parseBlobError(blob)) ||
          `Failed to export ${format.toUpperCase()} report`;
        throw new Error(message);
      }

      const filename = filenameFromDisposition(
        res?.headers?.["content-disposition"],
        `agroconnect-report.${format === "pdf" ? "pdf" : "csv"}`
      );

      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);

      const generatedBy = safeString(res?.headers?.["x-report-generated-by"]);
      const generatedAt = safeString(res?.headers?.["x-report-generated-at"]);
      setReportForm((prev) => ({ ...prev, report_key: workingReportKey }));
      setActionTone("emerald");
      setActionMessage(`${format.toUpperCase()} export downloaded successfully.`);
      toast.success(
        generatedBy || generatedAt
          ? `${format.toUpperCase()} report downloaded`
          : `${format.toUpperCase()} export downloaded`
      );
    } catch (error) {
      console.error("Failed to export generated report:", error);
      const message = safeString(error?.message, `Failed to export ${format.toUpperCase()}`);
      setActionTone("rose");
      setActionMessage(message);
      toast.error(message);
    } finally {
      setActiveExportKey("");
      setActiveExportFormat("");
      toast.dismiss(toastId);
    }
  };

  const previewStandardReport = async (reportKey) => {
    await previewReport(buildStandardPayload(reportKey));
  };

  const exportStandardReport = async (reportKey, format) => {
    await exportGeneratedReport(format, buildStandardPayload(reportKey));
  };

  const totals = useMemo(() => overview?.totals || {}, [overview]);
  const timeSeries = useMemo(() => overview?.time_series || {}, [overview]);
  const loginStats = useMemo(
    () => auditOverview?.login_stats || overview?.login_stats || {},
    [auditOverview, overview]
  );
  const auditStats = useMemo(
    () => auditOverview?.audit_stats || overview?.audit_stats || {},
    [auditOverview, overview]
  );
  const recentActivity = useMemo(
    () => safeArray(auditOverview?.recent_activity || overview?.recent?.recent_activity),
    [auditOverview, overview]
  );

  const registrationRows = useMemo(() => {
    if (period === "day") return pickSeries(timeSeries, "daily_registrations");
    if (period === "month") return pickSeries(timeSeries, "monthly_registrations");
    if (period === "biweek" || period === "biweekly") return pickSeries(timeSeries, "biweekly_registrations");
    return pickSeries(timeSeries, "weekly_registrations");
  }, [timeSeries, period]);

  const orderRows = useMemo(() => {
    if (period === "day") return pickSeries(timeSeries, "daily_orders");
    if (period === "month") return pickSeries(timeSeries, "monthly_orders");
    if (period === "biweek" || period === "biweekly") return pickSeries(timeSeries, "biweekly_orders");
    return pickSeries(timeSeries, "weekly_orders");
  }, [timeSeries, period]);

  const registrationChart = useMemo(
    () => ({
      labels: extractLabels(registrationRows),
      datasets: [
        {
          label: "Registrations",
          data: extractValues(registrationRows),
          borderColor: "#10B981",
          backgroundColor: "rgba(16,185,129,0.14)",
          tension: 0.35,
          fill: true,
        },
      ],
    }),
    [registrationRows]
  );

  const orderChart = useMemo(
    () => ({
      labels: extractLabels(orderRows),
      datasets: [
        {
          label: "Orders",
          data: extractValues(orderRows),
          borderColor: "#3B82F6",
          backgroundColor: "rgba(59,130,246,0.14)",
          tension: 0.35,
          fill: true,
        },
      ],
    }),
    [orderRows]
  );

  const authChart = useMemo(
    () => ({
      labels: ["Logins", "Logouts", "Failed logins", "Refreshes"],
      datasets: [
        {
          label: "Auth events",
          data: [
            safeNumber(loginStats.last_30_days),
            safeNumber(loginStats.logouts_last_30_days),
            safeNumber(loginStats.failed_logins_last_30_days),
            safeNumber(loginStats.refreshes_last_30_days),
          ],
          backgroundColor: [
            "rgba(16,185,129,0.25)",
            "rgba(59,130,246,0.25)",
            "rgba(244,63,94,0.25)",
            "rgba(245,158,11,0.25)",
          ],
          borderColor: ["#10B981", "#3B82F6", "#F43F5E", "#F59E0B"],
          borderWidth: 1,
        },
      ],
    }),
    [loginStats]
  );

  const streamChart = useMemo(
    () => ({
      labels: ["Activity", "Governance", "Auth"],
      datasets: [
        {
          label: "Last 30 days",
          data: [
            safeNumber(auditStats?.last_30_days?.activity_events),
            safeNumber(auditStats?.last_30_days?.governance_events),
            safeNumber(auditStats?.last_30_days?.auth_events),
          ],
          backgroundColor: [
            "rgba(16,185,129,0.25)",
            "rgba(139,92,246,0.25)",
            "rgba(59,130,246,0.25)",
          ],
          borderColor: ["#10B981", "#8B5CF6", "#3B82F6"],
          borderWidth: 1,
        },
      ],
    }),
    [auditStats]
  );

  const slaTrendRows = safeArray(moderationSla?.trend);
  const slaChart = useMemo(
    () => ({
      labels: slaTrendRows.map((row) => row?.bucket || "—"),
      datasets: [
        {
          label: "Reviewed",
          data: slaTrendRows.map((row) => safeNumber(row?.reviewed)),
          backgroundColor: "rgba(16,185,129,0.25)",
          borderColor: "#10B981",
          borderWidth: 1,
        },
        {
          label: "Breached",
          data: slaTrendRows.map((row) => safeNumber(row?.breached)),
          backgroundColor: "rgba(244,63,94,0.25)",
          borderColor: "#F43F5E",
          borderWidth: 1,
        },
      ],
    }),
    [slaTrendRows]
  );

  return (
    <ProtectedRoute roles={["admin"]}>
      <AdminLayout>
        <motion.div
          initial={{ opacity: 0, y: 14 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3 }}
          className="space-y-6"
        >
          <div className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1fr)_auto] xl:items-start">
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <TrendingUp className="h-5 w-5 text-emerald-700" />
                <h1 className="truncate text-2xl font-black tracking-tight text-slate-900">
                  Reports & Analytics
                </h1>
              </div>
              <p className="mt-2 max-w-5xl text-sm font-medium text-slate-600">
                Review operational trends, authentication behaviour, audit activity, moderation
                performance, and generate professional standard or ad hoc reports.
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <label className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm font-bold text-slate-700 shadow-sm">
                <span>Period</span>
                <select
                  value={period}
                  onChange={(e) => setPeriod(e.target.value)}
                  className="bg-transparent outline-none"
                >
                  <option value="day">Daily</option>
                  <option value="week">Weekly</option>
                  <option value="biweekly">Biweekly</option>
                  <option value="month">Monthly</option>
                </select>
              </label>

              <label className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm font-bold text-slate-700 shadow-sm">
                <span>Span</span>
                <select
                  value={String(span)}
                  onChange={(e) => setSpan(Number(e.target.value) || 12)}
                  className="bg-transparent outline-none"
                >
                  <option value="6">6</option>
                  <option value="12">12</option>
                  <option value="18">18</option>
                  <option value="24">24</option>
                </select>
              </label>

              <button
                type="button"
                onClick={openBuilder}
                className="inline-flex items-center gap-2 rounded-xl border border-emerald-200 bg-emerald-50 px-4 py-2 text-sm font-bold text-emerald-800 shadow-sm transition hover:bg-emerald-100"
              >
                <Wand2 className="h-4 w-4" />
                Open report builder
              </button>

              <button
                type="button"
                onClick={refreshReports}
                className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-4 py-2 text-sm font-bold text-slate-800 shadow-sm transition hover:bg-slate-50"
              >
                <RefreshCw className="h-4 w-4" />
                Refresh
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 gap-4 md:grid-cols-2 2xl:grid-cols-4">
            <KpiCard
              icon={<Users className="h-5 w-5" />}
              title="Total users"
              value={loadingOverview ? "…" : safeNumber(totals.total_users)}
              subtitle="All registered users"
              tone="emerald"
            />
            <KpiCard
              icon={<Package className="h-5 w-5" />}
              title="Total products"
              value={loadingOverview ? "…" : safeNumber(totals.total_products)}
              subtitle="Products in the platform"
              tone="blue"
            />
            <KpiCard
              icon={<ShoppingCart className="h-5 w-5" />}
              title="Total orders"
              value={loadingOverview ? "…" : safeNumber(totals.total_orders)}
              subtitle="Orders recorded"
              tone="amber"
            />
            <KpiCard
              icon={<Star className="h-5 w-5" />}
              title="Average rating"
              value={loadingOverview ? "…" : safeNumber(totals.avg_rating).toFixed(2)}
              subtitle={`${safeNumber(totals.total_ratings)} ratings`}
              tone="violet"
            />
          </div>

          <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
            <Card className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
              <SectionTitle
                icon={<Users className="h-4 w-4 text-emerald-700" />}
                title="Registration trend"
                subtitle="Registrations over the selected reporting period."
              />
              {loadingOverview ? (
                <SkeletonChart />
              ) : registrationRows.length ? (
                <div className="h-80">
                  <Line data={registrationChart} options={chartOptions()} />
                </div>
              ) : (
                <EmptyState message="No registration trend data available." />
              )}
            </Card>

            <Card className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
              <SectionTitle
                icon={<ShoppingCart className="h-4 w-4 text-blue-700" />}
                title="Order trend"
                subtitle="Orders over the selected reporting period."
              />
              {loadingOverview ? (
                <SkeletonChart />
              ) : orderRows.length ? (
                <div className="h-80">
                  <Line data={orderChart} options={chartOptions()} />
                </div>
              ) : (
                <EmptyState message="No order trend data available." />
              )}
            </Card>
          </div>

          <div className="grid grid-cols-1 gap-4 md:grid-cols-2 2xl:grid-cols-4">
            <KpiCard
              icon={<LogIn className="h-5 w-5" />}
              title="Logins (30 days)"
              value={loadingAudit ? "…" : safeNumber(loginStats.last_30_days)}
              subtitle="True login events only"
              tone="emerald"
            />
            <KpiCard
              icon={<AlertTriangle className="h-5 w-5" />}
              title="Failed logins (30 days)"
              value={loadingAudit ? "…" : safeNumber(loginStats.failed_logins_last_30_days)}
              subtitle="Authentication failures"
              tone="rose"
            />
            <KpiCard
              icon={<Activity className="h-5 w-5" />}
              title="Activity events"
              value={loadingAudit ? "…" : safeNumber(auditStats?.last_30_days?.activity_events)}
              subtitle="User actions in the system"
              tone="emerald"
            />
            <KpiCard
              icon={<ShieldCheck className="h-5 w-5" />}
              title="Governance events"
              value={loadingAudit ? "…" : safeNumber(auditStats?.last_30_days?.governance_events)}
              subtitle="Privileged admin changes"
              tone="violet"
            />
          </div>

          <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
            <Card className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
              <SectionTitle
                icon={<LogIn className="h-4 w-4 text-blue-700" />}
                title="Authentication snapshot"
                subtitle="Last 30 days of logins, logouts, failed logins, and refreshes."
              />
              {loadingAudit ? (
                <SkeletonChart />
              ) : (
                <div className="h-80">
                  <Bar data={authChart} options={chartOptions()} />
                </div>
              )}
            </Card>

            <Card className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
              <SectionTitle
                icon={<Activity className="h-4 w-4 text-slate-700" />}
                title="Audit stream distribution"
                subtitle="Relative size of activity, governance, and auth records."
              />
              {loadingAudit ? (
                <SkeletonChart />
              ) : (
                <div className="h-80">
                  <Doughnut
                    data={streamChart}
                    options={{
                      responsive: true,
                      maintainAspectRatio: false,
                      plugins: {
                        legend: {
                          position: "bottom",
                          labels: {
                            color: "#334155",
                            font: { weight: "700" },
                          },
                        },
                      },
                    }}
                  />
                </div>
              )}
            </Card>
          </div>

          <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
            <KpiCard
              icon={<Clock3 className="h-5 w-5" />}
              title="SLA reviewed"
              value={loadingSla ? "…" : safeNumber(moderationSla?.summary?.reviewed)}
              subtitle="Products reviewed in range"
              tone="blue"
            />
            <KpiCard
              icon={<AlertTriangle className="h-5 w-5" />}
              title="SLA breached"
              value={loadingSla ? "…" : safeNumber(moderationSla?.summary?.breached)}
              subtitle={`Threshold: ${slaHours} hours`}
              tone="rose"
            />
            <KpiCard
              icon={<ShieldCheck className="h-5 w-5" />}
              title="Average review hours"
              value={loadingSla ? "…" : safeNumber(moderationSla?.summary?.avg_hours).toFixed(2)}
              subtitle="Moderation turnaround"
              tone="amber"
            />
          </div>

          <Card className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
            <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
              <SectionTitle
                icon={<Clock3 className="h-4 w-4 text-slate-700" />}
                title="Moderation SLA trend"
                subtitle="Monthly reviewed vs breached moderation counts."
              />
              <div className="flex flex-wrap gap-2">
                <label className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm font-bold text-slate-700 shadow-sm">
                  <span>SLA hours</span>
                  <select
                    value={String(slaHours)}
                    onChange={(e) => setSlaHours(Number(e.target.value) || 48)}
                    className="bg-transparent outline-none"
                  >
                    <option value="24">24</option>
                    <option value="48">48</option>
                    <option value="72">72</option>
                    <option value="96">96</option>
                  </select>
                </label>

                <button
                  type="button"
                  onClick={() => exportLegacyModerationSla("csv")}
                  className="inline-flex items-center gap-2 rounded-xl border border-sky-200 bg-sky-50 px-4 py-2 text-sm font-bold text-sky-800 shadow-sm transition hover:bg-sky-100"
                >
                  <FileDown className="h-4 w-4" />
                  SLA CSV
                </button>

                <button
                  type="button"
                  onClick={() => exportLegacyModerationSla("pdf")}
                  className="inline-flex items-center gap-2 rounded-xl border border-rose-200 bg-rose-50 px-4 py-2 text-sm font-bold text-rose-800 shadow-sm transition hover:bg-rose-100"
                >
                  <FileDown className="h-4 w-4" />
                  SLA PDF
                </button>
              </div>
            </div>

            {loadingSla ? (
              <SkeletonChart />
            ) : slaTrendRows.length ? (
              <div className="h-80">
                <Bar data={slaChart} options={chartOptions()} />
              </div>
            ) : (
              <EmptyState message="No moderation SLA trend data available." />
            )}
          </Card>

          <Card className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
            <SectionTitle
              icon={<Wand2 className="h-4 w-4 text-slate-700" />}
              title="Standard & ad hoc report generator"
              subtitle="Generate polished management reports from one-click standard presets or open the ad hoc builder for a custom reporting window and filters."
              right={
                <div className="flex flex-wrap items-center gap-2">
                  <label className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm font-bold text-slate-700 shadow-sm">
                    <span>Standard window</span>
                    <select
                      value={String(standardDays)}
                      onChange={(e) => setStandardDays(Number(e.target.value) || 90)}
                      className="bg-transparent outline-none"
                    >
                      <option value="7">Last 7 days</option>
                      <option value="14">Last 14 days</option>
                      <option value="30">Last 30 days</option>
                      <option value="90">Last 90 days</option>
                      <option value="180">Last 180 days</option>
                      <option value="365">Last 365 days</option>
                    </select>
                  </label>

                  <div className="text-xs font-semibold text-slate-500">
                    Standard previews default to 90 days, and sparse lifecycle, search, and SLA presets can expand automatically when no rows exist in a smaller standard window.
                  </div>

                  <button
                    type="button"
                    onClick={() => openAdHocBuilder(reportForm.report_key)}
                    className="inline-flex items-center gap-2 rounded-xl border border-emerald-200 bg-emerald-50 px-4 py-2 text-sm font-bold text-emerald-800 shadow-sm transition hover:bg-emerald-100"
                  >
                    <Wand2 className="h-4 w-4" />
                    Open ad hoc builder
                  </button>
                </div>
              }
            />

            <div className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1fr)_360px]">
              <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
                {loadingCatalog ? (
                  <div className="xl:col-span-2 rounded-2xl border border-slate-200 bg-slate-50 p-5 text-sm font-semibold text-slate-500">
                    Loading report catalog…
                  </div>
                ) : catalog.length ? (
                  catalog.map((report) => (
                    <div
                      key={report.report_key}
                      className={`rounded-2xl border p-4 shadow-sm ${reportToneClasses(report.report_key)}`}
                    >
                      <div className="flex items-start justify-between gap-3">
                        <div className="min-w-0">
                          <div className="text-sm font-black text-slate-900">
                            {safeString(report.title, "Report")}
                          </div>
                          <div className="mt-1 text-sm font-medium text-slate-600">
                            {safeString(report.subtitle)}
                          </div>
                        </div>
                        <div className="rounded-xl border border-slate-200 bg-white px-2 py-1 text-[11px] font-extrabold uppercase tracking-wide text-slate-500">
                          Standard
                        </div>
                      </div>

                      <div className="mt-4 flex flex-wrap gap-2">
                        <button
                          type="button"
                          onClick={() => previewStandardReport(report.report_key)}
                          disabled={loadingPreview || !!activeExportKey}
                          className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm font-bold text-slate-800 shadow-sm transition hover:bg-slate-100 disabled:cursor-not-allowed disabled:opacity-60"
                        >
                          <Eye className="h-4 w-4" />
                          {loadingPreview && activePreviewKey === report.report_key ? "Generating…" : "Preview"}
                        </button>

                        <button
                          type="button"
                          onClick={() => exportStandardReport(report.report_key, "pdf")}
                          disabled={loadingPreview || !!activeExportKey}
                          className="inline-flex items-center gap-2 rounded-xl border border-rose-200 bg-rose-50 px-3 py-2 text-sm font-bold text-rose-800 shadow-sm transition hover:bg-rose-100 disabled:cursor-not-allowed disabled:opacity-60"
                        >
                          <FileDown className="h-4 w-4" />
                          {activeExportKey === report.report_key && activeExportFormat === "pdf" ? "Working…" : "PDF"}
                        </button>

                        <button
                          type="button"
                          onClick={() => exportStandardReport(report.report_key, "csv")}
                          disabled={loadingPreview || !!activeExportKey}
                          className="inline-flex items-center gap-2 rounded-xl border border-sky-200 bg-sky-50 px-3 py-2 text-sm font-bold text-sky-800 shadow-sm transition hover:bg-sky-100 disabled:cursor-not-allowed disabled:opacity-60"
                        >
                          <FileDown className="h-4 w-4" />
                          {activeExportKey === report.report_key && activeExportFormat === "csv" ? "Working…" : "CSV"}
                        </button>

                        <button
                          type="button"
                          onClick={() => openAdHocBuilder(report.report_key)}
                          className="inline-flex items-center gap-2 rounded-xl border border-emerald-200 bg-emerald-50 px-3 py-2 text-sm font-bold text-emerald-800 shadow-sm transition hover:bg-emerald-100"
                        >
                          <Wand2 className="h-4 w-4" />
                          Ad hoc
                        </button>
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="xl:col-span-2">
                    <EmptyState message="No report catalog available." />
                  </div>
                )}
              </div>

              <div className="space-y-4">
                {actionMessage ? (
                  <div
                    className={`rounded-2xl border p-4 text-sm font-semibold shadow-sm ${
                      actionTone === "rose"
                        ? "border-rose-200 bg-rose-50 text-rose-800"
                        : actionTone === "emerald"
                          ? "border-emerald-200 bg-emerald-50 text-emerald-800"
                          : "border-slate-200 bg-slate-50 text-slate-700"
                    }`}
                  >
                    {actionMessage}
                  </div>
                ) : null}

                <div className={`rounded-2xl border p-4 shadow-sm ${reportToneClasses(reportForm.report_key)}`}>
                  <div className="text-xs font-extrabold uppercase tracking-wide text-slate-500">
                    Active ad hoc setup
                  </div>
                  <div className="mt-2 text-lg font-black text-slate-900">
                    {safeString(activeReportMeta?.title, "Report Generator")}
                  </div>
                  <div className="mt-1 text-sm font-medium text-slate-600">
                    {safeString(
                      activeReportMeta?.subtitle,
                      "Open the builder to refine period, date range, roles, status, actions, and other report-specific filters."
                    )}
                  </div>

                  <div className="mt-4 grid grid-cols-2 gap-3">
                    <div className="rounded-xl border border-slate-200 bg-white p-3">
                      <div className="text-xs font-bold uppercase tracking-wide text-slate-500">Ad hoc period</div>
                      <div className="mt-1 text-sm font-black text-slate-900">
                        {safeString(reportForm.period, "month")}
                      </div>
                    </div>
                    <div className="rounded-xl border border-slate-200 bg-white p-3">
                      <div className="text-xs font-bold uppercase tracking-wide text-slate-500">Preview rows</div>
                      <div className="mt-1 text-sm font-black text-slate-900">
                        {safeNumber(reportForm.preview_limit, 25)}
                      </div>
                    </div>
                  </div>

                  <div className="mt-4 flex flex-wrap gap-2">
                    <button
                      type="button"
                      onClick={() => openAdHocBuilder(reportForm.report_key)}
                      className="inline-flex items-center gap-2 rounded-xl border border-emerald-200 bg-emerald-50 px-4 py-2 text-sm font-bold text-emerald-800 shadow-sm transition hover:bg-emerald-100"
                    >
                      <Wand2 className="h-4 w-4" />
                      Configure ad hoc report
                    </button>
                    <button
                      type="button"
                      onClick={reportPreview ? openPreviewDialog : () => previewStandardReport(reportForm.report_key)}
                      className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-4 py-2 text-sm font-bold text-slate-800 shadow-sm transition hover:bg-slate-100"
                    >
                      <Eye className="h-4 w-4" />
                      {reportPreview ? "Open latest preview" : "Preview current report"}
                    </button>
                  </div>
                </div>

                <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                  <div className="flex items-center gap-2 text-sm font-extrabold text-slate-900">
                    <FileText className="h-4 w-4 text-slate-700" />
                    Latest generated preview
                  </div>

                  {!reportPreview ? (
                    <div className="mt-4">
                      <EmptyState message="No preview generated yet. Preview any standard report or build an ad hoc report to open the preview dialog." />
                    </div>
                  ) : (
                    <div className="mt-4 space-y-3">
                      <div className="rounded-xl border border-slate-200 bg-white p-3">
                        <div className="text-xs font-bold uppercase tracking-wide text-slate-500">Title</div>
                        <div className="mt-1 text-sm font-black text-slate-900">
                          {safeString(reportPreview?.title, "Generated Report")}
                        </div>
                        <div className="mt-1 text-xs font-medium text-slate-500">
                          {safeString(reportPreview?.subtitle)}
                        </div>
                      </div>

                      <div className="grid grid-cols-2 gap-3">
                        <div className="rounded-xl border border-slate-200 bg-white p-3">
                          <div className="text-xs font-bold uppercase tracking-wide text-slate-500">Generated by</div>
                          <div className="mt-1 text-sm font-black text-slate-900">
                            {safeString(reportPreview?.context?.generated_by_name, "—")}
                          </div>
                        </div>
                        <div className="rounded-xl border border-slate-200 bg-white p-3">
                          <div className="text-xs font-bold uppercase tracking-wide text-slate-500">Generated at</div>
                          <div className="mt-1 text-sm font-black text-slate-900">
                            {formatDateTime(reportPreview?.context?.generated_at)}
                          </div>
                        </div>
                      </div>

                      <div className="flex flex-wrap gap-2">
                        <button
                          type="button"
                          onClick={openPreviewDialog}
                          className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-4 py-2 text-sm font-bold text-slate-800 shadow-sm transition hover:bg-slate-100"
                        >
                          <Eye className="h-4 w-4" />
                          Open preview dialog
                        </button>

                        <button
                          type="button"
                          onClick={() => exportGeneratedReport("pdf", previewExportPayload)}
                          className="inline-flex items-center gap-2 rounded-xl border border-rose-200 bg-rose-50 px-4 py-2 text-sm font-bold text-rose-800 shadow-sm transition hover:bg-rose-100"
                        >
                          <FileDown className="h-4 w-4" />
                          PDF
                        </button>

                        <button
                          type="button"
                          onClick={() => exportGeneratedReport("csv", previewExportPayload)}
                          className="inline-flex items-center gap-2 rounded-xl border border-sky-200 bg-sky-50 px-4 py-2 text-sm font-bold text-sky-800 shadow-sm transition hover:bg-sky-100"
                        >
                          <FileDown className="h-4 w-4" />
                          CSV
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>
          </Card>

          <Card className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
            <SectionTitle
              icon={<Activity className="h-4 w-4 text-slate-700" />}
              title="Recent activity feed"
              subtitle="Most recent unified activity from audit, auth, and governance streams."
            />

            {loadingAudit ? (
              <p className="text-sm font-semibold text-slate-500">Loading recent activity…</p>
            ) : recentActivity.length ? (
              <div className="overflow-x-auto">
                <table className="min-w-full text-sm">
                  <thead className="border-b border-slate-200 text-slate-500">
                    <tr>
                      <th className="px-3 py-3 text-left text-xs font-extrabold uppercase tracking-wide">
                        Time
                      </th>
                      <th className="px-3 py-3 text-left text-xs font-extrabold uppercase tracking-wide">
                        Stream
                      </th>
                      <th className="px-3 py-3 text-left text-xs font-extrabold uppercase tracking-wide">
                        Actor
                      </th>
                      <th className="px-3 py-3 text-left text-xs font-extrabold uppercase tracking-wide">
                        Action
                      </th>
                      <th className="px-3 py-3 text-left text-xs font-extrabold uppercase tracking-wide">
                        Target
                      </th>
                      <th className="px-3 py-3 text-left text-xs font-extrabold uppercase tracking-wide">
                        Status
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {recentActivity.map((item, idx) => (
                      <tr
                        key={`${item?.stream || "stream"}-${idx}`}
                        className="border-b border-slate-100 hover:bg-slate-50/70"
                      >
                        <td className="px-3 py-3 font-semibold text-slate-700">
                          {safeString(item?.occurred_at, "—").replace("T", " ").slice(0, 19) || "—"}
                        </td>
                        <td className="px-3 py-3 font-bold capitalize text-slate-700">
                          {safeString(item?.stream, "—")}
                        </td>
                        <td className="px-3 py-3">
                          <div className="font-bold text-slate-900">
                            {safeString(item?.actor_name, "Unknown")}
                          </div>
                          <div className="text-xs font-medium text-slate-500">
                            {safeString(item?.actor_role, "—")}
                          </div>
                        </td>
                        <td className="px-3 py-3 font-semibold text-slate-800">
                          {safeString(item?.action, "—")}
                        </td>
                        <td className="px-3 py-3 text-slate-700">
                          <div>{safeString(item?.target_type, "system")}</div>
                          <div className="max-w-[240px] truncate text-xs text-slate-500">
                            {safeString(item?.target_id, "—")}
                          </div>
                        </td>
                        <td className="px-3 py-3 text-slate-700">
                          {safeString(item?.status, "—")}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <EmptyState message="No recent activity available." />
            )}
          </Card>
        </motion.div>

        {previewDialogOpen && reportPreview ? (
          <div className="fixed inset-0 z-[98] flex items-center justify-center bg-slate-900/45 p-4 backdrop-blur-[1px]">
            <div className="flex max-h-[92vh] w-full max-w-7xl flex-col overflow-hidden rounded-3xl border border-slate-200 bg-white shadow-2xl">
              <div className="flex items-start justify-between gap-4 border-b border-slate-200 px-6 py-5">
                <div className="min-w-0">
                  <div className="text-xs font-extrabold uppercase tracking-wide text-slate-500">Generated preview</div>
                  <div className="mt-1 text-2xl font-black text-slate-900">
                    {safeString(reportPreview?.title, "Generated Report")}
                  </div>
                  <div className="mt-1 text-sm font-medium text-slate-600">
                    {safeString(reportPreview?.subtitle)}
                  </div>
                </div>

                <button
                  type="button"
                  onClick={closePreviewDialog}
                  className="rounded-xl border border-slate-200 bg-white p-2 text-slate-700 shadow-sm transition hover:bg-slate-50"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>

              <div className="flex-1 overflow-y-auto px-6 py-5">
                <div className="grid grid-cols-1 gap-4 xl:grid-cols-[320px_minmax(0,1fr)]">
                  <div className="space-y-4">
                    <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                      <div className="text-xs font-extrabold uppercase tracking-wide text-slate-500">Report metadata</div>
                      <div className="mt-3 space-y-3">
                        <div className="rounded-xl border border-slate-200 bg-white p-3">
                          <div className="text-xs font-bold uppercase tracking-wide text-slate-500">Generated by</div>
                          <div className="mt-1 text-sm font-black text-slate-900">
                            {safeString(reportPreview?.context?.generated_by_name, "—")}
                          </div>
                          <div className="text-xs font-medium text-slate-500">
                            {safeString(reportPreview?.context?.generated_by_email, "—")}
                          </div>
                        </div>
                        <div className="rounded-xl border border-slate-200 bg-white p-3">
                          <div className="text-xs font-bold uppercase tracking-wide text-slate-500">Generated at</div>
                          <div className="mt-1 text-sm font-black text-slate-900">
                            {formatDateTime(reportPreview?.context?.generated_at)}
                          </div>
                        </div>
                        <div className="rounded-xl border border-slate-200 bg-white p-3">
                          <div className="text-xs font-bold uppercase tracking-wide text-slate-500">Row count</div>
                          <div className="mt-1 text-sm font-black text-slate-900">
                            {safeNumber(reportPreview?.row_count, 0)}
                          </div>
                        </div>
                      </div>
                    </div>

                    <div className="rounded-2xl border border-slate-200 bg-white p-4">
                      <div className="mb-3 text-xs font-extrabold uppercase tracking-wide text-slate-500">Summary</div>
                      <div className="space-y-2">
                        {Object.entries(reportPreview?.summary || {}).length ? (
                          Object.entries(reportPreview?.summary || {}).map(([key, value]) => (
                            <div key={key} className="flex items-center justify-between rounded-xl border border-slate-200 bg-slate-50 px-3 py-2">
                              <span className="text-sm font-semibold capitalize text-slate-700">
                                {key.replace(/_/g, " ")}
                              </span>
                              <span className="text-sm font-black text-slate-900">{String(value)}</span>
                            </div>
                          ))
                        ) : (
                          <div className="text-sm font-medium text-slate-500">No summary available.</div>
                        )}
                      </div>
                    </div>

                    <div className="rounded-2xl border border-slate-200 bg-white p-4">
                      <div className="mb-3 text-xs font-extrabold uppercase tracking-wide text-slate-500">Applied filters</div>
                      <pre className="max-h-56 overflow-auto rounded-xl bg-slate-900 p-3 text-xs font-medium text-slate-100">
                        {JSON.stringify(reportPreview?.context?.filters || {}, null, 2)}
                      </pre>
                    </div>
                  </div>

                  <div className="rounded-2xl border border-slate-200 bg-white p-4">
                    <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
                      <div>
                        <div className="text-xs font-extrabold uppercase tracking-wide text-slate-500">Preview rows</div>
                        <div className="mt-1 text-sm font-medium text-slate-600">
                          Showing the preview sample returned by the server.
                        </div>
                      </div>

                      <div className="flex flex-wrap gap-2">
                        <button
                          type="button"
                          onClick={() => exportGeneratedReport("pdf", previewExportPayload)}
                          className="inline-flex items-center gap-2 rounded-xl border border-rose-200 bg-rose-50 px-4 py-2 text-sm font-bold text-rose-800 shadow-sm transition hover:bg-rose-100"
                        >
                          <FileDown className="h-4 w-4" />
                          Export PDF
                        </button>
                        <button
                          type="button"
                          onClick={() => exportGeneratedReport("csv", previewExportPayload)}
                          className="inline-flex items-center gap-2 rounded-xl border border-sky-200 bg-sky-50 px-4 py-2 text-sm font-bold text-sky-800 shadow-sm transition hover:bg-sky-100"
                        >
                          <FileDown className="h-4 w-4" />
                          Export CSV
                        </button>
                      </div>
                    </div>

                    {reportPreview?.summary?.window_auto_expanded ? (
                      <div className="mb-4 rounded-2xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm font-semibold text-amber-900">
                        {safeString(reportPreview?.summary?.window_note, "The report window was expanded automatically to include available data.")}
                      </div>
                    ) : null}

                    {safeArray(reportPreview?.rows_preview).length ? (
                      <div className="overflow-x-auto">
                        <table className="min-w-full text-sm">
                          <thead className="border-b border-slate-200 text-slate-500">
                            <tr>
                              {safeArray(reportPreview?.columns).map((column) => (
                                <th key={column} className="px-3 py-3 text-left text-xs font-extrabold uppercase tracking-wide">
                                  {safeString(column)}
                                </th>
                              ))}
                            </tr>
                          </thead>
                          <tbody>
                            {safeArray(reportPreview?.rows_preview).map((row, idx) => (
                              <tr key={`modal-preview-row-${idx}`} className="border-b border-slate-100 hover:bg-slate-50/70">
                                {safeArray(reportPreview?.columns).map((column) => (
                                  <td key={`${idx}-${column}`} className="px-3 py-3 align-top text-slate-700">
                                    <div className="max-w-[340px] break-words">{String(row?.[column] ?? "—")}</div>
                                  </td>
                                ))}
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    ) : (
                      <EmptyState message="This report has no preview rows for the selected filters." />
                    )}
                  </div>
                </div>
              </div>
            </div>
          </div>
        ) : null}

        <ReportBuilderDrawer
          open={drawerOpen}
          onClose={closeBuilder}
          catalog={catalog}
          loadingCatalog={loadingCatalog}
          form={reportForm}
          setForm={setReportForm}
          onPreview={previewReport}
          onExport={exportGeneratedReport}
          preview={reportPreview}
          loadingPreview={loadingPreview}
        />
      </AdminLayout>
    </ProtectedRoute>
  );
}