// ============================================================================
// frontend/src/components/admin/ReportBuilderDrawer.jsx
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Reusable admin report-builder drawer for:
//     • selecting a standard report
//     • configuring ad hoc filters
//     • generating a preview
//     • exporting PDF / CSV
//
// WHY THIS FILE EXISTS:
//   The current AdminReportsPage already contains an inline report generator.
//   This component lets you move that workflow into a reusable right-side panel
//   without duplicating form logic again in future pages.
//
// CURRENT STATUS:
//   ✅ Safe to add now
//   ✅ Reusable for admin reports, analytics, and audit pages
//   ✅ Does NOT break existing pages until you wire it in
//
// EXPECTED PROPS:
//   open: boolean
//   onClose: function
//   catalog: array
//   loadingCatalog: boolean
//   form: object
//   setForm: function
//   onPreview: function
//   onExport: function(format)
//   preview: object|null
//   loadingPreview: boolean
// ============================================================================

import React, { useMemo } from "react";
import { AnimatePresence, motion } from "framer-motion";
import {
  X,
  FileText,
  Wand2,
  Eye,
  Download,
  Search,
  Filter,
  FileStack,
} from "lucide-react";

import EmptyState from "../ui/EmptyState";

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------
function safeArray(value) {
  return Array.isArray(value) ? value : [];
}

function safeString(value, fallback = "") {
  return typeof value === "string" && value.trim() ? value.trim() : fallback;
}

function fieldVisible(reportKey, fieldName) {
  const map = {
    auth_activity: new Set(["period", "span", "days", "date_from", "date_to", "role", "event_type", "limit"]),
    user_activity: new Set(["period", "span", "days", "date_from", "date_to", "role", "action", "status", "q", "limit"]),
    product_lifecycle: new Set(["period", "span", "days", "date_from", "date_to", "action", "actor_role", "q", "limit"]),
    product_search_statistics: new Set(["period", "span", "days", "date_from", "date_to", "q", "limit"]),
    moderation_sla: new Set(["period", "span", "days", "date_from", "date_to", "sla_hours", "limit"]),
  };

  return map[reportKey]?.has(fieldName) ?? false;
}

function reportTone(reportKey) {
  if (reportKey === "auth_activity") return "blue";
  if (reportKey === "user_activity") return "emerald";
  if (reportKey === "product_lifecycle") return "amber";
  if (reportKey === "product_search_statistics") return "violet";
  if (reportKey === "moderation_sla") return "rose";
  return "slate";
}

function toneClasses(reportKey, isActive) {
  const tone = reportTone(reportKey);

  const lookup = {
    emerald: isActive
      ? "border-emerald-300 bg-emerald-50"
      : "border-slate-200 bg-white hover:border-emerald-200 hover:bg-emerald-50/40",
    blue: isActive
      ? "border-blue-300 bg-blue-50"
      : "border-slate-200 bg-white hover:border-blue-200 hover:bg-blue-50/40",
    amber: isActive
      ? "border-amber-300 bg-amber-50"
      : "border-slate-200 bg-white hover:border-amber-200 hover:bg-amber-50/40",
    violet: isActive
      ? "border-violet-300 bg-violet-50"
      : "border-slate-200 bg-white hover:border-violet-200 hover:bg-violet-50/40",
    rose: isActive
      ? "border-rose-300 bg-rose-50"
      : "border-slate-200 bg-white hover:border-rose-200 hover:bg-rose-50/40",
    slate: isActive
      ? "border-slate-300 bg-slate-50"
      : "border-slate-200 bg-white hover:bg-slate-50",
  };

  return lookup[tone] || lookup.slate;
}

// ----------------------------------------------------------------------------
// Component
// ----------------------------------------------------------------------------
export default function ReportBuilderDrawer({
  open = false,
  onClose,
  catalog = [],
  loadingCatalog = false,
  form,
  setForm,
  onPreview,
  onExport,
  preview,
  loadingPreview = false,
}) {
  const activeReportMeta = useMemo(
    () => safeArray(catalog).find((item) => item?.report_key === form?.report_key) || null,
    [catalog, form?.report_key]
  );

  return (
    <AnimatePresence>
      {open ? (
        <>
          {/* Backdrop */}
          <motion.button
            type="button"
            aria-label="Close report builder"
            onClick={onClose}
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-[90] bg-slate-900/35 backdrop-blur-[1px]"
          />

          {/* Drawer */}
          <motion.aside
            initial={{ x: "100%" }}
            animate={{ x: 0 }}
            exit={{ x: "100%" }}
            transition={{ type: "spring", damping: 26, stiffness: 240 }}
            className="fixed right-0 top-0 z-[95] flex h-screen w-full max-w-[760px] flex-col border-l border-slate-200 bg-slate-50 shadow-2xl"
          >
            {/* Header */}
            <div className="flex items-center justify-between border-b border-slate-200 bg-white px-5 py-4">
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <Wand2 className="h-5 w-5 text-emerald-700" />
                  <h2 className="truncate text-lg font-black text-slate-900">
                    Report Builder
                  </h2>
                </div>
                <p className="mt-1 text-xs font-semibold text-slate-500">
                  Generate standard and ad hoc reports, then export professional PDF or CSV outputs.
                </p>
              </div>

              <button
                type="button"
                onClick={onClose}
                className="rounded-xl border border-slate-200 bg-white p-2 text-slate-700 shadow-sm transition hover:bg-slate-50"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            {/* Content */}
            <div className="flex-1 overflow-y-auto px-5 py-5">
              <div className="grid grid-cols-1 gap-5 xl:grid-cols-[260px_minmax(0,1fr)]">
                {/* Catalog */}
                <div className="space-y-3">
                  <div className="text-xs font-extrabold uppercase tracking-wide text-slate-500">
                    Report catalog
                  </div>

                  {loadingCatalog ? (
                    <div className="rounded-2xl border border-slate-200 bg-white p-4 text-sm font-semibold text-slate-500">
                      Loading report catalog…
                    </div>
                  ) : safeArray(catalog).length ? (
                    safeArray(catalog).map((report) => {
                      const isActive = report?.report_key === form?.report_key;

                      return (
                        <button
                          key={report?.report_key}
                          type="button"
                          onClick={() =>
                            setForm((prev) => ({
                              ...prev,
                              report_key: report?.report_key || prev.report_key,
                            }))
                          }
                          className={`block w-full rounded-2xl border p-4 text-left shadow-sm transition ${toneClasses(
                            report?.report_key,
                            isActive
                          )}`}
                        >
                          <div className="flex items-start gap-3">
                            <div className="rounded-xl border border-slate-200 bg-white p-2 text-slate-700">
                              <FileText className="h-4 w-4" />
                            </div>

                            <div className="min-w-0">
                              <div className="text-sm font-extrabold text-slate-900">
                                {safeString(report?.title, "Report")}
                              </div>
                              <div className="mt-1 text-xs font-medium text-slate-600">
                                {safeString(report?.subtitle)}
                              </div>
                              <div className="mt-2 text-[11px] font-bold uppercase tracking-wide text-slate-500">
                                {safeArray(report?.supports).join(" • ")}
                              </div>
                            </div>
                          </div>
                        </button>
                      );
                    })
                  ) : (
                    <EmptyState message="No report catalog available." />
                  )}
                </div>

                {/* Builder */}
                <div className="space-y-4">
                  <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
                    <div className="text-xs font-extrabold uppercase tracking-wide text-slate-500">
                      Selected report
                    </div>
                    <div className="mt-2 text-lg font-black text-slate-900">
                      {safeString(activeReportMeta?.title, "Report Generator")}
                    </div>
                    <div className="mt-1 text-sm font-medium text-slate-600">
                      {safeString(
                        activeReportMeta?.subtitle,
                        "Configure filters and generate a preview before export."
                      )}
                    </div>
                  </div>

                  {/* Filters */}
                  <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
                    <div className="mb-4 flex items-center gap-2 text-sm font-extrabold text-slate-900">
                      <Filter className="h-4 w-4 text-slate-700" />
                      Report filters
                    </div>

                    <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
                      {fieldVisible(form?.report_key, "period") && (
                        <label className="block">
                          <span className="mb-1 block text-xs font-bold uppercase tracking-wide text-slate-500">
                            Period
                          </span>
                          <select
                            value={form?.period || "month"}
                            onChange={(e) => setForm((prev) => ({ ...prev, period: e.target.value }))}
                            className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm font-semibold text-slate-700 outline-none focus:border-emerald-400"
                          >
                            <option value="day">Daily</option>
                            <option value="week">Weekly</option>
                            <option value="month">Monthly</option>
                            <option value="year">Yearly</option>
                          </select>
                        </label>
                      )}

                      {fieldVisible(form?.report_key, "span") && (
                        <label className="block">
                          <span className="mb-1 block text-xs font-bold uppercase tracking-wide text-slate-500">
                            Span
                          </span>
                          <input
                            type="number"
                            min="1"
                            max="120"
                            value={form?.span ?? 12}
                            onChange={(e) => setForm((prev) => ({ ...prev, span: e.target.value }))}
                            className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm font-semibold text-slate-700 outline-none focus:border-emerald-400"
                          />
                        </label>
                      )}

                      {fieldVisible(form?.report_key, "days") && (
                        <label className="block">
                          <span className="mb-1 block text-xs font-bold uppercase tracking-wide text-slate-500">
                            Days override
                          </span>
                          <input
                            type="number"
                            min="1"
                            max="3650"
                            value={form?.days ?? ""}
                            onChange={(e) => setForm((prev) => ({ ...prev, days: e.target.value }))}
                            placeholder="Optional"
                            className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm font-semibold text-slate-700 outline-none placeholder:text-slate-400 focus:border-emerald-400"
                          />
                        </label>
                      )}

                      {fieldVisible(form?.report_key, "date_from") && (
                        <label className="block">
                          <span className="mb-1 block text-xs font-bold uppercase tracking-wide text-slate-500">
                            Date from
                          </span>
                          <input
                            type="date"
                            value={form?.date_from ?? ""}
                            onChange={(e) => setForm((prev) => ({ ...prev, date_from: e.target.value }))}
                            className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm font-semibold text-slate-700 outline-none focus:border-emerald-400"
                          />
                        </label>
                      )}

                      {fieldVisible(form?.report_key, "date_to") && (
                        <label className="block">
                          <span className="mb-1 block text-xs font-bold uppercase tracking-wide text-slate-500">
                            Date to
                          </span>
                          <input
                            type="date"
                            value={form?.date_to ?? ""}
                            onChange={(e) => setForm((prev) => ({ ...prev, date_to: e.target.value }))}
                            className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm font-semibold text-slate-700 outline-none focus:border-emerald-400"
                          />
                        </label>
                      )}

                      {fieldVisible(form?.report_key, "q") && (
                        <label className="block md:col-span-2">
                          <span className="mb-1 block text-xs font-bold uppercase tracking-wide text-slate-500">
                            Search / query
                          </span>
                          <div className="relative">
                            <Search className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-slate-400" />
                            <input
                              value={form?.q ?? ""}
                              onChange={(e) => setForm((prev) => ({ ...prev, q: e.target.value }))}
                              placeholder="Optional search filter"
                              className="w-full rounded-xl border border-slate-200 bg-white py-2 pl-9 pr-3 text-sm font-semibold text-slate-700 outline-none placeholder:text-slate-400 focus:border-emerald-400"
                            />
                          </div>
                        </label>
                      )}

                      {fieldVisible(form?.report_key, "role") && (
                        <label className="block">
                          <span className="mb-1 block text-xs font-bold uppercase tracking-wide text-slate-500">
                            Role
                          </span>
                          <select
                            value={form?.role ?? ""}
                            onChange={(e) => setForm((prev) => ({ ...prev, role: e.target.value }))}
                            className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm font-semibold text-slate-700 outline-none focus:border-emerald-400"
                          >
                            <option value="">All roles</option>
                            <option value="admin">Admin</option>
                            <option value="farmer">Farmer</option>
                            <option value="customer">Customer</option>
                          </select>
                        </label>
                      )}

                      {fieldVisible(form?.report_key, "action") && (
                        <label className="block">
                          <span className="mb-1 block text-xs font-bold uppercase tracking-wide text-slate-500">
                            Action
                          </span>
                          <input
                            value={form?.action ?? ""}
                            onChange={(e) => setForm((prev) => ({ ...prev, action: e.target.value }))}
                            placeholder="e.g. approve_product"
                            className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm font-semibold text-slate-700 outline-none placeholder:text-slate-400 focus:border-emerald-400"
                          />
                        </label>
                      )}

                      {fieldVisible(form?.report_key, "status") && (
                        <label className="block">
                          <span className="mb-1 block text-xs font-bold uppercase tracking-wide text-slate-500">
                            Status
                          </span>
                          <select
                            value={form?.status ?? ""}
                            onChange={(e) => setForm((prev) => ({ ...prev, status: e.target.value }))}
                            className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm font-semibold text-slate-700 outline-none focus:border-emerald-400"
                          >
                            <option value="">All statuses</option>
                            <option value="success">Success</option>
                            <option value="failed">Failed</option>
                            <option value="blocked">Blocked</option>
                          </select>
                        </label>
                      )}

                      {fieldVisible(form?.report_key, "event_type") && (
                        <label className="block">
                          <span className="mb-1 block text-xs font-bold uppercase tracking-wide text-slate-500">
                            Event type
                          </span>
                          <select
                            value={form?.event_type ?? ""}
                            onChange={(e) => setForm((prev) => ({ ...prev, event_type: e.target.value }))}
                            className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm font-semibold text-slate-700 outline-none focus:border-emerald-400"
                          >
                            <option value="">All auth events</option>
                            <option value="login">Login</option>
                            <option value="logout">Logout</option>
                            <option value="logout_all">Logout all</option>
                            <option value="refresh">Refresh</option>
                            <option value="failed_login">Failed login</option>
                            <option value="session_expired">Session expired</option>
                            <option value="token_revoked">Token revoked</option>
                          </select>
                        </label>
                      )}

                      {fieldVisible(form?.report_key, "actor_role") && (
                        <label className="block">
                          <span className="mb-1 block text-xs font-bold uppercase tracking-wide text-slate-500">
                            Actor role
                          </span>
                          <select
                            value={form?.actor_role ?? ""}
                            onChange={(e) => setForm((prev) => ({ ...prev, actor_role: e.target.value }))}
                            className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm font-semibold text-slate-700 outline-none focus:border-emerald-400"
                          >
                            <option value="">All actor roles</option>
                            <option value="admin">Admin</option>
                            <option value="farmer">Farmer</option>
                            <option value="customer">Customer</option>
                          </select>
                        </label>
                      )}

                      {fieldVisible(form?.report_key, "sla_hours") && (
                        <label className="block">
                          <span className="mb-1 block text-xs font-bold uppercase tracking-wide text-slate-500">
                            SLA hours
                          </span>
                          <input
                            type="number"
                            min="1"
                            max="240"
                            value={form?.sla_hours ?? 48}
                            onChange={(e) => setForm((prev) => ({ ...prev, sla_hours: e.target.value }))}
                            className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm font-semibold text-slate-700 outline-none focus:border-emerald-400"
                          />
                        </label>
                      )}

                      {fieldVisible(form?.report_key, "limit") && (
                        <label className="block">
                          <span className="mb-1 block text-xs font-bold uppercase tracking-wide text-slate-500">
                            Result limit
                          </span>
                          <input
                            type="number"
                            min="1"
                            max="10000"
                            value={form?.limit ?? 500}
                            onChange={(e) => setForm((prev) => ({ ...prev, limit: e.target.value }))}
                            className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm font-semibold text-slate-700 outline-none focus:border-emerald-400"
                          />
                        </label>
                      )}

                      <label className="block">
                        <span className="mb-1 block text-xs font-bold uppercase tracking-wide text-slate-500">
                          Preview rows
                        </span>
                        <input
                          type="number"
                          min="1"
                          max="200"
                          value={form?.preview_limit ?? 25}
                          onChange={(e) => setForm((prev) => ({ ...prev, preview_limit: e.target.value }))}
                          className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm font-semibold text-slate-700 outline-none focus:border-emerald-400"
                        />
                      </label>
                    </div>

                    <div className="mt-4 flex flex-wrap gap-2">
                      <button
                        type="button"
                        onClick={() => onPreview?.()}
                        disabled={loadingPreview}
                        className="inline-flex items-center gap-2 rounded-xl border border-emerald-200 bg-emerald-50 px-4 py-2 text-sm font-bold text-emerald-800 shadow-sm transition hover:bg-emerald-100 disabled:cursor-not-allowed disabled:opacity-60"
                      >
                        <Eye className="h-4 w-4" />
                        {loadingPreview ? "Generating…" : "Preview report"}
                      </button>

                      <button
                        type="button"
                        onClick={() => onExport?.("pdf")}
                        disabled={loadingPreview}
                        className="inline-flex items-center gap-2 rounded-xl border border-rose-200 bg-rose-50 px-4 py-2 text-sm font-bold text-rose-800 shadow-sm transition hover:bg-rose-100 disabled:cursor-not-allowed disabled:opacity-60"
                      >
                        <Download className="h-4 w-4" />
                        Export PDF
                      </button>

                      <button
                        type="button"
                        onClick={() => onExport?.("csv")}
                        disabled={loadingPreview}
                        className="inline-flex items-center gap-2 rounded-xl border border-sky-200 bg-sky-50 px-4 py-2 text-sm font-bold text-sky-800 shadow-sm transition hover:bg-sky-100 disabled:cursor-not-allowed disabled:opacity-60"
                      >
                        <Download className="h-4 w-4" />
                        Export CSV
                      </button>
                    </div>
                  </div>

                  {/* Preview handoff */}
                  <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4 shadow-sm">
                    <div className="mb-2 flex items-center gap-2 text-sm font-extrabold text-slate-900">
                      <FileStack className="h-4 w-4 text-slate-700" />
                      Generated preview
                    </div>

                    {loadingPreview ? (
                      <div className="text-sm font-semibold text-slate-500">Generating preview…</div>
                    ) : preview ? (
                      <div className="space-y-3">
                        <div className="rounded-xl border border-slate-200 bg-white p-3">
                          <div className="text-xs font-bold uppercase tracking-wide text-slate-500">Latest preview</div>
                          <div className="mt-1 text-sm font-black text-slate-900">
                            {safeString(preview?.title, "Generated Report")}
                          </div>
                          <div className="mt-1 text-xs font-medium text-slate-500">
                            {safeString(preview?.subtitle)}
                          </div>
                        </div>
                        <div className="rounded-xl border border-slate-200 bg-white p-3 text-sm font-medium text-slate-600">
                          Preview opens in a dedicated dialog so the admin can inspect the summary and rows in a larger workspace.
                        </div>
                      </div>
                    ) : (
                      <EmptyState message="Preview opens in a separate dialog after you generate it." />
                    )}
                  </div>
                </div>
              </div>
            </div>
          </motion.aside>
        </>
      ) : null}
    </AnimatePresence>
  );
}