// ============================================================================
// frontend/src/pages/dashboards/admin/AdminReviewGovernancePage.jsx
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Admin review-governance workspace for Phase 3 moderation.
// ============================================================================

import React, { useCallback, useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  EyeOff,
  FileWarning,
  RefreshCcw,
  Search,
  Shield,
  ShieldAlert,
  Trash2,
} from "lucide-react";

import api from "../../../api";
import AdminLayout from "../../../components/AdminLayout";
import Card from "../../../components/ui/Card";

const POLICY_ACTIONS = [
  { value: "mark_under_review", label: "Mark under review", icon: ShieldAlert },
  { value: "hide_review", label: "Hide review", icon: EyeOff },
  { value: "remove_review", label: "Remove review", icon: Trash2 },
  { value: "dismiss_flags", label: "Dismiss flags", icon: CheckCircle2 },
  { value: "restore_review", label: "Restore review", icon: Shield },
  { value: "publish_review", label: "Publish review", icon: CheckCircle2 },
];

function safeArray(v) {
  return Array.isArray(v) ? v : [];
}

function safeStr(v) {
  return typeof v === "string" ? v : v == null ? "" : String(v);
}

function fmtDate(value) {
  try {
    if (!value) return "—";
    const d = new Date(value);
    if (Number.isNaN(d.getTime())) return "—";
    return d.toLocaleString();
  } catch {
    return "—";
  }
}

function toneForStatus(status) {
  const s = safeStr(status).toLowerCase();
  if (["removed"].includes(s)) return "bg-red-50 text-red-700 border-red-200";
  if (["hidden", "flagged", "under_review"].includes(s)) return "bg-amber-50 text-amber-700 border-amber-200";
  return "bg-emerald-50 text-emerald-700 border-emerald-200";
}

function StatCard({ icon: Icon, label, value, tone = "emerald" }) {
  const toneMap = {
    emerald: "bg-emerald-50 text-emerald-700 border-emerald-200",
    amber: "bg-amber-50 text-amber-700 border-amber-200",
    red: "bg-red-50 text-red-700 border-red-200",
    slate: "bg-slate-50 text-slate-700 border-slate-200",
  };

  return (
    <Card className="rounded-3xl border border-slate-200 bg-white p-5 shadow-sm">
      <div className="flex items-center gap-4">
        <div className={`rounded-2xl border p-3 ${toneMap[tone] || toneMap.slate}`}>
          <Icon className="h-5 w-5" />
        </div>
        <div>
          <div className="text-sm font-medium text-slate-500">{label}</div>
          <div className="text-2xl font-extrabold text-slate-900">{value}</div>
        </div>
      </div>
    </Card>
  );
}

function QueueCard({ item, onAction }) {
  const latestFlag = item?.latest_flag;
  const latestAction = item?.latest_policy_action;

  return (
    <Card className="rounded-3xl border border-slate-200 bg-white p-5 shadow-sm">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <h3 className="text-lg font-bold text-slate-900">
              {item?.product_name || "Product review"}
            </h3>
            <span className={`inline-flex rounded-full border px-2.5 py-1 text-xs font-semibold ${toneForStatus(item?.moderation_status)}`}>
              {safeStr(item?.moderation_status || "visible").replace(/_/g, " ")}
            </span>
            {item?.verified_purchase ? (
              <span className="inline-flex rounded-full bg-emerald-50 px-2.5 py-1 text-xs font-semibold text-emerald-700">
                Verified purchase
              </span>
            ) : null}
          </div>
          <div className="mt-1 text-sm text-slate-500">
            Customer: <span className="font-semibold text-slate-700">{item?.customer_name || "Customer"}</span>
          </div>
          <div className="mt-1 text-xs text-slate-400">Created {fmtDate(item?.created_at)}</div>
        </div>

        <div className="rounded-2xl bg-slate-50 px-3 py-2 text-right">
          <div className="text-xs font-semibold uppercase tracking-wide text-slate-500">Open flags</div>
          <div className="text-xl font-extrabold text-slate-900">{item?.open_flag_count || 0}</div>
        </div>
      </div>

      <p className="mt-4 whitespace-pre-wrap text-sm leading-6 text-slate-700">
        {item?.comments || item?.comment || "No written comment."}
      </p>

      <div className="mt-4 grid gap-3 md:grid-cols-3">
        <div className="rounded-2xl border border-slate-200 bg-slate-50 p-3">
          <div className="text-xs font-semibold uppercase tracking-wide text-slate-500">Latest flag</div>
          <div className="mt-1 text-sm font-semibold text-slate-900">
            {latestFlag?.reason_code ? latestFlag.reason_code.replace(/_/g, " ") : "—"}
          </div>
          <div className="mt-1 text-xs text-slate-500">{fmtDate(latestFlag?.created_at)}</div>
        </div>
        <div className="rounded-2xl border border-slate-200 bg-slate-50 p-3">
          <div className="text-xs font-semibold uppercase tracking-wide text-slate-500">Latest policy action</div>
          <div className="mt-1 text-sm font-semibold text-slate-900">
            {latestAction?.action_type ? latestAction.action_type.replace(/_/g, " ") : "—"}
          </div>
          <div className="mt-1 text-xs text-slate-500">{fmtDate(latestAction?.created_at)}</div>
        </div>
        <div className="rounded-2xl border border-slate-200 bg-slate-50 p-3">
          <div className="text-xs font-semibold uppercase tracking-wide text-slate-500">Response SLA</div>
          <div className="mt-1 text-sm font-semibold text-slate-900">
            {safeStr(item?.response_sla_status || item?.response_status || "unknown").replace(/_/g, " ")}
          </div>
          <div className="mt-1 text-xs text-slate-500">Due {fmtDate(item?.response_sla_due_at)}</div>
        </div>
      </div>

      <div className="mt-5 flex flex-wrap gap-2">
        {POLICY_ACTIONS.map((action) => {
          const Icon = action.icon;
          return (
            <button
              key={action.value}
              type="button"
              onClick={() => onAction?.(item, action.value)}
              className="inline-flex items-center gap-2 rounded-2xl border border-slate-200 px-3 py-2 text-sm font-semibold text-slate-700 hover:bg-slate-50"
            >
              <Icon className="h-4 w-4" /> {action.label}
            </button>
          );
        })}
      </div>
    </Card>
  );
}

export default function AdminReviewGovernancePage() {
  const [queue, setQueue] = useState([]);
  const [auditItems, setAuditItems] = useState([]);
  const [summary, setSummary] = useState({ total: 0, flagged: 0, under_review: 0, hidden: 0, removed: 0, open_flags: 0 });
  const [filters, setFilters] = useState({ moderation_status: "flagged", only_open_flags: true, days: 90 });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [actionModal, setActionModal] = useState({ open: false, item: null, action: "mark_under_review" });
  const [rationale, setRationale] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const loadData = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const [queueRes, auditRes] = await Promise.all([
        api.get("/ratings/admin/queue", { params: filters }),
        api.get("/ratings/admin/audit", { params: { limit: 25 } }),
      ]);
      const queuePayload = queueRes?.data || {};
      const auditPayload = auditRes?.data || {};
      setQueue(safeArray(queuePayload.queue));
      setSummary(queuePayload.summary || { total: 0, flagged: 0, under_review: 0, hidden: 0, removed: 0, open_flags: 0 });
      setAuditItems(safeArray(auditPayload.items));
    } catch (err) {
      setError(err?.response?.data?.message || err?.message || "Could not load review governance queue.");
    } finally {
      setLoading(false);
    }
  }, [filters]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const openActionModal = (item, action) => {
    setActionModal({ open: true, item, action });
    setRationale("");
  };

  const closeActionModal = () => {
    if (submitting) return;
    setActionModal({ open: false, item: null, action: "mark_under_review" });
    setRationale("");
  };

  const submitAction = async () => {
    const ratingId = actionModal?.item?.rating_id || actionModal?.item?.id;
    if (!ratingId) return;
    setSubmitting(true);
    try {
      await api.post(`/ratings/admin/${ratingId}/moderate`, {
        action_type: actionModal.action,
        rationale,
      });
      closeActionModal();
      loadData();
    } catch (err) {
      setError(err?.response?.data?.message || err?.message || "Could not apply review policy action.");
    } finally {
      setSubmitting(false);
    }
  };

  const filteredQueue = useMemo(() => {
    return queue;
  }, [queue]);

  return (
    <AdminLayout>
      <div className="space-y-6">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h1 className="text-2xl font-extrabold text-slate-900">Review Governance</h1>
            <p className="mt-1 max-w-3xl text-sm text-slate-500">
              Govern flagged reviews, apply policy actions, and monitor the moderation queue with an auditable workflow.
            </p>
          </div>
          <button
            type="button"
            onClick={loadData}
            className="inline-flex items-center gap-2 rounded-2xl border border-slate-200 bg-white px-4 py-2.5 text-sm font-semibold text-slate-700 shadow-sm hover:bg-slate-50"
          >
            <RefreshCcw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} /> Refresh
          </button>
        </div>

        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-5">
          <StatCard icon={FileWarning} label="Queue total" value={summary.total || 0} tone="slate" />
          <StatCard icon={AlertTriangle} label="Flagged" value={summary.flagged || 0} tone="amber" />
          <StatCard icon={ShieldAlert} label="Under review" value={summary.under_review || 0} tone="amber" />
          <StatCard icon={EyeOff} label="Hidden" value={summary.hidden || 0} tone="red" />
          <StatCard icon={Trash2} label="Removed" value={summary.removed || 0} tone="red" />
        </div>

        <Card className="rounded-3xl border border-slate-200 bg-white p-5 shadow-sm">
          <div className="grid gap-4 md:grid-cols-3 xl:grid-cols-4">
            <label className="block">
              <span className="mb-2 block text-xs font-semibold uppercase tracking-wide text-slate-500">Moderation status</span>
              <select
                value={filters.moderation_status}
                onChange={(e) => setFilters((prev) => ({ ...prev, moderation_status: e.target.value }))}
                className="w-full rounded-2xl border border-slate-300 px-4 py-3 text-sm outline-none focus:border-emerald-500"
              >
                <option value="flagged">Flagged</option>
                <option value="under_review">Under review</option>
                <option value="hidden">Hidden</option>
                <option value="removed">Removed</option>
                <option value="visible">Visible</option>
              </select>
            </label>

            <label className="block">
              <span className="mb-2 block text-xs font-semibold uppercase tracking-wide text-slate-500">Days window</span>
              <input
                type="number"
                min="1"
                max="365"
                value={filters.days}
                onChange={(e) => setFilters((prev) => ({ ...prev, days: Number(e.target.value) || 90 }))}
                className="w-full rounded-2xl border border-slate-300 px-4 py-3 text-sm outline-none focus:border-emerald-500"
              />
            </label>

            <label className="flex items-center gap-3 rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3">
              <input
                type="checkbox"
                checked={Boolean(filters.only_open_flags)}
                onChange={(e) => setFilters((prev) => ({ ...prev, only_open_flags: e.target.checked }))}
                className="h-4 w-4 rounded border-slate-300"
              />
              <span className="text-sm font-medium text-slate-700">Only reviews with open flags</span>
            </label>

            <div className="flex items-end">
              <button
                type="button"
                onClick={loadData}
                className="inline-flex w-full items-center justify-center gap-2 rounded-2xl bg-emerald-600 px-4 py-3 text-sm font-semibold text-white hover:bg-emerald-700"
              >
                <Search className="h-4 w-4" /> Apply filters
              </button>
            </div>
          </div>
        </Card>

        {error ? (
          <div className="rounded-2xl border border-red-200 bg-red-50 px-4 py-3 text-sm font-medium text-red-700">
            {error}
          </div>
        ) : null}

        <div className="grid gap-6 xl:grid-cols-[1.7fr_1fr]">
          <div className="space-y-4">
            {loading ? (
              <Card className="rounded-3xl border border-slate-200 bg-white p-8 text-center text-sm text-slate-500 shadow-sm">
                Loading moderation queue…
              </Card>
            ) : filteredQueue.length === 0 ? (
              <Card className="rounded-3xl border border-dashed border-slate-300 bg-white p-8 text-center text-sm text-slate-500 shadow-sm">
                No reviews match the current moderation filters.
              </Card>
            ) : (
              filteredQueue.map((item) => (
                <QueueCard key={item?.rating_id || item?.id} item={item} onAction={openActionModal} />
              ))
            )}
          </div>

          <Card className="rounded-3xl border border-slate-200 bg-white p-5 shadow-sm">
            <div className="flex items-center gap-2">
              <Shield className="h-5 w-5 text-slate-700" />
              <h2 className="text-lg font-bold text-slate-900">Policy action audit</h2>
            </div>
            <div className="mt-4 space-y-3">
              {safeArray(auditItems).length === 0 ? (
                <div className="rounded-2xl border border-dashed border-slate-300 px-4 py-6 text-center text-sm text-slate-500">
                  No review policy actions recorded yet.
                </div>
              ) : (
                safeArray(auditItems).map((entry) => (
                  <div key={entry?.action_id || entry?.id} className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                    <div className="text-sm font-semibold text-slate-900">
                      {safeStr(entry?.action_type).replace(/_/g, " ") || "Policy action"}
                    </div>
                    <div className="mt-1 text-xs text-slate-500">{fmtDate(entry?.created_at)}</div>
                    <div className="mt-2 text-sm text-slate-700">{entry?.rationale || "No rationale recorded."}</div>
                  </div>
                ))
              )}
            </div>
          </Card>
        </div>
      </div>

      {actionModal.open ? (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/50 p-4">
          <div className="w-full max-w-xl rounded-3xl bg-white p-6 shadow-2xl">
            <h3 className="text-lg font-bold text-slate-900">Apply review policy action</h3>
            <p className="mt-1 text-sm text-slate-500">
              This action will be written to the review-governance audit log.
            </p>
            <div className="mt-4 rounded-2xl border border-slate-200 bg-slate-50 p-4 text-sm text-slate-700">
              <div className="font-semibold text-slate-900">
                {safeStr(actionModal?.item?.product_name || "Product review")}
              </div>
              <div className="mt-1">Action: <span className="font-semibold">{safeStr(actionModal?.action).replace(/_/g, " ")}</span></div>
            </div>

            <label className="mt-4 block">
              <span className="mb-2 block text-sm font-semibold text-slate-700">Rationale</span>
              <textarea
                rows={5}
                value={rationale}
                onChange={(e) => setRationale(e.target.value)}
                placeholder="Explain why this policy action is being applied."
                className="w-full rounded-2xl border border-slate-300 px-4 py-3 text-sm outline-none focus:border-emerald-500"
              />
            </label>

            <div className="mt-6 flex items-center justify-end gap-3">
              <button
                type="button"
                onClick={closeActionModal}
                className="rounded-2xl border border-slate-300 px-4 py-2.5 text-sm font-semibold text-slate-700 hover:bg-slate-50"
              >
                Cancel
              </button>
              <button
                type="button"
                disabled={submitting}
                onClick={submitAction}
                className="rounded-2xl bg-emerald-600 px-4 py-2.5 text-sm font-semibold text-white hover:bg-emerald-700 disabled:cursor-not-allowed disabled:opacity-60"
              >
                {submitting ? "Applying…" : "Apply action"}
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </AdminLayout>
  );
}
