import React, { useMemo, useState } from "react";
import {
  CalendarDays,
  MessageSquare,
  RefreshCcw,
  Send,
  ShieldAlert,
  Tag,
} from "lucide-react";

import api from "../../../api";
import FarmerLayout from "../../../components/FarmerLayout";
import { useAuth } from "../../../components/auth/AuthProvider";
import SimpleBarChart from "../../../components/ui/SimpleBarChart";
import useApi from "../../../hooks/useApi";

// ============================================================================
// frontend/src/pages/dashboards/farmer/FarmerFeedbackPage.jsx
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Farmer feedback / review-management page.
//
// THIS VERSION:
//   ✅ Fixes the nullish-coalescing parse error
//   ✅ Keeps the farmer feedback analytics experience
//   ✅ Adds response composer support for Phase 2 review workflow
//   ✅ Adds issue-tag + resolution-status draft handling
//   ✅ Supports public farmer responses and workflow updates
//   ✅ Uses card-local retry / refresh UX
// ============================================================================

function safeArray(value) {
  return Array.isArray(value) ? value : [];
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

function toDateKey(value) {
  try {
    const dt = new Date(value);
    if (Number.isNaN(dt.getTime())) return null;
    return dt.toISOString().slice(0, 10);
  } catch {
    return null;
  }
}

function uniqEndpoints(list) {
  const out = [];
  const seen = new Set();
  for (const item of list || []) {
    if (!item || seen.has(item)) continue;
    seen.add(item);
    out.push(item);
  }
  return out;
}

const ISSUE_TAG_OPTIONS = [
  "",
  "freshness",
  "quality",
  "packaging",
  "delivery_delay",
  "wrong_item",
  "quantity",
  "communication",
  "value",
  "damaged",
  "other",
];

const RESOLUTION_STATUS_OPTIONS = [
  "open",
  "acknowledged",
  "in_progress",
  "resolved",
];

const RESPONSE_STATUS_OPTIONS = [
  { value: "all", label: "All" },
  { value: "needs_response", label: "Needs response" },
  { value: "responded_on_time", label: "Responded on time" },
  { value: "responded_late", label: "Responded late" },
  { value: "sla_breached", label: "SLA breached" },
];

export default function FarmerFeedbackPage() {
  const { user } = useAuth();
  const farmerId = user?.id;

  const [mode, setMode] = useState("weekly");
  const [days, setDays] = useState(60);
  const [onlyComments, setOnlyComments] = useState(true);
  const [ratingFilter, setRatingFilter] = useState(0);
  const [issueTagFilter, setIssueTagFilter] = useState("");
  const [responseStatusFilter, setResponseStatusFilter] = useState("all");

  const [openComposerByRating, setOpenComposerByRating] = useState({});
  const [responseDraftByRating, setResponseDraftByRating] = useState({});
  const [issueDraftByRating, setIssueDraftByRating] = useState({});
  const [resolutionDraftByRating, setResolutionDraftByRating] = useState({});
  const [savingByRating, setSavingByRating] = useState({});
  const [workflowSavingByRating, setWorkflowSavingByRating] = useState({});
  const [pageError, setPageError] = useState("");

  const endpoints = useMemo(
    () =>
      uniqEndpoints([
        farmerId ? `/api/ratings/farmer/${farmerId}` : null,
        farmerId ? `/ratings/farmer/${farmerId}` : null,
      ]),
    [farmerId]
  );

  const res = useApi(endpoints, {
    enabled: Boolean(farmerId),
    params: {
      days,
      farmerId,
      response_status: responseStatusFilter,
    },
    deps: [farmerId, days, responseStatusFilter],
  });

  const rawPayload = useMemo(() => res.data ?? {}, [res.data]);
  const ratings = useMemo(() => {
    const rows = safeArray(rawPayload?.ratings ?? rawPayload?.items ?? rawPayload);
    return rows.filter((row) => {
      const score = Math.round(
        safeNumber(row?.rating_score ?? row?.rating ?? row?.score, 0)
      );
      const comment = safeStr(row?.comment ?? row?.comments ?? "");
      const issueTag = safeStr(row?.issue_tag ?? "");
      const responseStatus = safeStr(
        row?.response_status ?? row?.response_sla_status ?? "all"
      );

      if (ratingFilter > 0 && score !== ratingFilter) return false;
      if (onlyComments && !comment.trim()) return false;
      if (issueTagFilter && issueTag !== issueTagFilter) return false;
      if (responseStatusFilter !== "all" && responseStatus !== responseStatusFilter) {
        return false;
      }
      return true;
    });
  }, [rawPayload, ratingFilter, onlyComments, issueTagFilter, responseStatusFilter]);

  const summary = useMemo(() => {
    const nums = ratings
      .map((r) => safeNumber(r?.rating_score ?? r?.rating ?? r?.score, 0))
      .filter((n) => n > 0);

    const avg = nums.length ? nums.reduce((a, b) => a + b, 0) / nums.length : 0;

    const dist = { 1: 0, 2: 0, 3: 0, 4: 0, 5: 0 };
    for (const r of ratings) {
      const score = Math.round(
        safeNumber(r?.rating_score ?? r?.rating ?? r?.score, 0)
      );
      if (score >= 1 && score <= 5) dist[score] += 1;
    }

    return {
      avg,
      count: ratings.length,
      dist,
      verifiedCount: ratings.filter((r) => Boolean(r?.verified_purchase)).length,
      needsResponse: ratings.filter(
        (r) => safeStr(r?.response_status ?? r?.response_sla_status) === "needs_response"
      ).length,
      breached: ratings.filter(
        (r) => safeStr(r?.response_status ?? r?.response_sla_status) === "sla_breached"
      ).length,
    };
  }, [ratings]);

  const distBars = useMemo(() => {
    const total = summary.count || 1;
    return [5, 4, 3, 2, 1].map((n) => ({
      n,
      count: summary.dist[n] || 0,
      pct: Math.round(((summary.dist[n] || 0) / total) * 100),
    }));
  }, [summary]);

  const trendData = useMemo(() => {
    const rows = safeArray(rawPayload?.trend);
    if (rows.length) {
      return rows.map((row) => ({
        label: safeStr(row?.bucket ?? row?.label ?? ""),
        value: safeNumber(row?.avg ?? row?.value, 0),
      }));
    }

    const map = new Map();
    for (const r of ratings) {
      const keyBase = toDateKey(r?.created_at ?? r?.date ?? r?.createdAt);
      if (!keyBase) continue;

      let key = keyBase;
      if (mode === "monthly") key = keyBase.slice(0, 7);
      if (mode === "annual") key = keyBase.slice(0, 4);

      const prev = map.get(key) || { sum: 0, count: 0 };
      const score = safeNumber(r?.rating_score ?? r?.rating ?? r?.score, 0);
      map.set(key, { sum: prev.sum + score, count: prev.count + 1 });
    }

    return Array.from(map.entries())
      .sort((a, b) => a[0].localeCompare(b[0]))
      .map(([label, value]) => ({
        label,
        value: value.count ? value.sum / value.count : 0,
      }));
  }, [rawPayload, ratings, mode]);

  const visibleRows = useMemo(() => {
    return [...ratings]
      .sort((a, b) => {
        const da = new Date(a?.created_at ?? a?.date ?? 0).getTime();
        const db = new Date(b?.created_at ?? b?.date ?? 0).getTime();
        return db - da;
      })
      .slice(0, 30);
  }, [ratings]);

  function openComposer(row) {
    const ratingId = String(row?.rating_id || row?.id || "");
    if (!ratingId) return;

    setOpenComposerByRating((prev) => ({
      ...prev,
      [ratingId]: !prev[ratingId],
    }));

    setIssueDraftByRating((prev) => ({
      ...prev,
      [ratingId]: prev[ratingId] ?? safeStr(row?.issue_tag, ""),
    }));

    setResolutionDraftByRating((prev) => ({
      ...prev,
      [ratingId]: prev[ratingId] ?? (safeStr(row?.resolution_status, "open") || "open"),
    }));

    setResponseDraftByRating((prev) => ({
      ...prev,
      [ratingId]: prev[ratingId] ?? "",
    }));
  }

  async function submitResponse(row) {
    const ratingId = String(row?.rating_id || row?.id || "");
    if (!ratingId) return;

    const responseText = safeStr(responseDraftByRating[ratingId], "").trim();
    const issueTag = safeStr(issueDraftByRating[ratingId], "").trim();
    const resolutionStatus =
      safeStr(resolutionDraftByRating[ratingId], "open").trim() || "open";

    if (!responseText) {
      setPageError("Please type a response before sending.");
      return;
    }

    setPageError("");
    setSavingByRating((prev) => ({ ...prev, [ratingId]: true }));

    try {
      await api.post(`/ratings/${ratingId}/response`, {
        response_text: responseText,
        issue_tag: issueTag || null,
        resolution_status: resolutionStatus,
        is_public: true,
      });

      setResponseDraftByRating((prev) => ({ ...prev, [ratingId]: "" }));
      setOpenComposerByRating((prev) => ({ ...prev, [ratingId]: false }));
      await res.refetch?.();
    } catch (error) {
      setPageError(
        error?.response?.data?.message ||
          error?.message ||
          "Could not save farmer response right now."
      );
    } finally {
      setSavingByRating((prev) => ({ ...prev, [ratingId]: false }));
    }
  }

  async function saveWorkflow(row) {
    const ratingId = String(row?.rating_id || row?.id || "");
    if (!ratingId) return;

    const issueTag = safeStr(issueDraftByRating[ratingId], "").trim();
    const resolutionStatus =
      safeStr(resolutionDraftByRating[ratingId], "open").trim() || "open";

    setPageError("");
    setWorkflowSavingByRating((prev) => ({ ...prev, [ratingId]: true }));

    try {
      await api.patch(`/ratings/${ratingId}/workflow`, {
        issue_tag: issueTag || null,
        resolution_status: resolutionStatus,
      });
      await res.refetch?.();
    } catch (error) {
      setPageError(
        error?.response?.data?.message ||
          error?.message ||
          "Could not update review workflow right now."
      );
    } finally {
      setWorkflowSavingByRating((prev) => ({ ...prev, [ratingId]: false }));
    }
  }

  return (
    <FarmerLayout>
      <div className="space-y-6">
        <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
          <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
            <div>
              <div className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                Farmer
              </div>
              <h1 className="text-2xl font-extrabold text-slate-900">Feedback</h1>
              <p className="mt-1 text-sm text-slate-600">
                Track product quality, respond publicly, and manage issue tags and
                review status.
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <div className="inline-flex h-10 items-center gap-2 rounded-xl border border-slate-200 bg-white px-3">
                <CalendarDays className="h-4 w-4 text-slate-400" />
                <select
                  value={days}
                  onChange={(e) => setDays(Number(e.target.value))}
                  className="h-9 bg-transparent text-sm font-semibold text-slate-800 outline-none"
                >
                  <option value={14}>Last 14 days</option>
                  <option value={28}>Last 28 days</option>
                  <option value={60}>Last 60 days</option>
                  <option value={180}>Last 180 days</option>
                </select>
              </div>

              <button
                type="button"
                onClick={() => res.refetch?.()}
                className="inline-flex h-10 items-center gap-2 rounded-xl border border-slate-200 bg-white px-4 text-sm font-semibold text-slate-800 hover:bg-slate-50"
              >
                <RefreshCcw className="h-4 w-4" />
                Refresh
              </button>
            </div>
          </div>
        </div>

        {pageError ? (
          <div className="rounded-2xl border border-rose-200 bg-rose-50 p-4 text-sm text-rose-700">
            {pageError}
          </div>
        ) : null}

        {res.error ? (
          <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
            <div className="flex items-center justify-between gap-3 rounded-xl border border-rose-200 bg-rose-50 p-4 text-sm text-rose-700">
              <div>Feedback is not available right now.</div>
              <button
                type="button"
                onClick={() => res.refetch?.()}
                className="rounded-xl border border-rose-200 bg-white px-3 py-2 font-semibold text-rose-700"
              >
                Retry
              </button>
            </div>
          </div>
        ) : null}

        <div className="grid grid-cols-1 gap-4 xl:grid-cols-4">
          <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
            <div className="text-xs font-semibold text-slate-500">Average Rating</div>
            <div className="mt-2 text-3xl font-extrabold text-slate-900">
              {res.loading ? "…" : summary.avg.toFixed(1)}
            </div>
          </div>
          <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
            <div className="text-xs font-semibold text-slate-500">Feedback Count</div>
            <div className="mt-2 text-3xl font-extrabold text-slate-900">
              {res.loading ? "…" : summary.count}
            </div>
          </div>
          <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
            <div className="text-xs font-semibold text-slate-500">Verified Reviews</div>
            <div className="mt-2 text-3xl font-extrabold text-slate-900">
              {res.loading ? "…" : summary.verifiedCount}
            </div>
          </div>
          <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
            <div className="text-xs font-semibold text-slate-500">Needs Response / Breached</div>
            <div className="mt-2 text-3xl font-extrabold text-slate-900">
              {res.loading ? "…" : `${summary.needsResponse} / ${summary.breached}`}
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
          <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm xl:col-span-2">
            <div className="mb-3 flex items-center justify-between gap-3">
              <div className="text-sm font-extrabold text-slate-900">Rating Trend</div>
              <div className="inline-flex rounded-xl border border-slate-200 bg-slate-50 p-1">
                {[
                  ["weekly", "Weekly"],
                  ["monthly", "Monthly"],
                  ["annual", "Annual"],
                ].map(([value, label]) => (
                  <button
                    key={value}
                    type="button"
                    onClick={() => setMode(value)}
                    className={`rounded-lg px-3 py-1.5 text-sm font-semibold ${
                      mode === value
                        ? "bg-emerald-600 text-white"
                        : "text-slate-700 hover:bg-white"
                    }`}
                  >
                    {label}
                  </button>
                ))}
              </div>
            </div>
            <SimpleBarChart data={trendData} />
          </div>

          <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
            <div className="text-sm font-extrabold text-slate-900">Rating Distribution</div>
            <div className="mt-4 space-y-2">
              {distBars.map((bar) => (
                <div key={bar.n} className="flex items-center gap-3">
                  <div className="w-10 text-sm font-bold text-slate-800">{bar.n}★</div>
                  <div className="h-3 flex-1 overflow-hidden rounded-full border border-slate-200 bg-slate-100">
                    <div
                      className="h-full bg-emerald-500/50"
                      style={{ width: `${bar.pct}%` }}
                    />
                  </div>
                  <div className="w-16 text-right text-sm font-semibold text-slate-700">
                    {bar.count}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
          <div className="mb-4 flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
            <div>
              <div className="text-sm font-extrabold text-slate-900">Review Management</div>
              <div className="text-sm text-slate-600">
                Filter reviews, tag issues, and respond publicly.
              </div>
            </div>

            <div className="grid grid-cols-2 gap-2 md:grid-cols-5">
              <select
                value={ratingFilter}
                onChange={(e) => setRatingFilter(Number(e.target.value))}
                className="rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm"
              >
                <option value={0}>All ratings</option>
                <option value={5}>5 stars</option>
                <option value={4}>4 stars</option>
                <option value={3}>3 stars</option>
                <option value={2}>2 stars</option>
                <option value={1}>1 star</option>
              </select>

              <select
                value={issueTagFilter}
                onChange={(e) => setIssueTagFilter(e.target.value)}
                className="rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm"
              >
                <option value="">All issue tags</option>
                {ISSUE_TAG_OPTIONS.filter(Boolean).map((tag) => (
                  <option key={tag} value={tag}>
                    {tag.replaceAll("_", " ")}
                  </option>
                ))}
              </select>

              <select
                value={responseStatusFilter}
                onChange={(e) => setResponseStatusFilter(e.target.value)}
                className="rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm"
              >
                {RESPONSE_STATUS_OPTIONS.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>

              <label className="inline-flex items-center gap-2 rounded-xl border border-slate-200 px-3 py-2 text-sm text-slate-700">
                <input
                  type="checkbox"
                  checked={onlyComments}
                  onChange={(e) => setOnlyComments(e.target.checked)}
                />
                Comments only
              </label>

              <button
                type="button"
                onClick={() => {
                  setRatingFilter(0);
                  setIssueTagFilter("");
                  setResponseStatusFilter("all");
                  setOnlyComments(true);
                }}
                className="rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm font-semibold text-slate-700 hover:bg-slate-50"
              >
                Reset filters
              </button>
            </div>
          </div>

          <div className="space-y-4">
            {visibleRows.length === 0 ? (
              <div className="rounded-xl border border-dashed border-slate-300 p-6 text-center text-sm text-slate-500">
                No matching feedback found for the selected filters.
              </div>
            ) : null}

            {visibleRows.map((row) => {
              const ratingId = String(row?.rating_id || row?.id || "");
              const score = Math.round(
                safeNumber(row?.rating_score ?? row?.rating ?? row?.score, 0)
              );
              const comment = safeStr(row?.comment ?? row?.comments ?? "");
              const issueTag = safeStr(
                issueDraftByRating[ratingId] ?? row?.issue_tag ?? ""
              );
              const resolutionStatus = safeStr(
                resolutionDraftByRating[ratingId] ?? row?.resolution_status ?? "open",
                "open"
              );
              const publicResponses = safeArray(row?.public_responses);
              const responseStatus = safeStr(
                row?.response_status ?? row?.response_sla_status,
                "unknown"
              );

              return (
                <div
                  key={ratingId}
                  className="rounded-2xl border border-slate-200 bg-slate-50/40 p-4"
                >
                  <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
                    <div className="space-y-2">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="rounded-full bg-emerald-100 px-3 py-1 text-xs font-bold text-emerald-700">
                          {score}★ review
                        </span>
                        {row?.verified_purchase ? (
                          <span className="rounded-full bg-sky-100 px-3 py-1 text-xs font-bold text-sky-700">
                            Verified purchase
                          </span>
                        ) : null}
                        {responseStatus ? (
                          <span className="rounded-full bg-amber-100 px-3 py-1 text-xs font-bold text-amber-700">
                            {responseStatus.replaceAll("_", " ")}
                          </span>
                        ) : null}
                        {row?.issue_tag ? (
                          <span className="rounded-full bg-purple-100 px-3 py-1 text-xs font-bold text-purple-700">
                            {safeStr(row.issue_tag).replaceAll("_", " ")}
                          </span>
                        ) : null}
                      </div>

                      <div className="text-sm font-semibold text-slate-900">
                        {safeStr(row?.product_name, "Product")}
                      </div>

                      <div className="text-sm text-slate-600">
                        <span className="font-semibold text-slate-700">
                          {safeStr(row?.customer_name || row?.buyer_name, "Customer")}
                        </span>
                        {row?.buyer_location ? ` • ${row.buyer_location}` : ""}
                        {row?.created_at ? ` • ${new Date(row.created_at).toLocaleString()}` : ""}
                      </div>

                      {comment ? (
                        <p className="rounded-xl border border-slate-200 bg-white p-3 text-sm leading-6 text-slate-700">
                          {comment}
                        </p>
                      ) : (
                        <p className="text-sm italic text-slate-400">No written comment.</p>
                      )}

                      {publicResponses.length ? (
                        <div className="space-y-2">
                          {publicResponses.map((response) => (
                            <div
                              key={response?.response_id || response?.id}
                              className="rounded-xl border border-emerald-200 bg-emerald-50 p-3 text-sm text-emerald-900"
                            >
                              <div className="mb-1 font-semibold">
                                Farmer response
                                {response?.created_at
                                  ? ` • ${new Date(response.created_at).toLocaleString()}`
                                  : ""}
                              </div>
                              <div>{safeStr(response?.response_text)}</div>
                            </div>
                          ))}
                        </div>
                      ) : null}
                    </div>

                    <div className="flex flex-wrap items-center gap-2">
                      <button
                        type="button"
                        onClick={() => openComposer(row)}
                        className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm font-semibold text-slate-700 hover:bg-slate-50"
                      >
                        <MessageSquare className="h-4 w-4" />
                        {openComposerByRating[ratingId] ? "Close" : "Respond"}
                      </button>
                    </div>
                  </div>

                  {openComposerByRating[ratingId] ? (
                    <div className="mt-4 grid grid-cols-1 gap-3 rounded-2xl border border-slate-200 bg-white p-4 lg:grid-cols-3">
                      <div className="space-y-3 lg:col-span-2">
                        <label className="block text-sm font-semibold text-slate-700">
                          Public response
                        </label>
                        <textarea
                          rows={4}
                          value={responseDraftByRating[ratingId] ?? ""}
                          onChange={(e) =>
                            setResponseDraftByRating((prev) => ({
                              ...prev,
                              [ratingId]: e.target.value,
                            }))
                          }
                          className="w-full rounded-xl border border-slate-200 px-3 py-2 text-sm outline-none focus:border-emerald-400"
                          placeholder="Write a public response to the customer..."
                        />
                      </div>

                      <div className="space-y-3">
                        <div>
                          <label className="mb-1 inline-flex items-center gap-2 text-sm font-semibold text-slate-700">
                            <Tag className="h-4 w-4" />
                            Issue tag
                          </label>
                          <select
                            value={issueTag}
                            onChange={(e) =>
                              setIssueDraftByRating((prev) => ({
                                ...prev,
                                [ratingId]: e.target.value,
                              }))
                            }
                            className="w-full rounded-xl border border-slate-200 px-3 py-2 text-sm"
                          >
                            {ISSUE_TAG_OPTIONS.map((tag) => (
                              <option key={tag || "blank"} value={tag}>
                                {tag ? tag.replaceAll("_", " ") : "No tag"}
                              </option>
                            ))}
                          </select>
                        </div>

                        <div>
                          <label className="mb-1 inline-flex items-center gap-2 text-sm font-semibold text-slate-700">
                            <ShieldAlert className="h-4 w-4" />
                            Resolution status
                          </label>
                          <select
                            value={resolutionStatus}
                            onChange={(e) =>
                              setResolutionDraftByRating((prev) => ({
                                ...prev,
                                [ratingId]: e.target.value,
                              }))
                            }
                            className="w-full rounded-xl border border-slate-200 px-3 py-2 text-sm"
                          >
                            {RESOLUTION_STATUS_OPTIONS.map((status) => (
                              <option key={status} value={status}>
                                {status.replaceAll("_", " ")}
                              </option>
                            ))}
                          </select>
                        </div>

                        <div className="flex flex-col gap-2">
                          <button
                            type="button"
                            onClick={() => saveWorkflow(row)}
                            disabled={Boolean(workflowSavingByRating[ratingId])}
                            className="rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm font-semibold text-slate-700 hover:bg-slate-50 disabled:opacity-60"
                          >
                            {workflowSavingByRating[ratingId] ? "Saving…" : "Save workflow"}
                          </button>

                          <button
                            type="button"
                            onClick={() => submitResponse(row)}
                            disabled={Boolean(savingByRating[ratingId])}
                            className="inline-flex items-center justify-center gap-2 rounded-xl bg-emerald-600 px-3 py-2 text-sm font-semibold text-white hover:bg-emerald-700 disabled:opacity-60"
                          >
                            <Send className="h-4 w-4" />
                            {savingByRating[ratingId] ? "Sending…" : "Post public response"}
                          </button>
                        </div>
                      </div>
                    </div>
                  ) : null}
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </FarmerLayout>
  );
}
