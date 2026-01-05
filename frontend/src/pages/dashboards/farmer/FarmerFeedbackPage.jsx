// ============================================================================
// src/pages/dashboards/farmer/FarmerFeedbackPage.jsx — Farmer Feedback
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Full feedback analytics page for farmer products.
//   • Summary: avg rating, feedback count
//   • Distribution: 1–5 bars
//   • Trend: Weekly | Monthly (Annual disabled unless you add history)
//   • Comments list with filters
//
// UX RULES:
//   • No dev text. If endpoint missing: "Feedback is not available right now."
//   • Card-local retry.
// ============================================================================

import React, { useMemo, useState } from "react";
import { RefreshCcw } from "lucide-react";

import FarmerLayout from "../../../components/FarmerLayout";
import { useAuth } from "../../../components/auth/AuthProvider";
import useApi from "../../../hooks/useApi";
import SimpleBarChart from "../../../components/ui/SimpleBarChart";

function safeArray(v) {
  return Array.isArray(v) ? v : [];
}
function safeStr(v, fallback = "") {
  if (typeof v === "string") return v;
  if (v == null) return fallback;
  return String(v);
}
function safeNumber(v, fallback = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}
function toDateKey(d) {
  try {
    const dt = new Date(d);
    if (Number.isNaN(dt.getTime())) return null;
    return dt.toISOString().slice(0, 10);
  } catch {
    return null;
  }
}

export default function FarmerFeedbackPage() {
  const { user } = useAuth();
  const farmerId = user?.id;

  const [mode, setMode] = useState("weekly"); // weekly | monthly | annual (disabled)
  const [days, setDays] = useState(90);
  const [onlyComments, setOnlyComments] = useState(true);
  const [ratingFilter, setRatingFilter] = useState(0); // 0 = all, else 1-5

  const endpoints = useMemo(() => {
    return [
      farmerId ? `/ratings/farmer/${farmerId}` : null,
      "/ratings/farmer",
      "/farmer/ratings",
      "/ratings",
    ].filter(Boolean);
  }, [farmerId]);

  const res = useApi(endpoints, {
    enabled: Boolean(farmerId),
    params: { days, farmerId },
    initialData: undefined,
    deps: [farmerId, days],
  });

  const ratings = useMemo(() => {
    const raw = res.data;
    return Array.isArray(raw) ? raw : safeArray(raw?.ratings ?? raw?.items);
  }, [res.data]);

  const summary = useMemo(() => {
    const nums = ratings.map((r) => safeNumber(r?.rating ?? r?.score)).filter((n) => n > 0);
    const avg = nums.length ? nums.reduce((a, b) => a + b, 0) / nums.length : 0;

    const dist = { 1: 0, 2: 0, 3: 0, 4: 0, 5: 0 };
    for (const r of ratings) {
      const n = Math.round(safeNumber(r?.rating ?? r?.score));
      if (n >= 1 && n <= 5) dist[n] += 1;
    }

    return { avg, count: ratings.length, dist };
  }, [ratings]);

  const trend = useMemo(() => {
    const map = new Map();

    for (const r of ratings) {
      const d = toDateKey(r?.created_at ?? r?.date ?? r?.createdAt);
      if (!d) continue;

      let key = d;
      if (mode === "monthly") key = d.slice(0, 7);
      if (mode === "annual") key = d.slice(0, 4);

      const prev = map.get(key) || { sum: 0, count: 0 };
      const val = safeNumber(r?.rating ?? r?.score);
      map.set(key, { sum: prev.sum + val, count: prev.count + 1 });
    }

    return Array.from(map.entries())
      .sort((a, b) => a[0].localeCompare(b[0]))
      .map(([k, v]) => ({ label: k, value: v.count ? v.sum / v.count : 0 }));
  }, [ratings, mode]);

  const filteredComments = useMemo(() => {
    return ratings
      .filter((r) => {
        const rating = Math.round(safeNumber(r?.rating ?? r?.score));
        const comment = safeStr(r?.comment ?? r?.message ?? "");
        if (ratingFilter && rating !== ratingFilter) return false;
        if (onlyComments && !comment.trim()) return false;
        return true;
      })
      .sort((a, b) => {
        const da = new Date(a?.created_at ?? a?.date ?? 0).getTime();
        const db = new Date(b?.created_at ?? b?.date ?? 0).getTime();
        return db - da;
      })
      .slice(0, 20);
  }, [ratings, ratingFilter, onlyComments]);

  const distBars = useMemo(() => {
    const total = summary.count || 1;
    return [5, 4, 3, 2, 1].map((n) => ({
      n,
      count: summary.dist[n] || 0,
      pct: Math.round(((summary.dist[n] || 0) / total) * 100),
    }));
  }, [summary]);

  return (
    <FarmerLayout>
      <div className="space-y-6">
        {/* Header */}
        <div className="rounded-2xl bg-white border border-slate-200 shadow-sm p-6">
          <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3">
            <div>
              <div className="text-xs text-slate-500">Farmer</div>
              <h1 className="text-2xl font-extrabold text-slate-900">Feedback</h1>
              <p className="text-sm text-slate-600 mt-1">
                Track product quality and respond to customer comments.
              </p>
            </div>

            <div className="flex items-center gap-2">
              <select
                value={days}
                onChange={(e) => setDays(Number(e.target.value))}
                className="h-10 px-3 rounded-xl border border-slate-200 bg-white text-sm font-semibold text-slate-800"
              >
                <option value={30}>Last 30 days</option>
                <option value={90}>Last 90 days</option>
                <option value={180}>Last 180 days</option>
              </select>

              <button
                type="button"
                onClick={res.refetch}
                className="h-10 px-4 rounded-xl border border-slate-200 bg-white hover:bg-slate-50 text-sm font-semibold text-slate-800 inline-flex items-center gap-2"
              >
                <RefreshCcw className="h-4 w-4" />
                Refresh
              </button>
            </div>
          </div>
        </div>

        {/* Error state */}
        {res.error ? (
          <div className="rounded-2xl bg-white border border-slate-200 shadow-sm p-6">
            <div className="rounded-xl border border-rose-200 bg-rose-50 p-4 text-sm text-rose-700 flex items-center justify-between gap-3">
              <div>Feedback is not available right now.</div>
              <button
                type="button"
                onClick={res.refetch}
                className="h-9 px-3 rounded-xl bg-white border border-rose-200 text-rose-700 font-semibold"
              >
                Retry
              </button>
            </div>
          </div>
        ) : null}

        {/* Summary + Distribution */}
        <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
          <div className="rounded-2xl bg-white border border-slate-200 shadow-sm p-4">
            <div className="text-sm font-extrabold text-slate-900">Summary</div>
            <div className="mt-3 grid grid-cols-2 gap-3">
              <div className="rounded-xl border border-slate-200 p-3">
                <div className="text-xs text-slate-500 font-semibold">Avg Rating</div>
                <div className="text-2xl font-extrabold text-slate-900">
                  {res.loading ? "…" : summary.avg.toFixed(1)}
                </div>
              </div>
              <div className="rounded-xl border border-slate-200 p-3">
                <div className="text-xs text-slate-500 font-semibold">Feedback Count</div>
                <div className="text-2xl font-extrabold text-slate-900">
                  {res.loading ? "…" : summary.count}
                </div>
              </div>
            </div>
          </div>

          <div className="xl:col-span-2 rounded-2xl bg-white border border-slate-200 shadow-sm p-4">
            <div className="text-sm font-extrabold text-slate-900">Rating Distribution</div>
            <div className="mt-3 space-y-2">
              {distBars.map((b) => (
                <div key={b.n} className="flex items-center gap-3">
                  <div className="w-10 text-sm font-bold text-slate-800">{b.n}★</div>
                  <div className="flex-1 h-3 rounded-full bg-slate-100 border border-slate-200 overflow-hidden">
                    <div className="h-full bg-emerald-500/40" style={{ width: `${b.pct}%` }} />
                  </div>
                  <div className="w-20 text-right text-sm font-semibold text-slate-700">
                    {b.count} ({b.pct}%)
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Trend */}
        <div className="rounded-2xl bg-white border border-slate-200 shadow-sm p-4">
          <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3 mb-3">
            <div>
              <div className="text-sm font-extrabold text-slate-900">Rating Trend</div>
              <div className="text-xs text-slate-500">Weekly or Monthly view</div>
            </div>

            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => setMode("weekly")}
                className={[
                  "h-9 px-3 rounded-xl border text-sm font-semibold",
                  mode === "weekly"
                    ? "border-emerald-200 bg-emerald-50 text-emerald-800"
                    : "border-slate-200 bg-white text-slate-800 hover:bg-slate-50",
                ].join(" ")}
              >
                Weekly
              </button>
              <button
                type="button"
                onClick={() => setMode("monthly")}
                className={[
                  "h-9 px-3 rounded-xl border text-sm font-semibold",
                  mode === "monthly"
                    ? "border-emerald-200 bg-emerald-50 text-emerald-800"
                    : "border-slate-200 bg-white text-slate-800 hover:bg-slate-50",
                ].join(" ")}
              >
                Monthly
              </button>
              <button
                type="button"
                disabled
                title="Needs more history"
                className="h-9 px-3 rounded-xl border border-slate-200 bg-slate-50 text-slate-400 text-sm font-semibold cursor-not-allowed"
              >
                Annual
              </button>
            </div>
          </div>

          {res.loading ? (
            <div className="text-sm text-slate-600">Loading trend…</div>
          ) : trend.length === 0 ? (
            <div className="text-sm text-slate-500">No trend data available.</div>
          ) : (
            <SimpleBarChart
              labels={trend.map((r) => r.label)}
              values={trend.map((r) => Number(r.value.toFixed(2)))}
              height={260}
              valuePrefix=""
            />
          )}
        </div>

        {/* Comments */}
        <div className="rounded-2xl bg-white border border-slate-200 shadow-sm p-4">
          <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3 mb-3">
            <div>
              <div className="text-sm font-extrabold text-slate-900">Comments</div>
              <div className="text-xs text-slate-500">Filter and address customer concerns</div>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <select
                value={ratingFilter}
                onChange={(e) => setRatingFilter(Number(e.target.value))}
                className="h-9 px-3 rounded-xl border border-slate-200 bg-white text-sm font-semibold text-slate-800"
              >
                <option value={0}>All ratings</option>
                <option value={5}>5★</option>
                <option value={4}>4★</option>
                <option value={3}>3★</option>
                <option value={2}>2★</option>
                <option value={1}>1★</option>
              </select>

              <label className="h-9 px-3 rounded-xl border border-slate-200 bg-white text-sm font-semibold text-slate-800 inline-flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={onlyComments}
                  onChange={(e) => setOnlyComments(e.target.checked)}
                />
                Has comment only
              </label>
            </div>
          </div>

          {res.loading ? (
            <div className="text-sm text-slate-600">Loading feedback…</div>
          ) : filteredComments.length === 0 ? (
            <div className="text-sm text-slate-500">No comments match your filters.</div>
          ) : (
            <ul className="space-y-2">
              {filteredComments.map((r, idx) => {
                const who = safeStr(r?.customer_name ?? r?.customer ?? "Customer");
                const prod = safeStr(r?.product_name ?? r?.product ?? "Product");
                const rating = Math.round(safeNumber(r?.rating ?? r?.score));
                const comment = safeStr(r?.comment ?? r?.message ?? "");
                const date = safeStr(r?.created_at ?? r?.date ?? "").slice(0, 10);
                return (
                  <li key={`${who}-${idx}`} className="rounded-xl border border-slate-200 p-4">
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0">
                        <div className="text-sm font-extrabold text-slate-900 truncate">
                          {prod} • {who}
                        </div>
                        <div className="text-xs text-slate-500">{date}</div>
                      </div>
                      <div className="text-sm font-extrabold text-slate-900">{rating}★</div>
                    </div>
                    <div className="mt-2 text-sm text-slate-700 whitespace-pre-wrap">
                      {comment || "—"}
                    </div>

                    <div className="mt-3 text-xs text-slate-500">
                      Optional: add “Mark addressed” if you store an addressed flag.
                    </div>
                  </li>
                );
              })}
            </ul>
          )}
        </div>
      </div>
    </FarmerLayout>
  );
}
