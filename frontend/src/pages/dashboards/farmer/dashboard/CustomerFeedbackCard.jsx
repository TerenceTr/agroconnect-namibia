// ============================================================================
// frontend/src/pages/dashboards/farmer/dashboard/CustomerFeedbackCard.jsx
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Ratings & comments panel for FarmerDashboard.
//
// RESPONSIBILITIES:
//   • Show average rating + distribution + recent comments
//   • Explain missing endpoint (GET /ratings) if necessary
// ============================================================================

import React from "react";
import { MessageSquare, Star } from "lucide-react";
import { format } from "date-fns";

// IMPORTANT: this file is inside .../farmer/dashboard/, so go up 4 levels to /src
import Card, { CardHeader, CardTitle, CardContent } from "../../../../components/ui/Card";
import EmptyState from "../../../../components/ui/EmptyState";

import { pickDate, toNumber } from "./utils";

function Stars({ value }) {
  const v = Math.max(0, Math.min(5, Number(value) || 0));
  const full = Math.round(v);
  return (
    <div className="flex items-center gap-1">
      {Array.from({ length: 5 }).map((_, i) => (
        <Star
          key={i}
          size={14}
          className={i < full ? "text-emerald-600 fill-emerald-600" : "text-slate-300"}
        />
      ))}
    </div>
  );
}

function MiniBar({ label, value, max }) {
  const pct = max > 0 ? Math.round((value / max) * 100) : 0;
  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between text-xs text-slate-600">
        <span>{label}</span>
        <span className="font-semibold text-slate-800">{value}</span>
      </div>
      <div className="h-2 rounded-full bg-slate-100 overflow-hidden border border-slate-200">
        <div className="h-full bg-emerald-600" style={{ width: `${Math.max(0, Math.min(100, pct))}%` }} />
      </div>
    </div>
  );
}

export default function CustomerFeedbackCard({
  loading,
  error,
  ratings,
  avgRating,
  ratingDistribution,
  recentFeedback,
}) {
  return (
    <Card variant="surface">
      <CardHeader>
        <div className="flex items-center justify-between gap-3">
          <div>
            <CardTitle>Customer Feedback</CardTitle>
            <p className="text-xs text-slate-500 mt-1">Ratings & comments for your products</p>
          </div>
          <div className="flex items-center gap-2 text-emerald-700">
            <MessageSquare size={18} />
          </div>
        </div>
      </CardHeader>

      <CardContent>
        {loading ? (
          <p className="text-sm text-slate-500">Loading…</p>
        ) : error ? (
          <div className="text-sm text-slate-700">
            Couldn’t load ratings. If your backend doesn’t have a{" "}
            <code className="px-1 py-0.5 border rounded bg-slate-50">GET /ratings</code>{" "}
            endpoint yet, you’ll need to add it.
            <div className="text-xs text-slate-500 mt-2">
              Database change is usually <b>not</b> needed if you already have a <b>ratings</b> table.
            </div>
          </div>
        ) : ratings.length === 0 ? (
          <EmptyState message="No ratings yet. Reviews will appear here once customers rate products." />
        ) : (
          <div className="space-y-4">
            {/* Summary */}
            <div className="flex items-center justify-between gap-3 p-3 rounded-2xl bg-slate-50 border border-slate-200">
              <div>
                <div className="text-sm font-semibold text-slate-900">
                  Average rating: {avgRating.toFixed(1)} / 5
                </div>
                <div className="mt-1">
                  <Stars value={avgRating} />
                </div>
                <div className="text-xs text-slate-500 mt-1">{ratings.length} total review(s)</div>
              </div>
              <div className="h-10 w-10 rounded-2xl bg-emerald-600 text-white flex items-center justify-center shadow-sm">
                <Star size={18} />
              </div>
            </div>

            {/* Distribution */}
            <div className="space-y-2">
              {(() => {
                const max = Math.max(
                  ratingDistribution[5],
                  ratingDistribution[4],
                  ratingDistribution[3],
                  ratingDistribution[2],
                  ratingDistribution[1]
                );
                return (
                  <>
                    <MiniBar label="5 stars" value={ratingDistribution[5]} max={max} />
                    <MiniBar label="4 stars" value={ratingDistribution[4]} max={max} />
                    <MiniBar label="3 stars" value={ratingDistribution[3]} max={max} />
                    <MiniBar label="2 stars" value={ratingDistribution[2]} max={max} />
                    <MiniBar label="1 star" value={ratingDistribution[1]} max={max} />
                  </>
                );
              })()}
            </div>

            {/* Recent comments */}
            <div className="space-y-2">
              <div className="text-xs font-semibold text-slate-600">Recent comments</div>

              <div className="space-y-2">
                {recentFeedback.map((r, idx) => {
                  const rid = r?.id || r?.rating_id || idx;
                  const score = toNumber(r?.rating_score ?? r?.rating ?? 0, 0);
                  const comment = String(r?.comment || "").trim();
                  const when = pickDate(r);

                  return (
                    <div key={rid} className="p-3 rounded-2xl bg-white border border-slate-200 shadow-sm">
                      <div className="flex items-center justify-between gap-3">
                        <Stars value={score} />
                        <div className="text-xs text-slate-500">{when ? format(when, "dd MMM") : ""}</div>
                      </div>

                      <div className="text-sm text-slate-800 mt-2">
                        {comment ? <span className="line-clamp-3">{comment}</span> : <span className="text-slate-400">No written comment.</span>}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
