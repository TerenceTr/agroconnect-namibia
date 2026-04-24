// ============================================================================
// frontend/src/components/customer/RatingsPanel.jsx
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Customer-facing reviews panel with verified reviews, public farmer responses,
//   and Phase 3 review flagging controls.
// ============================================================================

import React, { useMemo, useState } from "react";
import { AlertTriangle, Flag, MessageSquare, Shield, Star } from "lucide-react";
import api from "../../api";

const FLAG_REASONS = [
  { value: "abusive_language", label: "Abusive language" },
  { value: "spam", label: "Spam" },
  { value: "fake_review", label: "Fake review" },
  { value: "harassment", label: "Harassment" },
  { value: "privacy_violation", label: "Privacy violation" },
  { value: "other", label: "Other" },
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

function Stars({ value = 0 }) {
  const score = Math.max(0, Math.min(5, Number(value) || 0));
  return (
    <div className="flex items-center gap-1 text-amber-500">
      {Array.from({ length: 5 }).map((_, idx) => (
        <Star key={idx} className={`h-4 w-4 ${idx < Math.round(score) ? "fill-current" : ""}`} />
      ))}
    </div>
  );
}

function ReviewCard({ review, onFlag }) {
  const responses = safeArray(review?.public_responses);
  const moderationStatus = safeStr(review?.moderation_status || "visible").toLowerCase();

  return (
    <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-3">
            <Stars value={review?.rating_score ?? review?.score ?? review?.rating ?? 0} />
            {review?.verified_purchase ? (
              <span className="inline-flex items-center gap-1 rounded-full bg-emerald-50 px-2.5 py-1 text-xs font-semibold text-emerald-700">
                <Shield className="h-3.5 w-3.5" /> Verified purchase
              </span>
            ) : null}
            {moderationStatus !== "visible" ? (
              <span className="inline-flex rounded-full bg-amber-50 px-2.5 py-1 text-xs font-semibold text-amber-700">
                {moderationStatus.replace(/_/g, " ")}
              </span>
            ) : null}
          </div>
          <div className="mt-2 text-sm font-semibold text-slate-900">
            {review?.customer_name || review?.buyer_name || "Customer"}
          </div>
          <div className="text-xs text-slate-500">{fmtDate(review?.created_at)}</div>
        </div>

        <button
          type="button"
          onClick={() => onFlag?.(review)}
          className="inline-flex items-center gap-2 rounded-xl border border-slate-200 px-3 py-2 text-xs font-semibold text-slate-700 hover:bg-slate-50"
        >
          <Flag className="h-4 w-4" /> Flag review
        </button>
      </div>

      {review?.comments || review?.comment ? (
        <p className="mt-3 whitespace-pre-wrap text-sm leading-6 text-slate-700">
          {review?.comments || review?.comment}
        </p>
      ) : (
        <p className="mt-3 text-sm italic text-slate-400">No written comment.</p>
      )}

      {responses.length > 0 ? (
        <div className="mt-4 rounded-2xl border border-emerald-100 bg-emerald-50/70 p-3">
          <div className="mb-2 flex items-center gap-2 text-sm font-semibold text-emerald-900">
            <MessageSquare className="h-4 w-4" /> Farmer response{responses.length > 1 ? "s" : ""}
          </div>
          <div className="space-y-3">
            {responses.map((response) => (
              <div key={response?.response_id || response?.id} className="rounded-xl bg-white/80 p-3">
                <div className="flex items-center justify-between gap-2">
                  <div className="text-sm font-semibold text-slate-900">
                    {response?.responder_name || "Farmer"}
                  </div>
                  <div className="text-xs text-slate-500">{fmtDate(response?.created_at)}</div>
                </div>
                <p className="mt-2 whitespace-pre-wrap text-sm leading-6 text-slate-700">
                  {response?.response_text}
                </p>
              </div>
            ))}
          </div>
        </div>
      ) : null}
    </div>
  );
}

export default function RatingsPanel({ ratings = [], onFlagSubmitted = null }) {
  const [flagModalOpen, setFlagModalOpen] = useState(false);
  const [selectedReview, setSelectedReview] = useState(null);
  const [flagReason, setFlagReason] = useState("abusive_language");
  const [flagNotes, setFlagNotes] = useState("");
  const [savingFlag, setSavingFlag] = useState(false);
  const [flagError, setFlagError] = useState("");
  const [successMessage, setSuccessMessage] = useState("");

  const visibleRatings = useMemo(
    () => safeArray(ratings).filter((item) => {
      const status = safeStr(item?.moderation_status || "visible").toLowerCase();
      return ["visible", "published", "approved", "flagged", "under_review"].includes(status);
    }),
    [ratings]
  );

  const openFlagModal = (review) => {
    setSelectedReview(review || null);
    setFlagReason("abusive_language");
    setFlagNotes("");
    setFlagError("");
    setSuccessMessage("");
    setFlagModalOpen(true);
  };

  const closeFlagModal = () => {
    if (savingFlag) return;
    setFlagModalOpen(false);
    setSelectedReview(null);
  };

  const submitFlag = async () => {
    const ratingId = selectedReview?.rating_id || selectedReview?.id;
    if (!ratingId) {
      setFlagError("Review identifier is missing.");
      return;
    }
    setSavingFlag(true);
    setFlagError("");
    try {
      await api.post(`/ratings/${ratingId}/flag`, {
        reason_code: flagReason,
        notes: flagNotes,
      });
      setSuccessMessage("Review flagged for admin moderation.");
      setFlagModalOpen(false);
      setSelectedReview(null);
      if (typeof onFlagSubmitted === "function") {
        onFlagSubmitted();
      }
    } catch (error) {
      const message =
        error?.response?.data?.message || error?.message || "Could not flag review.";
      setFlagError(message);
    } finally {
      setSavingFlag(false);
    }
  };

  return (
    <div className="space-y-4">
      {successMessage ? (
        <div className="rounded-2xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm font-medium text-emerald-800">
          {successMessage}
        </div>
      ) : null}

      {visibleRatings.length === 0 ? (
        <div className="rounded-2xl border border-dashed border-slate-300 bg-white px-5 py-10 text-center text-sm text-slate-500">
          No reviews yet.
        </div>
      ) : (
        <div className="space-y-4">
          {visibleRatings.map((review) => (
            <ReviewCard
              key={review?.rating_id || review?.id}
              review={review}
              onFlag={openFlagModal}
            />
          ))}
        </div>
      )}

      {flagModalOpen ? (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/50 p-4">
          <div className="w-full max-w-lg rounded-3xl bg-white p-6 shadow-2xl">
            <div className="flex items-start gap-3">
              <div className="rounded-2xl bg-amber-50 p-3 text-amber-700">
                <AlertTriangle className="h-5 w-5" />
              </div>
              <div>
                <h3 className="text-lg font-bold text-slate-900">Flag review for moderation</h3>
                <p className="mt-1 text-sm text-slate-500">
                  This sends the review to the admin moderation queue for policy review.
                </p>
              </div>
            </div>

            <div className="mt-5 space-y-4">
              <label className="block">
                <span className="mb-2 block text-sm font-semibold text-slate-700">Reason</span>
                <select
                  value={flagReason}
                  onChange={(e) => setFlagReason(e.target.value)}
                  className="w-full rounded-2xl border border-slate-300 px-4 py-3 text-sm outline-none focus:border-emerald-500"
                >
                  {FLAG_REASONS.map((option) => (
                    <option key={option.value} value={option.value}>
                      {option.label}
                    </option>
                  ))}
                </select>
              </label>

              <label className="block">
                <span className="mb-2 block text-sm font-semibold text-slate-700">Notes</span>
                <textarea
                  value={flagNotes}
                  onChange={(e) => setFlagNotes(e.target.value)}
                  rows={4}
                  placeholder="Explain why this review should be checked."
                  className="w-full rounded-2xl border border-slate-300 px-4 py-3 text-sm outline-none focus:border-emerald-500"
                />
              </label>

              {flagError ? (
                <div className="rounded-2xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
                  {flagError}
                </div>
              ) : null}
            </div>

            <div className="mt-6 flex items-center justify-end gap-3">
              <button
                type="button"
                onClick={closeFlagModal}
                className="rounded-2xl border border-slate-300 px-4 py-2.5 text-sm font-semibold text-slate-700 hover:bg-slate-50"
              >
                Cancel
              </button>
              <button
                type="button"
                disabled={savingFlag}
                onClick={submitFlag}
                className="rounded-2xl bg-emerald-600 px-4 py-2.5 text-sm font-semibold text-white hover:bg-emerald-700 disabled:cursor-not-allowed disabled:opacity-60"
              >
                {savingFlag ? "Submitting…" : "Submit flag"}
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}
