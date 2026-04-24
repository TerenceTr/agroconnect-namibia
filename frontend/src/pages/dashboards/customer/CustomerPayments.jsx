// ============================================================================
// frontend/src/pages/dashboards/customer/CustomerPayments.jsx
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Customer payments workspace.
//   • Payment summary
//   • Payment methods used
//   • Payment history
//   • Proof-of-payment archive
//   • Refund feature placeholder (coming soon)
//
// NOTE:
//   The refund experience is currently surfaced as a customer-facing preview only.
//   No live refund workflow is triggered from this page yet.
//
// THIS UPDATE:
//   ✅ Keeps all existing payment data intact
//   ✅ Keeps paginated payment ledger
//   ✅ Adds search to the payment ledger
//   ✅ Adds a clear "Refunds coming soon" customer-facing section
//   ✅ Uses simpler language for customer understanding
// ============================================================================

import React, { useCallback, useEffect, useMemo, useState } from "react";
import {
  RefreshCcw,
  CreditCard,
  Receipt,
  FileSearch,
  ChevronLeft,
  ChevronRight,
  Search,
  Wallet,
  Clock3,
  BadgeAlert,
  LifeBuoy,
  RotateCcw,
  Landmark,
} from "lucide-react";
import { fetchCustomerPayments } from "../../../services/customerApi";

const LEDGER_PAGE_SIZE = 6;

function safeArray(value) {
  return Array.isArray(value) ? value : [];
}

function safeStr(value, fallback = "") {
  const s = String(value ?? "").trim();
  return s || fallback;
}

function safeNumber(value, fallback = 0) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function money(value) {
  return `N$ ${safeNumber(value, 0).toFixed(2)}`;
}

function when(value) {
  const raw = safeStr(value, "");
  if (!raw) return "—";
  const dt = new Date(raw);
  if (Number.isNaN(dt.getTime())) return raw;
  return dt.toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

function relativeWhen(value) {
  const raw = safeStr(value, "");
  if (!raw) return "—";

  const dt = new Date(raw);
  if (Number.isNaN(dt.getTime())) return when(value);

  const diffMs = Date.now() - dt.getTime();
  const diffMin = Math.floor(diffMs / 60000);

  if (diffMin < 1) return "just now";
  if (diffMin < 60) return `${diffMin}m ago`;

  const diffHr = Math.floor(diffMin / 60);
  if (diffHr < 24) return `${diffHr}h ago`;

  const diffDay = Math.floor(diffHr / 24);
  if (diffDay < 7) return `${diffDay}d ago`;

  return when(value);
}

function titleize(value) {
  return safeStr(value, "—")
    .replace(/_/g, " ")
    .replace(/\b([a-z])/gi, (m) => m.toUpperCase());
}

function statusTone(status) {
  const s = safeStr(status, "").toLowerCase();

  if (["paid", "completed", "confirmed"].includes(s)) {
    return "border-emerald-200 bg-emerald-50 text-emerald-800";
  }
  if (["pending", "review"].includes(s)) {
    return "border-amber-200 bg-amber-50 text-amber-800";
  }
  if (["failed", "unpaid", "cancelled"].includes(s)) {
    return "border-rose-200 bg-rose-50 text-rose-800";
  }

  return "border-slate-200 bg-slate-50 text-slate-700";
}

function SectionCard({ title, subtitle, icon: Icon, children, actions = null }) {
  return (
    <section className="overflow-hidden rounded-[24px] border border-[#D8F3DC] bg-white shadow-sm">
      <div className="flex items-start justify-between gap-4 border-b border-[#EEF7F0] px-5 py-4">
        <div className="min-w-0">
          <div className="flex items-center gap-2 text-slate-900">
            {Icon ? <Icon className="h-4 w-4 text-[#2D6A4F]" /> : null}
            <h2 className="text-sm font-extrabold uppercase tracking-wide">{title}</h2>
          </div>
          {subtitle ? <p className="mt-1 text-xs text-slate-500">{subtitle}</p> : null}
        </div>
        {actions}
      </div>
      <div className="p-5">{children}</div>
    </section>
  );
}

function StatCard({ icon: Icon, label, value, subtext }) {
  return (
    <div className="rounded-2xl border border-[#D8F3DC] bg-white p-4 shadow-sm">
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="text-xs font-bold uppercase tracking-wide text-slate-500">{label}</div>
          <div className="mt-1 text-2xl font-black tracking-tight text-slate-900">{value}</div>
          {subtext ? <div className="mt-1 text-xs text-slate-500">{subtext}</div> : null}
        </div>

        <div className="grid h-11 w-11 place-items-center rounded-2xl border border-[#D8F3DC] bg-[#F4FBF7]">
          <Icon className="h-5 w-5 text-[#2D6A4F]" />
        </div>
      </div>
    </div>
  );
}

function MethodsBars({ rows }) {
  const max = rows.reduce((m, row) => Math.max(m, safeNumber(row?.amount, 0)), 0);

  if (!rows.length) {
    return <div className="text-sm text-slate-500">No payment methods have been recorded yet.</div>;
  }

  return (
    <div className="space-y-3">
      {rows.map((row, index) => {
        const amount = safeNumber(row?.amount, 0);
        const pctWidth = max > 0 ? Math.max(8, (amount / max) * 100) : 8;

        return (
          <div key={`${row?.payment_method}-${index}`} className="space-y-1.5">
            <div className="flex items-center justify-between gap-3 text-sm">
              <div className="font-semibold text-slate-700">{titleize(row?.payment_method)}</div>
              <div className="text-right font-black text-slate-900">{money(amount)}</div>
            </div>

            <div className="flex items-center justify-between gap-3 text-xs text-slate-500">
              <div>{safeNumber(row?.orders_count, 0)} orders</div>
            </div>

            <div className="h-2.5 overflow-hidden rounded-full bg-slate-100">
              <div
                className="h-full rounded-full bg-gradient-to-r from-[#2D6A4F] to-[#74C69D]"
                style={{ width: `${pctWidth}%` }}
              />
            </div>
          </div>
        );
      })}
    </div>
  );
}

function Pager({ currentPage, totalPages, onPageChange }) {
  if (totalPages <= 1) return null;

  return (
    <div className="flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-[#E7F5EA] bg-[#F7FBF8] px-3 py-3">
      <div className="text-xs font-medium text-slate-500">
        Page <span className="font-bold text-slate-800">{currentPage}</span> of{" "}
        <span className="font-bold text-slate-800">{totalPages}</span>
      </div>

      <div className="flex items-center gap-2">
        <button
          type="button"
          onClick={() => onPageChange(currentPage - 1)}
          disabled={currentPage <= 1}
          className="inline-flex items-center gap-1 rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm font-semibold text-slate-700 hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-50"
        >
          <ChevronLeft className="h-4 w-4" />
          Previous
        </button>

        <button
          type="button"
          onClick={() => onPageChange(currentPage + 1)}
          disabled={currentPage >= totalPages}
          className="inline-flex items-center gap-1 rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm font-semibold text-slate-700 hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-50"
        >
          Next
          <ChevronRight className="h-4 w-4" />
        </button>
      </div>
    </div>
  );
}

function RefundPreviewCard({ icon: Icon, title, text }) {
  return (
    <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
      <div className="flex items-start gap-3">
        <div className="grid h-10 w-10 shrink-0 place-items-center rounded-2xl border border-[#D8F3DC] bg-white">
          <Icon className="h-4 w-4 text-[#2D6A4F]" />
        </div>

        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <div className="text-sm font-extrabold text-slate-900">{title}</div>
            <span className="rounded-full border border-amber-200 bg-amber-50 px-2.5 py-1 text-[11px] font-bold text-amber-800">
              Coming soon
            </span>
          </div>
          <p className="mt-1 text-sm leading-6 text-slate-600">{text}</p>
        </div>
      </div>
    </div>
  );
}

export default function CustomerPayments() {
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");
  const [payload, setPayload] = useState(null);
  const [ledgerPage, setLedgerPage] = useState(1);
  const [ledgerSearch, setLedgerSearch] = useState("");

  const loadWorkspace = useCallback(async ({ silent = false } = {}) => {
    try {
      if (silent) setRefreshing(true);
      else setLoading(true);

      setError("");
      const data = await fetchCustomerPayments();
      setPayload(data || null);
    } catch (err) {
      setError(
        err?.response?.data?.message ||
          err?.message ||
          "Could not load payments workspace right now."
      );
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    loadWorkspace();
  }, [loadWorkspace]);

  const summary = payload?.summary || {};
  const methods = safeArray(payload?.payment_methods_used);
  const paymentHistory = safeArray(payload?.payment_history);
  const proofArchive = safeArray(payload?.proof_archive);
  const notes = safeArray(payload?.notes);

  const methodsWithShare = useMemo(() => {
    const totalObserved = methods.reduce((sum, row) => sum + safeNumber(row?.amount, 0), 0);

    return methods.map((row) => ({
      ...row,
      share_pct: totalObserved > 0 ? (safeNumber(row?.amount, 0) / totalObserved) * 100 : 0,
    }));
  }, [methods]);

  const filteredPaymentHistory = useMemo(() => {
    const query = safeStr(ledgerSearch, "").toLowerCase();
    if (!query) return paymentHistory;

    return paymentHistory.filter((row) => {
      const haystack = [
        safeStr(row?.order_id),
        safeStr(row?.payment_reference),
        safeStr(row?.payment_method),
        safeStr(row?.payment_status),
        safeStr(row?.order_status),
        safeStr(row?.delivery_status),
      ]
        .join(" ")
        .toLowerCase();

      return haystack.includes(query);
    });
  }, [paymentHistory, ledgerSearch]);

  const ledgerTotalPages = Math.max(1, Math.ceil(filteredPaymentHistory.length / LEDGER_PAGE_SIZE));
  const safeLedgerPage = Math.min(ledgerPage, ledgerTotalPages);

  const pagedLedger = useMemo(() => {
    const start = (safeLedgerPage - 1) * LEDGER_PAGE_SIZE;
    return filteredPaymentHistory.slice(start, start + LEDGER_PAGE_SIZE);
  }, [filteredPaymentHistory, safeLedgerPage]);

  const ledgerRange = useMemo(() => {
    if (!filteredPaymentHistory.length) return { start: 0, end: 0 };

    const start = (safeLedgerPage - 1) * LEDGER_PAGE_SIZE + 1;
    const end = Math.min(start + LEDGER_PAGE_SIZE - 1, filteredPaymentHistory.length);

    return { start, end };
  }, [filteredPaymentHistory.length, safeLedgerPage]);

  useEffect(() => {
    setLedgerPage(1);
  }, [paymentHistory.length, ledgerSearch]);

  useEffect(() => {
    if (ledgerPage > ledgerTotalPages) {
      setLedgerPage(ledgerTotalPages);
    }
  }, [ledgerPage, ledgerTotalPages]);

  const handleLedgerPageChange = (nextPage) => {
    const page = Math.min(Math.max(nextPage, 1), ledgerTotalPages);
    setLedgerPage(page);

    if (typeof window !== "undefined") {
      window.requestAnimationFrame(() => {
        const el = document.getElementById("customer-payment-ledger");
        el?.scrollIntoView({ behavior: "smooth", block: "start" });
      });
    }
  };

  if (loading) {
    return (
      <div className="space-y-4">
        <div className="rounded-[28px] border border-[#D8F3DC] bg-white/90 p-6 shadow-sm">
          <div className="text-xs font-bold uppercase tracking-[0.18em] text-[#2D6A4F]">Payments</div>
          <div className="mt-2 text-2xl font-black tracking-tight text-slate-900">
            Loading payment workspace…
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-5">
      <div className="rounded-[28px] border border-[#D8F3DC] bg-white/90 p-6 shadow-sm">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
          <div>
            <div className="text-xs font-bold uppercase tracking-[0.18em] text-[#2D6A4F]">
              Customer Payments
            </div>
            <h1 className="mt-2 text-[30px] font-black tracking-tight text-slate-900">
              Payments workspace
            </h1>
            <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">
              Review what has been paid, what is still waiting for confirmation,
              which payment methods you use most, and whether proof-of-payment files are visible.
            </p>
          </div>

          <button
            type="button"
            onClick={() => loadWorkspace({ silent: true })}
            className="inline-flex items-center gap-2 rounded-2xl border border-[#D8F3DC] bg-white px-4 py-2 text-sm font-semibold text-slate-800 shadow-sm hover:bg-[#F8FCF9]"
          >
            <RefreshCcw className={`h-4 w-4 ${refreshing ? "animate-spin" : ""}`} />
            {refreshing ? "Refreshing…" : "Refresh workspace"}
          </button>
        </div>

        {notes.length ? (
          <div className="mt-4 grid grid-cols-1 gap-3 lg:grid-cols-2">
            {notes.slice(0, 4).map((note, index) => (
              <div
                key={`${note}-${index}`}
                className="rounded-2xl border border-[#E7F5EA] bg-[#F7FBF8] px-4 py-3 text-sm text-slate-700"
              >
                {note}
              </div>
            ))}
          </div>
        ) : null}

        {error ? (
          <div className="mt-4 rounded-2xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-800">
            {error}
          </div>
        ) : null}
      </div>

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
        <StatCard
          icon={Wallet}
          label="Paid amount"
          value={money(summary.paid_amount)}
          subtext={`${safeNumber(summary.paid_orders, 0)} paid order(s)`}
        />
        <StatCard
          icon={Clock3}
          label="Pending payments"
          value={safeNumber(summary.pending_orders, 0)}
          subtext="Payments still awaiting confirmation"
        />
        <StatCard
          icon={BadgeAlert}
          label="Unpaid orders"
          value={safeNumber(summary.unpaid_orders, 0)}
          subtext="Orders without confirmed payment"
        />
        <StatCard
          icon={FileSearch}
          label="Proof archive"
          value={safeNumber(summary.proof_count, 0)}
          subtext="Proof-of-payment file(s) traceable"
        />
      </div>

      <div className="grid grid-cols-1 gap-5 xl:grid-cols-[0.95fr_1.05fr]">
        <SectionCard
          title="Payment methods used"
          subtitle="This shows how you usually complete checkout across your visible payment records."
          icon={CreditCard}
        >
          <div className="mb-4 rounded-2xl border border-[#E7F5EA] bg-[#F7FBF8] px-4 py-3 text-sm text-slate-700">
            The strongest payment method here reflects the payment pattern most visible in your recorded orders.
          </div>

          <MethodsBars rows={methodsWithShare} />
        </SectionCard>

        <SectionCard
          title="Proof-of-payment archive"
          subtitle="Files already attached to payment records for easy customer-side checking."
          icon={FileSearch}
        >
          {proofArchive.length ? (
            <div className="space-y-3">
              {proofArchive.map((row, index) => (
                <div
                  key={`${row.payment_id}-${index}`}
                  className="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <div className="text-sm font-extrabold text-slate-900">
                        Order #{row.order_id}
                      </div>
                      <div className="mt-1 text-xs text-slate-500">
                        {titleize(row.payment_method)} • {money(row.amount)}
                      </div>
                    </div>

                    <div
                      className={`rounded-full border px-2.5 py-1 text-[11px] font-bold ${statusTone(
                        row.payment_status
                      )}`}
                    >
                      {titleize(row.payment_status)}
                    </div>
                  </div>

                  <div className="mt-3 flex flex-wrap gap-2 text-xs text-slate-600">
                    <span className="rounded-full border border-[#D8F3DC] bg-white px-2.5 py-1">
                      Uploaded {relativeWhen(row.proof_uploaded_at)}
                    </span>

                    {row.payment_reference ? (
                      <span className="rounded-full border border-[#D8F3DC] bg-white px-2.5 py-1">
                        Ref {row.payment_reference}
                      </span>
                    ) : null}

                    {row.proof_url ? (
                      <a
                        href={row.proof_url}
                        target="_blank"
                        rel="noreferrer"
                        className="rounded-full border border-[#B7E4C7] bg-[#F7FBF8] px-2.5 py-1 font-semibold text-[#2D6A4F] hover:bg-white"
                      >
                        Open proof
                      </a>
                    ) : null}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-sm text-slate-500">No proof-of-payment files are archived yet.</div>
          )}
        </SectionCard>
      </div>

      <SectionCard
        title="Refunds & payment support"
        subtitle="A customer-friendly preview of the refund area planned for a later phase."
        icon={RotateCcw}
      >
        <div className="mb-4 rounded-2xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm leading-6 text-amber-900">
          Refund requests are not yet live from this workspace. This section is shown now so you can see that
          refund visibility and support tracking are planned.
        </div>

        <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
          <RefundPreviewCard
            icon={RotateCcw}
            title="Refund request tracking"
            text="You will be able to follow refund progress from submission to final outcome in one place."
          />
          <RefundPreviewCard
            icon={LifeBuoy}
            title="Payment issue support"
            text="A guided support path will help customers report payment problems or order-related payment concerns."
          />
          <RefundPreviewCard
            icon={Landmark}
            title="Refund payout visibility"
            text="When refunds go live, this area can show refund method details, payout direction, and completion history."
          />
        </div>

        <div className="mt-4 grid grid-cols-1 gap-3 lg:grid-cols-2">
          <div className="rounded-2xl border border-[#E7F5EA] bg-[#F7FBF8] px-4 py-3 text-sm text-slate-700">
            For now, this payments workspace continues to focus on paid amounts, payment status, proof-of-payment, and
            payment history.
          </div>
          <div className="rounded-2xl border border-[#E7F5EA] bg-[#F7FBF8] px-4 py-3 text-sm text-slate-700">
            Once the refund workflow is released, customers will be able to see clearer follow-up actions and refund
            outcomes here.
          </div>
        </div>
      </SectionCard>

      <div id="customer-payment-ledger">
        <SectionCard
          title="Payment ledger"
          subtitle="Latest visible payment record per order for easier customer-side payment tracking."
          icon={Receipt}
          actions={
            filteredPaymentHistory.length ? (
              <div className="text-xs font-medium text-slate-500">
                Showing <span className="font-bold text-slate-800">{ledgerRange.start}</span>–
                <span className="font-bold text-slate-800">{ledgerRange.end}</span> of{" "}
                <span className="font-bold text-slate-800">{filteredPaymentHistory.length}</span>
              </div>
            ) : null
          }
        >
          {paymentHistory.length ? (
            <div className="space-y-4">
              <div className="relative">
                <Search className="pointer-events-none absolute left-4 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
                <input
                  type="text"
                  value={ledgerSearch}
                  onChange={(e) => setLedgerSearch(e.target.value)}
                  placeholder="Search order ID, reference, method, or status"
                  className="w-full rounded-2xl border border-[#D8F3DC] bg-white py-3 pl-11 pr-4 text-sm text-slate-800 outline-none placeholder:text-slate-400 focus:border-[#95D5B2] focus:ring-2 focus:ring-[#D8F3DC]"
                />
              </div>

              <Pager
                currentPage={safeLedgerPage}
                totalPages={ledgerTotalPages}
                onPageChange={handleLedgerPageChange}
              />

              {pagedLedger.length ? (
                <div className="space-y-3">
                  {pagedLedger.map((row, index) => (
                    <div
                      key={`${row.order_id}-${row.payment_id}-${index}`}
                      className="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3"
                    >
                      <div className="flex items-start justify-between gap-3">
                        <div>
                          <div className="text-sm font-extrabold text-slate-900">
                            Order #{row.order_id}
                          </div>
                          <div className="mt-1 text-xs text-slate-500">
                            Placed {when(row.order_date)} • {titleize(row.payment_method)}
                          </div>
                        </div>

                        <div className="text-right">
                          <div className="text-sm font-black text-slate-900">
                            {money(row.amount || row.order_total)}
                          </div>
                          <div
                            className={`mt-1 inline-flex rounded-full border px-2.5 py-1 text-[11px] font-bold ${statusTone(
                              row.payment_status
                            )}`}
                          >
                            {titleize(row.payment_status)}
                          </div>
                        </div>
                      </div>

                      <div className="mt-3 flex flex-wrap gap-2 text-xs text-slate-600">
                        <span className="rounded-full border border-[#D8F3DC] bg-white px-2.5 py-1">
                          Order status {titleize(row.order_status)}
                        </span>
                        <span className="rounded-full border border-[#D8F3DC] bg-white px-2.5 py-1">
                          Delivery {titleize(row.delivery_status)}
                        </span>
                        {row.payment_reference ? (
                          <span className="rounded-full border border-[#D8F3DC] bg-white px-2.5 py-1">
                            Ref {row.payment_reference}
                          </span>
                        ) : null}
                        <span className="rounded-full border border-[#D8F3DC] bg-white px-2.5 py-1">
                          Updated {relativeWhen(row.updated_at || row.created_at)}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="rounded-2xl border border-dashed border-slate-200 bg-slate-50 px-4 py-6 text-sm text-slate-500">
                  No payment ledger records match your search.
                </div>
              )}

              <Pager
                currentPage={safeLedgerPage}
                totalPages={ledgerTotalPages}
                onPageChange={handleLedgerPageChange}
              />
            </div>
          ) : (
            <div className="text-sm text-slate-500">No payment history is available yet.</div>
          )}
        </SectionCard>
      </div>
    </div>
  );
}