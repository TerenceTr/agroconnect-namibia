// ============================================================================
// frontend/src/pages/dashboards/customer/CustomerInsights.jsx
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Customer-only shopping insights workspace.
//
// WHAT THIS UPDATE DOES:
//   ✅ Rewrites the page in a customer-friendly tone
//   ✅ Replaces internal / analyst wording with simpler explanations
//   ✅ Keeps the existing backend payload intact
//   ✅ Improves layout balance on desktop without looking too technical
//   ✅ Focuses on what a customer actually wants to understand:
//      - how much they spend
//      - where their money goes
//      - which farmers they buy from most
//      - how they usually pay
//      - what they may want to buy again
//      - how visible / complete their orders are
// ============================================================================

import React, { useCallback, useEffect, useMemo, useState } from "react";
import {
  BarChart3,
  CalendarClock,
  CreditCard,
  RefreshCcw,
  Repeat,
  ShieldCheck,
  ShoppingBag,
  Sparkles,
  Store,
  Tractor,
  TrendingUp,
  Truck,
  Wallet,
} from "lucide-react";

import { fetchCustomerInsights } from "../../../services/customerApi";

// -----------------------------------------------------------------------------
// Small helpers
// -----------------------------------------------------------------------------
function safeArray(value) {
  return Array.isArray(value) ? value : [];
}

function safeNumber(value, fallback = 0) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function safeStr(value, fallback = "") {
  const s = String(value ?? "").trim();
  return s || fallback;
}

function money(value) {
  return `N$ ${safeNumber(value, 0).toFixed(2)}`;
}

function pct(value) {
  return `${safeNumber(value, 0).toFixed(0)}%`;
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

function titleize(value) {
  return safeStr(value, "—")
    .replace(/_/g, " ")
    .replace(/\b([a-z])/gi, (match) => match.toUpperCase());
}

function reorderStageLabel(stage) {
  const raw = safeStr(stage, "").toLowerCase();
  if (raw === "due_now") return "Buy again soon";
  if (raw === "approaching") return "Keep an eye on it";
  return "Not urgent";
}

function reorderStageTone(stage) {
  const raw = safeStr(stage, "").toLowerCase();
  if (raw === "due_now") return "border-rose-200 bg-rose-50 text-rose-800";
  if (raw === "approaching") return "border-amber-200 bg-amber-50 text-amber-800";
  return "border-emerald-200 bg-emerald-50 text-emerald-800";
}

function confidenceLabel(value) {
  const raw = safeStr(value, "");
  if (!raw) return "Not stated";
  return titleize(raw);
}

// -----------------------------------------------------------------------------
// UI atoms
// -----------------------------------------------------------------------------
function SectionCard({
  title,
  subtitle,
  icon: Icon,
  actions = null,
  children,
  className = "",
  bodyClassName = "",
}) {
  return (
    <section
      className={`overflow-hidden rounded-[24px] border border-[#D8F3DC] bg-white shadow-sm ${className}`.trim()}
    >
      <div className="flex items-start justify-between gap-4 border-b border-[#EEF7F0] px-5 py-4">
        <div className="min-w-0">
          <div className="flex items-center gap-2 text-slate-900">
            {Icon ? <Icon className="h-4 w-4 text-[#2D6A4F]" /> : null}
            <h2 className="text-sm font-extrabold uppercase tracking-[0.12em]">{title}</h2>
          </div>
          {subtitle ? <p className="mt-1 text-xs leading-5 text-slate-500">{subtitle}</p> : null}
        </div>
        {actions}
      </div>

      <div className={`p-5 ${bodyClassName}`.trim()}>{children}</div>
    </section>
  );
}

function StatCard({ icon: Icon, label, value, subtext, emphasis = false }) {
  return (
    <div
      className={[
        "rounded-2xl border p-4 shadow-sm",
        emphasis ? "border-[#B7E4C7] bg-[#F7FBF8]" : "border-[#D8F3DC] bg-white",
      ].join(" ")}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="text-[11px] font-bold uppercase tracking-[0.12em] text-slate-500">
            {label}
          </div>
          <div className="mt-1 text-2xl font-black tracking-tight text-slate-900 sm:text-[30px]">
            {value}
          </div>
          {subtext ? <div className="mt-1 text-xs text-slate-500">{subtext}</div> : null}
        </div>

        <div className="grid h-11 w-11 shrink-0 place-items-center rounded-2xl border border-[#D8F3DC] bg-white">
          <Icon className="h-5 w-5 text-[#2D6A4F]" />
        </div>
      </div>
    </div>
  );
}

function HighlightCard({ title, value, detail, icon: Icon }) {
  return (
    <div className="rounded-2xl border border-[#D8F3DC] bg-white px-4 py-3 shadow-sm">
      <div className="flex items-start gap-3">
        <div className="grid h-10 w-10 shrink-0 place-items-center rounded-2xl border border-[#D8F3DC] bg-[#F4FBF7]">
          <Icon className="h-4 w-4 text-[#2D6A4F]" />
        </div>

        <div className="min-w-0">
          <div className="text-[11px] font-bold uppercase tracking-[0.12em] text-slate-500">
            {title}
          </div>
          <div className="mt-1 text-base font-black leading-5 text-slate-900">{value}</div>
          {detail ? <div className="mt-1 text-xs leading-5 text-slate-600">{detail}</div> : null}
        </div>
      </div>
    </div>
  );
}

function MetricPill({ children }) {
  return (
    <span className="rounded-full border border-[#D8F3DC] bg-white px-2.5 py-1 text-xs text-slate-600">
      {children}
    </span>
  );
}

function EmptyState({ text }) {
  return <div className="text-sm text-slate-500">{text}</div>;
}

function ScrollRegion({ children, className = "" }) {
  return (
    <div
      className={[
        "min-w-0",
        "xl:max-h-[min(52vh,680px)] xl:overflow-y-auto xl:pr-1",
        className,
      ].join(" ")}
    >
      {children}
    </div>
  );
}

function HorizontalBars({
  rows = [],
  labelKey,
  valueKey,
  suffix = "",
  emptyLabel = "No data yet.",
  valueFormatter = null,
}) {
  const safeRows = safeArray(rows);
  const maxValue = safeRows.reduce(
    (max, row) => Math.max(max, safeNumber(row?.[valueKey], 0)),
    0
  );

  if (!safeRows.length) {
    return <EmptyState text={emptyLabel} />;
  }

  return (
    <div className="space-y-3">
      {safeRows.map((row, index) => {
        const label = safeStr(row?.[labelKey], "—");
        const value = safeNumber(row?.[valueKey], 0);
        const widthPct = maxValue > 0 ? Math.max(8, (value / maxValue) * 100) : 8;

        return (
          <div key={`${label}-${index}`} className="space-y-1.5">
            <div className="flex items-center justify-between gap-3 text-sm">
              <div className="truncate font-semibold text-slate-700">{label}</div>
              <div className="whitespace-nowrap font-bold text-slate-900">
                {typeof valueFormatter === "function"
                  ? valueFormatter(value, row)
                  : `${value}${suffix}`}
              </div>
            </div>

            <div className="h-2.5 overflow-hidden rounded-full bg-slate-100">
              <div
                className="h-full rounded-full bg-gradient-to-r from-[#2D6A4F] to-[#74C69D]"
                style={{ width: `${widthPct}%` }}
              />
            </div>
          </div>
        );
      })}
    </div>
  );
}

function ReorderCard({ item }) {
  return (
    <div className="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-4">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="text-sm font-extrabold text-slate-900">
            {safeStr(item.product_name, "Product")}
          </div>
          <div className="mt-1 text-xs text-slate-500">
            {safeStr(item.category, "Other")} • {safeNumber(item.purchase_count, 0)} purchase(s)
          </div>
        </div>

        <div
          className={`shrink-0 rounded-full border px-2.5 py-1 text-[11px] font-bold ${reorderStageTone(
            item.reorder_stage
          )}`}
        >
          {reorderStageLabel(item.reorder_stage)}
        </div>
      </div>

      <div className="mt-3 flex flex-wrap gap-2">
        <MetricPill>Last bought {when(item.last_order_at)}</MetricPill>
        <MetricPill>{safeNumber(item.days_since_last_order, 0)} day(s) since last order</MetricPill>
        <MetricPill>Usually every {safeNumber(item.avg_gap_days, 0)} day(s)</MetricPill>
        <MetricPill>Current price {money(item.current_price)}</MetricPill>
        <MetricPill>Past average {money(item.avg_paid_unit_price)}</MetricPill>
        <MetricPill>Price change {pct(item.price_delta_pct)}</MetricPill>
        <MetricPill>Available qty {safeNumber(item.available_qty, 0)}</MetricPill>
      </div>

      <div className="mt-3 text-sm leading-6 text-slate-700">
        {safeStr(item.recommendation, "No buy-again suggestion yet.")}
      </div>

      {item.low_stock_risk ? (
        <div className="mt-3 rounded-2xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-800">
          Stock may be getting low. {safeStr(item.substitute_hint, "")}
        </div>
      ) : null}
    </div>
  );
}

function FarmerCard({ farmer }) {
  return (
    <div className="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="text-sm font-extrabold text-slate-900">
            {safeStr(farmer.farmer_name, "Farmer")}
          </div>
          <div className="mt-1 text-xs text-slate-500">
            {safeStr(farmer.location, "Location not specified")}
          </div>
        </div>

        <div className="shrink-0 text-right">
          <div className="text-sm font-black text-slate-900">{money(farmer.amount)}</div>
          <div className="text-xs text-slate-500">
            {safeNumber(farmer.orders_count, 0)} order(s)
          </div>
        </div>
      </div>

      <div className="mt-3 flex flex-wrap gap-2">
        <MetricPill>{safeNumber(farmer.products_count, 0)} product(s)</MetricPill>
        <MetricPill>Last order {when(farmer.last_order_at)}</MetricPill>
      </div>
    </div>
  );
}

// -----------------------------------------------------------------------------
// Main page
// -----------------------------------------------------------------------------
export default function CustomerInsights() {
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");
  const [payload, setPayload] = useState(null);

  const loadInsights = useCallback(async ({ silent = false } = {}) => {
    try {
      if (silent) setRefreshing(true);
      else setLoading(true);

      setError("");
      const data = await fetchCustomerInsights({ months: 6 });
      setPayload(data || null);
    } catch (err) {
      setError(
        err?.response?.data?.message ||
          err?.message ||
          "Could not load customer insights right now."
      );
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    loadInsights();
  }, [loadInsights]);

  const summary = useMemo(() => payload?.summary || {}, [payload]);
  const notes = safeArray(payload?.notes);
  const spendingByMonth = safeArray(payload?.spending_by_month);
  const spendByCategory = safeArray(payload?.spend_by_category);
  const topFarmers = safeArray(payload?.top_farmers);
  const paymentMix = safeArray(payload?.payment_mix);
  const segmentation = useMemo(() => payload?.segmentation || {}, [payload]);
  const reorderIntelligence = safeArray(payload?.reorder_intelligence);
  const deliveryFeeShare = useMemo(() => payload?.delivery_fee_share || {}, [payload]);
  const trustMetrics = useMemo(() => payload?.trust_metrics || {}, [payload]);

  const primarySegment = segmentation?.primary_segment || {};
  const segmentList = safeArray(segmentation?.segments);
  const topReorder = reorderIntelligence[0] || null;
  const strongestCategory = spendByCategory[0] || null;
  const strongestFarmer = topFarmers[0] || null;
  const mainPaymentMethod = paymentMix[0] || null;

  const observedOrders = useMemo(() => {
    const fromSummary = Math.max(
      safeNumber(summary.total_orders, 0),
      safeNumber(summary.orders_count, 0)
    );
    const fromPayments = paymentMix.reduce(
      (sum, row) => Math.max(sum, safeNumber(row?.orders_count, 0)),
      0
    );
    return Math.max(fromSummary, fromPayments);
  }, [paymentMix, summary.orders_count, summary.total_orders]);

  const shoppingSummary = useMemo(() => {
    if (topReorder && strongestCategory && strongestFarmer) {
      return `You spend the most on ${safeStr(
        strongestCategory.category,
        "this category"
      )}, you buy most often from ${safeStr(
        strongestFarmer.farmer_name,
        "this farmer"
      )}, and ${safeStr(topReorder.product_name, "one product")} looks like your next likely repeat purchase.`;
    }

    if (strongestCategory && strongestFarmer) {
      return `Your spending is currently strongest in ${safeStr(
        strongestCategory.category,
        "one category"
      )}, and ${safeStr(strongestFarmer.farmer_name, "one farmer")} is your main supplier relationship so far.`;
    }

    if (safeStr(primarySegment.label, "")) {
      return safeStr(
        primarySegment.reason,
        "Your shopping pattern is becoming clearer from your recent marketplace activity."
      );
    }

    return "As you place more orders, this page will explain your spending, buying patterns, and repeat-purchase behaviour in a simpler way.";
  }, [primarySegment.label, primarySegment.reason, strongestCategory, strongestFarmer, topReorder]);

  const plainLanguageNotes = useMemo(() => {
    const items = [];

    if (safeNumber(summary.total_spend, 0) > 0) {
      items.push(
        `You have spent ${money(summary.total_spend)} in total, with an average order value of ${money(
          summary.avg_order_value
        )}.`
      );
    }

    if (strongestCategory) {
      items.push(
        `You spend most in ${safeStr(strongestCategory.category, "this category")} at ${money(
          strongestCategory.amount
        )}.`
      );
    }

    if (mainPaymentMethod) {
      items.push(
        `Your most used payment method is ${titleize(
          mainPaymentMethod.payment_method
        )}, based on recorded order value.`
      );
    }

    if (strongestFarmer) {
      items.push(
        `${safeStr(strongestFarmer.farmer_name, "This farmer")} is the farmer you buy from most so far.`
      );
    }

    if (topReorder) {
      items.push(
        `${safeStr(topReorder.product_name, "This product")} is your strongest buy-again signal right now.`
      );
    }

    if (safeNumber(deliveryFeeShare.delivery_fee_share_pct, 0) > 0) {
      items.push(
        `Delivery fees currently make up ${pct(
          deliveryFeeShare.delivery_fee_share_pct
        )} of your recorded order value.`
      );
    }

    if (safeNumber(trustMetrics.payment_confirmed_rate_pct, 0) > 0) {
      items.push(
        `${pct(
          trustMetrics.payment_confirmed_rate_pct
        )} of your recorded orders have confirmed payment visibility.`
      );
    }

    return [...items, ...notes].slice(0, 6);
  }, [
    deliveryFeeShare.delivery_fee_share_pct,
    mainPaymentMethod,
    notes,
    strongestCategory,
    strongestFarmer,
    summary.avg_order_value,
    summary.total_spend,
    topReorder,
    trustMetrics.payment_confirmed_rate_pct,
  ]);

  const paymentMixRows = useMemo(() => {
    return paymentMix.map((row) => ({
      ...row,
      payment_label: titleize(row.payment_method),
    }));
  }, [paymentMix]);

  const trustRows = useMemo(
    () => [
      {
        label: "Proof received",
        metric: safeNumber(trustMetrics.proof_received_rate_pct, 0),
      },
      {
        label: "Payment confirmed",
        metric: safeNumber(trustMetrics.payment_confirmed_rate_pct, 0),
      },
      {
        label: "Delivery completed",
        metric: safeNumber(trustMetrics.delivery_completed_rate_pct, 0),
      },
      {
        label: "On-time delivery",
        metric: safeNumber(trustMetrics.on_time_delivery_rate_pct, 0),
      },
    ],
    [trustMetrics]
  );

  const deliveryFeeRows = useMemo(
    () => [
      {
        label: "Delivery fees paid",
        amount: safeNumber(deliveryFeeShare.total_delivery_fees, 0),
      },
      {
        label: "Average fee when charged",
        amount: safeNumber(deliveryFeeShare.avg_delivery_fee_nonzero, 0),
      },
    ],
    [deliveryFeeShare]
  );

  if (loading) {
    return (
      <div className="mx-auto w-full max-w-[1700px] px-4 pb-8 sm:px-5 lg:px-6 2xl:px-8">
        <div className="rounded-[28px] border border-[#D8F3DC] bg-white/90 p-6 shadow-sm">
          <div className="text-xs font-bold uppercase tracking-[0.18em] text-[#2D6A4F]">
            Shopping Insights
          </div>
          <div className="mt-2 text-2xl font-black tracking-tight text-slate-900">
            Loading your shopping insights…
          </div>
          <div className="mt-2 text-sm text-slate-600">
            Preparing spend, payment, delivery, and buy-again information.
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="mx-auto w-full max-w-[1700px] px-4 pb-8 sm:px-5 lg:px-6 2xl:px-8">
      <div className="space-y-5 2xl:space-y-6">
        {/* ------------------------------------------------------------------ */}
        {/* Header                                                              */}
        {/* ------------------------------------------------------------------ */}
        <div className="rounded-[28px] border border-[#D8F3DC] bg-white/90 p-5 shadow-sm sm:p-6 xl:p-7">
          <div className="grid grid-cols-1 gap-5 xl:grid-cols-[minmax(0,1.25fr)_minmax(320px,0.75fr)] xl:items-start">
            <div className="min-w-0">
              <div className="text-xs font-bold uppercase tracking-[0.18em] text-[#2D6A4F]">
                Shopping Insights
              </div>
              <h1 className="mt-2 text-[28px] font-black tracking-tight text-slate-900 sm:text-[32px] xl:text-[36px]">
                Your spending & buying habits
              </h1>
              <p className="mt-2 max-w-4xl text-sm leading-6 text-slate-600 sm:text-[15px]">
                This page explains your shopping activity in a simpler way — how much
                you spend, where your money goes, which farmers you buy from most,
                how you usually pay, and what you may want to buy again.
              </p>

              <div className="mt-4 rounded-2xl border border-[#E7F5EA] bg-[#F7FBF8] p-4">
                <div className="flex items-start gap-3">
                  <Sparkles className="mt-0.5 h-5 w-5 shrink-0 text-[#2D6A4F]" />
                  <div>
                    <div className="text-sm font-bold text-slate-900">Quick summary</div>
                    <div className="mt-1 text-sm leading-6 text-slate-600">{shoppingSummary}</div>
                  </div>
                </div>
              </div>
            </div>

            <div className="flex flex-col gap-3 xl:items-end">
              <button
                type="button"
                onClick={() => loadInsights({ silent: true })}
                className="inline-flex items-center justify-center gap-2 rounded-2xl border border-[#D8F3DC] bg-white px-4 py-2.5 text-sm font-semibold text-slate-800 shadow-sm hover:bg-[#F8FCF9]"
              >
                <RefreshCcw className={`h-4 w-4 ${refreshing ? "animate-spin" : ""}`} />
                {refreshing ? "Refreshing…" : "Refresh insights"}
              </button>

              <div className="grid w-full grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-1 xl:w-[360px]">
                <HighlightCard
                  icon={Store}
                  title="Shopping profile"
                  value={safeStr(primarySegment.label, "Still building")}
                  detail={safeStr(
                    primarySegment.reason,
                    "Your overall shopping pattern will become clearer as more orders are recorded."
                  )}
                />
                <HighlightCard
                  icon={Tractor}
                  title="Farmer you buy from most"
                  value={safeStr(strongestFarmer?.farmer_name, "Not yet clear")}
                  detail={
                    strongestFarmer
                      ? `${money(strongestFarmer.amount)} across ${safeNumber(
                          strongestFarmer.orders_count,
                          0
                        )} order(s).`
                      : "This will appear once there is a clear purchase pattern."
                  }
                />
                <HighlightCard
                  icon={Repeat}
                  title="Most likely buy-again item"
                  value={safeStr(topReorder?.product_name, "Not yet clear")}
                  detail={
                    topReorder
                      ? `${reorderStageLabel(topReorder.reorder_stage)} • ${safeNumber(
                          topReorder.purchase_count,
                          0
                        )} purchase(s)`
                      : "Buy-again suggestions will appear after repeat purchases."
                  }
                />
              </div>
            </div>
          </div>

          {error ? (
            <div className="mt-4 rounded-2xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-800">
              {error}
            </div>
          ) : null}
        </div>

        {/* ------------------------------------------------------------------ */}
        {/* Top stats                                                           */}
        {/* ------------------------------------------------------------------ */}
        <div className="grid grid-cols-[repeat(auto-fit,minmax(220px,1fr))] gap-4">
          <StatCard
            icon={Wallet}
            label="Total spent"
            value={money(summary.total_spend)}
            subtext={`Confirmed paid spend: ${money(summary.paid_spend)}`}
            emphasis
          />
          <StatCard
            icon={ShoppingBag}
            label="Orders placed"
            value={safeNumber(observedOrders, 0)}
            subtext={`Last order: ${when(summary.last_order_at)}`}
          />
          <StatCard
            icon={TrendingUp}
            label="Average order"
            value={money(summary.avg_order_value)}
            subtext="Typical basket size from recorded orders"
          />
          <StatCard
            icon={BarChart3}
            label="Top category"
            value={safeStr(strongestCategory?.category, "Not yet clear")}
            subtext={
              strongestCategory
                ? `${money(strongestCategory.amount)} spent here`
                : "No category pattern yet"
            }
          />
          <StatCard
            icon={CreditCard}
            label="Main payment method"
            value={mainPaymentMethod ? titleize(mainPaymentMethod.payment_method) : "Not yet clear"}
            subtext={
              mainPaymentMethod
                ? `${money(mainPaymentMethod.amount)} observed value`
                : "No payment pattern yet"
            }
          />
        </div>

        {/* ------------------------------------------------------------------ */}
        {/* Main content                                                        */}
        {/* ------------------------------------------------------------------ */}
        <div className="grid grid-cols-1 gap-5 xl:grid-cols-[minmax(0,1.38fr)_minmax(360px,0.92fr)] 2xl:gap-6">
          {/* ============================== MAIN ============================= */}
          <div className="min-w-0 space-y-5 2xl:space-y-6">
            <SectionCard
              title="Your spending over time"
              subtitle="A simple month-by-month view of how your spending has changed."
              icon={BarChart3}
            >
              <HorizontalBars
                rows={spendingByMonth}
                labelKey="month"
                valueKey="amount"
                emptyLabel="No monthly spending data yet."
                valueFormatter={(value) => money(value)}
              />
            </SectionCard>

            <div className="grid grid-cols-1 gap-5 2xl:grid-cols-2">
              <SectionCard
                title="Where your money goes"
                subtitle="The categories where you spend the most."
                icon={ShoppingBag}
              >
                <HorizontalBars
                  rows={spendByCategory}
                  labelKey="category"
                  valueKey="amount"
                  emptyLabel="No category spending data yet."
                  valueFormatter={(value) => money(value)}
                />
              </SectionCard>

              <SectionCard
                title="How you usually pay"
                subtitle="Your payment methods based on recorded order value."
                icon={CreditCard}
              >
                <HorizontalBars
                  rows={paymentMixRows}
                  labelKey="payment_label"
                  valueKey="amount"
                  emptyLabel="No payment method data yet."
                  valueFormatter={(value) => money(value)}
                />
              </SectionCard>
            </div>

            <SectionCard
              title="Products you may want to buy again"
              subtitle="These are products that look like repeat purchases based on your past buying pattern."
              icon={Repeat}
            >
              {topReorder ? (
                <div className="mb-4 rounded-2xl border border-[#E7F5EA] bg-[#F7FBF8] px-4 py-3 text-sm text-slate-700">
                  {safeStr(topReorder.product_name, "This product")} is your strongest
                  buy-again signal right now.
                </div>
              ) : null}

              {reorderIntelligence.length ? (
                <ScrollRegion>
                  <div className="space-y-3">
                    {reorderIntelligence.map((item, index) => (
                      <ReorderCard
                        key={`${item.product_id || item.product_name}-${index}`}
                        item={item}
                      />
                    ))}
                  </div>
                </ScrollRegion>
              ) : (
                <EmptyState text="No buy-again suggestions are available yet." />
              )}
            </SectionCard>

            <SectionCard
              title="Order visibility"
              subtitle="How clear your payment, proof, and delivery records currently are."
              icon={ShieldCheck}
            >
              <div className="grid grid-cols-[repeat(auto-fit,minmax(200px,1fr))] gap-4">
                <StatCard
                  icon={ShieldCheck}
                  label="Visibility score"
                  value={pct(trustMetrics.transparency_score)}
                  subtext="Overall record completeness"
                />
                <StatCard
                  icon={CreditCard}
                  label="Payment confirmed"
                  value={pct(trustMetrics.payment_confirmed_rate_pct)}
                  subtext={`${safeNumber(trustMetrics.payment_confirmed_orders, 0)} order(s)`}
                />
                <StatCard
                  icon={ShoppingBag}
                  label="Proof received"
                  value={pct(trustMetrics.proof_received_rate_pct)}
                  subtext={`${safeNumber(trustMetrics.proof_received_orders, 0)} order(s)`}
                />
                <StatCard
                  icon={Truck}
                  label="Delivery completed"
                  value={pct(trustMetrics.delivery_completed_rate_pct)}
                  subtext={`${safeNumber(trustMetrics.delivered_orders, 0)} delivered`}
                />
              </div>

              <div className="mt-5 grid grid-cols-1 gap-5 2xl:grid-cols-[minmax(0,1fr)_minmax(320px,0.9fr)]">
                <div className="min-w-0">
                  <HorizontalBars
                    rows={trustRows}
                    labelKey="label"
                    valueKey="metric"
                    suffix="%"
                    emptyLabel="No order visibility data yet."
                    valueFormatter={(value) => pct(value)}
                  />
                </div>

                <div className="space-y-3">
                  <div className="rounded-2xl border border-[#E7F5EA] bg-[#F7FBF8] px-4 py-3 text-sm text-slate-700">
                    A higher visibility score means your orders are easier to follow because
                    payment, proof, and delivery records are more complete.
                  </div>

                  <div className="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3">
                    <div className="text-sm font-extrabold text-slate-900">On-time delivery</div>
                    <div className="mt-1 text-sm leading-6 text-slate-600">
                      {safeNumber(trustMetrics.comparable_deliveries, 0) > 0
                        ? `${pct(trustMetrics.on_time_delivery_rate_pct)} across ${safeNumber(
                            trustMetrics.comparable_deliveries,
                            0
                          )} comparable delivery record(s).`
                        : "There is not enough expected-vs-delivered timing data yet to judge on-time delivery fairly."}
                    </div>
                  </div>

                  <div className="rounded-2xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-800">
                    {safeStr(
                      trustMetrics.farmer_response_time_note,
                      "Farmer response-time tracking is not yet available in this version."
                    )}
                  </div>
                </div>
              </div>
            </SectionCard>
          </div>

          {/* ============================ SIDE RAIL ========================== */}
          <aside className="min-w-0 space-y-5 xl:sticky xl:top-5 xl:self-start 2xl:space-y-6">
            <SectionCard
              title="What this means"
              subtitle="Short explanations written in plain language."
              icon={Sparkles}
            >
              {plainLanguageNotes.length ? (
                <div className="space-y-3">
                  {plainLanguageNotes.map((note, index) => (
                    <div
                      key={`${note}-${index}`}
                      className="rounded-2xl border border-[#E7F5EA] bg-[#F7FBF8] px-4 py-3 text-sm leading-6 text-slate-700"
                    >
                      {safeStr(note, "")}
                    </div>
                  ))}
                </div>
              ) : (
                <EmptyState text="Simple explanations will appear here as more activity is recorded." />
              )}
            </SectionCard>

            <SectionCard
              title="Your shopping profile"
              subtitle="A simple description of your overall shopping pattern."
              icon={Store}
            >
              <div className="space-y-4">
                <div className="rounded-2xl border border-[#E7F5EA] bg-[#F7FBF8] px-4 py-3">
                  <div className="text-[11px] font-bold uppercase tracking-[0.12em] text-slate-500">
                    Main profile
                  </div>
                  <div className="mt-1 text-lg font-black text-slate-900">
                    {safeStr(primarySegment.label, "Still building")}
                  </div>
                  <div className="mt-1 text-sm leading-6 text-slate-600">
                    {safeStr(primarySegment.reason, "There is not enough shopping history yet.")}
                  </div>
                  <div className="mt-2 text-xs text-slate-500">
                    Confidence: {confidenceLabel(primarySegment.confidence)}
                  </div>
                </div>

                {segmentList.length ? (
                  <div className="grid grid-cols-1 gap-3">
                    {segmentList.map((segment, index) => (
                      <div
                        key={`${segment.label}-${index}`}
                        className="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3"
                      >
                        <div className="text-sm font-extrabold text-slate-900">
                          {safeStr(segment.label, "Profile")}
                        </div>
                        <div className="mt-1 text-xs text-slate-500">
                          Confidence: {confidenceLabel(segment.confidence)}
                        </div>
                        <div className="mt-2 text-sm leading-6 text-slate-700">
                          {safeStr(segment.reason, "")}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : null}
              </div>
            </SectionCard>

            <SectionCard
              title="Farmers you buy from most"
              subtitle="Your strongest supplier relationships so far."
              icon={Tractor}
            >
              {topFarmers.length ? (
                <ScrollRegion className="xl:max-h-[min(42vh,520px)]">
                  <div className="space-y-3">
                    {topFarmers.map((farmer, index) => (
                      <FarmerCard
                        key={`${farmer.farmer_id || farmer.farmer_name}-${index}`}
                        farmer={farmer}
                      />
                    ))}
                  </div>
                </ScrollRegion>
              ) : (
                <EmptyState text="No farmer relationship data yet." />
              )}
            </SectionCard>

            <SectionCard
              title="Delivery costs"
              subtitle="How much delivery adds to your recorded order value."
              icon={Truck}
            >
              <div className="mb-4 grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-1 2xl:grid-cols-2">
                <div className="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3">
                  <div className="text-[11px] font-bold uppercase tracking-[0.12em] text-slate-500">
                    Delivery fee share
                  </div>
                  <div className="mt-1 text-lg font-black text-slate-900">
                    {pct(deliveryFeeShare.delivery_fee_share_pct)}
                  </div>
                  <div className="mt-1 text-xs text-slate-500">Of recorded order value</div>
                </div>

                <div className="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3">
                  <div className="text-[11px] font-bold uppercase tracking-[0.12em] text-slate-500">
                    Fee-free orders
                  </div>
                  <div className="mt-1 text-lg font-black text-slate-900">
                    {safeNumber(deliveryFeeShare.fee_free_orders, 0)}
                  </div>
                  <div className="mt-1 text-xs text-slate-500">Orders with no delivery fee</div>
                </div>
              </div>

              <HorizontalBars
                rows={deliveryFeeRows}
                labelKey="label"
                valueKey="amount"
                emptyLabel="No delivery fee data yet."
                valueFormatter={(value) => money(value)}
              />
            </SectionCard>

            <SectionCard
              title="Helpful timing"
              subtitle="A quick reminder of your latest recorded order."
              icon={CalendarClock}
            >
              <div className="rounded-2xl border border-[#E7F5EA] bg-[#F7FBF8] px-4 py-3">
                <div className="text-sm font-extrabold text-slate-900">Last recorded order</div>
                <div className="mt-1 text-sm leading-6 text-slate-600">
                  {when(summary.last_order_at)}
                </div>
              </div>
            </SectionCard>
          </aside>
        </div>
      </div>
    </div>
  );
}