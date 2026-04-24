// ============================================================================
// frontend/src/pages/dashboards/customer/CustomerSavedSearch.jsx
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Customer-only saved / search / discovery workspace.
//   • Previous searches
//   • Liked products
//   • Recently viewed products
//   • Repeat-buy candidates
//   • Calm, customer-facing interpretation of browsing behaviour
//
// DESIGN GOALS IN THIS UPDATE:
//   ✅ Makes the page feel customer-friendly instead of analyst-heavy
//   ✅ Uses desktop width more effectively with a wide primary content area
//   ✅ Removes the "empty canvas" feel caused by the old inner rail layout
//   ✅ Keeps all existing backend payload fields intact
//   ✅ Keeps filtering simple and readable for non-admin users
// ============================================================================

import React, { useCallback, useEffect, useMemo, useState } from "react";
import {
  RefreshCcw,
  Search,
  Heart,
  Eye,
  Repeat,
  Sparkles,
  Clock3,
  BadgeCheck,
  ShoppingBag,
  Star,
  ChevronRight,
  X,
} from "lucide-react";

import { fetchCustomerSavedSearch } from "../../../services/customerApi";

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

function titleize(value) {
  return safeStr(value, "—")
    .replace(/_/g, " ")
    .replace(/\b([a-z])/gi, (m) => m.toUpperCase());
}

function categoryLabel(value) {
  const raw = safeStr(value, "Other");
  return titleize(raw) || "Other";
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

function relativeWhen(value) {
  const raw = safeStr(value, "");
  if (!raw) return "—";

  const dt = new Date(raw);
  if (Number.isNaN(dt.getTime())) return when(raw);

  const diffMs = Date.now() - dt.getTime();
  const diffMin = Math.floor(diffMs / 60000);

  if (diffMin < 1) return "just now";
  if (diffMin < 60) return `${diffMin}m ago`;

  const diffHr = Math.floor(diffMin / 60);
  if (diffHr < 24) return `${diffHr}h ago`;

  const diffDay = Math.floor(diffHr / 24);
  if (diffDay < 7) return `${diffDay}d ago`;

  return when(raw);
}

function timeValue(value) {
  const raw = safeStr(value, "");
  if (!raw) return 0;
  const dt = new Date(raw);
  return Number.isNaN(dt.getTime()) ? 0 : dt.getTime();
}

function firstLetter(value, fallback = "P") {
  const s = safeStr(value, fallback);
  return s.charAt(0).toUpperCase() || fallback;
}

function SectionCard({ title, subtitle, actions = null, children }) {
  return (
    <section className="overflow-hidden rounded-[28px] border border-[#D8F3DC] bg-white shadow-sm">
      <div className="flex flex-col gap-3 border-b border-[#EEF7F0] px-5 py-4 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <div className="text-sm font-extrabold uppercase tracking-wide text-slate-900">
            {title}
          </div>
          {subtitle ? <div className="mt-1 text-sm text-slate-500">{subtitle}</div> : null}
        </div>
        {actions}
      </div>
      <div className="p-5">{children}</div>
    </section>
  );
}

function SummaryCard({ eyebrow, title, body, icon: Icon }) {
  return (
    <div className="rounded-[24px] border border-[#E4F2E8] bg-white px-4 py-4 shadow-sm">
      <div className="flex items-start gap-3">
        <div className="grid h-11 w-11 shrink-0 place-items-center rounded-2xl bg-[#F3FAF5] text-[#2D6A4F]">
          <Icon className="h-4.5 w-4.5" />
        </div>
        <div className="min-w-0">
          <div className="text-[11px] font-bold uppercase tracking-[0.16em] text-slate-500">
            {eyebrow}
          </div>
          <div className="mt-1 text-sm font-extrabold text-slate-900">{title}</div>
          <div className="mt-1 text-sm leading-6 text-slate-600">{body}</div>
        </div>
      </div>
    </div>
  );
}

function StatCard({ icon: Icon, label, value, subtext }) {
  return (
    <div className="rounded-[24px] border border-[#DDEFE3] bg-white px-4 py-4 shadow-sm">
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="text-[11px] font-bold uppercase tracking-[0.16em] text-slate-500">
            {label}
          </div>
          <div className="mt-1 text-[28px] font-black leading-none tracking-tight text-slate-900">
            {value}
          </div>
          {subtext ? <div className="mt-2 text-xs text-slate-500">{subtext}</div> : null}
        </div>

        <div className="grid h-11 w-11 place-items-center rounded-2xl bg-[#F3FAF5] text-[#2D6A4F]">
          <Icon className="h-4.5 w-4.5" />
        </div>
      </div>
    </div>
  );
}

function TabButton({ active, onClick, icon: Icon, label, count }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`inline-flex items-center gap-2 rounded-full border px-3.5 py-2 text-sm font-semibold transition ${
        active
          ? "border-[#95D5B2] bg-[#EAF7F0] text-[#1B4332]"
          : "border-slate-200 bg-white text-slate-700 hover:bg-slate-50"
      }`}
    >
      <Icon className="h-4 w-4" />
      <span>{label}</span>
      <span
        className={`rounded-full px-2 py-0.5 text-[11px] font-bold ${
          active ? "bg-white text-[#1B4332]" : "bg-slate-100 text-slate-600"
        }`}
      >
        {count}
      </span>
    </button>
  );
}

function MiniMetric({ label, value, helper = "" }) {
  return (
    <div className="rounded-2xl border border-[#E7F1EA] bg-[#F8FCF9] px-4 py-3">
      <div className="text-[11px] font-bold uppercase tracking-[0.14em] text-slate-500">
        {label}
      </div>
      <div className="mt-1 text-xl font-black text-slate-900">{value}</div>
      {helper ? <div className="mt-1 text-xs text-slate-500">{helper}</div> : null}
    </div>
  );
}

function EmptyState({ title, body }) {
  return (
    <div className="grid min-h-[260px] place-items-center rounded-[24px] border border-dashed border-[#D5E8DB] bg-[#FAFCFB] px-6 py-10 text-center">
      <div>
        <div className="text-sm font-bold text-slate-900">{title}</div>
        <div className="mt-2 max-w-md text-sm leading-6 text-slate-500">{body}</div>
      </div>
    </div>
  );
}

function ToneChip({ label, tone = "default" }) {
  const toneClass =
    tone === "emerald"
      ? "border-[#CDEDD8] bg-[#F4FBF7] text-[#1B4332]"
      : tone === "violet"
      ? "border-[#E8E0F4] bg-[#FAF8FD] text-[#5B4B7A]"
      : tone === "blue"
      ? "border-[#DCEAF5] bg-[#F6FAFD] text-[#335B7C]"
      : "border-slate-200 bg-slate-50 text-slate-700";

  return (
    <span className={`rounded-full border px-2.5 py-1 text-[11px] font-bold ${toneClass}`}>
      {label}
    </span>
  );
}

function SearchMemoryCard({ query, createdAt }) {
  return (
    <div className="rounded-[24px] border border-[#E7EEF0] bg-white px-4 py-4 shadow-sm transition hover:-translate-y-[1px] hover:shadow-md">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <ToneChip label="Search phrase" tone="emerald" />
          </div>
          <div className="mt-3 text-base font-black leading-6 text-slate-900">{query}</div>
        </div>

        <div className="shrink-0 text-xs font-semibold text-slate-500">{relativeWhen(createdAt)}</div>
      </div>

      <div className="mt-4 flex items-center gap-2 text-xs text-slate-500">
        <Clock3 className="h-3.5 w-3.5" />
        <span>Searched on {when(createdAt)}</span>
      </div>
    </div>
  );
}

function ProductSignalCard({
  title,
  category,
  farmer,
  primaryValue,
  primaryLabel,
  metaLine,
  accent = "default",
}) {
  const tone =
    accent === "repeat"
      ? "border-[#DDEFE3] bg-[#F5FBF7]"
      : accent === "liked"
      ? "border-[#E9E1F4] bg-[#FCFAFF]"
      : accent === "viewed"
      ? "border-[#DCEAF5] bg-[#F8FBFE]"
      : "border-[#E8EEF0] bg-white";

  const chipTone =
    accent === "repeat"
      ? "emerald"
      : accent === "liked"
      ? "violet"
      : accent === "viewed"
      ? "blue"
      : "default";

  return (
    <div className={`rounded-[24px] border px-4 py-4 shadow-sm transition hover:-translate-y-[1px] hover:shadow-md ${tone}`}>
      <div className="flex items-start gap-3">
        <div className="grid h-12 w-12 shrink-0 place-items-center rounded-2xl bg-white text-sm font-black text-[#2D6A4F] shadow-sm ring-1 ring-[#E8F2EC]">
          {firstLetter(title)}
        </div>

        <div className="min-w-0 flex-1">
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                <ToneChip
                  label={
                    accent === "repeat"
                      ? "Reorder signal"
                      : accent === "liked"
                      ? "Saved item"
                      : accent === "viewed"
                      ? "Recently viewed"
                      : "Product"
                  }
                  tone={chipTone}
                />
              </div>
              <div className="mt-3 truncate text-base font-black text-slate-900">{title}</div>
              <div className="mt-1 text-sm text-slate-500">
                {categoryLabel(category)} • {safeStr(farmer, "Farmer")}
              </div>
            </div>

            <div className="shrink-0 text-right">
              <div className="text-base font-black text-slate-900">{primaryValue}</div>
              <div className="mt-1 text-xs font-medium text-slate-500">{primaryLabel}</div>
            </div>
          </div>

          {metaLine ? <div className="mt-4 text-xs font-medium text-slate-600">{metaLine}</div> : null}
        </div>
      </div>
    </div>
  );
}

function FunnelBars({ rows }) {
  const max = rows.reduce((m, row) => Math.max(m, safeNumber(row.value, 0)), 0);

  return (
    <div className="space-y-3">
      {rows.map((row) => {
        const numeric = safeNumber(row.value, 0);
        const width = max > 0 ? Math.max(10, (numeric / max) * 100) : 10;

        return (
          <div key={row.label}>
            <div className="mb-1.5 flex items-center justify-between gap-3 text-xs">
              <span className="font-semibold text-slate-600">{row.label}</span>
              <span className="font-bold text-slate-900">{numeric}</span>
            </div>
            <div className="h-2.5 overflow-hidden rounded-full bg-slate-100">
              <div
                className="h-full rounded-full bg-gradient-to-r from-[#2D6A4F] to-[#74C69D]"
                style={{ width: `${width}%` }}
              />
            </div>
          </div>
        );
      })}
    </div>
  );
}

function HighlightRow({ icon: Icon, label, title, meta }) {
  return (
    <div className="rounded-2xl border border-[#E7F1EA] bg-[#F8FCF9] px-4 py-3">
      <div className="flex items-start gap-3">
        <div className="grid h-9 w-9 shrink-0 place-items-center rounded-2xl bg-white text-[#2D6A4F] ring-1 ring-[#E7F1EA]">
          <Icon className="h-4 w-4" />
        </div>
        <div className="min-w-0">
          <div className="text-[11px] font-bold uppercase tracking-[0.14em] text-slate-500">
            {label}
          </div>
          <div className="mt-1 text-sm font-bold text-slate-900">{title}</div>
          {meta ? <div className="mt-1 text-xs text-slate-500">{meta}</div> : null}
        </div>
      </div>
    </div>
  );
}

export default function CustomerSavedSearch() {
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");
  const [payload, setPayload] = useState(null);
  const [activeTab, setActiveTab] = useState("repeat");
  const [memoryQuery, setMemoryQuery] = useState("");

  const loadWorkspace = useCallback(async ({ silent = false } = {}) => {
    try {
      if (silent) {
        setRefreshing(true);
      } else {
        setLoading(true);
      }

      setError("");
      const data = await fetchCustomerSavedSearch();
      setPayload(data || null);
    } catch (err) {
      setError(
        err?.response?.data?.message ||
          err?.message ||
          "Could not load the saved and search workspace right now."
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
  const apiNotes = safeArray(payload?.notes);
  const previousSearches = safeArray(payload?.recent_searches);
  const likedProducts = safeArray(payload?.liked_products);
  const recentlyViewed = safeArray(payload?.recently_viewed);
  const repeatPurchases = safeArray(payload?.repeat_purchases);
  const funnel = useMemo(() => payload?.behavior_funnel || {}, [payload]);

  const counts = useMemo(
    () => ({
      searches: previousSearches.length,
      liked: likedProducts.length,
      viewed: recentlyViewed.length,
      repeat: repeatPurchases.length,
    }),
    [previousSearches.length, likedProducts.length, recentlyViewed.length, repeatPurchases.length]
  );

  useEffect(() => {
    const preferred = ["repeat", "liked", "viewed", "searches"];
    if (safeNumber(counts[activeTab], 0) > 0) return;

    const next = preferred.find((key) => safeNumber(counts[key], 0) > 0);
    if (next) setActiveTab(next);
  }, [activeTab, counts]);

  const topRepeat = repeatPurchases[0] || null;
  const topLiked = likedProducts[0] || null;
  const topViewed = recentlyViewed[0] || null;
  const latestSearch = previousSearches[0] || null;

  const latestMoment = useMemo(() => {
    const candidates = [
      latestSearch
        ? {
            title: `Latest search: ${safeStr(latestSearch.query, "—")}`,
            meta: `Searched ${when(latestSearch.created_at)}`,
            at: latestSearch.created_at,
          }
        : null,
      topLiked
        ? {
            title: `Saved: ${safeStr(topLiked.product_name, "Product")}`,
            meta: `Liked ${relativeWhen(topLiked.liked_at)}`,
            at: topLiked.liked_at,
          }
        : null,
      topViewed
        ? {
            title: `Viewed: ${safeStr(topViewed.product_name, "Product")}`,
            meta: `Viewed ${relativeWhen(topViewed.last_viewed_at)}`,
            at: topViewed.last_viewed_at,
          }
        : null,
      topRepeat
        ? {
            title: `Reordered: ${safeStr(topRepeat.product_name, "Product")}`,
            meta: `Last reordered ${when(topRepeat.last_order_at)}`,
            at: topRepeat.last_order_at,
          }
        : null,
    ]
      .filter(Boolean)
      .sort((a, b) => timeValue(b.at) - timeValue(a.at));

    return candidates[0] || null;
  }, [latestSearch, topLiked, topRepeat, topViewed]);

  const conversion = useMemo(() => {
    const searched = safeNumber(funnel?.searched, 0);
    const viewed = safeNumber(funnel?.viewed, 0);
    const liked = safeNumber(funnel?.liked, 0);
    const checkedOut = safeNumber(funnel?.checked_out, 0);
    const completed = safeNumber(funnel?.completed, 0);

    return {
      searchToView: searched > 0 ? (viewed / searched) * 100 : 0,
      viewToLike: viewed > 0 ? (liked / viewed) * 100 : 0,
      checkoutCompletion: checkedOut > 0 ? (completed / checkedOut) * 100 : 0,
    };
  }, [funnel]);

  const strongestSignal = useMemo(() => {
    if (topRepeat) {
      return {
        title: safeStr(topRepeat.product_name, "Ready to reorder"),
        subtitle: `${categoryLabel(topRepeat.category)} • ${safeStr(topRepeat.farmer_name, "Farmer")}`,
        meta: `${safeNumber(topRepeat.purchase_count, 0)} purchases • ${money(topRepeat.amount)}`,
      };
    }

    if (topLiked) {
      return {
        title: safeStr(topLiked.product_name, "Saved for later"),
        subtitle: `${categoryLabel(topLiked.category)} • ${safeStr(topLiked.farmer_name, "Farmer")}`,
        meta: `Saved ${relativeWhen(topLiked.liked_at)} • ${money(topLiked.price)}`,
      };
    }

    if (topViewed) {
      return {
        title: safeStr(topViewed.product_name, "Recently viewed"),
        subtitle: `${categoryLabel(topViewed.category)} • ${safeStr(topViewed.farmer_name, "Farmer")}`,
        meta: `${safeNumber(topViewed.views_count, 0)} view(s) • ${money(topViewed.price)}`,
      };
    }

    if (latestSearch) {
      return {
        title: safeStr(latestSearch.query, "Latest search"),
        subtitle: "Most recent visible search phrase.",
        meta: when(latestSearch.created_at),
      };
    }

    return {
      title: "Your shopping memory will appear here",
      subtitle: "Searches, views, likes, and reorders will gradually shape this workspace.",
      meta: "No strong signal yet",
    };
  }, [latestSearch, topLiked, topRepeat, topViewed]);

  const summaryLine = useMemo(() => {
    if (topRepeat) {
      return `${safeStr(topRepeat.product_name, "This item")} currently stands out as your clearest reorder signal.`;
    }
    if (topLiked) {
      return `${safeStr(topLiked.product_name, "A saved item")} is currently leading your saved-product interest.`;
    }
    if (topViewed) {
      return `${safeStr(topViewed.product_name, "A viewed item")} is currently leading your recent browsing attention.`;
    }
    return "This page becomes more useful as you search, view, like, and reorder products.";
  }, [topLiked, topRepeat, topViewed]);

  const conversionLine = useMemo(() => {
    const searched = safeNumber(funnel?.searched, 0);
    const completed = safeNumber(funnel?.completed, 0);

    if (searched > 0 || completed > 0) {
      return `${pct(conversion.searchToView)} of visible searches turned into views, and ${pct(
        conversion.checkoutCompletion
      )} of checkouts reached completion.`;
    }

    return "Shopping activity is still light, so conversion patterns are not strong yet.";
  }, [conversion, funnel]);

  const notes = useMemo(() => {
    const items = [];

    if (latestSearch) {
      items.push(`Latest search: “${safeStr(latestSearch.query, "—")}" on ${when(latestSearch.created_at)}.`);
    }
    if (likedProducts.length) {
      items.push(`${likedProducts.length} saved product(s) are available for quick rediscovery.`);
    }
    if (recentlyViewed.length) {
      items.push(`${recentlyViewed.length} product(s) have recent browsing attention.`);
    }
    if (repeatPurchases.length) {
      items.push(`${repeatPurchases.length} product(s) already look suitable for reordering.`);
    }

    return Array.from(new Set([...items, ...apiNotes])).slice(0, 4);
  }, [apiNotes, latestSearch, likedProducts.length, recentlyViewed.length, repeatPurchases.length]);

  const tabs = useMemo(
    () => [
      { key: "searches", label: "Searches", icon: Search, count: counts.searches },
      { key: "liked", label: "Saved items", icon: Heart, count: counts.liked },
      { key: "viewed", label: "Recently viewed", icon: Eye, count: counts.viewed },
      { key: "repeat", label: "Ready to reorder", icon: Repeat, count: counts.repeat },
    ],
    [counts]
  );

  const activeTabConfig = useMemo(
    () => tabs.find((tab) => tab.key === activeTab) || tabs[0],
    [activeTab, tabs]
  );

  const filteredSearches = useMemo(() => {
    const q = safeStr(memoryQuery, "").toLowerCase();
    if (!q) return previousSearches;
    return previousSearches.filter((entry) => safeStr(entry.query, "").toLowerCase().includes(q));
  }, [memoryQuery, previousSearches]);

  const filterProducts = useCallback(
    (rows) => {
      const q = safeStr(memoryQuery, "").toLowerCase();
      if (!q) return rows;

      return rows.filter((product) =>
        [product.product_name, product.category, product.farmer_name]
          .map((item) => safeStr(item, "").toLowerCase())
          .join(" ")
          .includes(q)
      );
    },
    [memoryQuery]
  );

  const filteredLiked = useMemo(() => filterProducts(likedProducts), [filterProducts, likedProducts]);
  const filteredViewed = useMemo(() => filterProducts(recentlyViewed), [filterProducts, recentlyViewed]);
  const filteredRepeat = useMemo(() => filterProducts(repeatPurchases), [filterProducts, repeatPurchases]);

  const visibleCount =
    activeTab === "searches"
      ? filteredSearches.length
      : activeTab === "liked"
      ? filteredLiked.length
      : activeTab === "viewed"
      ? filteredViewed.length
      : filteredRepeat.length;

  const totalCount = safeNumber(counts[activeTab], 0);

  const funnelRows = [
    { label: "Searched", value: funnel?.searched },
    { label: "Viewed", value: funnel?.viewed },
    { label: "Liked", value: funnel?.liked },
    { label: "Completed", value: funnel?.completed },
  ];

  const highlightRows = [
    topRepeat
      ? {
          icon: Repeat,
          label: "Top reorder signal",
          title: safeStr(topRepeat.product_name, "Ready to reorder"),
          meta: `${safeNumber(topRepeat.purchase_count, 0)} purchases • ${money(topRepeat.amount)}`,
        }
      : null,
    topLiked
      ? {
          icon: Heart,
          label: "Most recently saved",
          title: safeStr(topLiked.product_name, "Saved item"),
          meta: `${categoryLabel(topLiked.category)} • ${safeStr(topLiked.farmer_name, "Farmer")}`,
        }
      : null,
    topViewed
      ? {
          icon: Eye,
          label: "Most viewed item",
          title: safeStr(topViewed.product_name, "Viewed item"),
          meta: `${safeNumber(topViewed.views_count, 0)} view(s) • ${money(topViewed.price)}`,
        }
      : null,
    latestSearch
      ? {
          icon: Search,
          label: "Latest search",
          title: safeStr(latestSearch.query, "Latest search"),
          meta: when(latestSearch.created_at),
        }
      : null,
  ].filter(Boolean);

  const productGridClass =
    activeTab === "searches"
      ? "grid grid-cols-1 gap-3 lg:grid-cols-2"
      : "grid grid-cols-1 gap-3 md:grid-cols-2";

  if (loading) {
    return (
      <div className="space-y-4">
        <div className="rounded-[28px] border border-[#D8F3DC] bg-white p-6 shadow-sm">
          <div className="text-xs font-bold uppercase tracking-[0.18em] text-[#2D6A4F]">
            Saved & Search
          </div>
          <div className="mt-2 text-2xl font-black tracking-tight text-slate-900">
            Loading saved and search workspace…
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-5">
      <section className="overflow-hidden rounded-[30px] border border-[#D8F3DC] bg-white shadow-sm">
        <div className="bg-gradient-to-r from-[#F7FBF8] via-white to-[#EEF8F2] p-6">
          <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
            <div className="max-w-4xl">
              <div className="text-xs font-bold uppercase tracking-[0.18em] text-[#2D6A4F]">
                Customer Shopping Memory
              </div>
              <h1 className="mt-2 text-[30px] font-black tracking-tight text-slate-900">
                Saved items & search activity
              </h1>
              <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">
                Review what you searched for, what you saved, what you viewed recently, and what
                already looks ready to reorder from one customer-friendly workspace.
              </p>
            </div>

            <button
              type="button"
              onClick={() => loadWorkspace({ silent: true })}
              className="inline-flex items-center gap-2 self-start rounded-2xl border border-[#D8F3DC] bg-white px-4 py-2 text-sm font-semibold text-slate-800 shadow-sm transition hover:bg-[#F8FCF9]"
            >
              <RefreshCcw className={`h-4 w-4 ${refreshing ? "animate-spin" : ""}`} />
              {refreshing ? "Refreshing…" : "Refresh workspace"}
            </button>
          </div>

          {error ? (
            <div className="mt-4 rounded-2xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-800">
              {error}
            </div>
          ) : null}

          <div className="mt-5 grid grid-cols-1 gap-4 xl:grid-cols-3">
            <SummaryCard
              eyebrow="Top signal"
              title={strongestSignal.title}
              body={`${strongestSignal.subtitle} ${strongestSignal.meta}`}
              icon={Sparkles}
            />
            <SummaryCard
              eyebrow="Latest moment"
              title={latestMoment?.title || "No recent shopping activity yet"}
              body={
                latestMoment?.meta ||
                "Your latest search, saved item, or viewed product will appear here."
              }
              icon={Clock3}
            />
            <SummaryCard
              eyebrow="Customer view"
              title="A clearer shopping summary"
              body={`${summaryLine} ${conversionLine}`}
              icon={BadgeCheck}
            />
          </div>
        </div>
      </section>

      <section className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
        <StatCard
          icon={Search}
          label="Searches"
          value={safeNumber(summary.searches_count, 0)}
          subtext="Visible search memory"
        />
        <StatCard
          icon={Heart}
          label="Saved items"
          value={safeNumber(summary.likes_count, 0)}
          subtext="Products you kept for later"
        />
        <StatCard
          icon={Eye}
          label="Recently viewed"
          value={safeNumber(summary.viewed_count, 0)}
          subtext="Browsing signals now visible"
        />
        <StatCard
          icon={Repeat}
          label="Ready to reorder"
          value={safeNumber(summary.repeat_products_count, 0)}
          subtext="Products with repeat-buy history"
        />
      </section>

      <div className="grid grid-cols-1 gap-5 xl:grid-cols-[minmax(0,1.45fr)_360px]">
        <SectionCard
          title="Explore your saved activity"
          subtitle="Switch between searches, saved items, recently viewed products, and reorder signals."
          actions={
            <div className="rounded-full border border-[#D8F3DC] bg-[#F7FBF8] px-3 py-1 text-xs font-bold text-slate-700">
              Showing {visibleCount} of {totalCount}
            </div>
          }
        >
          <div className="space-y-4">
            <div className="flex flex-wrap gap-2">
              {tabs.map((tab) => (
                <TabButton
                  key={tab.key}
                  active={activeTab === tab.key}
                  onClick={() => setActiveTab(tab.key)}
                  icon={tab.icon}
                  label={tab.label}
                  count={tab.count}
                />
              ))}
            </div>

            <div className="flex flex-col gap-3 lg:flex-row lg:items-center">
              <div className="flex min-w-0 flex-1 items-center gap-2 rounded-2xl border border-slate-200 bg-white px-3 shadow-sm">
                <Search className="h-4 w-4 text-slate-400" />
                <input
                  value={memoryQuery}
                  onChange={(e) => setMemoryQuery(e.target.value)}
                  placeholder={`Filter ${activeTabConfig?.label?.toLowerCase() || "items"}`}
                  className="h-11 w-full bg-transparent text-sm text-slate-800 outline-none placeholder:text-slate-400"
                />
                {memoryQuery ? (
                  <button
                    type="button"
                    onClick={() => setMemoryQuery("")}
                    className="inline-flex h-8 w-8 items-center justify-center rounded-full text-slate-400 transition hover:bg-slate-100 hover:text-slate-600"
                    aria-label="Clear filter"
                  >
                    <X className="h-4 w-4" />
                  </button>
                ) : null}
              </div>

              <div className="inline-flex items-center gap-2 self-start rounded-full border border-slate-200 bg-slate-50 px-3 py-2 text-xs font-semibold text-slate-600">
                <ShoppingBag className="h-3.5 w-3.5" />
                {activeTabConfig?.label}
              </div>
            </div>

            {activeTab === "searches" ? (
              filteredSearches.length ? (
                <div className={productGridClass}>
                  {filteredSearches.map((entry, index) => (
                    <SearchMemoryCard
                      key={`${entry.query}-${index}`}
                      query={safeStr(entry.query, "—")}
                      createdAt={entry.created_at}
                    />
                  ))}
                </div>
              ) : (
                <EmptyState
                  title="No search phrases match this filter"
                  body="Try a broader keyword or clear the filter to review your visible search activity."
                />
              )
            ) : null}

            {activeTab === "liked" ? (
              filteredLiked.length ? (
                <div className={productGridClass}>
                  {filteredLiked.map((product, index) => (
                    <ProductSignalCard
                      key={`${product.product_id || product.product_name}-${index}`}
                      title={safeStr(product.product_name, "Product")}
                      category={product.category}
                      farmer={product.farmer_name}
                      primaryValue={money(product.price)}
                      primaryLabel="current price"
                      metaLine={`Saved on ${when(product.liked_at)}`}
                      accent="liked"
                    />
                  ))}
                </div>
              ) : (
                <EmptyState
                  title="No saved items match this filter"
                  body="Try a different keyword or clear the filter to review products you saved for later."
                />
              )
            ) : null}

            {activeTab === "viewed" ? (
              filteredViewed.length ? (
                <div className={productGridClass}>
                  {filteredViewed.map((product, index) => (
                    <ProductSignalCard
                      key={`${product.product_id || product.product_name}-${index}`}
                      title={safeStr(product.product_name, "Product")}
                      category={product.category}
                      farmer={product.farmer_name}
                      primaryValue={`${safeNumber(product.views_count, 0)}x`}
                      primaryLabel="views"
                      metaLine={`Last viewed ${when(product.last_viewed_at)} • ${money(product.price)}`}
                      accent="viewed"
                    />
                  ))}
                </div>
              ) : (
                <EmptyState
                  title="No recently viewed items match this filter"
                  body="Try a broader keyword or clear the filter to review recent browsing attention."
                />
              )
            ) : null}

            {activeTab === "repeat" ? (
              filteredRepeat.length ? (
                <div className={productGridClass}>
                  {filteredRepeat.map((product, index) => (
                    <ProductSignalCard
                      key={`${product.product_id || product.product_name}-${index}`}
                      title={safeStr(product.product_name, "Product")}
                      category={product.category}
                      farmer={product.farmer_name}
                      primaryValue={`${safeNumber(product.purchase_count, 0)}x`}
                      primaryLabel="purchases"
                      metaLine={`Last reordered ${when(product.last_order_at)} • ${money(product.amount)}`}
                      accent="repeat"
                    />
                  ))}
                </div>
              ) : (
                <EmptyState
                  title="No reorder candidates match this filter"
                  body="Try a broader keyword or clear the filter to review products that already show repeat-buy behaviour."
                />
              )
            ) : null}
          </div>
        </SectionCard>

        <div className="space-y-5 xl:sticky xl:top-24">
          <SectionCard
            title="Shopping highlights"
            subtitle="A quick customer-facing summary of what stands out right now."
          >
            <div className="space-y-3">
              {highlightRows.length ? (
                highlightRows.map((row, index) => (
                  <HighlightRow
                    key={`${row.label}-${row.title}-${index}`}
                    icon={row.icon}
                    label={row.label}
                    title={row.title}
                    meta={row.meta}
                  />
                ))
              ) : (
                <div className="rounded-2xl border border-[#E7F1EA] bg-[#F8FCF9] px-4 py-3 text-sm text-slate-500">
                  Highlights will appear as shopping activity grows.
                </div>
              )}
            </div>
          </SectionCard>

          <SectionCard
            title="Shopping funnel"
            subtitle="A simplified view of how discovery activity is progressing."
          >
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-3 xl:grid-cols-1 2xl:grid-cols-3">
              <MiniMetric
                label="Search → View"
                value={pct(conversion.searchToView)}
                helper="Searches that turned into views"
              />
              <MiniMetric
                label="View → Save"
                value={pct(conversion.viewToLike)}
                helper="Viewed items later saved"
              />
              <MiniMetric
                label="Completion"
                value={pct(conversion.checkoutCompletion)}
                helper="Checkouts that completed"
              />
            </div>

            <div className="mt-4 border-t border-[#EEF7F0] pt-4">
              <FunnelBars rows={funnelRows} />
            </div>
          </SectionCard>

          <SectionCard
            title="Quick notes"
            subtitle="Short explanations that keep the workspace understandable."
          >
            <div className="space-y-2.5">
              {notes.length ? (
                notes.map((note, index) => (
                  <div
                    key={`${note}-${index}`}
                    className="rounded-2xl border border-[#E7F1EA] bg-[#F8FCF9] px-4 py-3 text-sm leading-6 text-slate-700"
                  >
                    {note}
                  </div>
                ))
              ) : (
                <div className="rounded-2xl border border-[#E7F1EA] bg-[#F8FCF9] px-4 py-3 text-sm text-slate-500">
                  Notes will appear as visible shopping signals become available.
                </div>
              )}
            </div>

            <div className="mt-4 inline-flex items-center gap-2 rounded-full border border-[#D8F3DC] bg-[#F7FBF8] px-3 py-2 text-xs font-semibold text-slate-600">
              <Star className="h-3.5 w-3.5 text-[#2D6A4F]" />
              Designed for customers, not admin review
              <ChevronRight className="h-3.5 w-3.5 text-slate-400" />
            </div>
          </SectionCard>
        </div>
      </div>
    </div>
  );
}