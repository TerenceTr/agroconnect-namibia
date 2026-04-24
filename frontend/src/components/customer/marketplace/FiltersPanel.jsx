// ============================================================================
// frontend/src/components/customer/marketplace/FiltersPanel.jsx
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Sticky filters column for the Customer Marketplace.
//
// RESPONSIBILITIES:
//   • Search, Category, Location, Price range, In-stock toggle, Sort
//   • Active filter chips + clear all
//   • Mobile support: optional close button
//
// DESIGN:
//   Neutral surface + subtle borders. Green used only for small accents.
// ============================================================================

import React, { useMemo } from "react";
import { Search, X, SlidersHorizontal } from "lucide-react";
import Card, { CardHeader, CardTitle, CardContent } from "../../ui/Card";

function safeArray(x) {
  return Array.isArray(x) ? x : [];
}

function uniqueSorted(values) {
  const set = new Set(values.filter(Boolean));
  return Array.from(set).sort((a, b) => String(a).localeCompare(String(b)));
}

export default function FiltersPanel({ products, filters, setFilters, onCloseMobile = null }) {
  const categories = useMemo(() => {
    const list = safeArray(products).map(
      (p) => p?.category ?? p?.type ?? p?.product_type ?? p?.group ?? "Other"
    );
    return ["All", ...uniqueSorted(list)];
  }, [products]);

  const locations = useMemo(() => {
    const list = safeArray(products).flatMap((p) => [p?.location, p?.region]);
    return ["All", ...uniqueSorted(list)];
  }, [products]);

  const activeChips = useMemo(() => {
    const chips = [];
    if ((filters.q || "").trim()) chips.push({ key: "q", label: `Search: “${filters.q.trim()}”` });
    if (filters.category !== "All") chips.push({ key: "category", label: `Category: ${filters.category}` });
    if (filters.location !== "All") chips.push({ key: "location", label: `Location: ${filters.location}` });
    if ((filters.minPrice || "").trim()) chips.push({ key: "minPrice", label: `Min: ${filters.minPrice}` });
    if ((filters.maxPrice || "").trim()) chips.push({ key: "maxPrice", label: `Max: ${filters.maxPrice}` });
    if (filters.inStockOnly) chips.push({ key: "inStockOnly", label: "In stock" });
    if (filters.sort && filters.sort !== "relevance") {
      const map = {
        price_asc: "Price ↑",
        price_desc: "Price ↓",
        rating: "Rating",
        newest: "Newest",
      };
      chips.push({ key: "sort", label: `Sort: ${map[filters.sort] || filters.sort}` });
    }
    return chips;
  }, [filters]);

  function clearAll() {
    setFilters((f) => ({
      ...f,
      q: "",
      category: "All",
      location: "All",
      minPrice: "",
      maxPrice: "",
      inStockOnly: false,
      sort: "relevance",
    }));
  }

  return (
    <Card className="rounded-2xl border border-[#E6E8EF] bg-white shadow-sm">
      <CardHeader>
        <CardTitle>
          <div className="flex items-center justify-between">
            <div className="inline-flex items-center gap-2">
              <SlidersHorizontal className="h-4 w-4 text-[#1F7A4D]" />
              <span className="text-base font-extrabold text-[#111827]">Filters</span>
            </div>

            {onCloseMobile && (
              <button
                type="button"
                onClick={onCloseMobile}
                className="h-9 w-9 rounded-xl border border-[#E6E8EF] bg-white hover:bg-slate-50 inline-flex items-center justify-center"
                aria-label="Close filters panel"
              >
                <X className="h-4 w-4 text-slate-700" />
              </button>
            )}
          </div>
        </CardTitle>
      </CardHeader>

      <CardContent className="space-y-4">
        {/* Search */}
        <div>
          <div className="text-xs font-semibold text-slate-500 mb-2">Search</div>
          <div className="rounded-2xl border border-[#E6E8EF] bg-white px-3 h-10 flex items-center gap-2">
            <Search className="h-4 w-4 text-slate-400" />
            <input
              value={filters.q}
              onChange={(e) => setFilters((f) => ({ ...f, q: e.target.value }))}
              className="w-full outline-none text-sm text-[#111827]"
              placeholder="Search products..."
              aria-label="Search products"
            />
          </div>
        </div>

        {/* Category */}
        <div>
          <div className="text-xs font-semibold text-slate-500 mb-2">Category</div>
          <select
            value={filters.category}
            onChange={(e) => setFilters((f) => ({ ...f, category: e.target.value }))}
            className="w-full h-10 rounded-2xl border border-[#E6E8EF] bg-white px-3 text-sm text-[#111827] outline-none"
            aria-label="Category filter"
          >
            {categories.map((c) => (
              <option key={String(c)} value={c}>
                {c}
              </option>
            ))}
          </select>
        </div>

        {/* Location */}
        <div>
          <div className="text-xs font-semibold text-slate-500 mb-2">Location</div>
          <select
            value={filters.location}
            onChange={(e) => setFilters((f) => ({ ...f, location: e.target.value }))}
            className="w-full h-10 rounded-2xl border border-[#E6E8EF] bg-white px-3 text-sm text-[#111827] outline-none"
            aria-label="Location filter"
          >
            {locations.map((l) => (
              <option key={String(l)} value={l}>
                {l}
              </option>
            ))}
          </select>
        </div>

        {/* Price */}
        <div>
          <div className="text-xs font-semibold text-slate-500 mb-2">Price range</div>
          <div className="grid grid-cols-2 gap-2">
            <input
              value={filters.minPrice}
              onChange={(e) => setFilters((f) => ({ ...f, minPrice: e.target.value }))}
              className="h-10 rounded-2xl border border-[#E6E8EF] bg-white px-3 text-sm text-[#111827] outline-none"
              placeholder="Min"
              inputMode="decimal"
              aria-label="Minimum price"
            />
            <input
              value={filters.maxPrice}
              onChange={(e) => setFilters((f) => ({ ...f, maxPrice: e.target.value }))}
              className="h-10 rounded-2xl border border-[#E6E8EF] bg-white px-3 text-sm text-[#111827] outline-none"
              placeholder="Max"
              inputMode="decimal"
              aria-label="Maximum price"
            />
          </div>
        </div>

        {/* In stock */}
        <div className="flex items-center justify-between">
          <div>
            <div className="text-sm font-semibold text-[#111827]">In stock only</div>
            <div className="text-xs text-[#6B7280]">Hide out-of-stock items</div>
          </div>
          <button
            type="button"
            onClick={() => setFilters((f) => ({ ...f, inStockOnly: !f.inStockOnly }))}
            className={[
              "h-9 w-16 rounded-2xl border transition relative",
              filters.inStockOnly
                ? "bg-[#1F7A4D] border-[#1F7A4D]"
                : "bg-white border-[#E6E8EF]",
            ].join(" ")}
            role="switch"
            aria-checked={filters.inStockOnly}
            aria-label="Toggle in stock only"
          >
            <span
              className={[
                "absolute top-1/2 -translate-y-1/2 h-7 w-7 rounded-xl bg-white shadow-sm transition",
                filters.inStockOnly ? "right-1" : "left-1",
              ].join(" ")}
            />
          </button>
        </div>

        {/* Sort */}
        <div>
          <div className="text-xs font-semibold text-slate-500 mb-2">Sort</div>
          <select
            value={filters.sort}
            onChange={(e) => setFilters((f) => ({ ...f, sort: e.target.value }))}
            className="w-full h-10 rounded-2xl border border-[#E6E8EF] bg-white px-3 text-sm text-[#111827] outline-none"
            aria-label="Sort products"
          >
            <option value="relevance">Relevance</option>
            <option value="price_asc">Price: low → high</option>
            <option value="price_desc">Price: high → low</option>
            <option value="rating">Rating</option>
            <option value="newest">Newest</option>
          </select>
        </div>

        {/* Active chips */}
        {activeChips.length > 0 && (
          <div>
            <div className="flex items-center justify-between mb-2">
              <div className="text-xs font-semibold text-slate-500">Active filters</div>
              <button
                type="button"
                onClick={clearAll}
                className="text-xs font-semibold text-[#1F7A4D] hover:underline"
              >
                Clear all
              </button>
            </div>

            <div className="flex flex-wrap gap-2">
              {activeChips.map((c) => (
                <span
                  key={c.key}
                  className="inline-flex items-center gap-2 px-3 py-1 rounded-2xl border border-[#E6E8EF] bg-[#F7F8FA] text-xs font-semibold text-slate-700"
                >
                  {c.label}
                  <button
                    type="button"
                    className="h-5 w-5 rounded-full hover:bg-slate-200 inline-flex items-center justify-center"
                    aria-label={`Remove filter: ${c.label}`}
                    onClick={() =>
                      setFilters((f) => {
                        const next = { ...f };
                        if (c.key === "q") next.q = "";
                        if (c.key === "category") next.category = "All";
                        if (c.key === "location") next.location = "All";
                        if (c.key === "minPrice") next.minPrice = "";
                        if (c.key === "maxPrice") next.maxPrice = "";
                        if (c.key === "inStockOnly") next.inStockOnly = false;
                        if (c.key === "sort") next.sort = "relevance";
                        return next;
                      })
                    }
                  >
                    <X className="h-3 w-3" />
                  </button>
                </span>
              ))}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
