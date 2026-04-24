// ============================================================================
// frontend/src/components/customer/CustomerFiltersSidebar.jsx
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Marketplace filters panel for customer dashboard.
//
// RESPONSIBILITIES:
//   • Render secondary marketplace filters for the customer dashboard
//   • Support both modern state-object props and legacy explicit handler props
//   • Avoid crashing when optional handlers are missing
//   • Optionally hide the sidebar search so the page can keep a single
//     primary search input in the command bar
//
// MASTER'S-LEVEL CLEANUP UPDATE:
//   ✅ Backward + forward compatible props support
//      - Works with either:
//          • filters + setFilters
//          • explicit handlers (onCategoryChange, onSortChange, etc.)
//   ✅ Prevents runtime crash when setFilters is missing/non-function
//   ✅ Supports location options from `locations` OR `locationOptions`
//   ✅ Supports `showSearch={false}` so the page can remove duplicate search
//   ✅ Keeps this component focused on secondary filters only
// ============================================================================

import React, { useCallback, useMemo } from "react";
import { Search, Tag, MapPin, SlidersHorizontal, X } from "lucide-react";

// ----------------------------------------------------------------------------
// Small styling helpers
// Keeping these as functions keeps the JSX cleaner and easier to maintain.
// ----------------------------------------------------------------------------
function labelCls() {
  return "mb-1 flex items-center gap-1.5 text-xs font-semibold text-slate-700";
}

function inputCls() {
  return "w-full rounded-xl border border-[#D0D7DE] bg-white px-3 py-2 text-sm text-slate-800 outline-none transition focus:border-[#93C5AA]";
}

// ----------------------------------------------------------------------------
// Small value helpers
// ----------------------------------------------------------------------------
function normalizeArray(values, fallback = []) {
  if (Array.isArray(values) && values.length > 0) return values;
  return fallback;
}

function asBool(v, fallback = false) {
  if (typeof v === "boolean") return v;
  return fallback;
}

export default function CustomerFiltersSidebar(props) {
  const {
    // Optional UI control:
    // When false, the page-level command bar becomes the only search input.
    showSearch = true,

    // Newer state-object shape
    filters,
    setFilters,

    // Legacy explicit props
    categories = ["All"],
    locationOptions,
    locations,
    selectedCategory = "All",
    selectedLocation = "All",
    minPrice = "",
    maxPrice = "",
    inStockOnly = true,
    sortBy = "relevance",
    query = "",
    onCategoryChange,
    onLocationChange,
    onMinPriceChange,
    onMaxPriceChange,
    onInStockOnlyChange,
    onSortChange,
    onQueryChange,
    onClear,
  } = props;

  // --------------------------------------------------------------------------
  // Resolve values from the modern `filters` object first.
  // If not provided, fall back to older explicit props.
  // This keeps the component compatible with both integration styles.
  // --------------------------------------------------------------------------
  const valueQuery = filters?.query ?? query ?? "";
  const valueCategory = filters?.category ?? selectedCategory ?? "All";
  const valueLocation = filters?.location ?? selectedLocation ?? "All";
  const valueMin = filters?.minPrice ?? minPrice ?? "";
  const valueMax = filters?.maxPrice ?? maxPrice ?? "";
  const valueInStock = asBool(filters?.inStockOnly ?? inStockOnly, true);
  const valueSort = filters?.sort ?? sortBy ?? "relevance";

  // Support both `locations` and `locationOptions`.
  // Always make sure "All" exists exactly once.
  const resolvedLocations = useMemo(() => {
    const locs = normalizeArray(locations, normalizeArray(locationOptions, ["All"]));
    const withAll = new Set(["All", ...locs.filter(Boolean)]);
    return [...withAll];
  }, [locations, locationOptions]);

  // --------------------------------------------------------------------------
  // Safe update helper
  // Priority:
  //   1) use setFilters if available
  //   2) otherwise call the matching explicit handler
  //
  // This prevents crashes when one integration style is missing.
  // --------------------------------------------------------------------------
  const safeUpdate = useCallback(
    (key, value, fallbackHandler) => {
      if (typeof setFilters === "function") {
        setFilters((prev) => ({
          ...(prev || {}),
          [key]: value,
        }));
        return;
      }

      if (typeof fallbackHandler === "function") {
        fallbackHandler(value);
      }
    },
    [setFilters]
  );

  // Clear all filters using the page-provided handler when available.
  // Fall back to local state-object update if the page did not provide onClear.
  const clearAll = () => {
    if (typeof onClear === "function") {
      onClear();
      return;
    }

    if (typeof setFilters === "function") {
      setFilters((prev) => ({
        ...(prev || {}),
        query: "",
        category: "All",
        location: "All",
        minPrice: "",
        maxPrice: "",
        inStockOnly: true,
        sort: "relevance",
      }));
    }
  };

  return (
    <aside className="rounded-2xl border border-[#D8F3DC] bg-white p-3 sm:p-4">
      {/* Small helper banner to guide users without cluttering the page */}
      <div className="mb-3 rounded-xl border border-[#B7E4C7] bg-[#F1FBF5] px-3 py-2 text-xs text-slate-700">
        Use filters to narrow results quickly.
      </div>

      {/* -------------------------------------------------------------------- */}
      {/* Search                                                                */}
      {/* Optional so the dashboard can keep a single top-level search field.   */}
      {/* -------------------------------------------------------------------- */}
      {showSearch ? (
        <div className="mb-3">
          <label className={labelCls()}>
            <Search className="h-3.5 w-3.5" />
            Search
          </label>
          <input
            type="text"
            value={valueQuery}
            onChange={(e) => safeUpdate("query", e.target.value, onQueryChange)}
            placeholder="Search products..."
            className={inputCls()}
          />
        </div>
      ) : null}

      {/* -------------------------------------------------------------------- */}
      {/* Category                                                              */}
      {/* -------------------------------------------------------------------- */}
      <div className="mb-3">
        <label className={labelCls()}>
          <Tag className="h-3.5 w-3.5" />
          Category
        </label>
        <select
          value={valueCategory}
          onChange={(e) => safeUpdate("category", e.target.value, onCategoryChange)}
          className={inputCls()}
        >
          {normalizeArray(categories, ["All"]).map((cat) => (
            <option key={String(cat)} value={String(cat)}>
              {String(cat)}
            </option>
          ))}
        </select>
      </div>

      {/* -------------------------------------------------------------------- */}
      {/* Location                                                              */}
      {/* -------------------------------------------------------------------- */}
      <div className="mb-3">
        <label className={labelCls()}>
          <MapPin className="h-3.5 w-3.5" />
          Location
        </label>
        <select
          value={valueLocation}
          onChange={(e) => safeUpdate("location", e.target.value, onLocationChange)}
          className={inputCls()}
        >
          {resolvedLocations.map((loc) => (
            <option key={String(loc)} value={String(loc)}>
              {String(loc)}
            </option>
          ))}
        </select>
      </div>

      {/* -------------------------------------------------------------------- */}
      {/* Price range                                                           */}
      {/* -------------------------------------------------------------------- */}
      <div className="mb-3">
        <label className={labelCls()}>Price range (N$)</label>
        <div className="grid grid-cols-2 gap-2">
          <input
            type="number"
            inputMode="decimal"
            min="0"
            value={valueMin}
            onChange={(e) => safeUpdate("minPrice", e.target.value, onMinPriceChange)}
            placeholder="Min"
            className={inputCls()}
          />
          <input
            type="number"
            inputMode="decimal"
            min="0"
            value={valueMax}
            onChange={(e) => safeUpdate("maxPrice", e.target.value, onMaxPriceChange)}
            placeholder="Max"
            className={inputCls()}
          />
        </div>
      </div>

      {/* -------------------------------------------------------------------- */}
      {/* In-stock only                                                         */}
      {/* -------------------------------------------------------------------- */}
      <div className="mb-3">
        <label className="inline-flex w-full cursor-pointer items-center gap-2 rounded-xl border border-[#D0D7DE] bg-white px-3 py-2 text-sm text-slate-800">
          <input
            type="checkbox"
            checked={!!valueInStock}
            onChange={(e) =>
              safeUpdate("inStockOnly", e.target.checked, onInStockOnlyChange)
            }
          />
          In stock only
        </label>
      </div>

      {/* -------------------------------------------------------------------- */}
      {/* Sort                                                                  */}
      {/* -------------------------------------------------------------------- */}
      <div className="mb-4">
        <label className={labelCls()}>
          <SlidersHorizontal className="h-3.5 w-3.5" />
          Sort
        </label>
        <select
          value={valueSort}
          onChange={(e) => safeUpdate("sort", e.target.value, onSortChange)}
          className={inputCls()}
        >
          <option value="relevance">Relevance</option>
          <option value="price_asc">Price: Low to high</option>
          <option value="price_desc">Price: High to low</option>
          <option value="name_asc">Name: A to Z</option>
          <option value="name_desc">Name: Z to A</option>
          <option value="stock_desc">Stock: High to low</option>
        </select>
      </div>

      {/* Clear all filters */}
      <button
        type="button"
        onClick={clearAll}
        className="inline-flex w-full items-center justify-center gap-2 rounded-xl border border-[#D0D7DE] bg-white px-3 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50"
      >
        <X className="h-4 w-4" />
        Clear filters
      </button>
    </aside>
  );
}