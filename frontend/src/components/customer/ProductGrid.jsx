// ============================================================================
// frontend/src/components/customer/ProductGrid.jsx
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Responsive marketplace product grid.
//
// RESPONSIBILIBILITIES:
//   • Render skeletons while loading
//   • Render simplified marketplace ProductCard tiles
//   • Grid columns adapt by screen width
//   • Stay compatible with older and newer marketplace props
//
// THIS UPDATE:
//   ✅ Forwards triggerContext from product cards to the page handler
//   ✅ Keeps quick-view opening anchored to the clicked card
//   ✅ Preserves all existing compatibility behavior
// ============================================================================

import React from "react";
import ProductCardMarketplace from "./marketplace/ProductCardMarketplace";

// ----------------------------------------------------------------------------
// Small numeric helpers
// ----------------------------------------------------------------------------
function asNumber(v, fallback = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

function clampRating(value) {
  const n = Math.round(asNumber(value, 0));
  if (!Number.isFinite(n)) return 0;
  return Math.max(0, Math.min(5, n));
}

// ----------------------------------------------------------------------------
// Product identity + seeded rating fallback helpers
// ----------------------------------------------------------------------------
function getProductId(product) {
  return product?.product_id ?? product?.id ?? product?.uuid ?? null;
}

function getSeedRatingSnapshot(product) {
  return {
    average: asNumber(
      product?.rating_avg ??
        product?.rating_average ??
        product?.average_rating ??
        product?.rating ??
        0,
      0
    ),
    count: Math.max(
      0,
      Math.round(
        asNumber(
          product?.rating_count ?? product?.ratings_count ?? product?.total_ratings ?? 0,
          0
        )
      )
    ),
  };
}

// ----------------------------------------------------------------------------
// Loading skeleton
// ----------------------------------------------------------------------------
function SkeletonCard() {
  return (
    <div className="overflow-hidden rounded-2xl border border-[#E6E8EF] bg-white shadow-sm">
      <div className="aspect-[4/3] animate-pulse bg-slate-100" />
      <div className="space-y-3 p-4">
        <div className="h-4 w-3/4 animate-pulse rounded bg-slate-100" />
        <div className="h-3 w-1/2 animate-pulse rounded bg-slate-100" />
        <div className="h-4 w-1/3 animate-pulse rounded bg-slate-100" />
        <div className="h-10 w-full animate-pulse rounded-xl bg-slate-100" />
      </div>
    </div>
  );
}

// ----------------------------------------------------------------------------
// Empty state text varies by feed so the user gets clearer feedback
// ----------------------------------------------------------------------------
function getEmptyStateMessage(activeFeed) {
  if (activeFeed === "liked") return "You have not liked any products in this view yet.";
  if (activeFeed === "rated") return "You have not rated any products in this view yet.";
  if (activeFeed === "new") return "No recent products match your current filters.";
  return "Try changing filters or clearing your search.";
}

export default function ProductGrid({
  products = [],
  loading = false,
  activeFeed = "all",

  // Quick view / card open compatibility
  onOpenQuickView,
  onOpen,
  onCardClick,

  // Like compatibility
  likedMap = {},
  likeBusyByProduct = {},
  onToggleLike,

  // Rating summary compatibility
  myRatingsByProduct = {},
  ratingSummaryByProduct = {},

  // Optional marketplace helpers
  isRecentProduct,
  onAddToCart,
}) {
  // Backward-compatible open handler:
  // newer pages can use onOpenQuickView, older code can still pass onOpen/onCardClick.
  const openHandler = onOpenQuickView || onOpen || onCardClick;

  // --------------------------------------------------------------------------
  // Loading state
  // --------------------------------------------------------------------------
  if (loading) {
    return (
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3">
        {Array.from({ length: 9 }).map((_, i) => (
          <SkeletonCard key={`skeleton-${i}`} />
        ))}
      </div>
    );
  }

  // --------------------------------------------------------------------------
  // Empty state
  // --------------------------------------------------------------------------
  if (!Array.isArray(products) || products.length === 0) {
    return (
      <div className="rounded-2xl border border-[#E6E8EF] bg-white p-8 text-center shadow-sm">
        <div className="text-sm font-extrabold text-slate-900">No products found</div>
        <div className="mt-1 text-sm text-slate-600">{getEmptyStateMessage(activeFeed)}</div>
      </div>
    );
  }

  // --------------------------------------------------------------------------
  // Product grid
  // --------------------------------------------------------------------------
  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-3">
      {products.map((product, idx) => {
        const id = String(getProductId(product) ?? `tmp-${idx}`);

        const ratingSummary =
          ratingSummaryByProduct?.[id] ?? getSeedRatingSnapshot(product);

        const myRating = clampRating(
          myRatingsByProduct?.[id] ?? product?.my_rating ?? 0
        );

        const liked = !!likedMap?.[id];
        const likeBusy = !!likeBusyByProduct?.[id];
        const isNew =
          typeof isRecentProduct === "function" ? !!isRecentProduct(product) : false;

        return (
          <ProductCardMarketplace
            key={id}
            product={product}
            isNew={isNew}
            liked={liked}
            likeBusy={likeBusy}
            myRating={myRating}
            ratingSummary={ratingSummary}
            // KEY FIX:
            // Forward both product and triggerContext so the quick view
            // can position near the clicked card.
            onClick={(p, triggerContext) =>
              openHandler?.(p ?? product, triggerContext ?? null)
            }
            onQuickView={(p, triggerContext) =>
              openHandler?.(p ?? product, triggerContext ?? null)
            }
            onLikeToggle={() => onToggleLike?.(product)}
            onAddToCart={() => onAddToCart?.(product)}
          />
        );
      })}
    </div>
  );
}