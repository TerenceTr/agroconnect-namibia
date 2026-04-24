// ============================================================================
// frontend/src/components/customer/marketplace/ProductCardMarketplace.jsx
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Premium marketplace product card for the customer dashboard.
//
// THIS UPDATE:
//   ✅ Captures the clicked card position and click coordinates
//   ✅ Sends triggerContext to the quick-view open handler
//   ✅ Keeps current premium card design intact
// ============================================================================

import React, { useEffect, useMemo, useRef, useState } from "react";
import {
  Heart,
  Star,
  Eye,
  ShoppingCart,
  MapPin,
  ImageOff,
  Package,
  Store,
} from "lucide-react";
import {
  DEFAULT_PRODUCT_IMG,
  resolvePrimaryProductImage,
  resolveProductImageCandidates,
} from "../../../utils/productImage";

// ----------------------------------------------------------------------------
// Small helpers
// ----------------------------------------------------------------------------
function safeNumber(x, fallback = 0) {
  const n = Number(x);
  return Number.isFinite(n) ? n : fallback;
}

function clampRating(value) {
  const n = Math.round(safeNumber(value, 0));
  return Math.max(0, Math.min(5, n));
}

function getProductId(product) {
  return product?.product_id ?? product?.id ?? product?.uuid ?? null;
}

function getProductName(product) {
  return product?.name ?? product?.product_name ?? product?.title ?? "Unnamed product";
}

function getProductCategory(product) {
  return (
    product?.category_name ??
    product?.category ??
    product?.product_category ??
    "Other"
  );
}

function getFarmerName(product) {
  return (
    product?.farmer_name ||
    product?.farmer?.full_name ||
    product?.farmer?.name ||
    product?.seller_name ||
    "Farmer"
  );
}

function getLocation(product) {
  return (
    product?.location ||
    product?.farmer_location ||
    product?.farmer?.location ||
    product?.town ||
    product?.city ||
    "—"
  );
}

function formatMoney(value) {
  return `N$ ${safeNumber(value, 0).toFixed(2)}`;
}

function stockTone(inStock, numericStock) {
  if (!inStock) return "border-rose-200 bg-rose-50 text-rose-700";
  if (numericStock > 0 && numericStock <= 10) {
    return "border-amber-200 bg-amber-50 text-amber-700";
  }
  return "border-emerald-200 bg-emerald-50 text-emerald-700";
}

function stockLabel(inStock, numericStock) {
  if (!inStock) return "Out of stock";
  if (numericStock > 0 && numericStock <= 10) return "Low stock";
  return "In stock";
}

function InfoChip({ icon: Icon, children, tone = "default" }) {
  const toneClass =
    tone === "stock"
      ? "border-emerald-200 bg-emerald-50 text-emerald-800"
      : tone === "new"
        ? "border-sky-200 bg-sky-50 text-sky-800"
        : "border-slate-200 bg-white/90 text-slate-700";

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[11px] font-extrabold backdrop-blur ${toneClass}`}
    >
      {Icon ? <Icon className="h-3.5 w-3.5" /> : null}
      <span>{children}</span>
    </span>
  );
}

export default function ProductCardMarketplace({
  product,
  onClick,
  onQuickView,
  onAddToCart,
  onLikeToggle,

  liked,
  isLiked,
  myRating = 0,
  ratingSummary = { average: 0, count: 0 },
  isNew = false,
  likeBusy = false,
}) {
  const cardRef = useRef(null);

  const productId = useMemo(() => String(getProductId(product) ?? ""), [product]);
  const name = useMemo(() => getProductName(product), [product]);
  const category = useMemo(() => getProductCategory(product), [product]);
  const farmerName = useMemo(() => getFarmerName(product), [product]);
  const location = useMemo(() => getLocation(product), [product]);

  const price = useMemo(
    () => safeNumber(product?.price ?? product?.unit_price, 0),
    [product]
  );

  const unit = product?.unit || product?.unit_name || "";
  const stock = product?.stock_quantity ?? product?.stock ?? product?.quantity ?? null;
  const numericStock = safeNumber(stock, 0);
  const inStock = stock == null ? true : numericStock > 0;

  const avgRating = safeNumber(ratingSummary?.average, 0);
  const ratingCount = Math.max(0, Math.round(safeNumber(ratingSummary?.count, 0)));
  const currentMyRating = clampRating(myRating);

  const controlledLiked = typeof liked === "boolean" ? liked : isLiked;
  const [localLiked, setLocalLiked] = useState(false);

  useEffect(() => {
    if (typeof controlledLiked === "boolean") {
      setLocalLiked(controlledLiked);
    }
  }, [controlledLiked]);

  const resolvedLiked = typeof controlledLiked === "boolean" ? controlledLiked : localLiked;

  const primaryImage = useMemo(
    () => resolvePrimaryProductImage(product || {}),
    [product]
  );

  const imgCandidates = useMemo(() => {
    const chain = resolveProductImageCandidates(product || {});
    return [primaryImage, ...chain.filter((src) => src !== primaryImage)];
  }, [product, primaryImage]);
  const [imgIdx, setImgIdx] = useState(0);

  useEffect(() => {
    setImgIdx(0);
  }, [productId, product?.image_url, product?.image, product?.photo_url]);

  const imgSrc = imgCandidates[imgIdx] || DEFAULT_PRODUCT_IMG;
  const maxImgIdx = Math.max(0, imgCandidates.length - 1);

  // --------------------------------------------------------------------------
  // Build viewport-aware context for anchored quick view placement
  // --------------------------------------------------------------------------
  function buildTriggerContext(eventLike = null) {
    const rect = cardRef.current?.getBoundingClientRect?.();
    if (!rect) return null;

    const clickX =
      typeof eventLike?.clientX === "number"
        ? eventLike.clientX
        : rect.left + rect.width / 2;

    const clickY =
      typeof eventLike?.clientY === "number"
        ? eventLike.clientY
        : rect.top + Math.min(140, rect.height / 2);

    return {
      rect: {
        left: rect.left,
        top: rect.top,
        right: rect.right,
        bottom: rect.bottom,
        width: rect.width,
        height: rect.height,
      },
      clickX,
      clickY,
      viewportWidth: window.innerWidth,
      viewportHeight: window.innerHeight,
      scrollX: window.scrollX,
      scrollY: window.scrollY,
    };
  }

  const openCard = (eventLike = null) => {
    const triggerContext = buildTriggerContext(eventLike);
    (onQuickView || onClick)?.(product, triggerContext);
  };

  const handleCardKeyDown = (e) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      openCard();
    }
  };

  const handleLike = (e) => {
    e.stopPropagation();

    if (likeBusy) return;

    if (typeof controlledLiked !== "boolean") {
      setLocalLiked((prev) => !prev);
    }

    onLikeToggle?.(product);
  };

  const handleQuickView = (e) => {
    e.stopPropagation();
    openCard(e);
  };

  const handleAddToCart = (e) => {
    e.stopPropagation();
    onAddToCart?.(product);
  };

  return (
    <article
      ref={cardRef}
      role="button"
      tabIndex={0}
      onClick={openCard}
      onKeyDown={handleCardKeyDown}
      className={[
        "group overflow-hidden rounded-[24px] border border-[#E6E8EF] bg-white text-left shadow-sm transition-all duration-200",
        "hover:-translate-y-[2px] hover:shadow-[0_10px_24px_rgba(15,23,42,0.08)]",
        "focus:outline-none focus:ring-2 focus:ring-[#1F7A4D]/25",
      ].join(" ")}
      aria-label={`Open quick view for ${name}`}
    >
      <div className="relative overflow-hidden border-b border-[#EEF1F4] bg-[linear-gradient(180deg,#F8FAFC_0%,#F3F4F6_100%)]">
        <div className="aspect-[4/3]">
          {imgSrc ? (
            <img
              src={imgSrc}
              alt={name}
              className="h-full w-full object-cover transition duration-300 group-hover:scale-[1.02]"
              loading="lazy"
              onError={() => setImgIdx((prev) => Math.min(prev + 1, maxImgIdx))}
            />
          ) : (
            <div className="flex h-full w-full items-center justify-center text-xs font-semibold text-[#6B7280]">
              <div className="flex flex-col items-center gap-1">
                <ImageOff className="h-5 w-5" />
                <span>No image</span>
              </div>
            </div>
          )}
        </div>

        <div className="absolute left-3 top-3 flex items-start gap-2">
          {isNew ? <InfoChip children="New" tone="new" /> : null}
        </div>

        <button
          type="button"
          onClick={handleLike}
          disabled={likeBusy}
          className="absolute right-3 top-3 inline-flex h-10 w-10 items-center justify-center rounded-2xl border border-[#E6E8EF] bg-white/90 shadow-sm transition hover:bg-white disabled:cursor-not-allowed disabled:opacity-60"
          aria-label={resolvedLiked ? "Remove from favorites" : "Add to favorites"}
          aria-pressed={resolvedLiked}
          title={resolvedLiked ? "Liked" : "Like"}
        >
          <Heart
            className={`h-4 w-4 transition ${
              resolvedLiked ? "fill-rose-600 text-rose-600" : "text-slate-700"
            }`}
          />
        </button>

        <div className="absolute bottom-3 left-3">
          <span
            className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[11px] font-extrabold shadow-sm backdrop-blur ${stockTone(
              inStock,
              numericStock
            )}`}
          >
            <Package className="h-3.5 w-3.5" />
            {stockLabel(inStock, numericStock)}
          </span>
        </div>
      </div>

      <div className="space-y-4 p-4">
        <div className="space-y-2">
          <div className="min-h-[50px]">
            <h3 className="line-clamp-2 text-[17px] font-black tracking-tight text-[#111827]">
              {name}
            </h3>
          </div>

          <div className="flex flex-wrap items-center gap-2 text-xs text-[#6B7280]">
            <span className="rounded-full border border-[#E6E8EF] bg-[#F8FAFC] px-2.5 py-1 font-semibold">
              {category}
            </span>
          </div>

          <div className="space-y-1.5 text-xs text-[#6B7280]">
            <div className="flex items-center gap-1.5">
              <Store className="h-3.5 w-3.5" />
              <span className="truncate font-medium">{farmerName}</span>
            </div>

            <div className="flex items-center gap-1.5">
              <MapPin className="h-3.5 w-3.5" />
              <span className="truncate">{location}</span>
            </div>
          </div>
        </div>

        <div className="rounded-2xl border border-[#EEF1F4] bg-[#FAFBFC] p-3">
          <div className="flex items-end justify-between gap-3">
            <div>
              <div className="text-[11px] font-semibold uppercase tracking-wide text-[#6B7280]">
                Price
              </div>
              <div className="mt-1 text-[16px] font-black text-[#111827]">
                {formatMoney(price)}
                {unit ? (
                  <span className="ml-1 text-[12px] font-semibold text-[#6B7280]">
                    / {unit}
                  </span>
                ) : null}
              </div>
            </div>

            <div className="text-right">
              <div className="text-[11px] font-semibold uppercase tracking-wide text-[#6B7280]">
                Stock
              </div>
              <div className="mt-1 text-[13px] font-bold text-[#111827]">
                {stock == null ? "Seller stock" : numericStock}
              </div>
            </div>
          </div>
        </div>

        <div className="rounded-2xl border border-[#EEF1F4] bg-white p-3">
          <div className="flex items-start justify-between gap-3">
            <div>
              <div className="text-[12px] font-extrabold text-[#111827]">
                {ratingCount > 0 ? avgRating.toFixed(1) : "Not rated yet"}
              </div>
              <div className="mt-1 text-[11px] text-[#6B7280]">
                Open Quick View to leave your rating.
              </div>
            </div>

            <div className="flex flex-col items-end gap-2">
              <div className="flex items-center gap-1">
                {Array.from({ length: 5 }).map((_, i) => {
                  const active = i < currentMyRating;
                  return (
                    <Star
                      key={`my-rating-${productId}-${i}`}
                      className={`h-3.5 w-3.5 ${
                        active ? "fill-amber-400 text-amber-400" : "text-slate-300"
                      }`}
                    />
                  );
                })}
              </div>

              <span className="rounded-full border border-[#E6E8EF] bg-[#F8FAFC] px-2.5 py-1 text-[11px] font-bold text-[#374151]">
                {ratingCount > 0 ? `${ratingCount} rating${ratingCount === 1 ? "" : "s"}` : "No ratings"}
              </span>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-2 gap-2">
          <button
            type="button"
            onClick={handleQuickView}
            className="inline-flex h-11 items-center justify-center gap-2 rounded-2xl border border-[#D9E0EA] bg-white px-4 text-sm font-bold text-[#374151] transition hover:bg-[#F8FAFC]"
          >
            <Eye className="h-4 w-4" />
            Quick View
          </button>

          <button
            type="button"
            onClick={handleAddToCart}
            className="inline-flex h-11 items-center justify-center gap-2 rounded-2xl bg-[#1F7A4D] px-4 text-sm font-black text-white transition hover:brightness-95"
          >
            <ShoppingCart className="h-4 w-4" />
            Add
          </button>
        </div>
      </div>
    </article>
  );
}