// ============================================================================
// frontend/src/components/customer/ProductCard.jsx
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Premium Marketplace product card (neutral, modern, not green-dominated).
//
// RESPONSIBILITIES:
//   • Show product image, name, price/unit
//   • Show farmer + location meta
//   • Optional rating + stock badge
//   • Click card -> open Quick View modal
//   • Like button toggles favorite without opening modal
//
// IMAGE RULES:
//   • Uses shared resolver from utils/productImage
//   • Final fallback is /Assets/product_images/default.jpg
// ============================================================================

import React, { useMemo, useState } from "react";
import { Heart, MapPin, Store, Star } from "lucide-react";

import { DEFAULT_PRODUCT_IMG, resolveProductImageCandidates } from "../../utils/productImage";

function formatMoney(n) {
  const v = Number(n || 0);
  return `N$ ${v.toFixed(2)}`;
}

function safeText(x, fallback = "") {
  const s = String(x ?? "").trim();
  return s ? s : fallback;
}

export default function ProductCard({ product, onOpen, liked = false, onToggleLike }) {
  const name = safeText(product?.name || product?.product_name || product?.title, "Product");

  const price = product?.price ?? product?.unit_price ?? 0;
  const unit = safeText(product?.unit || product?.selling_unit || product?.uom, "");
  const farmer = safeText(product?.farmer_name || product?.farmerName || product?.seller, "");
  const location = safeText(product?.location || product?.region || product?.farmer_location, "");

  const candidates = useMemo(() => {
    const chain = resolveProductImageCandidates(product || {});
    if (!chain.length) return [DEFAULT_PRODUCT_IMG];
    return chain;
  }, [product]);

  // Fallback rotation handler
  const [imgIndex, setImgIndex] = useState(0);
  const safeIdx = Math.max(0, Math.min(imgIndex, candidates.length - 1));
  const imageSrc = candidates[safeIdx] || DEFAULT_PRODUCT_IMG;

  const rating = Number(product?.rating ?? product?.avg_rating ?? NaN);
  const ratingCount = Number(product?.rating_count ?? product?.reviews ?? NaN);

  const stockQty = product?.stock ?? product?.stock_qty ?? product?.quantity_available ?? product?.quantity ?? null;
  const stockLabel =
    stockQty == null
      ? null
      : stockQty <= 0
      ? "Out of stock"
      : stockQty <= 5
      ? "Low stock"
      : "In stock";

  const badgeClass =
    stockLabel === "In stock"
      ? "bg-emerald-50 text-emerald-800 border-emerald-100"
      : stockLabel === "Low stock"
      ? "bg-amber-50 text-amber-800 border-amber-100"
      : "bg-rose-50 text-rose-800 border-rose-100";

  return (
    <div
      className="group rounded-2xl border border-[#E6E8EF] bg-white shadow-sm transition hover:shadow-md cursor-pointer overflow-hidden"
      role="button"
      tabIndex={0}
      onClick={() => onOpen?.(product)}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") onOpen?.(product);
      }}
      aria-label={`Open quick view for ${name}`}
    >
      {/* IMAGE */}
      <div className="relative bg-[#F7F8FA] border-b border-[#E6E8EF]">
        <div className="aspect-[4/3] w-full overflow-hidden">
          <img
            src={imageSrc}
            alt={name}
            className="h-full w-full object-cover transition group-hover:scale-[1.02]"
            onError={() => {
              setImgIndex((i) => Math.min(i + 1, candidates.length - 1));
            }}
          />
        </div>

        {/* LIKE */}
        <button
          type="button"
          className={[
            "absolute top-3 right-3 h-10 w-10 rounded-xl border flex items-center justify-center transition",
            liked
              ? "border-rose-200 bg-rose-50 text-rose-600"
              : "border-[#E6E8EF] bg-white/90 text-slate-700 hover:bg-white",
          ].join(" ")}
          aria-label={liked ? "Remove from favorites" : "Add to favorites"}
          onClick={(e) => {
            e.stopPropagation();
            onToggleLike?.(product);
          }}
        >
          <Heart className="h-5 w-5" />
        </button>

        {/* STOCK BADGE */}
        {stockLabel ? (
          <div
            className={`absolute left-3 top-3 px-3 py-1.5 rounded-full border text-xs font-bold ${badgeClass}`}
          >
            {stockLabel}
          </div>
        ) : null}
      </div>

      {/* CONTENT */}
      <div className="p-4">
        <div className="flex items-start justify-between gap-2">
          <div className="min-w-0">
            <div className="text-sm font-extrabold text-slate-900 line-clamp-2" title={name}>
              {name}
            </div>

            <div className="text-xs text-slate-600 mt-1 flex items-center gap-2">
              {farmer ? (
                <span className="inline-flex items-center gap-1">
                  <Store className="h-4 w-4" />
                  <span className="font-semibold text-slate-800">{farmer}</span>
                </span>
              ) : null}
              {location ? (
                <span className="inline-flex items-center gap-1">
                  <MapPin className="h-4 w-4" />
                  {location}
                </span>
              ) : null}
            </div>
          </div>

          <div className="text-right">
            <div className="text-sm font-extrabold text-slate-900">{formatMoney(price)}</div>
            {unit ? <div className="text-xs font-semibold text-slate-500">/ {unit}</div> : null}
          </div>
        </div>

        {/* RATING */}
        {Number.isFinite(rating) ? (
          <div className="mt-3 flex items-center gap-2 text-xs text-slate-600">
            <Star className="h-4 w-4 text-amber-500" />
            <span className="font-bold text-slate-800">{rating.toFixed(1)}</span>
            {Number.isFinite(ratingCount) ? <span>({ratingCount})</span> : null}
          </div>
        ) : (
          <div className="mt-3 text-xs text-slate-500">No ratings yet</div>
        )}
      </div>
    </div>
  );
}
