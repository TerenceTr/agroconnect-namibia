// ============================================================================
// frontend/src/components/customer/marketplace/ProductQuickViewModal.jsx
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Premium customer product quick-view modal / anchored preview.
//
// CONSISTENCY FIX IN THIS VERSION:
//   ✅ All desktop quick views now use ONE consistent flyout design
//   ✅ Opening position may change (right of card / below card), but layout stays the same
//   ✅ Fixed desktop preview width + stable visual hierarchy across products
//   ✅ No more "third card looks different from first and second card"
//   ✅ Background page scroll is locked while quick view is open
//   ✅ Modal content scrolls internally
//   ✅ Responsive fallback still centers modal on smaller screens
// ============================================================================

import React, { useEffect, useMemo, useRef, useState } from "react";
import {
  X,
  Heart,
  MapPin,
  User,
  Package,
  Star,
  ShoppingCart,
  Tag,
  ShieldCheck,
  ChevronLeft,
  ChevronRight,
  Phone,
  Layers3,
} from "lucide-react";

import QuantityStepper from "./QuantityStepper";
import * as customerApi from "../../../services/customerApi";
import {
  DEFAULT_PRODUCT_IMG,
  resolvePrimaryProductImage,
  resolveProductImageCandidates,
} from "../../../utils/productImage";

// ----------------------------------------------------------------------------
// Small helpers
// ----------------------------------------------------------------------------
function safeNumber(value, fallback = 0) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function clamp(value, min, max) {
  return Math.min(max, Math.max(min, value));
}

function clampRating(value) {
  const n = Math.round(safeNumber(value, 0));
  return Math.max(0, Math.min(5, n));
}

function getProductId(product) {
  return product?.product_id ?? product?.id ?? product?.uuid ?? null;
}

function getProductName(product) {
  return product?.name ?? product?.product_name ?? product?.title ?? "Product";
}

function getProductCategory(product) {
  return product?.category ?? product?.product_category ?? "Other";
}

function getProductDescription(product) {
  return (
    product?.description ||
    product?.about ||
    product?.details ||
    "No product description has been added yet."
  );
}

function getProductUnit(product) {
  return product?.unit ?? product?.unit_name ?? "";
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

function getFarmerPhone(product) {
  return product?.farmer_phone || product?.farmer?.phone || product?.seller_phone || "";
}

function getLocation(product) {
  return (
    product?.location ||
    product?.farmer_location ||
    product?.farmer?.location ||
    product?.town ||
    product?.city ||
    "Location not set"
  );
}

function getRegion(product) {
  return product?.region || product?.farmer_region || product?.farmer?.region || "";
}

function qtyPolicyFromUnit(unitRaw) {
  const unit = String(unitRaw || "").toLowerCase().trim();

  if (
    unit.includes("each") ||
    unit.includes("pack") ||
    unit.includes("tray") ||
    unit.includes("box") ||
    unit.includes("piece") ||
    unit.includes("unit")
  ) {
    return { min: 1, step: 1 };
  }

  if (
    unit.includes("kg") ||
    unit === "g" ||
    unit.includes("lit") ||
    unit === "l" ||
    unit === "ml"
  ) {
    return { min: 0.25, step: 0.25 };
  }

  return { min: 1, step: 1 };
}

function uniqStrings(values) {
  const seen = new Set();
  const out = [];

  for (const raw of values) {
    const s = String(raw || "").trim();
    if (!s) continue;
    if (seen.has(s)) continue;
    seen.add(s);
    out.push(s);
  }

  return out;
}

function safeParseJson(raw, fallback = null) {
  if (!raw || typeof raw !== "string") return fallback;
  try {
    return JSON.parse(raw);
  } catch {
    return fallback;
  }
}

function normalizeImageSource(raw) {
  const s = String(raw || "").trim();
  if (!s) return "";
  if (s === "[object Object]") return "";

  const looksLikeUrl =
    /^https?:\/\//i.test(s) ||
    s.startsWith("/") ||
    s.startsWith("uploads/") ||
    s.startsWith("api/") ||
    s.startsWith("data:image/") ||
    s.startsWith("blob:");

  const looksLikeImageFile = /\.(png|jpe?g|webp|gif|svg)(\?|#|$)/i.test(s);

  return looksLikeUrl || looksLikeImageFile ? s : "";
}

function collectGalleryImages(product) {
  if (!product || typeof product !== "object") return [];

  const gathered = [];

  const pushCandidate = (value) => {
    const normalized = normalizeImageSource(value);
    if (normalized) gathered.push(normalized);
  };

  pushCandidate(product?.image_url);
  pushCandidate(product?.image);
  pushCandidate(product?.photo_url);
  pushCandidate(product?.thumbnail_url);
  pushCandidate(product?.preview_image);

  const arrayLikeFields = [
    product?.images,
    product?.gallery,
    product?.gallery_images,
    product?.image_urls,
    product?.photos,
    product?.media,
  ];

  for (const field of arrayLikeFields) {
    if (!Array.isArray(field)) continue;

    for (const entry of field) {
      if (typeof entry === "string") {
        pushCandidate(entry);
        continue;
      }

      if (entry && typeof entry === "object") {
        pushCandidate(entry.url);
        pushCandidate(entry.src);
        pushCandidate(entry.image_url);
        pushCandidate(entry.image);
        pushCandidate(entry.photo_url);
        pushCandidate(entry.thumbnail_url);
      }
    }
  }

  const jsonGalleryCandidates = [
    product?.gallery_json,
    product?.images_json,
    product?.gallery_images_json,
  ];

  for (const raw of jsonGalleryCandidates) {
    const parsed = safeParseJson(raw, null);
    if (!Array.isArray(parsed)) continue;

    for (const entry of parsed) {
      if (typeof entry === "string") {
        pushCandidate(entry);
        continue;
      }

      if (entry && typeof entry === "object") {
        pushCandidate(entry.url);
        pushCandidate(entry.src);
        pushCandidate(entry.image_url);
        pushCandidate(entry.image);
        pushCandidate(entry.photo_url);
        pushCandidate(entry.thumbnail_url);
      }
    }
  }

  return uniqStrings(gathered).slice(0, 8);
}

function getMainImageFallbacks(product) {
  return uniqStrings(
    resolveProductImageCandidates(product || {})
      .map(normalizeImageSource)
      .filter(Boolean)
  );
}

function formatMoney(value) {
  return `N$ ${safeNumber(value, 0).toFixed(2)}`;
}

function unitPillLabel(unitRaw) {
  const unit = String(unitRaw || "").trim();
  return unit ? `Per ${unit}` : "Per item";
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

function infoChipClass(tone = "default") {
  if (tone === "success") {
    return "border-emerald-200 bg-emerald-50 text-emerald-800";
  }
  if (tone === "muted") {
    return "border-slate-200 bg-slate-50 text-slate-700";
  }
  return "border-white/85 bg-white/95 text-slate-700";
}

// ----------------------------------------------------------------------------
// Focus trap
// ----------------------------------------------------------------------------
function useFocusTrap(open, onClose) {
  const rootRef = useRef(null);
  const lastActiveRef = useRef(null);

  useEffect(() => {
    if (!open) return undefined;

    lastActiveRef.current = document.activeElement;

    const root = rootRef.current;
    if (!root) return undefined;

    const getFocusable = () =>
      Array.from(
        root.querySelectorAll(
          'button,[href],input,select,textarea,[tabindex]:not([tabindex="-1"])'
        )
      ).filter((el) => !el.hasAttribute("disabled"));

    const focusFirst = () => {
      const first = getFocusable()[0];
      if (first?.focus) first.focus();
    };

    const timer = window.setTimeout(focusFirst, 0);

    function onKeyDown(e) {
      if (e.key === "Escape") {
        e.preventDefault();
        onClose?.();
        return;
      }

      if (e.key !== "Tab") return;

      const items = getFocusable();
      if (!items.length) return;

      const first = items[0];
      const last = items[items.length - 1];

      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    }

    document.addEventListener("keydown", onKeyDown);

    return () => {
      window.clearTimeout(timer);
      document.removeEventListener("keydown", onKeyDown);

      const previous = lastActiveRef.current;
      if (previous?.focus) previous.focus();
    };
  }, [open, onClose]);

  return rootRef;
}

// ----------------------------------------------------------------------------
// Lock background scrolling while quick view is open
// ----------------------------------------------------------------------------
function usePageScrollLock(open) {
  useEffect(() => {
    if (!open || typeof document === "undefined") return undefined;

    const html = document.documentElement;
    const body = document.body;
    const root = document.getElementById("root");

    // ------------------------------------------------------------------------
    // SCROLL-LOCK FIX:
    // Quick View can overlap with other overlay surfaces such as the cart drawer.
    // A simple "set overflow hidden / restore overflow" approach is fragile
    // because whichever overlay unmounts last wins, which can leave the page in
    // the wrong scroll state.
    //
    // This modal now uses a small reference-counted lock for html/body/root so
    // the scroll state is only restored when the final quick-view lock releases.
    // ------------------------------------------------------------------------
    const current = Number(body.dataset.quickViewScrollLockCount || 0);

    if (current === 0) {
      body.dataset.quickViewPrevHtmlOverflow = html.style.overflow || "";
      body.dataset.quickViewPrevBodyOverflow = body.style.overflow || "";
      body.dataset.quickViewPrevRootOverflow = root?.style?.overflow || "";
    }

    html.style.overflow = "hidden";
    body.style.overflow = "hidden";
    if (root) root.style.overflow = "hidden";

    body.dataset.quickViewScrollLockCount = String(current + 1);

    return () => {
      const now = Number(body.dataset.quickViewScrollLockCount || 1);
      const next = Math.max(0, now - 1);

      if (next === 0) {
        html.style.overflow = body.dataset.quickViewPrevHtmlOverflow || "";
        body.style.overflow = body.dataset.quickViewPrevBodyOverflow || "";
        if (root) root.style.overflow = body.dataset.quickViewPrevRootOverflow || "";

        delete body.dataset.quickViewScrollLockCount;
        delete body.dataset.quickViewPrevHtmlOverflow;
        delete body.dataset.quickViewPrevBodyOverflow;
        delete body.dataset.quickViewPrevRootOverflow;
        return;
      }

      body.dataset.quickViewScrollLockCount = String(next);
    };
  }, [open]);
}

function IconInfoPill({ icon: Icon, children, tone = "muted" }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border px-3 py-1.5 text-xs font-semibold ${infoChipClass(
        tone
      )}`}
    >
      {Icon ? <Icon className="h-3.5 w-3.5" /> : null}
      <span>{children}</span>
    </span>
  );
}

function MetricCard({ icon: Icon, label, value, rightSlot = null, valueClassName = "" }) {
  return (
    <div className="rounded-[20px] border border-[#E6E8EF] bg-[#F8FAFC] p-4">
      <div className="flex items-start justify-between gap-3">
        <div className="flex min-w-0 items-start gap-3">
          <div className="inline-flex h-10 w-10 items-center justify-center rounded-2xl border border-slate-200 bg-white">
            <Icon className="h-4 w-4 text-slate-700" />
          </div>
          <div className="min-w-0">
            <div className="text-[11px] font-semibold uppercase tracking-wide text-slate-500">
              {label}
            </div>
            <div className={`mt-1 text-sm font-black text-slate-900 ${valueClassName}`}>
              {value}
            </div>
          </div>
        </div>

        {rightSlot ? <div className="shrink-0">{rightSlot}</div> : null}
      </div>
    </div>
  );
}

function SectionCard({ title, subtitle, children }) {
  return (
    <section className="rounded-[22px] border border-[#E6E8EF] bg-white p-5 shadow-sm">
      <div className="text-base font-black text-slate-900">{title}</div>
      {subtitle ? <div className="mt-1 text-xs text-slate-500">{subtitle}</div> : null}
      <div className="mt-4">{children}</div>
    </section>
  );
}

function SkeletonBlock({ className = "" }) {
  return (
    <div
      className={`animate-pulse rounded-2xl border border-[#E6E8EF] bg-[#F7F8FA] ${className}`}
    />
  );
}

// ----------------------------------------------------------------------------
// Viewport + anchored placement helpers
// ----------------------------------------------------------------------------
function useViewportState(open) {
  const [viewport, setViewport] = useState({
    width: typeof window !== "undefined" ? window.innerWidth : 1440,
    height: typeof window !== "undefined" ? window.innerHeight : 900,
  });

  useEffect(() => {
    if (!open) return undefined;

    const onResize = () => {
      setViewport({
        width: window.innerWidth,
        height: window.innerHeight,
      });
    };

    onResize();
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, [open]);

  return viewport;
}

// KEY COMMENT:
// One stable width for all anchored desktop flyouts.
// This is the main fix for the inconsistency between first/second/third cards.
function getDesktopFlyoutWidth() {
  return 500;
}

function computeAnchoredPosition(triggerContext, viewportWidth, viewportHeight) {
  const margin = 18;
  const gap = 14;
  const fixedWidth = Math.min(getDesktopFlyoutWidth(), viewportWidth - margin * 2);
  const minHeight = 560;
  const maxHeight = Math.min(820, viewportHeight - margin * 2);

  if (!triggerContext?.rect) {
    const centeredWidth = Math.min(980, viewportWidth - margin * 2);
    const centeredHeight = Math.min(maxHeight, viewportHeight - margin * 2);

    return {
      placement: "center",
      width: Math.round(centeredWidth),
      height: Math.round(centeredHeight),
      left: Math.round((viewportWidth - centeredWidth) / 2),
      top: Math.round((viewportHeight - centeredHeight) / 2),
    };
  }

  const rect = triggerContext.rect;
  const spaceRight = viewportWidth - rect.right - gap - margin;

  // Prefer opening to the right when enough space exists.
  if (spaceRight >= fixedWidth) {
    const left = rect.right + gap;
    const top = clamp(rect.top - 8, margin, viewportHeight - minHeight - margin);
    const height = Math.max(
      minHeight,
      Math.min(maxHeight, viewportHeight - top - margin)
    );

    return {
      placement: "right",
      width: Math.round(fixedWidth),
      height: Math.round(height),
      left: Math.round(left),
      top: Math.round(top),
    };
  }

  // Otherwise open below the clicked card, but keep the same width and internal layout.
  const left = clamp(rect.left, margin, viewportWidth - fixedWidth - margin);

  let top = rect.bottom + gap;
  let availableHeight = viewportHeight - top - margin;

  if (availableHeight < minHeight) {
    top = Math.max(margin, viewportHeight - minHeight - margin);
    availableHeight = viewportHeight - top - margin;
  }

  const height = Math.max(
    minHeight,
    Math.min(maxHeight, availableHeight)
  );

  return {
    placement: "below",
    width: Math.round(fixedWidth),
    height: Math.round(height),
    left: Math.round(left),
    top: Math.round(top),
  };
}

// ----------------------------------------------------------------------------
// Component
// ----------------------------------------------------------------------------
export default function ProductQuickViewModal({
  open,
  isOpen,
  product,
  triggerContext = null,
  onClose,
  onAddToCart,
  liked: likedProp,
  onToggleLike,
  myRating = 0,
  ratingSummary = { average: 0, count: 0 },
  ratingBusy = false,
  onRate,
  onViewFarmer,
  onMessageFarmer,
}) {
  const modalOpen = open ?? isOpen ?? false;
  const rootRef = useFocusTrap(modalOpen, onClose);
  usePageScrollLock(modalOpen);

  const scrollRef = useRef(null);
  const viewport = useViewportState(modalOpen);

  const [fullProduct, setFullProduct] = useState(null);
  const [loading, setLoading] = useState(false);

  const [localLiked, setLocalLiked] = useState(false);
  const [qty, setQty] = useState(1);
  const [adding, setAdding] = useState(false);
  const [addError, setAddError] = useState("");
  const [ratingError, setRatingError] = useState("");
  const [selectedImageIndex, setSelectedImageIndex] = useState(0);
  const [mainFallbackIndex, setMainFallbackIndex] = useState(0);

  const productId = useMemo(() => getProductId(product), [product]);

  useEffect(() => {
    let active = true;

    async function loadFullProduct() {
      if (!modalOpen || !productId || typeof customerApi.fetchProductById !== "function") {
        return;
      }

      setLoading(true);
      setFullProduct(null);

      try {
        const data = await customerApi.fetchProductById(productId);
        if (!active) return;
        setFullProduct(data || product || null);
      } catch {
        if (!active) return;
        setFullProduct(product || null);
      } finally {
        if (active) setLoading(false);
      }
    }

    loadFullProduct();

    return () => {
      active = false;
    };
  }, [modalOpen, productId, product]);

  const data = useMemo(() => fullProduct || product || null, [fullProduct, product]);

  useEffect(() => {
    if (!modalOpen) return;

    const unitPolicy = qtyPolicyFromUnit(getProductUnit(fullProduct || product || {}));
    setQty(unitPolicy.min);
    setAddError("");
    setRatingError("");
    setSelectedImageIndex(0);
    setMainFallbackIndex(0);

    try {
      scrollRef.current?.scrollTo?.({ top: 0, behavior: "auto" });
    } catch {
      if (scrollRef.current) scrollRef.current.scrollTop = 0;
    }
  }, [modalOpen, productId, fullProduct, product]);

  useEffect(() => {
    if (typeof likedProp === "boolean") {
      setLocalLiked(likedProp);
    }
  }, [likedProp]);

  const liked = typeof likedProp === "boolean" ? likedProp : localLiked;

  function toggleLike() {
    if (typeof likedProp !== "boolean") {
      setLocalLiked((prev) => !prev);
    }
    onToggleLike?.(data || product);
  }

  const name = getProductName(data || {});
  const category = getProductCategory(data || {});
  const description = getProductDescription(data || {});
  const farmerName = getFarmerName(data || {});
  const farmerPhone = getFarmerPhone(data || {});
  const location = getLocation(data || {});
  const region = getRegion(data || {});
  const unit = getProductUnit(data || {});

  const price = safeNumber(data?.price ?? data?.unit_price, 0);
  const stock = data?.stock_quantity ?? data?.stock ?? data?.quantity ?? null;
  const numericStock = safeNumber(stock, 0);

  const inStock = stock == null ? true : numericStock > 0;
  const canAdd = data ? (stock == null ? true : numericStock > 0) : false;

  const qtyPolicy = qtyPolicyFromUnit(unit);
  const qtyMin = qtyPolicy.min;
  const qtyStep = qtyPolicy.step;
  const qtyMax =
    stock != null && Number.isFinite(numericStock) && numericStock > 0
      ? numericStock
      : 9999;

  const currentMyRating = clampRating(myRating);
  const avgRating = safeNumber(ratingSummary?.average, 0);
  const ratingCount = Math.max(0, Math.round(safeNumber(ratingSummary?.count, 0)));

  const primaryImage = useMemo(() => resolvePrimaryProductImage(data || {}), [data]);

  const galleryImages = useMemo(
    () => uniqStrings([primaryImage, ...collectGalleryImages(data || {})]),
    [data, primaryImage]
  );
  const mainImageFallbacks = useMemo(
    () => uniqStrings([primaryImage, ...getMainImageFallbacks(data || {})]),
    [data, primaryImage]
  );

  const effectiveMainImage = useMemo(() => {
    if (galleryImages[selectedImageIndex]) return galleryImages[selectedImageIndex];
    return mainImageFallbacks[mainFallbackIndex] || mainImageFallbacks[0] || DEFAULT_PRODUCT_IMG;
  }, [galleryImages, selectedImageIndex, mainImageFallbacks, mainFallbackIndex]);

  const hasGalleryRail = galleryImages.length > 1;

  useEffect(() => {
    setSelectedImageIndex(0);
    setMainFallbackIndex(0);
  }, [productId]);

  function handleMainImageError() {
    setMainFallbackIndex((prev) =>
      Math.min(prev + 1, Math.max(0, mainImageFallbacks.length - 1))
    );
  }

  function showPreviousImage() {
    if (!galleryImages.length) return;
    setSelectedImageIndex((prev) => (prev <= 0 ? galleryImages.length - 1 : prev - 1));
    setMainFallbackIndex(0);
  }

  function showNextImage() {
    if (!galleryImages.length) return;
    setSelectedImageIndex((prev) => (prev >= galleryImages.length - 1 ? 0 : prev + 1));
    setMainFallbackIndex(0);
  }

  async function handleAdd() {
    if (!canAdd || adding || typeof onAddToCart !== "function" || !data) return;

    setAdding(true);
    setAddError("");

    try {
      await Promise.resolve(onAddToCart(data, qty));
      onClose?.();
    } catch (e) {
      setAddError(e?.message ? String(e.message) : "Failed to add to cart.");
    } finally {
      setAdding(false);
    }
  }

  async function handleRate(score) {
    if (typeof onRate !== "function" || !data) return;

    setRatingError("");

    try {
      const maybePromise = onRate.length >= 2 ? onRate(data, score) : onRate(score);
      await Promise.resolve(maybePromise);
    } catch (e) {
      setRatingError(e?.message ? String(e.message) : "Failed to update rating.");
    }
  }

  const isDesktopAnchored = viewport.width >= 1024;

  const anchoredMetrics = useMemo(() => {
    return computeAnchoredPosition(triggerContext, viewport.width, viewport.height);
  }, [triggerContext, viewport.width, viewport.height]);

  const anchoredStyle = useMemo(
    () => ({
      width: `${anchoredMetrics.width}px`,
      height: `${anchoredMetrics.height}px`,
      left: `${anchoredMetrics.left}px`,
      top: `${anchoredMetrics.top}px`,
    }),
    [anchoredMetrics]
  );

  if (!modalOpen) return null;

  // KEY COMMENT:
  // Desktop anchored previews all use the same single-column design.
  // This removes layout switching between products and placements.
  const flyoutBody = (
    <div
      ref={rootRef}
      role="dialog"
      aria-modal="true"
      aria-label="Product quick view"
      className="flex h-full min-h-0 max-h-full flex-col overflow-hidden rounded-[28px] border border-[#E6E8EF] bg-white shadow-[0_28px_80px_rgba(15,23,42,0.24)]"
    >
      <div className="border-b border-[#E6E8EF] bg-white/95 px-4 py-4 backdrop-blur sm:px-5">
        <div className="flex items-start justify-between gap-4">
          <div className="min-w-0">
            <div className="truncate text-lg font-black tracking-tight text-[#111827]">
              {loading ? "Loading product..." : name}
            </div>
            <div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-slate-500">
              <span>Quick View</span>
              <span>•</span>
              <span>{category}</span>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={toggleLike}
              className="inline-flex h-10 w-10 items-center justify-center rounded-2xl border border-[#D9E0EA] bg-white hover:bg-[#F7F8FA]"
              aria-label={liked ? "Remove from favorites" : "Add to favorites"}
              aria-pressed={liked}
            >
              <Heart
                className={`h-4 w-4 ${
                  liked ? "fill-rose-600 text-rose-600" : "text-slate-700"
                }`}
              />
            </button>

            <button
              type="button"
              onClick={onClose}
              className="inline-flex h-10 w-10 items-center justify-center rounded-2xl border border-[#D9E0EA] bg-white hover:bg-[#F7F8FA]"
              aria-label="Close modal"
            >
              <X className="h-4 w-4 text-slate-700" />
            </button>
          </div>
        </div>
      </div>

      <div
        ref={scrollRef}
        className="min-h-0 flex-1 overflow-y-auto overscroll-contain"
      >
        {loading ? (
          <div className="space-y-4 p-4 sm:p-5">
            <SkeletonBlock className="aspect-[4/3] w-full" />
            <SkeletonBlock className="h-28 w-full" />
            <SkeletonBlock className="h-36 w-full" />
            <SkeletonBlock className="h-36 w-full" />
          </div>
        ) : (
          <div className="space-y-5 p-4 sm:p-5">
            <section className="space-y-4">
              <div className="relative overflow-hidden rounded-[24px] border border-[#E6E8EF] bg-[linear-gradient(180deg,#F8FAFC_0%,#F1F5F9_100%)]">
                <div className="absolute left-4 top-4 z-10 flex flex-wrap items-center gap-2">
                  <IconInfoPill icon={Layers3}>{category}</IconInfoPill>
                  <IconInfoPill icon={Package} tone={inStock ? "success" : "muted"}>
                    {stockLabel(inStock, numericStock)}
                  </IconInfoPill>
                </div>

                {galleryImages.length > 1 ? (
                  <>
                    <button
                      type="button"
                      onClick={showPreviousImage}
                      className="absolute left-4 top-1/2 z-10 inline-flex h-10 w-10 -translate-y-1/2 items-center justify-center rounded-full border border-slate-200 bg-white/95 text-slate-700 shadow-sm hover:bg-white"
                      aria-label="Previous image"
                    >
                      <ChevronLeft className="h-4 w-4" />
                    </button>

                    <button
                      type="button"
                      onClick={showNextImage}
                      className="absolute right-4 top-1/2 z-10 inline-flex h-10 w-10 -translate-y-1/2 items-center justify-center rounded-full border border-slate-200 bg-white/95 text-slate-700 shadow-sm hover:bg-white"
                      aria-label="Next image"
                    >
                      <ChevronRight className="h-4 w-4" />
                    </button>
                  </>
                ) : null}

                <div className="aspect-[4/3]">
                  <img
                    src={effectiveMainImage}
                    alt={name}
                    className="h-full w-full object-cover"
                    onError={handleMainImageError}
                  />
                </div>
              </div>

              {hasGalleryRail ? (
                <div className="grid grid-cols-4 gap-3">
                  {galleryImages.map((img, idx) => {
                    const active = idx === selectedImageIndex;

                    return (
                      <button
                        key={`gallery-${idx}-${img}`}
                        type="button"
                        onClick={() => {
                          setSelectedImageIndex(idx);
                          setMainFallbackIndex(0);
                        }}
                        className={`overflow-hidden rounded-2xl border bg-[#F8FAFC] transition ${
                          active
                            ? "border-emerald-300 ring-2 ring-emerald-100"
                            : "border-[#E6E8EF] hover:border-slate-300"
                        }`}
                        aria-label={`Open image ${idx + 1}`}
                      >
                        <div className="aspect-square">
                          <img src={img} alt={`${name} ${idx + 1}`} className="h-full w-full object-cover" />
                        </div>
                      </button>
                    );
                  })}
                </div>
              ) : null}

              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <MetricCard icon={MapPin} label="Location" value={location}>
                  {region ? <span className="text-xs text-slate-500">{region}</span> : null}
                </MetricCard>

                <MetricCard
                  icon={Package}
                  label="Stock"
                  value={stock != null ? String(stock) : "Available"}
                  rightSlot={
                    <div
                      className={`rounded-full border px-2.5 py-1 text-[11px] font-bold ${stockTone(
                        inStock,
                        numericStock
                      )}`}
                    >
                      {stockLabel(inStock, numericStock)}
                    </div>
                  }
                />

                <MetricCard
                  icon={ShieldCheck}
                  label="Seller"
                  value={farmerName}
                  valueClassName="line-clamp-2"
                />
              </div>
            </section>

            <section className="rounded-[24px] border border-[#E6E8EF] bg-white p-5 shadow-sm">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="line-clamp-2 text-[22px] font-black tracking-tight text-slate-900">
                    {name}
                  </div>
                  <div className="mt-1 text-xs font-medium text-slate-500">{category}</div>
                </div>

                <span className="shrink-0 rounded-full border border-emerald-200 bg-emerald-50 px-3 py-1 text-[11px] font-extrabold text-emerald-800">
                  {unitPillLabel(unit)}
                </span>
              </div>

              <div className="mt-5">
                <div className="text-[11px] font-semibold uppercase tracking-wide text-slate-500">
                  Price
                </div>
                <div className="mt-1 text-[42px] font-black leading-none tracking-tight text-slate-900">
                  {formatMoney(price)}
                  {unit ? (
                    <span className="ml-1 text-sm font-semibold text-slate-500">/ {unit}</span>
                  ) : null}
                </div>
              </div>

              <div className="mt-5 flex flex-wrap gap-2">
                <IconInfoPill icon={ShieldCheck} tone="muted">
                  AgroConnect
                </IconInfoPill>
                <IconInfoPill icon={Tag} tone="muted">
                  {unit || "each"}
                </IconInfoPill>
              </div>
            </section>

            <SectionCard title="About this product" subtitle="What the customer should know">
              <p className="text-sm leading-7 text-slate-600">{description}</p>
            </SectionCard>

            <SectionCard
              title="Your rating"
              subtitle="Help other customers make better buying decisions"
            >
              <div className="mb-4 rounded-full border border-[#E6E8EF] bg-[#F8FAFC] px-3 py-1.5 text-xs font-semibold text-slate-700 w-fit">
                {ratingCount > 0 ? (
                  <>
                    <span className="font-black text-slate-900">{avgRating.toFixed(1)}</span>
                    <span className="ml-1 text-slate-500">({ratingCount})</span>
                  </>
                ) : (
                  "No ratings yet"
                )}
              </div>

              <div className="text-xs text-slate-500">
                {currentMyRating > 0
                  ? `You rated this product ${currentMyRating} star${currentMyRating === 1 ? "" : "s"}.`
                  : "You have not rated this product yet."}
              </div>

              <div className="mt-4 flex flex-wrap items-center gap-2">
                {[1, 2, 3, 4, 5].map((score) => {
                  const active = score <= currentMyRating;

                  return (
                    <button
                      key={`modal-rate-${score}`}
                      type="button"
                      onClick={() => handleRate(score)}
                      disabled={ratingBusy}
                      className={`inline-flex h-11 w-11 items-center justify-center rounded-2xl border transition ${
                        active
                          ? "border-amber-300 bg-amber-50"
                          : "border-slate-200 bg-white hover:bg-slate-50"
                      } ${ratingBusy ? "cursor-not-allowed opacity-70" : "active:scale-95"}`}
                      aria-label={`Rate ${name} ${score} star${score === 1 ? "" : "s"}`}
                    >
                      <Star
                        className={`h-5 w-5 ${
                          active ? "fill-amber-400 text-amber-400" : "text-slate-300"
                        }`}
                      />
                    </button>
                  );
                })}
              </div>

              <p className="mt-4 text-xs leading-5 text-slate-500">
                Your rating improves trust, transparency, and product discovery.
              </p>

              {ratingError ? (
                <div className="mt-3 text-xs font-semibold text-rose-700">{ratingError}</div>
              ) : null}
            </SectionCard>

            <SectionCard title="Seller" subtitle="Supplied by a farmer in the marketplace">
              <div className="rounded-[20px] border border-[#EEF1F4] bg-[#F8FAFC] p-4">
                <div className="flex items-start justify-between gap-3">
                  <div className="flex min-w-0 items-start gap-3">
                    <div className="inline-flex h-11 w-11 items-center justify-center rounded-2xl border border-[#E6E8EF] bg-white">
                      <User className="h-4 w-4 text-slate-700" />
                    </div>

                    <div className="min-w-0">
                      <div className="truncate text-sm font-black text-slate-900">{farmerName}</div>
                      <div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-slate-500">
                        <span className="inline-flex items-center gap-1">
                          <MapPin className="h-3.5 w-3.5" />
                          {location}
                          {region ? ` • ${region}` : ""}
                        </span>
                      </div>

                      {farmerPhone ? (
                        <div className="mt-1 inline-flex items-center gap-1 text-xs text-slate-500">
                          <Phone className="h-3.5 w-3.5" />
                          {farmerPhone}
                        </div>
                      ) : null}
                    </div>
                  </div>

                  <div className="flex shrink-0 flex-wrap items-center gap-2">
                    {typeof onMessageFarmer === "function" ? (
                      <button
                        type="button"
                        onClick={() => onMessageFarmer(data)}
                        className="rounded-2xl border border-emerald-200 bg-emerald-50 px-4 py-2 text-xs font-semibold text-emerald-700 hover:bg-emerald-100"
                      >
                        Message Farmer
                      </button>
                    ) : null}

                    {typeof onViewFarmer === "function" ? (
                      <button
                        type="button"
                        onClick={() => onViewFarmer(data)}
                        className="rounded-2xl border border-[#D9E0EA] bg-white px-4 py-2 text-xs font-semibold text-slate-700 hover:bg-[#F8FAFC]"
                      >
                        View Farmer
                      </button>
                    ) : null}
                  </div>
                </div>
              </div>
            </SectionCard>

            <section className="rounded-[24px] border border-[#DDE7E1] bg-[linear-gradient(180deg,#F7FBF8_0%,#FFFFFF_100%)] p-5 shadow-sm">
              <div className="text-sm font-black text-slate-900">Buy this product</div>
              <div className="mt-1 text-xs text-slate-500">
                Choose quantity and add directly to your cart
              </div>

              <div className="mt-4 flex flex-col gap-3">
                <QuantityStepper
                  value={qty}
                  onChange={setQty}
                  min={qtyMin}
                  step={qtyStep}
                  max={qtyMax}
                  unitLabel={unit || "qty"}
                  ariaLabel="Quantity"
                  compact={false}
                  disabled={!canAdd || adding}
                />

                <button
                  type="button"
                  disabled={!canAdd || adding}
                  onClick={handleAdd}
                  className={[
                    "inline-flex h-12 items-center justify-center gap-2 rounded-2xl px-5 text-sm font-black",
                    canAdd && !adding
                      ? "bg-[#1F7A4D] text-white hover:brightness-95"
                      : "cursor-not-allowed bg-slate-200 text-slate-500",
                  ].join(" ")}
                >
                  <ShoppingCart className="h-4 w-4" />
                  {adding ? "Adding..." : "Add to cart"}
                </button>
              </div>

              {addError ? (
                <div className="mt-3 text-xs font-semibold text-rose-700">{addError}</div>
              ) : null}

              {!canAdd ? (
                <div className="mt-3 text-xs font-semibold text-rose-700">
                  This product is currently out of stock.
                </div>
              ) : null}
            </section>
          </div>
        )}
      </div>
    </div>
  );

  return (
    <div className="fixed inset-0 z-[60]">
      <button
        type="button"
        className="absolute inset-0 bg-slate-950/55 backdrop-blur-[3px]"
        aria-label="Close modal"
        onClick={onClose}
      />

      {isDesktopAnchored ? (
        <div className="absolute inset-0 overflow-hidden">
          <div className="absolute overflow-hidden" style={anchoredStyle}>
            {flyoutBody}
          </div>
        </div>
      ) : (
        <div className="absolute inset-0 overflow-hidden p-3 sm:p-5">
          <div className="flex h-full items-center justify-center">
            <div
              className="w-full max-w-[980px]"
              style={{ height: "calc(100dvh - 24px)", maxHeight: "calc(100dvh - 24px)" }}
            >
              {flyoutBody}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}