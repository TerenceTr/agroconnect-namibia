// ============================================================================
// frontend/src/components/customer/marketplace/CartDrawer.jsx
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Right-side cart drawer for customer marketplace.
//   • Renders cart items with quantity controls
//   • Opens professional checkout modal
//   • Handles cart-level UX for mobile + desktop
//
// KEY FIX IN THIS VERSION:
//   ✅ Cart drawer now renders through a React portal to document.body
//      so it always opens relative to the viewport, not the page scroll position
//   ✅ Drawer always opens from the top-right consistently, even after scrolling
//   ✅ Scrollable cart area resets to the top every time the drawer opens
//   ✅ Body scroll remains locked while drawer is open
//   ✅ ESC and backdrop close remain stable
//   ✅ Keeps current cart actions, checkout flow, and UI structure intact
// ============================================================================

import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import {
  X,
  ShoppingBag,
  Plus,
  Minus,
  Trash2,
  ImageOff,
  ArrowRight,
} from "lucide-react";

import CheckoutPanel from "../CheckoutPanel";
import {
  DEFAULT_PRODUCT_IMG,
  resolveProductImageCandidates,
} from "../../../utils/productImage";

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------
function toNumber(value, fallback = 0) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function toPositiveInt(value, fallback = 1) {
  const n = Math.floor(toNumber(value, fallback));
  return n > 0 ? n : fallback;
}

function money(value) {
  const n = toNumber(value, 0);
  try {
    return new Intl.NumberFormat("en-NA", {
      style: "currency",
      currency: "NAD",
      maximumFractionDigits: 2,
    }).format(n);
  } catch {
    return `N$ ${n.toFixed(2)}`;
  }
}

function pickFirst(...values) {
  for (const v of values) {
    if (v !== undefined && v !== null && v !== "") return v;
  }
  return undefined;
}

function getProductId(item = {}) {
  return String(pickFirst(item.product_id, item.productId, item.id, "") || "");
}

function getItemName(item = {}) {
  return String(
    pickFirst(item.product_name, item.name, item.title, item.product?.name, "Unnamed product")
  );
}

function getItemFarmer(item = {}) {
  return String(pickFirst(item.farmer_name, item.seller_name, item.farmer, "") || "");
}

function getItemQty(item = {}) {
  return toPositiveInt(pickFirst(item.quantity, item.qty), 1);
}

function getItemUnitPrice(item = {}) {
  return toNumber(pickFirst(item.unit_price, item.unitPrice, item.price), 0);
}

function getItemLineTotal(item = {}) {
  const explicit = pickFirst(item.line_total, item.lineTotal);
  if (explicit !== undefined) return toNumber(explicit, 0);
  return getItemQty(item) * getItemUnitPrice(item);
}

function buildItemForImageResolver(item = {}) {
  return {
    image_url: pickFirst(item.image_url, item.imageUrl, item.photo_url, item.photoUrl, ""),
    image: pickFirst(item.image, item.image_path, ""),
    name: getItemName(item),
    product_name: getItemName(item),
  };
}

// ----------------------------------------------------------------------------
// Scroll-lock helper
// ----------------------------------------------------------------------------
function lockBodyScrollWithCounter() {
  if (typeof document === "undefined") return () => {};

  const body = document.body;
  const html = document.documentElement;
  const current = Number(body.dataset.scrollLockCount || 0);

  if (current === 0) {
    body.dataset.prevOverflow = body.style.overflow || "";
    body.dataset.prevPaddingRight = body.style.paddingRight || "";

    const scrollbarGap = Math.max(0, window.innerWidth - html.clientWidth);
    if (scrollbarGap > 0) {
      body.style.paddingRight = `${scrollbarGap}px`;
    }

    body.style.overflow = "hidden";
  }

  body.dataset.scrollLockCount = String(current + 1);

  return () => {
    const now = Number(body.dataset.scrollLockCount || 1);
    const next = Math.max(0, now - 1);

    if (next === 0) {
      body.style.overflow = body.dataset.prevOverflow || "";
      body.style.paddingRight = body.dataset.prevPaddingRight || "";
      delete body.dataset.scrollLockCount;
      delete body.dataset.prevOverflow;
      delete body.dataset.prevPaddingRight;
      return;
    }

    body.dataset.scrollLockCount = String(next);
  };
}

async function invokeCheckoutAction(checkoutFn, payload, options) {
  if (typeof checkoutFn !== "function") {
    throw new Error("Checkout service is unavailable.");
  }

  // Supports both shapes:
  //   checkoutFn(payload)
  //   checkoutFn(payload, options)
  return checkoutFn(payload, options);
}

export default function CartDrawer({
  isOpen = false,
  onClose,
  cartState,
  actions,
  customerProfile,
  customerLocation,
  onCheckoutSuccess,
}) {
  const [isCheckoutOpen, setIsCheckoutOpen] = useState(false);
  const [isSubmittingCheckout, setIsSubmittingCheckout] = useState(false);
  const [errorMessage, setErrorMessage] = useState("");
  const [animateBadge, setAnimateBadge] = useState(false);
  const [imgIndexByKey, setImgIndexByKey] = useState({});
  const [isMounted, setIsMounted] = useState(false);

  const previousCountRef = useRef(0);

  // KEY COMMENT:
  // This ref points to the drawer's internal scrollable content area.
  // We reset it to the top every time the cart opens so reopen behaviour
  // stays visually consistent for the customer.
  const scrollAreaRef = useRef(null);

  // --------------------------------------------------------------------------
  // Mount gate for React portal
  // --------------------------------------------------------------------------
  useEffect(() => {
    setIsMounted(true);
    return () => setIsMounted(false);
  }, []);

  // --------------------------------------------------------------------------
  // Stable action mapping (compat across old/new cart surfaces)
  // --------------------------------------------------------------------------
  const compatActions = useMemo(() => {
    const fromProps = actions || {};
    const fromStateActions = cartState?.actions || {};

    return {
      addItem:
        fromProps.addItem ||
        fromProps.addToCart ||
        fromStateActions.addItem ||
        cartState?.addItem,

      removeItem:
        fromProps.removeItem ||
        fromProps.removeFromCart ||
        fromStateActions.removeItem ||
        cartState?.removeItem,

      updateQuantity:
        fromProps.updateQuantity ||
        fromStateActions.updateQuantity ||
        cartState?.updateQuantity,

      clearCart:
        fromProps.clearCart ||
        fromStateActions.clearCart ||
        cartState?.clearCart,

      checkoutOrder:
        fromProps.checkoutOrder ||
        fromProps.checkout ||
        fromStateActions.checkoutOrder ||
        fromStateActions.checkout ||
        cartState?.checkoutOrder ||
        cartState?.checkout,
    };
  }, [
    actions,
    cartState?.actions,
    cartState?.addItem,
    cartState?.removeItem,
    cartState?.updateQuantity,
    cartState?.clearCart,
    cartState?.checkoutOrder,
    cartState?.checkout,
  ]);

  const items = useMemo(() => {
    if (Array.isArray(cartState?.items)) return cartState.items;
    if (Array.isArray(cartState?.cartItems)) return cartState.cartItems;
    return [];
  }, [cartState?.items, cartState?.cartItems]);

  const totalItems = useMemo(
    () => items.reduce((sum, item) => sum + getItemQty(item), 0),
    [items]
  );

  const subtotal = useMemo(() => {
    const fallback = items.reduce((sum, item) => sum + getItemLineTotal(item), 0);
    return toNumber(
      pickFirst(cartState?.subtotal, cartState?.totalPrice, cartState?.total),
      fallback
    );
  }, [items, cartState?.subtotal, cartState?.totalPrice, cartState?.total]);

  const uniqueItems = items.length;

  const resolvedCustomerLocation = useMemo(() => {
    const raw = pickFirst(
      customerLocation,
      cartState?.customerLocation,
      customerProfile?.location,
      customerProfile?.address,
      customerProfile?.delivery_location
    );
    return raw ? String(raw) : "";
  }, [customerLocation, cartState?.customerLocation, customerProfile]);

  // --------------------------------------------------------------------------
  // Lock page scroll while cart drawer is open
  // --------------------------------------------------------------------------
  useEffect(() => {
    if (!isOpen) return undefined;
    const unlock = lockBodyScrollWithCounter();
    return () => unlock();
  }, [isOpen]);

  // --------------------------------------------------------------------------
  // Reset drawer internal scroll whenever it opens
  // --------------------------------------------------------------------------
  useEffect(() => {
    if (!isOpen) return;

    const reset = () => {
      if (scrollAreaRef.current) {
        scrollAreaRef.current.scrollTop = 0;
      }
    };

    // Reset immediately and again on the next frame to handle transition timing.
    reset();
    const raf = window.requestAnimationFrame(reset);

    return () => window.cancelAnimationFrame(raf);
  }, [isOpen]);

  // --------------------------------------------------------------------------
  // ESC closes checkout first, then drawer
  // --------------------------------------------------------------------------
  useEffect(() => {
    if (!isOpen) return undefined;

    const onKeyDown = (event) => {
      if (event.key !== "Escape") return;

      if (isCheckoutOpen) {
        setIsCheckoutOpen(false);
        return;
      }

      onClose?.();
    };

    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [isOpen, isCheckoutOpen, onClose]);

  // --------------------------------------------------------------------------
  // Keep inner state clean whenever the drawer closes
  // --------------------------------------------------------------------------
  useEffect(() => {
    if (!isOpen) {
      setIsCheckoutOpen(false);
      setIsSubmittingCheckout(false);
      setErrorMessage("");
    }
  }, [isOpen]);

  // --------------------------------------------------------------------------
  // Animate count badge when total changes
  // --------------------------------------------------------------------------
  useEffect(() => {
    if (previousCountRef.current === totalItems) return;
    previousCountRef.current = totalItems;

    setAnimateBadge(true);
    const timer = window.setTimeout(() => setAnimateBadge(false), 220);
    return () => window.clearTimeout(timer);
  }, [totalItems]);

  const handleRemove = useCallback(
    (productId) => {
      if (!productId || typeof compatActions.removeItem !== "function") return;
      compatActions.removeItem(productId);
    },
    [compatActions]
  );

  const handleIncrement = useCallback(
    (item) => {
      const id = getProductId(item);
      if (!id || typeof compatActions.updateQuantity !== "function") return;
      compatActions.updateQuantity(id, getItemQty(item) + 1);
    },
    [compatActions]
  );

  const handleDecrement = useCallback(
    (item) => {
      const id = getProductId(item);
      if (!id || typeof compatActions.updateQuantity !== "function") return;

      const nextQty = Math.max(1, getItemQty(item) - 1);
      compatActions.updateQuantity(id, nextQty);
    },
    [compatActions]
  );

  const handleClearCart = useCallback(() => {
    if (typeof compatActions.clearCart === "function") compatActions.clearCart();
  }, [compatActions]);

  const openCheckout = useCallback(
    (event) => {
      event?.preventDefault?.();
      event?.stopPropagation?.();

      if (!items.length || isSubmittingCheckout) return;

      setErrorMessage("");

      // Prevent event bleed through overlay state changes.
      window.requestAnimationFrame(() => {
        setIsCheckoutOpen(true);
      });
    },
    [items.length, isSubmittingCheckout]
  );

  const closeDrawer = useCallback(() => {
    if (isCheckoutOpen) return;
    setIsCheckoutOpen(false);
    onClose?.();
  }, [isCheckoutOpen, onClose]);

  const handleCheckoutSubmit = useCallback(
    async (payload, options) => {
      setIsSubmittingCheckout(true);
      setErrorMessage("");

      try {
        if (typeof compatActions.checkoutOrder !== "function") {
          throw new Error("Checkout service is unavailable.");
        }

        const result = await invokeCheckoutAction(
          compatActions.checkoutOrder,
          payload,
          options
        );

        if (typeof compatActions.clearCart === "function") {
          compatActions.clearCart();
        }

        setIsCheckoutOpen(false);
        onCheckoutSuccess?.(result);
        onClose?.();
      } catch (err) {
        const message =
          err?.response?.data?.message ||
          err?.message ||
          "Checkout failed. Please try again.";

        setErrorMessage(String(message));
        throw err;
      } finally {
        setIsSubmittingCheckout(false);
      }
    },
    [compatActions, onCheckoutSuccess, onClose]
  );

  const cartFooter = (
    <>
      <div className="space-y-2 rounded-2xl border border-slate-200 bg-slate-50 px-3.5 py-3.5 shadow-sm">
        <div className="flex items-center justify-between text-xs text-slate-600">
          <span>Unique items</span>
          <span className="font-semibold text-slate-900">{uniqueItems}</span>
        </div>

        <div className="flex items-center justify-between text-xs text-slate-600">
          <span>Total quantity</span>
          <span className="font-semibold text-slate-900">{totalItems}</span>
        </div>

        <div className="h-px bg-slate-200" />

        <div className="flex items-center justify-between text-sm">
          <span className="font-semibold text-slate-700">Subtotal</span>
          <span className="text-base font-extrabold text-slate-900">{money(subtotal)}</span>
        </div>
      </div>

      <div className="mt-3 grid grid-cols-2 gap-2">
        <button
          type="button"
          onClick={handleClearCart}
          disabled={!items.length}
          className="inline-flex h-11 items-center justify-center gap-2 rounded-xl border border-slate-300 px-3 text-sm font-medium text-slate-700 transition hover:bg-slate-50 active:scale-[0.99] disabled:cursor-not-allowed disabled:opacity-50"
        >
          <Trash2 className="h-4 w-4" />
          Clear
        </button>

        <button
          type="button"
          onClick={openCheckout}
          disabled={!items.length || isSubmittingCheckout}
          className="inline-flex h-11 items-center justify-center gap-2 rounded-xl bg-emerald-600 px-3 text-sm font-semibold text-white transition-all duration-200 hover:-translate-y-[1px] hover:bg-emerald-700 hover:shadow active:translate-y-0 disabled:cursor-not-allowed disabled:opacity-50"
        >
          Checkout
          <ArrowRight className="h-4 w-4" />
        </button>
      </div>

      {errorMessage ? (
        <div className="mt-2 rounded-xl border border-rose-200 bg-rose-50 px-3 py-2 text-xs text-rose-700">
          {errorMessage}
        </div>
      ) : null}
    </>
  );

  // --------------------------------------------------------------------------
  // Main drawer UI
  // --------------------------------------------------------------------------
  const drawerUi = (
    <>
      <div
        className={`fixed inset-0 z-[90] transition-opacity duration-200 ${
          isOpen
            ? "pointer-events-auto visible opacity-100"
            : "pointer-events-none invisible opacity-0"
        }`}
        aria-hidden={!isOpen}
      >
        {/* Backdrop */}
        <button
          type="button"
          aria-label="Close cart overlay"
          onClick={closeDrawer}
          className={`absolute inset-0 bg-black/45 backdrop-blur-[1px] transition-opacity duration-200 ${
            isOpen ? "opacity-100" : "opacity-0"
          }`}
        />

        {/* KEY COMMENT:
            The drawer itself is now FIXED to the viewport and rendered in a portal.
            This guarantees it opens in the same place even after the customer scrolls the page.
        */}
        <aside
          className={`fixed right-0 top-0 h-[100dvh] w-full max-w-[480px] shrink-0 border-l border-slate-200 bg-white shadow-[0_20px_48px_-18px_rgba(2,6,23,0.45)] transition-transform duration-300 ${
            isOpen ? "translate-x-0" : "translate-x-full"
          }`}
          role="dialog"
          aria-modal="true"
          aria-label="Shopping cart"
        >
          <div className="flex h-full min-h-0 flex-col overflow-hidden">
            {/* Header */}
            <div className="shrink-0 border-b border-slate-200 px-4 py-3.5">
              <div className="flex items-center justify-between">
                <div className="flex min-w-0 items-center gap-2.5">
                  <div className="inline-flex h-10 w-10 items-center justify-center rounded-xl bg-emerald-50 text-emerald-700">
                    <ShoppingBag className="h-4 w-4" />
                  </div>

                  <div className="min-w-0">
                    <h2 className="truncate text-base font-semibold text-slate-900">
                      Your Cart
                    </h2>
                    <p className="text-xs text-slate-500">Review items before checkout</p>
                  </div>

                  <span
                    className={`ml-1 inline-flex min-w-6 items-center justify-center rounded-full border border-slate-300 px-2 py-0.5 text-xs font-semibold leading-none text-slate-700 transition-transform duration-200 ${
                      animateBadge ? "scale-110" : "scale-100"
                    }`}
                  >
                    {totalItems}
                  </span>
                </div>

                <button
                  type="button"
                  onClick={closeDrawer}
                  className="inline-flex h-10 w-10 items-center justify-center rounded-xl border border-slate-200 text-slate-600 transition hover:bg-slate-50 active:scale-[0.98]"
                  aria-label="Close cart"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>

              {resolvedCustomerLocation ? (
                <p className="mt-2 line-clamp-1 text-xs text-slate-500">
                  Default delivery location:{" "}
                  <span className="font-medium text-slate-700">
                    {resolvedCustomerLocation}
                  </span>
                </p>
              ) : null}
            </div>

            {/* Scrollable cart list */}
            <div
              ref={scrollAreaRef}
              className="min-h-0 flex-1 overflow-y-auto px-4 py-4 pb-24 md:pb-4 [scrollbar-gutter:stable] overscroll-contain"
            >
              {!items.length ? (
                <div className="flex h-full flex-col items-center justify-center rounded-2xl border border-dashed border-slate-300 px-6 py-10 text-center">
                  <ShoppingBag className="mb-3 h-10 w-10 text-slate-300" />
                  <p className="text-sm font-medium text-slate-700">Your cart is empty</p>
                  <p className="mt-1 text-xs text-slate-500">
                    Add products from the marketplace to continue.
                  </p>
                </div>
              ) : (
                <>
                  <div className="space-y-3">
                    {items.map((item, index) => {
                      const id = getProductId(item) || `tmp-${index}`;
                      const qty = getItemQty(item);
                      const unitPrice = getItemUnitPrice(item);
                      const lineTotal = getItemLineTotal(item);
                      const farmerName = getItemFarmer(item);

                      const imageCandidates =
                        Array.isArray(item?.image_candidates) && item.image_candidates.length
                          ? item.image_candidates
                          : resolveProductImageCandidates(buildItemForImageResolver(item));

                      const currentIdx = Math.min(
                        imgIndexByKey[id] ?? 0,
                        Math.max(0, imageCandidates.length - 1)
                      );

                      const imgSrc = imageCandidates[currentIdx] || DEFAULT_PRODUCT_IMG;

                      return (
                        <article
                          key={id}
                          className="rounded-2xl border border-slate-200 bg-white p-3.5 shadow-sm transition duration-200 hover:shadow-md"
                        >
                          <div className="flex items-start gap-3">
                            <div className="h-16 w-16 shrink-0 overflow-hidden rounded-xl bg-slate-100">
                              {imgSrc ? (
                                <img
                                  src={imgSrc}
                                  alt={getItemName(item)}
                                  className="h-full w-full object-cover"
                                  loading="lazy"
                                  onError={() =>
                                    setImgIndexByKey((prev) => ({
                                      ...prev,
                                      [id]: Math.min(
                                        (prev[id] ?? 0) + 1,
                                        imageCandidates.length - 1
                                      ),
                                    }))
                                  }
                                />
                              ) : (
                                <div className="grid h-full w-full place-items-center text-slate-400">
                                  <ImageOff className="h-4 w-4" />
                                </div>
                              )}
                            </div>

                            <div className="min-w-0 flex-1">
                              <p className="line-clamp-1 text-sm font-semibold text-slate-900">
                                {getItemName(item)}
                              </p>

                              {farmerName ? (
                                <p className="line-clamp-1 text-xs text-slate-500">
                                  {farmerName}
                                </p>
                              ) : null}

                              <div className="mt-2.5 flex items-center justify-between gap-2">
                                <div className="inline-flex items-center rounded-xl border border-slate-200 bg-white shadow-sm">
                                  <button
                                    type="button"
                                    onClick={() => handleDecrement(item)}
                                    className="inline-flex h-10 w-10 items-center justify-center text-slate-700 transition hover:bg-slate-50 active:scale-95"
                                    aria-label="Decrease quantity"
                                  >
                                    <Minus className="h-3.5 w-3.5" />
                                  </button>

                                  <span className="min-w-8 text-center text-sm font-semibold text-slate-800">
                                    {qty}
                                  </span>

                                  <button
                                    type="button"
                                    onClick={() => handleIncrement(item)}
                                    className="inline-flex h-10 w-10 items-center justify-center text-slate-700 transition hover:bg-slate-50 active:scale-95"
                                    aria-label="Increase quantity"
                                  >
                                    <Plus className="h-3.5 w-3.5" />
                                  </button>
                                </div>

                                <div className="text-right">
                                  <p className="text-xs text-slate-500">
                                    {money(unitPrice)} each
                                  </p>
                                  <p className="text-sm font-semibold text-slate-900">
                                    {money(lineTotal)}
                                  </p>
                                </div>
                              </div>
                            </div>

                            <button
                              type="button"
                              onClick={() => handleRemove(id)}
                              className="inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-slate-200 text-slate-500 transition hover:bg-slate-50 active:scale-[0.98]"
                              aria-label="Remove item"
                            >
                              <Trash2 className="h-4 w-4" />
                            </button>
                          </div>
                        </article>
                      );
                    })}
                  </div>

                  {/* Mobile sticky footer */}
                  <div className="sticky bottom-0 z-20 -mx-4 mt-4 border-t border-slate-200 bg-white/95 px-4 py-3 backdrop-blur md:hidden">
                    {cartFooter}
                  </div>
                </>
              )}
            </div>

            {/* Desktop footer */}
            <div className="hidden shrink-0 border-t border-slate-200 bg-white px-4 py-3 md:block">
              {cartFooter}
            </div>
          </div>
        </aside>
      </div>

      {/* Checkout panel */}
      <CheckoutPanel
        isOpen={isOpen && isCheckoutOpen}
        items={items}
        customerProfile={customerProfile}
        defaultDeliveryLocation={resolvedCustomerLocation}
        onPlaceOrder={handleCheckoutSubmit}
        onCancel={() => {
          if (isSubmittingCheckout) return;
          setIsCheckoutOpen(false);
          setErrorMessage("");
        }}
      />
    </>
  );

  // KEY COMMENT:
  // Rendering into document.body avoids ancestor layout/scroll contexts,
  // which is the main reason drawer position can look inconsistent after scrolling.
  if (!isMounted || typeof document === "undefined") return null;
  return createPortal(drawerUi, document.body);
}