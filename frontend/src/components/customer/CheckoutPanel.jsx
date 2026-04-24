// ============================================================================
// frontend/src/components/customer/CheckoutPanel.jsx
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Professional checkout modal used by customer marketplace/cart.
//   • Collects contact + delivery details
//   • Initial checkout is now an ORDER REQUEST, not final payment
//   • Payment proof is uploaded later from order history
//   • Supports legacy and current prop shapes
//   • Sends payload aliases compatible with multiple backend contracts
//
// KEY FIXES IN THIS VERSION:
//   ✅ Renders through React Portal (always above drawer/overlays)
//   ✅ Respects `isOpen` prop (defaults to true for backward compatibility)
//   ✅ Professional two-pane layout with stronger spacing consistency
//   ✅ Checkout payload is object-based
//   ✅ ESC/backdrop close support with submit-safe behavior + focus trapping
//   ✅ Customer sees order-request messaging instead of final-payment messaging
//   ✅ Payment proof upload removed from initial checkout
//   ✅ EFT and cash-on-delivery now show different guidance
//   ✅ Cash on delivery uses the canonical value `cash_on_delivery`
// ============================================================================

import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import {
  X,
  Phone,
  MapPin,
  Receipt,
  FileText,
  ShoppingBag,
  Loader2,
  Wallet,
  ShieldCheck,
} from "lucide-react";
import toast from "react-hot-toast";

// ----------------------------------------------------------------------------
// Safe helpers
// ----------------------------------------------------------------------------
function safeNumber(v, fallback = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

function safeText(v, fallback = "") {
  const s = String(v ?? "").trim();
  return s || fallback;
}

function asArray(v) {
  return Array.isArray(v) ? v : [];
}

function normalizePaymentMethod(value) {
  const raw = String(value ?? "").trim().toLowerCase();
  if (!raw) return "eft";

  if (["cash", "cod", "cash_on_delivery", "cash-on-delivery", "cash on delivery"].includes(raw)) {
    return "cash_on_delivery";
  }

  if (["eft", "bank_transfer", "bank-transfer", "bank transfer", "electronic transfer"].includes(raw)) {
    return "eft";
  }

  return raw;
}

function paymentMethodIsCash(value) {
  return normalizePaymentMethod(value) === "cash_on_delivery";
}
function currency(v) {
  const n = safeNumber(v, 0);
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

function getItemId(item) {
  return (
    item?.product_id ??
    item?.productId ??
    item?.id ??
    item?.product?.product_id ??
    item?.product?.id ??
    null
  );
}

function getItemName(item) {
  return item?.product_name ?? item?.name ?? item?.title ?? item?.product?.name ?? "Product";
}

function getItemQty(item) {
  return Math.max(0, safeNumber(item?.quantity ?? item?.qty ?? item?.cart_quantity ?? 0, 0));
}

function getItemUnitPrice(item) {
  const direct = item?.unit_price ?? item?.price;
  if (direct != null) return safeNumber(direct, 0);
  return safeNumber(item?.product?.unit_price ?? item?.product?.price ?? 0, 0);
}

function getItemLineTotal(item) {
  const explicit = item?.line_total ?? item?.lineTotal;
  if (explicit != null) return safeNumber(explicit, 0);
  return getItemQty(item) * getItemUnitPrice(item);
}

function extractErrorMessage(err) {
  return (
    err?.response?.data?.message ||
    err?.response?.data?.error ||
    err?.message ||
    "Checkout failed. Please try again."
  );
}

function buildCheckoutItems(items) {
  return asArray(items)
    .map((it) => {
      const id = getItemId(it);
      const qty = Math.max(1, safeNumber(getItemQty(it), 1));
      if (!id) return null;

      return {
        product_id: id,
        id,
        quantity: qty,
        qty,
        unit_price: safeNumber(getItemUnitPrice(it), 0),
      };
    })
    .filter(Boolean);
}

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

async function invokeCheckout(placeOrderFn, payload, options) {
  if (typeof placeOrderFn !== "function") {
    throw new Error("Checkout action is not available.");
  }
  return placeOrderFn(payload, options);
}

function getFocusableElements(rootEl) {
  if (!rootEl) return [];
  const selector =
    'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';
  return Array.from(rootEl.querySelectorAll(selector)).filter(
    (el) => !el.hasAttribute("disabled") && el.getAttribute("aria-hidden") !== "true"
  );
}

export default function CheckoutPanel(props) {
  const {
    isOpen: isOpenProp,
    items: itemsProp,
    cartItems: cartItemsProp,
    subtotal: subtotalProp,
    defaultDeliveryLocation,
    customerLocation,
    customerProfile,
    onSuccess,
    onBack,
    onCancel,
    cart,
    totals,
    onPlaceOrder,
    actions,
    onRequestQuote,
    quoteState = { status: "idle", error: "" },
    defaultLocation = "",
    defaultPhone = "",
    disabled = false,
  } = props || {};

  const isOpen = isOpenProp === undefined ? true : !!isOpenProp;

  const items = useMemo(() => {
    if (Array.isArray(itemsProp)) return itemsProp;
    if (Array.isArray(cartItemsProp)) return cartItemsProp;
    if (Array.isArray(cart?.items)) return cart.items;
    if (Array.isArray(cart)) return cart;
    return [];
  }, [itemsProp, cartItemsProp, cart]);

  const resolvedDefaultLocation = useMemo(() => {
    return (
      safeText(defaultDeliveryLocation) ||
      safeText(customerLocation) ||
      safeText(defaultLocation) ||
      safeText(customerProfile?.delivery_location) ||
      safeText(customerProfile?.address) ||
      safeText(customerProfile?.location) ||
      ""
    );
  }, [defaultDeliveryLocation, customerLocation, defaultLocation, customerProfile]);

  const resolvedDefaultPhone = useMemo(() => {
    return (
      safeText(defaultPhone) ||
      safeText(customerProfile?.phone) ||
      safeText(customerProfile?.mobile) ||
      safeText(customerProfile?.contact_phone) ||
      ""
    );
  }, [defaultPhone, customerProfile]);

  const [phone, setPhone] = useState(() => safeText(resolvedDefaultPhone));
  const [location, setLocation] = useState(() => safeText(resolvedDefaultLocation));
  const [paymentMethod, setPaymentMethod] = useState("eft");
  const normalizedPaymentMethod = useMemo(() => normalizePaymentMethod(paymentMethod), [paymentMethod]);
  const [notes, setNotes] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const [phoneDirty, setPhoneDirty] = useState(false);
  const [locationDirty, setLocationDirty] = useState(false);
  const quoteTimer = useRef(null);
  const dialogPanelRef = useRef(null);
  const firstInputRef = useRef(null);
  const restoreFocusRef = useRef(null);

  const [portalTarget, setPortalTarget] = useState(null);
  useEffect(() => {
    if (typeof document !== "undefined") setPortalTarget(document.body);
  }, []);

  useEffect(() => {
    if (!phoneDirty && resolvedDefaultPhone) {
      setPhone(resolvedDefaultPhone);
    }
  }, [resolvedDefaultPhone, phoneDirty]);

  useEffect(() => {
    if (!locationDirty && resolvedDefaultLocation) {
      setLocation(resolvedDefaultLocation);
    }
  }, [resolvedDefaultLocation, locationDirty]);

  useEffect(() => {
    if (!isOpen) {
      setSubmitting(false);
      return;
    }

    setPhone((prev) => safeText(prev) || safeText(resolvedDefaultPhone));
    setLocation((prev) => safeText(prev) || safeText(resolvedDefaultLocation));
    setPaymentMethod((prev) => normalizePaymentMethod(prev));
    setNotes("");
    setPhoneDirty(false);
    setLocationDirty(false);
  }, [isOpen, resolvedDefaultPhone, resolvedDefaultLocation]);

  const handleBack = useCallback(() => {
    if (submitting) return;
    if (typeof onBack === "function") {
      onBack();
      return;
    }
    if (typeof onCancel === "function") {
      onCancel();
    }
  }, [onBack, onCancel, submitting]);

  useEffect(() => {
    if (!isOpen) return;

    const unlock = lockBodyScrollWithCounter();
    restoreFocusRef.current = document.activeElement;

    const t = window.setTimeout(() => {
      firstInputRef.current?.focus?.();
    }, 30);

    const onKeyDown = (event) => {
      if (event.key === "Escape") {
        event.preventDefault();
        handleBack();
        return;
      }

      if (event.key !== "Tab") return;
      const focusables = getFocusableElements(dialogPanelRef.current);
      if (!focusables.length) return;

      const first = focusables[0];
      const last = focusables[focusables.length - 1];
      const active = document.activeElement;

      if (event.shiftKey && active === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && active === last) {
        event.preventDefault();
        first.focus();
      }
    };

    window.addEventListener("keydown", onKeyDown);
    return () => {
      window.clearTimeout(t);
      window.removeEventListener("keydown", onKeyDown);
      unlock();
      if (restoreFocusRef.current && typeof restoreFocusRef.current.focus === "function") {
        restoreFocusRef.current.focus();
      }
    };
  }, [isOpen, handleBack]);

  const itemCount = useMemo(() => {
    return items.reduce((sum, it) => sum + getItemQty(it), 0);
  }, [items]);

  const computedSubtotal = useMemo(() => {
    return items.reduce((sum, it) => sum + getItemLineTotal(it), 0);
  }, [items]);

  const subtotal = useMemo(() => {
    const explicit = safeNumber(
      subtotalProp ?? totals?.subtotal ?? totals?.sub_total ?? totals?.subTotal ?? Number.NaN,
      Number.NaN
    );
    return Number.isFinite(explicit) ? explicit : computedSubtotal;
  }, [subtotalProp, totals, computedSubtotal]);

  const deliveryFee = useMemo(
    () => safeNumber(totals?.deliveryFee ?? totals?.delivery_fee ?? totals?.delivery ?? 0, 0),
    [totals]
  );

  const vat = useMemo(() => safeNumber(totals?.vat ?? totals?.VAT ?? 0, 0), [totals]);

  const total = useMemo(() => {
    const explicit = safeNumber(
      totals?.total ?? totals?.grand_total ?? totals?.grandTotal ?? Number.NaN,
      Number.NaN
    );
    if (Number.isFinite(explicit)) return explicit;
    return subtotal + deliveryFee + vat;
  }, [totals, subtotal, deliveryFee, vat]);

  const quoteLoading = quoteState?.status === "loading";
  const canSubmit = itemCount > 0 && !submitting && !disabled;

  useEffect(() => {
    if (!isOpen) return;
    if (typeof onRequestQuote !== "function") return;

    if (quoteTimer.current) clearTimeout(quoteTimer.current);

    quoteTimer.current = setTimeout(() => {
      onRequestQuote({
        location: safeText(location),
        phone: safeText(phone),
      });
    }, 450);

    return () => {
      if (quoteTimer.current) clearTimeout(quoteTimer.current);
    };
  }, [isOpen, location, phone, onRequestQuote]);

  const submit = async () => {
    if (!canSubmit) return;

    const cleanPhone = safeText(phone);
    const cleanLocation = safeText(location);
    const cleanNotes = safeText(notes);

    if (!cleanPhone) {
      toast.error("Please enter a phone number for SMS confirmation.");
      return;
    }

    if (!cleanLocation) {
      toast.error("Please enter a delivery location.");
      return;
    }

    const placeOrderFn =
      typeof onPlaceOrder === "function"
        ? onPlaceOrder
        : typeof actions?.checkoutOrder === "function"
          ? actions.checkoutOrder
          : null;

    if (!placeOrderFn) {
      toast.error("Checkout action is not available.");
      return;
    }

    setSubmitting(true);

    try {
      const checkoutItems = buildCheckoutItems(items);

      const uploadHandler = () => {
        /*
         * Checkout currently submits structured order payloads without a live proof-upload
         * progress bar in this dialog. Keep the upload progress callback stable because
         * some API helpers may still pass axios progress events through this option.
         */
      };

      const payload = {
        phone: cleanPhone,
        contact_phone: cleanPhone,
        location: cleanLocation,
        delivery_location: cleanLocation,
        delivery_address: cleanLocation,
        payment_method: normalizedPaymentMethod,
        notes: cleanNotes || undefined,
        delivery_notes: cleanNotes || undefined,
        items: checkoutItems,
        cart_items: checkoutItems,
        onUploadProgress: uploadHandler,
      };

      const options = {
        onUploadProgress: uploadHandler,
      };

      const result = await invokeCheckout(placeOrderFn, payload, options);

      setNotes("");

      toast.success("Order request submitted successfully.");
      onSuccess?.(result);
    } catch (err) {
      toast.error(extractErrorMessage(err));
    } finally {
      setSubmitting(false);
    }
  };

  if (!isOpen || !portalTarget) return null;

  const modalUI = (
    <div
      className="fixed inset-0 z-[120] animate-in fade-in duration-200"
      role="dialog"
      aria-modal="true"
      aria-label="Checkout"
      aria-describedby="checkout-description"
    >
      <button
        type="button"
        aria-label="Close checkout"
        onClick={handleBack}
        className="absolute inset-0 bg-black/60 backdrop-blur-[2px]"
      />

      <div className="relative z-[1] flex min-h-full items-center justify-center p-2 sm:p-4 lg:p-6">
        <div
          ref={dialogPanelRef}
          className="flex h-[min(92vh,920px)] w-full max-w-5xl flex-col overflow-hidden rounded-[28px] border border-slate-200 bg-white shadow-[0_24px_64px_-28px_rgba(2,6,23,0.55)] transition-all duration-200"
          onClick={(e) => e.stopPropagation()}
        >
          <div className="flex items-center justify-between border-b border-slate-200/90 px-4 py-3 sm:px-6 sm:py-4">
            <div className="min-w-0">
              <h2 className="truncate text-base font-bold text-slate-900 sm:text-lg">
                Secure Checkout
              </h2>
              <p id="checkout-description" className="mt-0.5 text-xs text-slate-500 sm:text-sm">
                Submit your order request now. The farmer will set the delivery fee, VAT will
                update automatically, and payment is completed later.
              </p>
            </div>

            <button
              type="button"
              onClick={handleBack}
              disabled={submitting}
              className="inline-flex h-11 w-11 items-center justify-center rounded-xl border border-slate-200 text-slate-600 transition hover:bg-slate-50 active:scale-[0.98] disabled:cursor-not-allowed disabled:opacity-60"
              aria-label="Close checkout"
            >
              <X className="h-4 w-4" />
            </button>
          </div>

          <div className="min-h-0 flex-1 overflow-y-auto">
            <div className="grid gap-0 lg:grid-cols-[360px,1fr]">
              <aside className="border-b border-slate-200 bg-gradient-to-b from-slate-50 to-white p-4 lg:min-h-full lg:border-b-0 lg:border-r lg:p-5">
                <div className="mb-4 flex items-center gap-2">
                  <div className="inline-flex h-8 w-8 items-center justify-center rounded-lg bg-emerald-50 text-emerald-700">
                    <ShoppingBag className="h-4 w-4" />
                  </div>
                  <h3 className="text-sm font-semibold text-slate-900">Order Summary</h3>
                </div>

                <div className="mb-4 grid grid-cols-2 gap-2.5 text-xs">
                  <div className="rounded-xl border border-slate-200 bg-white px-3 py-2.5 shadow-sm">
                    <div className="text-slate-500">Items</div>
                    <div className="font-bold text-slate-900">{itemCount}</div>
                  </div>
                  <div className="rounded-xl border border-slate-200 bg-white px-3 py-2.5 shadow-sm">
                    <div className="text-slate-500">Products</div>
                    <div className="font-bold text-slate-900">{currency(subtotal)}</div>
                  </div>
                </div>

                <div className="max-h-60 space-y-2 overflow-y-auto pr-1">
                  {items.length === 0 ? (
                    <p className="rounded-xl border border-dashed border-slate-300 bg-white px-3 py-4 text-center text-sm text-slate-500">
                      Your cart is empty.
                    </p>
                  ) : (
                    items.map((item, idx) => (
                      <div
                        key={String(getItemId(item) || idx)}
                        className="rounded-xl border border-slate-200 bg-white px-3 py-2.5 shadow-sm transition hover:shadow"
                      >
                        <div className="line-clamp-1 text-sm font-semibold text-slate-900">
                          {getItemName(item)}
                        </div>
                        <div className="mt-1.5 flex items-center justify-between text-xs text-slate-600">
                          <span>Qty: {getItemQty(item)}</span>
                          <span>{currency(getItemLineTotal(item))}</span>
                        </div>
                      </div>
                    ))
                  )}
                </div>

                <div className="mt-4 space-y-1.5 rounded-2xl border border-slate-200 bg-white px-3 py-3 text-xs shadow-sm">
                  <div className="flex items-center justify-between text-slate-600">
                    <span>Products subtotal</span>
                    <span className="font-semibold text-slate-900">{currency(subtotal)}</span>
                  </div>
                  <div className="flex items-center justify-between text-slate-600">
                    <span>Delivery fee</span>
                    <span className="font-semibold text-slate-900">
                      {deliveryFee > 0 ? currency(deliveryFee) : "Set by farmer"}
                    </span>
                  </div>
                  <div className="flex items-center justify-between text-slate-600">
                    <span>VAT (15%)</span>
                    <span className="font-semibold text-slate-900">
                      {deliveryFee > 0 || vat > 0 ? currency(vat) : "Auto after delivery fee"}
                    </span>
                  </div>
                  <div className="mt-1 h-px bg-slate-200" />
                  <div className="flex items-center justify-between pt-1 text-sm">
                    <span className="font-semibold text-slate-900">Final total</span>
                    <span className="font-extrabold text-slate-900">
                      {deliveryFee > 0 || vat > 0 ? currency(total) : "Shared after farmer quote"}
                    </span>
                  </div>
                </div>
              </aside>

              <section className="p-4 sm:p-5 lg:p-6">
                <div className="grid gap-4">
                  <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
                    <label className="space-y-1.5">
                      <div className="inline-flex items-center gap-1 text-xs font-semibold text-slate-600">
                        <Phone className="h-3.5 w-3.5" />
                        Phone (SMS)
                      </div>
                      <input
                        ref={firstInputRef}
                        value={phone}
                        onChange={(e) => {
                          setPhoneDirty(true);
                          setPhone(e.target.value);
                        }}
                        placeholder="e.g. +264 81 123 4567"
                        className="h-12 w-full rounded-xl border border-slate-200 bg-white px-3.5 text-sm text-slate-900 outline-none transition focus:border-emerald-400 focus:ring-2 focus:ring-emerald-100"
                      />
                    </label>

                    <label className="space-y-1.5">
                      <div className="inline-flex items-center gap-1 text-xs font-semibold text-slate-600">
                        <Wallet className="h-3.5 w-3.5" />
                        Payment method
                      </div>
                      <select
                        value={normalizedPaymentMethod}
                        onChange={(e) => setPaymentMethod(normalizePaymentMethod(e.target.value))}
                        className="h-12 w-full rounded-xl border border-slate-200 bg-white px-3.5 text-sm text-slate-900 outline-none transition focus:border-emerald-400 focus:ring-2 focus:ring-emerald-100"
                      >
                        <option value="eft">EFT / Bank Transfer</option>
                        <option value="cash_on_delivery">Cash on Delivery</option>
                      </select>
                    </label>
                  </div>

                  <label className="space-y-1.5">
                    <div className="inline-flex items-center gap-1 text-xs font-semibold text-slate-600">
                      <MapPin className="h-3.5 w-3.5" />
                      Delivery location
                    </div>
                    <input
                      value={location}
                      onChange={(e) => {
                        setLocationDirty(true);
                        setLocation(e.target.value);
                      }}
                      placeholder="Town / suburb / delivery point"
                      className="h-12 w-full rounded-xl border border-slate-200 bg-white px-3.5 text-sm text-slate-900 outline-none transition focus:border-emerald-400 focus:ring-2 focus:ring-emerald-100"
                    />
                    <div className="text-xs text-slate-500">
                      Pre-filled from your profile location. You can edit it for this order.
                    </div>
                  </label>

                  <div
                    className={`rounded-2xl p-3.5 text-xs shadow-sm ${
                      paymentMethodIsCash(normalizedPaymentMethod)
                        ? "border border-amber-200 bg-amber-50 text-amber-900"
                        : "border border-sky-200 bg-sky-50 text-sky-900"
                    }`}
                  >
                    <div className="inline-flex items-center gap-1 font-semibold">
                      <Receipt className="h-3.5 w-3.5" />
                      {paymentMethodIsCash(normalizedPaymentMethod)
                        ? "Cash on delivery selected"
                        : "Payment happens after the farmer confirms delivery cost"}
                    </div>
                    {paymentMethodIsCash(normalizedPaymentMethod) ? (
                      <p className="mt-2 leading-5 text-amber-800">
                        No proof of payment is required for cash on delivery. The farmer will
                        collect payment on delivery or pickup after the final total is confirmed.
                      </p>
                    ) : (
                      <p className="mt-2 leading-5 text-sky-800">
                        Your proof of payment is uploaded later from order history, only after the
                        farmer sets the delivery fee and the final total becomes ready.
                      </p>
                    )}
                  </div>

                  {quoteLoading ? (
                    <div className="rounded-xl border border-slate-200 bg-slate-50 px-3 py-2.5 text-xs text-slate-600">
                      Updating delivery quote…
                    </div>
                  ) : null}

                  {quoteState?.status === "error" && quoteState?.error ? (
                    <div className="rounded-xl border border-rose-200 bg-rose-50 px-3 py-2.5 text-xs text-rose-700">
                      {quoteState.error}
                    </div>
                  ) : null}

                  <label className="block space-y-1.5">
                    <div className="inline-flex items-center gap-1 text-xs font-semibold text-slate-600">
                      <FileText className="h-3.5 w-3.5" />
                      Notes (optional)
                    </div>
                    <textarea
                      value={notes}
                      onChange={(e) => setNotes(e.target.value)}
                      placeholder="Any delivery notes or instructions…"
                      rows={3}
                      className="w-full rounded-xl border border-slate-200 bg-white px-3.5 py-2.5 text-sm text-slate-900 outline-none transition focus:border-emerald-400 focus:ring-2 focus:ring-emerald-100"
                    />
                  </label>
                </div>
              </section>
            </div>
          </div>

          <div className="flex flex-col gap-2 border-t border-slate-200 bg-white px-4 py-3 sm:flex-row sm:items-center sm:justify-between sm:px-6 sm:py-4">
            <p className="inline-flex items-center gap-1.5 text-xs text-slate-500">
              <ShieldCheck className="h-3.5 w-3.5 text-emerald-600" />
              {paymentMethodIsCash(normalizedPaymentMethod)
                ? "You are submitting an order request. Cash orders do not require proof upload. Payment is collected on delivery or pickup after the farmer confirms the final total."
                : "You are submitting an order request. EFT payment happens later after the farmer sets the delivery fee and the final total is shown."}
            </p>

            <div className="grid grid-cols-1 gap-2 sm:flex sm:items-center">
              <button
                type="button"
                onClick={handleBack}
                disabled={submitting}
                className="h-11 rounded-xl border border-slate-300 px-4 text-sm font-semibold text-slate-700 transition hover:bg-slate-50 active:scale-[0.99] disabled:cursor-not-allowed disabled:opacity-60"
              >
                Back
              </button>

              <button
                type="button"
                onClick={submit}
                disabled={!canSubmit}
                className={`inline-flex h-11 min-w-[170px] items-center justify-center gap-2 rounded-xl px-4 text-sm font-bold text-white transition-all duration-200 ${
                  canSubmit
                    ? "bg-emerald-600 shadow-sm hover:-translate-y-[1px] hover:bg-emerald-700 hover:shadow active:translate-y-0"
                    : "cursor-not-allowed bg-slate-300"
                }`}
              >
                {submitting ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Submitting request…
                  </>
                ) : (
                  "Submit order request"
                )}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );

  return createPortal(modalUI, portalTarget);
}
