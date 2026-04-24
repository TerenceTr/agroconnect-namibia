// ============================================================================
// frontend/src/components/customer/marketplace/CheckoutFormModal.jsx
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Lightweight marketplace checkout modal/form UI.
//   • Uses profile-based default delivery location (editable)
//   • Submits an ORDER REQUEST through actions.checkoutOrder(...)
//   • Payment proof is no longer collected during initial checkout
//   • Supports EFT and Cash on Delivery messaging
//   • Keeps compatibility with existing action signatures
//
// THIS UPDATE:
//   ✅ Removes checkout-time proof upload and proof reference fields
//   ✅ Adds payment method selector (eft / cash_on_delivery)
//   ✅ Sends payment_method in the checkout payload
//   ✅ Keeps delivery_location + delivery_address + location aliases
//   ✅ Keeps scroll-safe modal layout for long content
//   ✅ Keeps submit progress UI for request submission only
//   ✅ Changes language from final payment to order-request wording
// ============================================================================

import React, { useEffect, useMemo, useState } from "react";

function safeNumber(v, fallback = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

function safeText(v, fallback = "") {
  const s = String(v ?? "").trim();
  return s || fallback;
}

function currency(n) {
  return `N$ ${safeNumber(n, 0).toFixed(2)}`;
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

function getQty(item) {
  return Math.max(1, safeNumber(item?.quantity ?? item?.qty ?? item?.cart_quantity ?? 1, 1));
}

function getUnitPrice(item) {
  const p = item?.unit_price ?? item?.price ?? item?.product?.unit_price ?? item?.product?.price;
  return safeNumber(p, 0);
}

function getLineTotal(item) {
  const explicit = item?.line_total ?? item?.lineTotal;
  if (explicit != null) return safeNumber(explicit, 0);
  return getQty(item) * getUnitPrice(item);
}

function normalizeItems(raw) {
  if (Array.isArray(raw)) return raw;
  if (Array.isArray(raw?.items)) return raw.items;
  return [];
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

function toCheckoutItems(items) {
  return normalizeItems(items)
    .map((it) => {
      const id = getItemId(it);
      if (!id) return null;
      return {
        product_id: id,
        id, // alias
        quantity: getQty(it),
        qty: getQty(it), // alias
        unit_price: getUnitPrice(it),
      };
    })
    .filter(Boolean);
}

async function invokeCheckout(checkoutFn, payload, options) {
  if (typeof checkoutFn !== "function") {
    throw new Error("Checkout action is unavailable.");
  }
  // Works for both (payload) and (payload, config)
  return checkoutFn(payload, options);
}

export default function CheckoutFormModal({
  isOpen,
  onClose,
  actions,
  cartItems = [],
  defaultDeliveryLocation = "",
  defaultPhone = "",
  customerProfile,
  customerLocation = "",
  onSuccess,
}) {
  const resolvedDefaultLocation = useMemo(() => {
    return (
      safeText(defaultDeliveryLocation) ||
      safeText(customerLocation) ||
      safeText(customerProfile?.delivery_location) ||
      safeText(customerProfile?.address) ||
      safeText(customerProfile?.location) ||
      ""
    );
  }, [defaultDeliveryLocation, customerLocation, customerProfile]);

  const resolvedDefaultPhone = useMemo(() => {
    return (
      safeText(defaultPhone) ||
      safeText(customerProfile?.phone) ||
      safeText(customerProfile?.mobile) ||
      safeText(customerProfile?.contact_phone) ||
      ""
    );
  }, [defaultPhone, customerProfile]);

  const [deliveryLocation, setDeliveryLocation] = useState("");
  const [phone, setPhone] = useState("");
  const [notes, setNotes] = useState("");
  const [paymentMethod, setPaymentMethod] = useState("eft");

  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submitPct, setSubmitPct] = useState(0);
  const [error, setError] = useState("");

  const items = useMemo(() => normalizeItems(cartItems), [cartItems]);
  const normalizedMethod = useMemo(() => normalizePaymentMethod(paymentMethod), [paymentMethod]);

  const total = useMemo(() => {
    return items.reduce((sum, item) => sum + getLineTotal(item), 0);
  }, [items]);

  useEffect(() => {
    if (!isOpen) return;

    setDeliveryLocation(resolvedDefaultLocation || "");
    setPhone(resolvedDefaultPhone || "");
    setNotes("");
    setPaymentMethod("eft");
    setError("");
    setSubmitPct(0);
  }, [isOpen, resolvedDefaultLocation, resolvedDefaultPhone]);

  if (!isOpen) return null;

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");

    const checkoutOrder = actions?.checkoutOrder;
    if (typeof checkoutOrder !== "function") {
      setError("Checkout action is unavailable. Please refresh and try again.");
      return;
    }

    const location = safeText(deliveryLocation);
    const phoneText = safeText(phone);
    const notesText = safeText(notes);

    if (!location) {
      setError("Please provide a delivery location.");
      return;
    }

    if (!phoneText) {
      setError("Please provide a contact phone number.");
      return;
    }

    try {
      setIsSubmitting(true);
      setSubmitPct(0);

      const checkoutItems = toCheckoutItems(items);

      const options = {
        onUploadProgress: (evt) => {
          // NOTE:
          // We keep progress handling because some axios wrappers reuse this callback
          // even for JSON requests. This is now request-submission progress, not proof upload.
          const loaded = safeNumber(evt?.loaded, 0);
          const totalBytes = safeNumber(evt?.total, 0);

          if (totalBytes > 0) {
            const pct = Math.round((loaded / totalBytes) * 100);
            setSubmitPct(Math.max(0, Math.min(100, pct)));
          } else if (loaded > 0) {
            setSubmitPct((prev) => (prev < 90 ? prev + 5 : prev));
          }
        },
      };

      const payload = {
        phone: phoneText,
        contact_phone: phoneText,
        location,
        delivery_location: location,
        delivery_address: location,
        payment_method: normalizedMethod,
        notes: notesText || undefined,
        delivery_notes: notesText || undefined,
        items: checkoutItems,
        cart_items: checkoutItems,
      };

      const result = await invokeCheckout(checkoutOrder, payload, options);

      setSubmitPct(100);
      onSuccess?.(result);
      onClose?.();
    } catch (err) {
      const msg =
        err?.response?.data?.error ||
        err?.response?.data?.message ||
        err?.message ||
        "Checkout failed. Please try again.";
      setError(msg);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
      role="dialog"
      aria-modal="true"
      aria-label="Checkout modal"
    >
      {/* Scroll-safe modal container */}
      <div className="flex max-h-[92vh] w-full max-w-2xl flex-col overflow-hidden rounded-2xl bg-white shadow-2xl">
        <div className="flex items-center justify-between border-b border-gray-200 px-5 py-4">
          <div>
            <h2 className="text-lg font-semibold text-gray-900">Submit Order Request</h2>
            <p className="mt-1 text-xs text-gray-500">
              The farmer will confirm the delivery fee first. Payment is handled later based on
              your selected payment method.
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-lg px-2 py-1 text-gray-500 hover:bg-gray-100 hover:text-gray-700"
            disabled={isSubmitting}
          >
            ✕
          </button>
        </div>

        {/* Body scrolls if content is long */}
        <form onSubmit={handleSubmit} className="grid gap-5 overflow-y-auto p-5">
          {/* Order summary */}
          <section className="rounded-xl border border-gray-200 p-4">
            <h3 className="mb-3 text-sm font-semibold text-gray-800">Order Summary</h3>

            {/* Scrollable items list */}
            <div className="max-h-44 space-y-2 overflow-y-auto pr-1">
              {items.length === 0 ? (
                <p className="text-sm text-gray-500">No items in cart.</p>
              ) : (
                items.map((item, idx) => (
                  <div
                    key={getItemId(item) || idx}
                    className="flex items-center justify-between text-sm"
                  >
                    <div className="min-w-0">
                      <p className="truncate text-gray-800">
                        {item?.name || item?.product_name || "Product"}
                      </p>
                      <p className="text-xs text-gray-500">Qty: {getQty(item)}</p>
                    </div>
                    <span className="font-medium text-gray-900">{currency(getLineTotal(item))}</span>
                  </div>
                ))
              )}
            </div>

            <div className="mt-3 border-t border-gray-200 pt-3 text-right text-sm font-semibold text-gray-900">
              Products total: {currency(total)}
            </div>
            <p className="mt-2 text-xs text-gray-500">
              Delivery fee and VAT are finalized after the farmer reviews your order request.
            </p>
          </section>

          {/* Contact + Delivery */}
          <section className="grid gap-3 sm:grid-cols-2">
            <label className="grid gap-2">
              <span className="text-sm font-medium text-gray-800">
                Phone <span className="text-red-500">*</span>
              </span>
              <input
                type="text"
                value={phone}
                onChange={(e) => setPhone(e.target.value)}
                placeholder="e.g. +264 81 123 4567"
                className="w-full rounded-xl border border-gray-300 px-3 py-2 text-sm outline-none transition focus:border-emerald-500 focus:ring-2 focus:ring-emerald-100"
                disabled={isSubmitting}
              />
            </label>

            <label className="grid gap-2">
              <span className="text-sm font-medium text-gray-800">Payment Method</span>
              <select
                value={normalizedMethod}
                onChange={(e) => setPaymentMethod(normalizePaymentMethod(e.target.value))}
                className="w-full rounded-xl border border-gray-300 px-3 py-2 text-sm outline-none transition focus:border-emerald-500 focus:ring-2 focus:ring-emerald-100"
                disabled={isSubmitting}
              >
                <option value="eft">EFT / Bank Transfer</option>
                <option value="cash_on_delivery">Cash on Delivery</option>
              </select>
            </label>

            <label className="grid gap-2 sm:col-span-2">
              <span className="text-sm font-medium text-gray-800">
                Delivery Location <span className="text-red-500">*</span>
              </span>
              <textarea
                rows={3}
                value={deliveryLocation}
                onChange={(e) => setDeliveryLocation(e.target.value)}
                placeholder="Enter your delivery address/location"
                className="w-full rounded-xl border border-gray-300 px-3 py-2 text-sm outline-none transition focus:border-emerald-500 focus:ring-2 focus:ring-emerald-100"
                disabled={isSubmitting}
              />
              <p className="text-xs text-gray-500">
                Pre-filled from your profile. You can edit it for this order.
              </p>
            </label>
          </section>

          {/* Payment guidance */}
          <section
            className={`rounded-xl border px-3 py-3 text-sm ${
              paymentMethodIsCash(normalizedMethod)
                ? "border-amber-200 bg-amber-50 text-amber-900"
                : "border-sky-200 bg-sky-50 text-sky-900"
            }`}
          >
            <div className="font-semibold">
              {paymentMethodIsCash(normalizedMethod)
                ? "Cash on delivery selected"
                : "EFT selected"}
            </div>
            {paymentMethodIsCash(normalizedMethod) ? (
              <p className="mt-1 leading-6 text-amber-800">
                No proof of payment is required during checkout. The farmer will collect payment on
                delivery or pickup after the final total is confirmed.
              </p>
            ) : (
              <p className="mt-1 leading-6 text-sky-800">
                Do not upload proof during checkout. After the farmer sets the delivery fee, you will
                upload proof of payment later from your order history.
              </p>
            )}
          </section>

          {/* Notes */}
          <section className="grid gap-2">
            <label className="text-sm font-medium text-gray-800">Delivery Notes (optional)</label>
            <textarea
              rows={3}
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              placeholder="Any instructions for delivery"
              className="w-full rounded-xl border border-gray-300 px-3 py-2 text-sm outline-none transition focus:border-emerald-500 focus:ring-2 focus:ring-emerald-100"
              disabled={isSubmitting}
            />
          </section>

          {/* Submit progress */}
          {(isSubmitting || submitPct > 0) && (
            <section className="grid gap-1">
              <div className="flex items-center justify-between text-xs text-gray-600">
                <span>Submitting order request...</span>
                <span>{submitPct}%</span>
              </div>
              <div className="h-2 w-full overflow-hidden rounded-full bg-gray-200">
                <div
                  className="h-full rounded-full bg-emerald-600 transition-all duration-200"
                  style={{ width: `${submitPct}%` }}
                />
              </div>
            </section>
          )}

          {error ? (
            <div className="rounded-xl border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
              {error}
            </div>
          ) : null}

          <div className="sticky bottom-0 flex flex-col-reverse gap-2 border-t bg-white pt-3 sm:flex-row sm:justify-end">
            <button
              type="button"
              onClick={onClose}
              disabled={isSubmitting}
              className="rounded-xl border border-gray-300 px-4 py-2 text-sm font-medium text-gray-700 hover:bg-gray-50 disabled:cursor-not-allowed disabled:opacity-50"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isSubmitting || !items.length}
              className="rounded-xl bg-emerald-600 px-4 py-2 text-sm font-semibold text-white hover:bg-emerald-700 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {isSubmitting ? "Submitting Request..." : "Submit Order Request"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
