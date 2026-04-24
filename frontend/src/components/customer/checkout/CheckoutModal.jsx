// ============================================================================
// src/components/customer/checkout/CheckoutModal.jsx
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Checkout modal (delivery + payment) before creating an order.
//
// FIXES (THIS UPDATE):
//   ✅ Allows parent-controlled submit via onConfirm(extraFields)
//      - CartDrawer uses this to call customerApi.placeOrder()
//   ✅ cartItems mapping supports different shapes safely
// ============================================================================

import React, { useMemo, useState } from "react";
import { X, Truck, Store, CreditCard, Banknote, Smartphone } from "lucide-react";
import api from "../../../api";

function money(v) {
  const n = Number(v);
  return Number.isFinite(n) ? n.toFixed(2) : "0.00";
}

export default function CheckoutModal({
  open,
  onClose,
  cartItems = [],
  totals = { subtotal: 0, deliveryFee: 0, vat: 0, total: 0 },

  // Optional: parent-driven order placement (recommended)
  onConfirm, // async (extra) => createdOrder (or nothing)
  onSuccess,

  busy: busyProp,
}) {
  const [deliveryMethod, setDeliveryMethod] = useState("delivery"); // delivery | pickup
  const [address, setAddress] = useState("");
  const [paymentMethod, setPaymentMethod] = useState("eft"); // eft | cash | mobile
  const [note, setNote] = useState("");

  const [busyLocal, setBusyLocal] = useState(false);
  const [err, setErr] = useState("");

  const busy = typeof busyProp === "boolean" ? busyProp : busyLocal;

  const canCheckout = useMemo(() => (Array.isArray(cartItems) ? cartItems.length > 0 : false), [cartItems]);

  if (!open) return null;

  const submit = async () => {
    if (!canCheckout || busy) return;

    setErr("");
    if (deliveryMethod === "delivery" && !address.trim()) {
      setErr("Delivery address is required.");
      return;
    }

    // extra fields (safe to send even if backend ignores some)
    const extra = {
      payment_method: paymentMethod,
      delivery_method: deliveryMethod,
      delivery_address: deliveryMethod === "delivery" ? address.trim() : null,
      note: note.trim() || null,
    };

    try {
      if (typeof onConfirm === "function") {
        // ✅ Parent handles actual API call
        const created = await onConfirm(extra);
        if (typeof onSuccess === "function") onSuccess(created);
        if (typeof onClose === "function") onClose();
        return;
      }

      // Fallback (if used elsewhere without CartDrawer)
      setBusyLocal(true);

      const items = (cartItems || [])
        .map((it) => ({
          product_id: it?.product_id ?? it?.productId ?? it?.product?.id ?? it?.id,
          qty: it?.qty ?? it?.quantity ?? 1,
        }))
        .filter((x) => x.product_id != null);

      const payload = { items, ...extra };
      const res = await api.post("/orders", payload);
      const order = res?.data?.order || res?.data;

      if (typeof onSuccess === "function") onSuccess(order);
      if (typeof onClose === "function") onClose();
    } catch (e) {
      const msg =
        e?.response?.data?.message ||
        e?.response?.data?.error ||
        e?.message ||
        "Checkout failed. Please try again.";
      setErr(String(msg));
    } finally {
      setBusyLocal(false);
    }
  };

  return (
    <div className="fixed inset-0 z-[90]">
      <button className="absolute inset-0 bg-black/40" onClick={onClose} aria-label="Close checkout" />

      <div className="absolute left-1/2 top-1/2 w-[min(720px,92vw)] -translate-x-1/2 -translate-y-1/2 rounded-3xl bg-white shadow-xl border border-slate-200 overflow-hidden">
        <div className="flex items-center justify-between px-5 py-4 border-b border-slate-100">
          <div>
            <div className="font-extrabold text-slate-900">Checkout</div>
            <div className="text-xs text-slate-500 mt-0.5">Choose delivery and payment method.</div>
          </div>

          <button
            type="button"
            onClick={onClose}
            disabled={busy}
            className="h-9 w-9 rounded-xl border border-slate-200 bg-white hover:bg-slate-50 flex items-center justify-center disabled:opacity-60"
          >
            <X className="h-4 w-4 text-slate-600" />
          </button>
        </div>

        <div className="p-5 space-y-4">
          {err ? <div className="rounded-xl border border-rose-200 bg-rose-50 p-3 text-sm text-rose-700">{err}</div> : null}

          {/* Delivery */}
          <div className="rounded-2xl border border-slate-200 p-4">
            <div className="text-sm font-extrabold text-slate-900 mb-3">Delivery</div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
              <button
                type="button"
                onClick={() => setDeliveryMethod("delivery")}
                disabled={busy}
                className={[
                  "p-3 rounded-2xl border text-left flex items-center gap-3 disabled:opacity-60",
                  deliveryMethod === "delivery" ? "border-emerald-200 bg-emerald-50" : "border-slate-200 bg-white hover:bg-slate-50",
                ].join(" ")}
              >
                <Truck className="h-5 w-5 text-slate-700" />
                <div>
                  <div className="text-sm font-bold text-slate-900">Delivery</div>
                  <div className="text-xs text-slate-500">Delivered to your address</div>
                </div>
              </button>

              <button
                type="button"
                onClick={() => setDeliveryMethod("pickup")}
                disabled={busy}
                className={[
                  "p-3 rounded-2xl border text-left flex items-center gap-3 disabled:opacity-60",
                  deliveryMethod === "pickup" ? "border-emerald-200 bg-emerald-50" : "border-slate-200 bg-white hover:bg-slate-50",
                ].join(" ")}
              >
                <Store className="h-5 w-5 text-slate-700" />
                <div>
                  <div className="text-sm font-bold text-slate-900">Pickup</div>
                  <div className="text-xs text-slate-500">Collect from the farmer</div>
                </div>
              </button>
            </div>

            {deliveryMethod === "delivery" ? (
              <div className="mt-3">
                <label className="text-xs font-semibold text-slate-700">Delivery address</label>
                <textarea
                  value={address}
                  onChange={(e) => setAddress(e.target.value)}
                  rows={3}
                  disabled={busy}
                  className="mt-1 w-full rounded-2xl border border-slate-200 bg-white p-3 text-sm outline-none disabled:opacity-60"
                  placeholder="Street, town, landmarks…"
                />
              </div>
            ) : null}
          </div>

          {/* Payment */}
          <div className="rounded-2xl border border-slate-200 p-4">
            <div className="text-sm font-extrabold text-slate-900 mb-3">Payment</div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
              <button
                type="button"
                onClick={() => setPaymentMethod("eft")}
                disabled={busy}
                className={[
                  "p-3 rounded-2xl border text-left flex items-center gap-3 disabled:opacity-60",
                  paymentMethod === "eft" ? "border-emerald-200 bg-emerald-50" : "border-slate-200 bg-white hover:bg-slate-50",
                ].join(" ")}
              >
                <CreditCard className="h-5 w-5 text-slate-700" />
                <div>
                  <div className="text-sm font-bold text-slate-900">EFT</div>
                  <div className="text-xs text-slate-500">Bank transfer</div>
                </div>
              </button>

              <button
                type="button"
                onClick={() => setPaymentMethod("cash")}
                disabled={busy}
                className={[
                  "p-3 rounded-2xl border text-left flex items-center gap-3 disabled:opacity-60",
                  paymentMethod === "cash" ? "border-emerald-200 bg-emerald-50" : "border-slate-200 bg-white hover:bg-slate-50",
                ].join(" ")}
              >
                <Banknote className="h-5 w-5 text-slate-700" />
                <div>
                  <div className="text-sm font-bold text-slate-900">Cash</div>
                  <div className="text-xs text-slate-500">Pay on delivery/pickup</div>
                </div>
              </button>

              <button
                type="button"
                onClick={() => setPaymentMethod("mobile")}
                disabled={busy}
                className={[
                  "p-3 rounded-2xl border text-left flex items-center gap-3 disabled:opacity-60",
                  paymentMethod === "mobile" ? "border-emerald-200 bg-emerald-50" : "border-slate-200 bg-white hover:bg-slate-50",
                ].join(" ")}
              >
                <Smartphone className="h-5 w-5 text-slate-700" />
                <div>
                  <div className="text-sm font-bold text-slate-900">Mobile</div>
                  <div className="text-xs text-slate-500">Wallet payment</div>
                </div>
              </button>
            </div>

            <div className="mt-3">
              <label className="text-xs font-semibold text-slate-700">Note (optional)</label>
              <input
                value={note}
                onChange={(e) => setNote(e.target.value)}
                disabled={busy}
                className="mt-1 w-full rounded-2xl border border-slate-200 bg-white p-3 text-sm outline-none disabled:opacity-60"
                placeholder="e.g. Call when outside"
              />
            </div>
          </div>

          {/* Totals */}
          <div className="rounded-2xl border border-slate-200 p-4">
            <div className="flex items-center justify-between text-sm text-slate-600">
              <span>Subtotal</span>
              <span>N$ {money(totals.subtotal)}</span>
            </div>
            <div className="flex items-center justify-between text-sm text-slate-600 mt-1">
              <span>Delivery fee</span>
              <span>N$ {money(totals.deliveryFee)}</span>
            </div>
            <div className="flex items-center justify-between text-sm text-slate-600 mt-1">
              <span>VAT</span>
              <span>N$ {money(totals.vat)}</span>
            </div>
            <div className="h-px bg-slate-200 my-3" />
            <div className="flex items-center justify-between font-extrabold text-slate-900">
              <span>Total</span>
              <span>N$ {money(totals.total)}</span>
            </div>
          </div>

          <button
            type="button"
            onClick={submit}
            disabled={!canCheckout || busy}
            className="w-full h-12 rounded-2xl bg-emerald-700 hover:bg-emerald-800 text-white font-extrabold disabled:opacity-60"
          >
            {busy ? "Processing…" : "Place order"}
          </button>
        </div>
      </div>
    </div>
  );
}
