// ============================================================================
// components/customer/CheckoutPanel.jsx
// ----------------------------------------------------------------------------
// ROLE:
// • Checkout + order placement UI
// • Sends order payload to API
// • Backend triggers SMS / Email + order status updates
// ============================================================================

import React, { useMemo, useState } from 'react';
import PropTypes from 'prop-types';
import toast from 'react-hot-toast';

export default function CheckoutPanel({ cart, totals, onPlaceOrder }) {
  const items = cart?.items ?? [];

  const [deliveryNote, setDeliveryNote] = useState('');
  const [paymentMethod, setPaymentMethod] = useState('cash');
  const [notifySms, setNotifySms] = useState(true);
  const [notifyEmail, setNotifyEmail] = useState(true);
  const [submitting, setSubmitting] = useState(false);

  // ------------------------------------------------------------------
  // Can checkout only if cart has items + valid total
  // ------------------------------------------------------------------
  const canCheckout = useMemo(
    () => items.length > 0 && Number(totals?.subtotal || 0) > 0,
    [items.length, totals?.subtotal]
  );

  // ------------------------------------------------------------------
  // Submit order
  // ------------------------------------------------------------------
  const submit = async () => {
    if (!canCheckout || submitting) return;

    try {
      setSubmitting(true);

      const payload = {
        items: items.map((it) => ({
          product_id: it.product_id,
          qty: it.qty,
        })),
        delivery_note: deliveryNote.trim(),
        payment_method: paymentMethod,
        notify: {
          sms: notifySms,
          email: notifyEmail,
        },
      };

      await onPlaceOrder(payload);

      toast.success(
        'Order placed successfully. SMS / Email confirmations sent.'
      );

      setDeliveryNote('');
    } catch (err) {
      console.error(err);
      toast.error('Failed to place order');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="glass-card p-6 rounded-2xl">
      <h3 className="font-semibold">Checkout</h3>

      <div className="mt-4 space-y-4">
        {/* Delivery note */}
        <div>
          <label className="text-sm text-white/80 block mb-2">
            Delivery note (optional)
          </label>
          <textarea
            rows={3}
            value={deliveryNote}
            onChange={(e) => setDeliveryNote(e.target.value)}
            className="w-full px-3 py-2 rounded-lg bg-white/10 border border-white/10 text-white outline-none"
          />
        </div>

        {/* Payment method */}
        <div>
          <label className="text-sm text-white/80 block mb-2">
            Payment method
          </label>
          <select
            value={paymentMethod}
            onChange={(e) => setPaymentMethod(e.target.value)}
            className="w-full px-3 py-2 rounded-lg bg-white/10 border border-white/10 text-white outline-none"
          >
            <option value="cash">Cash on delivery</option>
            <option value="eft">EFT / bank transfer</option>
            <option value="proof">Upload proof</option>
          </select>
        </div>

        {/* Notifications */}
        <div className="flex flex-col gap-2">
          <label className="inline-flex items-center gap-2 text-sm text-white/80">
            <input
              type="checkbox"
              checked={notifySms}
              onChange={(e) => setNotifySms(e.target.checked)}
            />
            Send SMS confirmation
          </label>

          <label className="inline-flex items-center gap-2 text-sm text-white/80">
            <input
              type="checkbox"
              checked={notifyEmail}
              onChange={(e) => setNotifyEmail(e.target.checked)}
            />
            Send email confirmation
          </label>
        </div>

        {/* Total */}
        <div className="pt-3 border-t border-white/10 flex justify-between">
          <span className="text-white/70">Total</span>
          <span className="font-semibold">
            {Number(totals?.subtotal || 0).toFixed(2)} N$
          </span>
        </div>

        {/* Submit */}
        <button
          type="button"
          onClick={submit}
          disabled={!canCheckout || submitting}
          className={`w-full px-4 py-2 rounded-lg font-semibold transition ${
            canCheckout
              ? 'bg-emerald-500 hover:bg-emerald-600'
              : 'bg-white/10 text-white/50 cursor-not-allowed'
          }`}
        >
          {submitting ? 'Placing order…' : 'Place Order'}
        </button>
      </div>
    </div>
  );
}

// ------------------------------------------------------------------
// PropTypes (fixes ESLint warnings)
// ------------------------------------------------------------------
CheckoutPanel.propTypes = {
  cart: PropTypes.shape({
    items: PropTypes.arrayOf(
      PropTypes.shape({
        product_id: PropTypes.oneOfType([PropTypes.string, PropTypes.number])
          .isRequired,
        qty: PropTypes.number.isRequired,
      })
    ),
  }).isRequired,

  totals: PropTypes.shape({
    subtotal: PropTypes.number.isRequired,
  }).isRequired,

  onPlaceOrder: PropTypes.func.isRequired,
};
