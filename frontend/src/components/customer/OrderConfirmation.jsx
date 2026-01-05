// ============================================================================
// components/customer/OrderConfirmation.jsx
// ----------------------------------------------------------------------------
// ROLE:
// • Displays confirmation after successful order
// • Confirms backend-triggered notifications
// ============================================================================

import React from 'react';
import PropTypes from 'prop-types';

export default function OrderConfirmation({ order }) {
  if (!order) return null;

  return (
    <div className="glass-card p-6 rounded-2xl text-center">
      <h2 className="text-2xl font-bold text-emerald-400">
        Order Confirmed 🎉
      </h2>

      <p className="mt-2 text-white/70">
        Order #{order.id} has been placed successfully.
      </p>

      <p className="text-sm mt-2 text-white/60">
        SMS / Email notifications have been sent.
      </p>
    </div>
  );
}

OrderConfirmation.propTypes = {
  order: PropTypes.shape({
    id: PropTypes.oneOfType([PropTypes.string, PropTypes.number]).isRequired,
  }),
};
