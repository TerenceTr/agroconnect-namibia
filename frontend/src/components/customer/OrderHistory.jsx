// ============================================================================
// components/customer/OrderHistory.jsx
// ----------------------------------------------------------------------------
// ROLE:
// • Displays customer order history
// • Shows lifecycle: placed → confirmed → delivered / rejected
// ============================================================================

import React, { useMemo, useState } from 'react';
import PropTypes from 'prop-types';
import { format } from 'date-fns';

export default function OrderHistory({ orders, loading, onRefresh }) {
  const [status, setStatus] = useState('all');

  const filtered = useMemo(() => {
    if (status === 'all') return orders;
    return orders.filter(
      (o) => String(o.status || '').toLowerCase() === status
    );
  }, [orders, status]);

  return (
    <div className="glass-card p-6 rounded-2xl">
      <div className="flex flex-col md:flex-row md:justify-between gap-3">
        <h3 className="font-semibold">Order History</h3>

        <div className="flex gap-3">
          <select
            value={status}
            onChange={(e) => setStatus(e.target.value)}
            className="px-3 py-2 rounded-lg bg-white/10 border border-white/10 text-white"
          >
            <option value="all">All</option>
            <option value="pending">Pending</option>
            <option value="confirmed">Confirmed</option>
            <option value="in_transit">In transit</option>
            <option value="delivered">Delivered</option>
            <option value="rejected">Rejected</option>
          </select>

          <button
            type="button"
            onClick={onRefresh}
            className="px-3 py-2 rounded-lg bg-white/10 hover:bg-white/15"
          >
            Refresh
          </button>
        </div>
      </div>

      {loading ? (
        <div className="py-10 text-center text-white/70">
          Loading orders…
        </div>
      ) : filtered.length === 0 ? (
        <div className="py-10 text-center text-white/70">
          No orders found.
        </div>
      ) : (
        <div className="mt-4 space-y-2">
          {filtered.map((o) => (
            <div
              key={o.id}
              className="p-3 rounded-xl bg-white/5 border border-white/10 flex justify-between"
            >
              <div>
                <div className="font-medium">
                  {o.product_name || `Order #${o.id}`}
                </div>
                <div className="text-xs text-white/60">
                  {o.created_at
                    ? format(new Date(o.created_at), 'dd MMM yyyy HH:mm')
                    : '—'}
                </div>
              </div>

              <div className="text-right">
                <div className="capitalize">
                  {String(o.status || 'unknown').replaceAll('_', ' ')}
                </div>
                <div className="text-xs text-white/60">
                  {Number(o.total || 0).toFixed(2)} N$
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

OrderHistory.propTypes = {
  orders: PropTypes.arrayOf(
    PropTypes.shape({
      id: PropTypes.oneOfType([PropTypes.string, PropTypes.number]).isRequired,
      status: PropTypes.string,
      total: PropTypes.number,
      created_at: PropTypes.string,
      product_name: PropTypes.string,
    })
  ).isRequired,

  loading: PropTypes.bool.isRequired,
  onRefresh: PropTypes.func.isRequired,
};
