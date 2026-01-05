// ============================================================================
// components/customer/RatingsPanel.jsx
// ----------------------------------------------------------------------------
// ROLE:
// • Allows customer to rate farmer + leave comment
// • Supports governance + feedback loop (MSc value)
// ============================================================================

import React, { useEffect, useState } from 'react';
import toast from 'react-hot-toast';
import { fetchRatings, submitRating } from '../../services/customerApi';

export default function RatingsPanel({ product }) {
  const [rating, setRating] = useState(5);
  const [comment, setComment] = useState('');
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  const load = async () => {
    if (!product?.id) return;
    try {
      setLoading(true);
      const data = await fetchRatings(product.id);
      setItems(Array.isArray(data) ? data : data?.ratings || []);
    } catch (e) {
      console.error(e);
      toast.error('Failed to load ratings');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
    // eslint-disable-next-line
  }, [product?.id]);

  const save = async () => {
    if (!product?.id) return;
    try {
      setSaving(true);
      await submitRating({
        product_id: product.id,
        farmer_id: product.farmer_id,
        rating: Number(rating),
        comment: comment.trim(),
      });
      toast.success('Thanks for your feedback!');
      setComment('');
      await load();
    } catch (e) {
      console.error(e);
      toast.error('Failed to submit rating');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="glass-card p-6 rounded-2xl">
      <h3 className="font-semibold">Ratings & Comments</h3>

      {!product ? (
        <div className="py-8 text-center text-white/70">
          Select a product to view ratings.
        </div>
      ) : (
        <>
          <div className="mt-4 grid grid-cols-1 md:grid-cols-3 gap-3">
            <div>
              <label className="text-sm text-white/80 block mb-2">Rating</label>
              <select
                value={rating}
                onChange={(e) => setRating(e.target.value)}
                className="w-full px-3 py-2 rounded-lg bg-white/10 border border-white/10 text-white outline-none"
              >
                {[5, 4, 3, 2, 1].map((n) => (
                  <option key={n} value={n}>
                    {n}
                  </option>
                ))}
              </select>
            </div>

            <div className="md:col-span-2">
              <label className="text-sm text-white/80 block mb-2">Comment</label>
              <input
                value={comment}
                onChange={(e) => setComment(e.target.value)}
                className="w-full px-3 py-2 rounded-lg bg-white/10 border border-white/10 text-white outline-none"
                placeholder="Optional feedback…"
              />
            </div>
          </div>

          <button
            type="button"
            onClick={save}
            disabled={saving}
            className="mt-4 px-4 py-2 rounded-lg bg-emerald-500 hover:bg-emerald-600 font-semibold"
          >
            {saving ? 'Submitting…' : 'Submit'}
          </button>

          <div className="mt-6">
            <h4 className="font-medium mb-2 text-white/90">Recent feedback</h4>

            {loading ? (
              <div className="text-white/70">Loading…</div>
            ) : items.length === 0 ? (
              <div className="text-white/70">No ratings yet.</div>
            ) : (
              <div className="space-y-2">
                {items.slice(0, 8).map((r) => (
                  <div
                    key={r.id}
                    className="p-3 rounded-xl bg-white/5 border border-white/10"
                  >
                    <div className="flex items-center justify-between">
                      <div className="font-medium">Rating: {r.rating}/5</div>
                      <div className="text-xs text-white/60">
                        {r.created_at?.slice(0, 10) || ''}
                      </div>
                    </div>
                    <div className="text-sm text-white/70 mt-1">{r.comment || '—'}</div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
