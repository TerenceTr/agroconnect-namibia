// ============================================================================
// src/components/ai/AIExplanationPanel.jsx
// ----------------------------------------------------------------------------
// ROLE:
// • Explains "why recommended?" for transparency (MSc value)
// • Calls backend explanation endpoint (recommended) but fails gracefully
//
// Suggested endpoint:
// GET /api/ai/explain?customer_id=...&product_id=...
// Response example:
// { reasons: ["Because you viewed tomatoes 3x", "Similar buyers purchased onions"], confidence: 0.74 }
// ============================================================================

import React, { useEffect, useState } from 'react';
import PropTypes from 'prop-types';

const API = process.env.REACT_APP_API_URL || '';

function authHeaders() {
  const token = localStorage.getItem('token');
  return token ? { Authorization: `Bearer ${token}` } : {};
}

export default function AIExplanationPanel({ customerId, productId }) {
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState(null);

  useEffect(() => {
    if (!customerId || !productId) {
      setData(null);
      return;
    }

    (async () => {
      try {
        setLoading(true);
        const qs = new URLSearchParams({
          customer_id: String(customerId),
          product_id: String(productId),
        });

        const res = await fetch(`${API}/api/ai/explain?${qs.toString()}`, {
          headers: { ...authHeaders() },
        });

        if (!res.ok) throw new Error('Explain endpoint missing');
        const json = await res.json();
        setData(json);
      } catch {
        // Silent fallback: show a generic message instead of breaking UI
        setData({
          reasons: [
            'Recommendations are based on your views and orders.',
            'More activity improves the relevance of suggestions.',
          ],
          confidence: null,
        });
      } finally {
        setLoading(false);
      }
    })();
  }, [customerId, productId]);

  if (!customerId || !productId) return null;

  return (
    <div className="rounded-2xl bg-white/5 border border-white/10 p-4">
      <div className="flex items-center justify-between gap-3">
        <h3 className="font-semibold">Why recommended?</h3>
        {loading && <span className="text-xs text-white/60">Loading…</span>}
      </div>

      <ul className="mt-3 space-y-2 text-sm text-white/80 list-disc pl-5">
        {(data?.reasons || []).slice(0, 5).map((r, idx) => (
          <li key={idx}>{r}</li>
        ))}
      </ul>

      {data?.confidence != null && (
        <div className="mt-3 text-xs text-white/60">
          Confidence: {Math.round(Number(data.confidence) * 100)}%
        </div>
      )}
    </div>
  );
}

AIExplanationPanel.propTypes = {
  customerId: PropTypes.oneOfType([PropTypes.string, PropTypes.number]),
  productId: PropTypes.oneOfType([PropTypes.string, PropTypes.number]),
};
