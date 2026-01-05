// ============================================================================
// AIExplanationPanel.jsx
// ----------------------------------------------------------------------------
// ROLE:
// • Explains WHY AI made a recommendation
// • Improves transparency & trust
//
// MSc VALUE:
// • Explainable AI (XAI)
// ============================================================================

import React from 'react';

export default function AIExplanationPanel({ reasons = [] }) {
  if (!reasons.length) return null;

  return (
    <div className="glass-card p-5 border border-white/10">
      <h4 className="font-semibold mb-2">Why this was recommended</h4>

      <ul className="list-disc list-inside text-sm text-white/80 space-y-1">
        {reasons.map((r, i) => (
          <li key={i}>{r}</li>
        ))}
      </ul>
    </div>
  );
}
