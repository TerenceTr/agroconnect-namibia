// ============================================================================
// RadioGroup.jsx — AgroConnect Namibia
// ---------------------------------------------------------------------------
// ROLE OF FILE:
// • Unified input selection components
// • Supports radio groups AND checkboxes
//
// MSc VALUE:
// • Reduces duplication
// • Clean API
// • Reusable across forms (auth, filters, settings)
// ============================================================================

import React from 'react';

/* ---------------------------------------------------------------------------
   Checkbox — simple boolean input
--------------------------------------------------------------------------- */
export function Checkbox({ label, checked, onChange }) {
  return (
    <label className="flex items-center gap-2 cursor-pointer text-white">
      <input
        type="checkbox"
        checked={checked}
        onChange={(e) => onChange?.(e.target.checked)}
        className="accent-namibia-green w-4 h-4"
      />
      <span className="select-none">{label}</span>
    </label>
  );
}

/* ---------------------------------------------------------------------------
   RadioGroup — multiple choice selector
--------------------------------------------------------------------------- */
export function RadioGroup({ label, options = [], value, onChange }) {
  return (
    <div>
      {label && <p className="text-white mb-2">{label}</p>}

      <div className="flex gap-6">
        {options.map((opt) => (
          <label
            key={opt.value}
            className="flex items-center gap-2 cursor-pointer text-white/90"
          >
            <input
              type="radio"
              value={opt.value}
              checked={value === opt.value}
              onChange={(e) => onChange?.(e.target.value)}
              className="accent-namibia-green w-4 h-4"
            />
            <span>{opt.label}</span>
          </label>
        ))}
      </div>
    </div>
  );
}

export default RadioGroup;
