// ============================================================================
// chartConfidence.js — Chart.js Confidence Bands (DIRECT DATASET WIRING)
// ----------------------------------------------------------------------------
// ROLE OF THIS FILE:
//   • Pure helper functions for mapping model confidence (0..1)
//   • Produces Chart.js dataset styling (bar fills + line segments)
//
// WHY THIS EXISTS:
//   • Keeps chart components small and testable
//   • Confidence logic becomes reusable across dashboards
//   • Avoids hard-coding color logic inside UI components
// ============================================================================

/** Clamp any value into the [0..1] interval. */
export function clamp01(x, fallback = 0.65) {
  const n = Number(x);
  if (Number.isNaN(n)) return fallback;
  return Math.max(0, Math.min(1, n));
}

/**
 * Convert a confidence score into a discrete "band" label + a fill alpha.
 *
 * NOTE:
 * - Alpha values are intentionally low so the UI stays readable on dark glass.
 */
export function confidenceBand(c) {
  const v = clamp01(c);

  // You can tune these thresholds to match your model calibration.
  if (v >= 0.8) return { label: 'High', alpha: 0.22 };
  if (v >= 0.6) return { label: 'Medium', alpha: 0.18 };
  return { label: 'Low', alpha: 0.14 };
}

// ----------------------------------------------------------------------------
// BAR CHART HELPERS
// ----------------------------------------------------------------------------
// Bar charts accept arrays for per-bar colors.
// This is the most direct way to visually encode confidence for categories.
// ----------------------------------------------------------------------------

export function barColorsFromConfidence(confArray, rgb = '16,185,129') {
  return (confArray || []).map((c) => {
    const { alpha } = confidenceBand(c);
    return `rgba(${rgb}, ${alpha})`;
  });
}

export function barBorderColorsFromConfidence(confArray, rgb = '16,185,129') {
  return (confArray || []).map((c) => {
    const v = clamp01(c);

    // Stronger border when more confident (helps visually anchor bars).
    const a = v >= 0.8 ? 0.65 : v >= 0.6 ? 0.55 : 0.45;
    return `rgba(${rgb}, ${a})`;
  });
}

// ----------------------------------------------------------------------------
// LINE CHART HELPERS
// ----------------------------------------------------------------------------
// For time series, the most correct visual encoding is per-segment styling.
// Chart.js supports `dataset.segment` as a scriptable option.
// ----------------------------------------------------------------------------

export function lineSegmentColor(confArray, rgb = '16,185,129') {
  return (ctx) => {
    const i = ctx.p0DataIndex; // segment start index
    const c = clamp01(confArray?.[i]);
    const { alpha } = confidenceBand(c);

    // Make the line stroke slightly stronger with confidence.
    const borderAlpha = c >= 0.8 ? 0.9 : c >= 0.6 ? 0.8 : 0.7;

    return {
      borderColor: `rgba(${rgb}, ${borderAlpha})`,
      backgroundColor: `rgba(${rgb}, ${alpha})`,
    };
  };
}

// ----------------------------------------------------------------------------
// DATASET WIRING
// ----------------------------------------------------------------------------
// This mutates and returns the dataset object (common Chart.js pattern).
// ----------------------------------------------------------------------------

export function applyConfidenceToDataset({ dataset, confidence, kind, rgb = '16,185,129' }) {
  if (!dataset) return dataset;

  if (kind === 'bar') {
    dataset.backgroundColor = barColorsFromConfidence(confidence, rgb);
    dataset.borderColor = barBorderColorsFromConfidence(confidence, rgb);
    dataset.borderWidth = 1;
    dataset.borderRadius = 10;
    dataset.hoverBorderWidth = 2;
    return dataset;
  }

  if (kind === 'line') {
    dataset.segment = lineSegmentColor(confidence, rgb);
    dataset.borderWidth = 2;
    dataset.pointRadius = 2;
    dataset.pointHoverRadius = 4;

    // Keep fill subtle; the segment function provides per-part styling.
    dataset.fill = true;
    dataset.backgroundColor = 'rgba(16,185,129,0.10)';
    return dataset;
  }

  return dataset;
}
