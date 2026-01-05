// ============================================================================
// chartConfidence.js — Chart.js Confidence Bands (DIRECT DATASET WIRING)
// ----------------------------------------------------------------------------
// GOAL:
// • Map AI confidence (0..1) into "certainty bands"
// • Apply styling at the dataset level (background/border/segment)
// ----------------------------------------------------------------------------
// WHY THIS IS MASTER'S-LEVEL CLEAN:
// • Pure functions (testable)
// • Works for Bar + Line charts
// • Uses Chart.js scriptable options / segment styling
// ============================================================================

export function clamp01(x, fallback = 0.65) {
  const n = Number(x);
  if (Number.isNaN(n)) return fallback;
  return Math.max(0, Math.min(1, n));
}

export function confidenceBand(c) {
  const v = clamp01(c);

  // You can tune these thresholds to match your model calibration
  if (v >= 0.8) {
    return { label: "High", alpha: 0.22 };
  }
  if (v >= 0.6) {
    return { label: "Medium", alpha: 0.18 };
  }
  return { label: "Low", alpha: 0.14 };
}

// ----------------------------------------------------------------------------
// BAR CHART: backgroundColor can be an array per bar.
// ----------------------------------------------------------------------------
export function barColorsFromConfidence(confArray, rgb = "16,185,129") {
  return (confArray || []).map((c) => {
    const { alpha } = confidenceBand(c);
    return `rgba(${rgb}, ${alpha})`;
  });
}

export function barBorderColorsFromConfidence(confArray, rgb = "16,185,129") {
  return (confArray || []).map((c) => {
    const v = clamp01(c);
    // stronger border when more confident
    const a = v >= 0.8 ? 0.65 : v >= 0.6 ? 0.55 : 0.45;
    return `rgba(${rgb}, ${a})`;
  });
}

// ----------------------------------------------------------------------------
// LINE CHART: use `segment` to color each segment based on the *starting* point.
// This is the most "direct" and visually correct for time-series confidence.
// ----------------------------------------------------------------------------
export function lineSegmentColor(confArray, rgb = "16,185,129") {
  return (ctx) => {
    const i = ctx.p0DataIndex; // segment start index
    const c = clamp01(confArray?.[i]);
    const { alpha } = confidenceBand(c);

    // border becomes slightly stronger with confidence
    const borderAlpha = c >= 0.8 ? 0.9 : c >= 0.6 ? 0.8 : 0.7;

    return {
      borderColor: `rgba(${rgb}, ${borderAlpha})`,
      backgroundColor: `rgba(${rgb}, ${alpha})`,
    };
  };
}

// ----------------------------------------------------------------------------
// Recommended dataset wiring helper.
// ----------------------------------------------------------------------------
export function applyConfidenceToDataset({
  dataset,
  confidence,
  kind, // "bar" | "line"
  rgb = "16,185,129",
}) {
  if (!dataset) return dataset;

  if (kind === "bar") {
    dataset.backgroundColor = barColorsFromConfidence(confidence, rgb);
    dataset.borderColor = barBorderColorsFromConfidence(confidence, rgb);
    dataset.borderWidth = 1;
    dataset.borderRadius = 10;
    dataset.hoverBorderWidth = 2;
    return dataset;
  }

  if (kind === "line") {
    dataset.segment = lineSegmentColor(confidence, rgb);
    dataset.borderWidth = 2;
    dataset.pointRadius = 2;
    dataset.pointHoverRadius = 4;

    // Keep fill subtle; segment() handles per-part styling
    dataset.fill = true;
    dataset.backgroundColor = "rgba(16,185,129,0.10)";
    return dataset;
  }

  return dataset;
}
