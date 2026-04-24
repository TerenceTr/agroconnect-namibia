// ============================================================================
// src/components/customer/marketplace/QuantityStepper.jsx
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Unified, premium quantity control used in BOTH Quick View modal and Cart.
//
// RESPONSIBILITIES:
//   • Decimal-safe quantity editing (supports 1.5kg, 2.25l, etc.)
//   • + / − controls + direct input (with “typing-safe” behavior)
//   • Keyboard-friendly (ArrowUp/ArrowDown, Shift = bigger step)
//   • Accessible labels + disabled states
//
// DESIGN NOTES:
//   This component deliberately keeps a local string state while the user types.
//   That prevents annoying “snap-back” behavior (e.g., typing "1." becoming "1").
//   We only commit a parsed number when the input is “stable” or on blur.
// ============================================================================

import React, { useEffect, useMemo, useRef, useState } from "react";
import { Minus, Plus } from "lucide-react";

// ----------------------------
// Helpers
// ----------------------------
function safeNum(v, fallback = 1) {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

function decimalsFromStep(step) {
  const s = String(step ?? "");
  if (!s.includes(".")) return 0;
  return Math.min(6, s.split(".")[1].length);
}

function clamp(n, min, max) {
  return Math.min(max, Math.max(min, n));
}

function roundTo(n, decimals) {
  const p = Math.pow(10, decimals);
  return Math.round(n * p) / p;
}

function formatNumber(n, decimals) {
  // Keep numbers compact (1.5 not 1.50), but respect precision for stepping.
  const fixed = Number(n).toFixed(decimals);
  return fixed.replace(/\.?0+$/, "");
}

function parseUserDecimal(input) {
  // Accept comma decimals: "1,5" -> 1.5
  const s = String(input ?? "")
    .trim()
    .replace(",", ".");
  if (!s) return null;

  // Reject bare "-" or "."
  if (s === "-" || s === "." || s === "-.") return null;

  const n = Number(s);
  return Number.isFinite(n) ? n : null;
}

// ----------------------------
// Component
// ----------------------------
export default function QuantityStepper({
  value,
  onChange,
  min = 0.25,
  step = 0.25,
  max = 9999,
  unitLabel = "",
  ariaLabel = "Quantity",
  compact = false,
  disabled = false,
}) {
  const decimals = useMemo(() => decimalsFromStep(step), [step]);

  // “Authoritative” numeric value (clamped + rounded)
  const v = useMemo(() => {
    const n = safeNum(value, min);
    const clamped = clamp(n, min, max);
    return roundTo(clamped, decimals);
  }, [value, min, max, decimals]);

  // Local string while user types (prevents snapping)
  const [raw, setRaw] = useState(() => formatNumber(v, decimals));
  const editingRef = useRef(false);

  // Sync raw string when parent value changes (but NOT while typing)
  useEffect(() => {
    if (editingRef.current) return;
    setRaw(formatNumber(v, decimals));
  }, [v, decimals]);

  function commit(next) {
    if (disabled) return;
    const n = safeNum(next, v);
    const clamped = clamp(n, min, max);
    const rounded = roundTo(clamped, decimals);
    onChange?.(rounded);
  }

  function bump(delta) {
    // Delta uses “step” increments, then rounded/clamped.
    commit(v + delta);
  }

  const height = compact ? "h-9" : "h-10";
  const pad = compact ? "px-2" : "px-3";

  const canDec = !disabled && v > min;
  const canInc = !disabled && v < max;

  return (
    <div
      className={[
        "inline-flex items-center rounded-2xl border border-[#E6E8EF] bg-white",
        height,
        disabled ? "opacity-60" : "",
      ].join(" ")}
      aria-label={ariaLabel}
    >
      <button
        type="button"
        onClick={() => bump(-step)}
        disabled={!canDec}
        className={[
          "w-10 inline-flex items-center justify-center rounded-l-2xl",
          height,
          canDec ? "hover:bg-[#F7F8FA]" : "cursor-not-allowed",
        ].join(" ")}
        aria-label={`Decrease ${ariaLabel}`}
      >
        <Minus className="h-4 w-4 text-slate-700" />
      </button>

      <div className={`flex items-center gap-2 ${pad}`}>
        <input
          value={raw}
          onFocus={() => {
            editingRef.current = true;
          }}
          onBlur={() => {
            editingRef.current = false;

            // On blur, commit if parseable; otherwise snap back to current value.
            const parsed = parseUserDecimal(raw);
            if (parsed == null) {
              setRaw(formatNumber(v, decimals));
              return;
            }

            commit(parsed);
            // After commit, show nicely formatted value
            setRaw(formatNumber(clamp(roundTo(parsed, decimals), min, max), decimals));
          }}
          onChange={(e) => {
            const nextRaw = e.target.value;
            setRaw(nextRaw);

            // If input is “in-progress” (ends with '.' or ','), do not commit yet.
            const trimmed = nextRaw.trim();
            if (!trimmed) return;
            if (/[.,]$/.test(trimmed)) return;

            const parsed = parseUserDecimal(nextRaw);
            if (parsed == null) return;

            // Commit numeric value, but keep raw string as typed while editing.
            commit(parsed);
          }}
          onKeyDown={(e) => {
            if (disabled) return;

            // Keyboard stepping
            if (e.key === "ArrowUp" || e.key === "ArrowDown") {
              e.preventDefault();
              const mult = e.shiftKey ? 10 : 1;
              const dir = e.key === "ArrowUp" ? 1 : -1;
              bump(dir * step * mult);
            }

            // Enter commits immediately
            if (e.key === "Enter") {
              e.preventDefault();
              e.currentTarget.blur();
            }
          }}
          inputMode="decimal"
          className="w-20 outline-none text-sm font-extrabold text-[#111827] text-center bg-transparent"
          aria-label={ariaLabel}
          disabled={disabled}
        />

        {unitLabel ? (
          <span className="text-xs font-semibold text-[#6B7280]">{unitLabel}</span>
        ) : null}
      </div>

      <button
        type="button"
        onClick={() => bump(step)}
        disabled={!canInc}
        className={[
          "w-10 inline-flex items-center justify-center rounded-r-2xl",
          height,
          canInc ? "hover:bg-[#F7F8FA]" : "cursor-not-allowed",
        ].join(" ")}
        aria-label={`Increase ${ariaLabel}`}
      >
        <Plus className="h-4 w-4 text-slate-700" />
      </button>
    </div>
  );
}
