// ====================================================================
// frontend/src/components/ui/Card.jsx — AgroConnect Namibia
// ====================================================================
// FILE ROLE:
//   Reusable Card primitives used across dashboards/pages.
//
// DESIGN GOAL:
//   • Default = WHITE SURFACE (clean admin UI style)
//   • Optional = GLASS (subtle blur for highlights / hero cards)
//   • Optional = SOFT (muted background for neutral sections)
//
// EXPORTS:
//   - named: Card, CardHeader, CardTitle, CardContent, CardFooter
//   - default: Card
// ====================================================================

import React from "react";
import clsx from "clsx";

// Centralized variants to keep UI consistent across the app.
const VARIANTS = {
  // Standard “panel” look for dashboards
  surface: "bg-white border border-slate-200/70 shadow-sm",

  // Glass for hero/overlay cards (use sparingly)
  glass: "bg-white/70 backdrop-blur-xl border border-white/60 shadow-md",

  // Soft section card for low-emphasis areas
  soft: "bg-slate-50 border border-slate-200/70 shadow-sm",
};

export function Card({ children, className = "", variant = "surface" }) {
  return (
    <div
      className={clsx("rounded-2xl", VARIANTS[variant] || VARIANTS.surface, className)}
    >
      {children}
    </div>
  );
}

export function CardHeader({ children, className = "" }) {
  return (
    <div
      className={clsx(
        "px-6 pt-6 pb-4 flex items-start justify-between gap-3",
        className
      )}
    >
      {children}
    </div>
  );
}

export function CardTitle({ children, className = "" }) {
  return (
    <h3 className={clsx("text-base md:text-lg font-semibold text-slate-900", className)}>
      {children}
    </h3>
  );
}

export function CardContent({ children, className = "" }) {
  // Note: text-slate-700 is intentional default for readability on white surfaces.
  return <div className={clsx("px-6 pb-6 text-slate-700", className)}>{children}</div>;
}

export function CardFooter({ children, className = "" }) {
  return <div className={clsx("px-6 pb-6 pt-2", className)}>{children}</div>;
}

export default Card;
