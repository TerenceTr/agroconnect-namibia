// ============================================================================
// frontend/src/components/ui/Card.jsx — Thesis UI Card Primitive
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Base “Card-first” container used across dashboards and panels.
//
// NOTE:
//   We export BOTH default and named Card to support older imports:
//     import Card from ".../Card"
//     import { Card } from ".../Card"
// ============================================================================

import React from "react";

const Card = ({ className = "", children, ...props }) => (
  <div className={`rounded-3xl border border-slate-200 bg-white shadow-sm ${className}`} {...props}>
    {children}
  </div>
);

const CardHeader = ({ className = "", children }) => (
  <div className={`px-6 py-4 border-b border-slate-200 ${className}`}>{children}</div>
);

const CardTitle = ({ className = "", children }) => (
  <h3 className={`text-lg font-semibold text-slate-900 ${className}`}>{children}</h3>
);

const CardContent = ({ className = "", children }) => (
  <div className={`p-6 ${className}`}>{children}</div>
);

export default Card;
export { Card, CardHeader, CardTitle, CardContent };
