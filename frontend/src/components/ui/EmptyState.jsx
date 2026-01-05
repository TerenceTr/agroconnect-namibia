// ====================================================================
// frontend/src/components/ui/EmptyState.jsx — AgroConnect Namibia
// ====================================================================
// FILE ROLE:
//   Small empty-state placeholder for lists/charts.
//
// DESIGN:
//   Light theme, subtle icon + muted copy.
// ====================================================================

import React from "react";
import { Inbox } from "lucide-react";

export function EmptyState({ message = "No data available." }) {
  return (
    <div className="text-center text-slate-500 py-10">
      <Inbox size={40} className="mx-auto mb-3 opacity-60" />
      <p className="text-sm">{message}</p>
    </div>
  );
}

export default EmptyState;
