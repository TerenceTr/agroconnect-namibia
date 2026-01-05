// frontend/src/components/ui/SkeletonChart.jsx
import React from "react";

export default function SkeletonChart({ className = "" }) {
  return (
    <div className={`animate-pulse bg-white/6 rounded-lg p-4 ${className}`}>
      <div className="h-4 bg-white/10 rounded w-1/3 mb-4" />
      <div className="h-56 bg-white/8 rounded" />
    </div>
  );
}
