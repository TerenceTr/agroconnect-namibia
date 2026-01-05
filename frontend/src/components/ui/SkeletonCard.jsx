// frontend/src/components/ui/DataCard.jsx
import React from "react";

export function SkeletonCard({ lines = 3 }) {
  return (
    <div className="p-4 rounded-lg bg-white/6 animate-pulse">
      <div className="h-4 bg-white/10 rounded w-1/4 mb-3" />
      {Array.from({ length: lines }).map((_, i) => (
        <div key={i} className="h-3 bg-white/8 rounded mb-2" />
      ))}
    </div>
  );
}
