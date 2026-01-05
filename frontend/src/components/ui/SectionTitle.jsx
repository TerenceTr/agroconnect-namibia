// frontend/src/components/ui/SectionTitle.jsx
import React from "react";

export function SectionTitle({ children }) {
  return (
    <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
      {children}
    </h3>
  );
}

export default SectionTitle;
