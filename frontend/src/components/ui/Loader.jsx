// frontend/src/components/ui/Loader.jsx
import React from "react";

export function Loader({ size = "md" }) {
  const sizes = {
    sm: "h-4 w-4",
    md: "h-6 w-6",
    lg: "h-10 w-10",
  };

  return (
    <div
      className={`border-4 border-white/20 border-t-namibia-green rounded-full animate-spin ${sizes[size]}`}
      aria-label="Loading"
    />
  );
}

export default Loader;
