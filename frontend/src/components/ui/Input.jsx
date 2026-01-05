// frontend/src/components/ui/Input.jsx
import React from "react";
import clsx from "clsx";

export function Input({ label, error, type = "text", className = "", ...props }) {
  return (
    <div className="w-full">
      {label && <label className="block mb-1 text-sm font-medium text-white">{label}</label>}

      <input
        type={type}
        className={clsx(
          "w-full p-3 rounded-lg bg-white/20 text-white placeholder-white/60 border border-white/30 focus:border-namibia-green focus:outline-none transition",
          className
        )}
        {...props}
      />

      {error && <p className="text-red-300 text-sm mt-1">{error}</p>}
    </div>
  );
}

export default Input;
