// frontend/src/components/ui/Button.jsx
import React from "react";
import clsx from "clsx";

export function Button({
  children,
  variant = "primary",
  className = "",
  ...props
}) {
  const base =
    "px-4 py-2 rounded-lg font-semibold transition-all duration-200 inline-flex items-center gap-2";

  const variants = {
    primary:
      "bg-namibia-green text-white hover:bg-namibia-dark shadow-button-hover",
    secondary:
      "bg-white/20 backdrop-blur-md text-white border border-white/30 hover:bg-white/30",
    outline:
      "border-2 border-namibia-green text-namibia-green hover:bg-namibia-green hover:text-white",
    danger: "bg-namibia-red text-white hover:bg-red-700 shadow-soft",
    subtle: "bg-white/10 text-white hover:bg-white/20 backdrop-blur-sm",
  };

  return (
    <button
      className={clsx(base, variants[variant] || variants.primary, className)}
      {...props}
    >
      {children}
    </button>
  );
}

export default Button;
