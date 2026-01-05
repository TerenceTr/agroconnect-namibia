// ============================================================================
// frontend/src/components/ui/Select.jsx
// -----------------------------------------------------------------------------
// Custom Select Component (lightweight replacement for shadcn/ui Select)
// This mirrors the API of <Select>, <SelectTrigger>, <SelectValue>, <SelectContent>, <SelectItem>
// so existing UI code (like AiDashboard.jsx) works perfectly.
// -----------------------------------------------------------------------------

import React, { useState, useRef } from "react";
import clsx from "clsx";

// -----------------------------------------------------------------------------
// Context Initialization
// -----------------------------------------------------------------------------
const SelectContext = React.createContext(null);

// Helper Hook: Access Select Context Safely
function useSelect() {
  const ctx = React.useContext(SelectContext);
  if (!ctx) {
    throw new Error("useSelect() must be used inside <Select>");
  }
  return ctx;
}

// -----------------------------------------------------------------------------
// <Select> Root Component
// -----------------------------------------------------------------------------
export function Select({ value, onValueChange, children }) {
  const [open, setOpen] = useState(false);
  const triggerRef = useRef(null);

  const context = {
    open,
    value,
    setOpen,
    onValueChange,
    triggerRef,
  };

  return (
    <SelectContext.Provider value={context}>
      <div className="relative w-full">{children}</div>
    </SelectContext.Provider>
  );
}

// -----------------------------------------------------------------------------
// <SelectTrigger> — the clickable box that opens the dropdown
// -----------------------------------------------------------------------------
export function SelectTrigger({ className = "", children }) {
  const { setOpen, triggerRef } = useSelect();

  return (
    <button
      ref={triggerRef}
      className={clsx(
        "w-full p-3 rounded-lg border bg-white text-black flex justify-between items-center",
        "focus:outline-none focus:ring-2 focus:ring-primary",
        className
      )}
      onClick={() => setOpen((o) => !o)}
      type="button"
    >
      {children}
    </button>
  );
}

// -----------------------------------------------------------------------------
// <SelectValue> — displays selected content or placeholder
// -----------------------------------------------------------------------------
export function SelectValue({ placeholder }) {
  const { value } = useSelect();
  return <span className="text-sm">{value || placeholder}</span>;
}

// -----------------------------------------------------------------------------
// <SelectContent> — dropdown container
// -----------------------------------------------------------------------------
export function SelectContent({ children }) {
  const { open, triggerRef, setOpen } = useSelect();

  if (!open) return null;

  return (
    <div
      className="absolute left-0 right-0 mt-1 bg-white border rounded-lg shadow-lg z-50"
      style={{
        top: triggerRef.current?.offsetHeight + 4,
      }}
    >
      <div
        className="max-h-60 overflow-auto"
        onClick={() => setOpen(false)}
      >
        {children}
      </div>
    </div>
  );
}

// -----------------------------------------------------------------------------
// <SelectItem> — individual selectable option
// -----------------------------------------------------------------------------
export function SelectItem({ value, children }) {
  const { onValueChange } = useSelect();

  return (
    <div
      className="px-3 py-2 hover:bg-primary/10 cursor-pointer text-sm"
      onClick={() => onValueChange(value)}
    >
      {children}
    </div>
  );
}

// Default export (for backward compatibility)
export default Select;
