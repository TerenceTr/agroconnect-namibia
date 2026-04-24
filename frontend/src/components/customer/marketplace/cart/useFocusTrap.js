// ============================================================================
// frontend/src/components/customer/marketplace/cart/useFocusTrap.js
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Lightweight focus trap + ESC close for drawers/modals.
// ============================================================================

import { useEffect, useRef } from "react";

export default function useFocusTrap(open, onClose) {
  const ref = useRef(null);

  useEffect(() => {
    if (!open) return;

    const root = ref.current;
    if (!root) return;

    const focusables = () =>
      Array.from(
        root.querySelectorAll(
          'a[href],button:not([disabled]),textarea,input,select,[tabindex]:not([tabindex="-1"])'
        )
      );

    const firstFocus = () => {
      const els = focusables();
      if (els.length) els[0].focus();
    };

    const onKeyDown = (e) => {
      if (e.key === "Escape") {
        onClose?.();
        return;
      }
      if (e.key !== "Tab") return;

      const els = focusables();
      if (!els.length) return;

      const first = els[0];
      const last = els[els.length - 1];

      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    };

    // focus first element on open
    setTimeout(firstFocus, 0);

    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [open, onClose]);

  return ref;
}
