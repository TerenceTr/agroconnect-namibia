// ============================================================================
// frontend/src/hooks/customer/useCart.js
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Backwards-compatible customer cart hook entry point.
//
// WHY THIS FILE EXISTS:
//   Some older screens/components still import the cart hook from:
//     import useCart from "src/hooks/customer/useCart"
//   while the actual maintained implementation now lives in:
//     src/hooks/useCart
//
// WHAT THIS FILE DOES:
//   ✅ Re-exports the main hook as the default export
//   ✅ Re-exports the named useCart export
//   ✅ Keeps legacy imports working without duplicating cart logic
//
// WHY WE USE EXPLICIT IMPORTS HERE:
//   Using explicit imports/exports is a little clearer for maintenance and
//   tends to be easier to debug than a one-line re-export when projects grow.
// ============================================================================

import useCartDefault, { useCart } from "../useCart";

// ---------------------------------------------------------------------------
// Named export:
//   Allows:
//     import { useCart } from "src/hooks/customer/useCart";
// ---------------------------------------------------------------------------
export { useCart };

// ---------------------------------------------------------------------------
// Default export:
//   Allows:
//     import useCart from "src/hooks/customer/useCart";
// ---------------------------------------------------------------------------
export default useCartDefault;