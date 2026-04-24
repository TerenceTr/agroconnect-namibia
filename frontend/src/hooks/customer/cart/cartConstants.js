// ============================================================================
// frontend/src/hooks/customer/cart/cartConstants.js
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Central constants for the customer cart domain (stable, thesis-friendly).
// ============================================================================

export const STORAGE_KEY = "agroconnect_customer_cart_v1";

// Namibia VAT (standard rate). Adjust if your thesis spec differs.
export const VAT_RATE = 0.15;

// Delivery fee policy (clean + explainable):
//   - Free delivery for subtotal >= 500
//   - Otherwise N$ 30
export const FREE_DELIVERY_THRESHOLD = 500;
export const STANDARD_DELIVERY_FEE = 30;
