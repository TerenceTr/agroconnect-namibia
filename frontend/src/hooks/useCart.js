// ============================================================================
// src/hooks/useCart.js
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Customer cart state + actions for AgroConnect.
//
// DESIGN GOALS IN THIS VERSION:
//   ✅ Keeps the same public hook API used by the current frontend
//   ✅ Remains localStorage-backed for reliability and simplicity
//   ✅ Uses shared public settings from usePublicSystemSettings
//   ✅ Supports decimal-safe quantities for weighted products (kg/l/g/ml)
//   ✅ Keeps integer quantities for discrete products (each/pack)
//   ✅ Performs settings-driven checkout validation
//   ✅ Treats maintenance mode as advisory, not a hard stop
//   ✅ Treats read-only mode as the actual write/checkout restriction
//   ✅ Computes frontend-ready commercial estimates:
//        - subtotal
//        - estimated delivery fee
//        - estimated VAT
//        - estimated grand total
//
// IMPORTANT BUSINESS RULE:
//   Initial checkout creates/submits the order request only.
//   Proof of payment is uploaded later when the farmer has:
//     • set/confirmed delivery charges
//     • marked the order ready for payment
//
// IMPORTANT POLICY CHANGE:
//   Maintenance mode should no longer block all users globally.
//   Therefore this hook:
//     • DOES NOT block checkout just because maintenance=true
//     • DOES block checkout when read_only_mode=true
//
// THIS UPDATE:
//   ✅ Fixes runtime crash by calling mergePublicSystemSettings(...)
//      instead of the undefined mergePublicSettings(...)
//   ✅ Keeps the rest of the settings-driven cart / checkout policy intact
// ============================================================================

import { useCallback, useEffect, useMemo, useState } from "react";
import customerApiDefault, * as customerApiNS from "../services/customerApi";
import usePublicSystemSettings, {
  DEFAULT_PUBLIC_SYSTEM_SETTINGS,
  mergePublicSystemSettings,
} from "./usePublicSystemSettings";

// ----------------------------------------------------------------------------
// Storage keys
// ----------------------------------------------------------------------------
const CART_STORAGE_KEY = "agroconnect_customer_cart_v5";
const LEGACY_CART_STORAGE_KEYS = [
  "agroconnect_customer_cart_v4",
  "agroconnect_customer_cart_v3",
  "agroconnect_customer_cart_v2",
  "agroconnect_customer_cart",
];

// ----------------------------------------------------------------------------
// Quantity behavior
// ----------------------------------------------------------------------------
const INTEGER_QTY_UNITS = new Set(["each", "pack"]);
const DEFAULT_QTY_PRECISION = 3;

// ----------------------------------------------------------------------------
// Generic helpers
// ----------------------------------------------------------------------------
function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function safeTrim(value, fallback = "") {
  const s = String(value ?? "").trim();
  return s || fallback;
}

function toNumber(value, fallback = 0) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function roundTo(value, precision = DEFAULT_QTY_PRECISION) {
  const factor = 10 ** precision;
  return Math.round(toNumber(value, 0) * factor) / factor;
}

function fileSizeBytes(fileLike) {
  const size = Number(fileLike?.size);
  return Number.isFinite(size) && size >= 0 ? size : 0;
}

function normalizeUnit(unit) {
  return safeTrim(unit, "each").toLowerCase();
}

function isIntegerQuantityUnit(unit) {
  return INTEGER_QTY_UNITS.has(normalizeUnit(unit));
}

function normalizeQuantity(value, unit = "each", fallback = 1) {
  const raw = toNumber(value, fallback);
  const normalizedUnit = normalizeUnit(unit);

  if (isIntegerQuantityUnit(normalizedUnit)) {
    const qty = Math.floor(raw);
    return qty > 0 ? qty : fallback;
  }

  const qty = roundTo(raw, DEFAULT_QTY_PRECISION);
  return qty > 0 ? qty : fallback;
}

function clampQuantity(value, min, max, unit = "each") {
  const normalizedUnit = normalizeUnit(unit);
  const resolvedMin = normalizeQuantity(min, normalizedUnit, 1);

  if (!Number.isFinite(Number(max))) {
    return normalizeQuantity(
      Math.max(toNumber(value, resolvedMin), resolvedMin),
      normalizedUnit,
      resolvedMin
    );
  }

  const resolvedMax = normalizeQuantity(max, normalizedUnit, resolvedMin);
  const bounded = Math.min(
    Math.max(toNumber(value, resolvedMin), resolvedMin),
    resolvedMax
  );
  return normalizeQuantity(bounded, normalizedUnit, resolvedMin);
}

// ----------------------------------------------------------------------------
// Local storage helpers
// ----------------------------------------------------------------------------
function readCartFromStorage() {
  try {
    if (typeof window === "undefined") return [];

    const tryRead = (key) => {
      const raw = window.localStorage.getItem(key);
      if (!raw) return null;

      const parsed = JSON.parse(raw);

      if (Array.isArray(parsed)) return parsed;
      if (isObject(parsed) && Array.isArray(parsed.items)) return parsed.items;

      return null;
    };

    const current = tryRead(CART_STORAGE_KEY);
    if (current) return current;

    for (const key of LEGACY_CART_STORAGE_KEYS) {
      const legacy = tryRead(key);
      if (legacy) return legacy;
    }

    return [];
  } catch {
    return [];
  }
}

function writeCartToStorage(items) {
  try {
    if (typeof window === "undefined") return;
    window.localStorage.setItem(CART_STORAGE_KEY, JSON.stringify(items));
  } catch {
    // Ignore storage write failures.
  }
}

function cleanupLegacyCartStorage() {
  try {
    if (typeof window === "undefined") return;

    for (const key of LEGACY_CART_STORAGE_KEYS) {
      if (window.localStorage.getItem(key)) {
        window.localStorage.removeItem(key);
      }
    }
  } catch {
    // Ignore cleanup failures.
  }
}

// ----------------------------------------------------------------------------
// Cart item normalization helpers
// ----------------------------------------------------------------------------
function resolveProductId(item = {}) {
  return (
    item.product_id ??
    item.productId ??
    item.id ??
    item.product?.product_id ??
    item.product?.id ??
    null
  );
}

function resolveItemUnit(item = {}) {
  return item.unit ?? item.product?.unit ?? item.pack_unit ?? item.product?.pack_unit ?? "each";
}

function normalizeCartItem(rawItem = {}, quantityOverride) {
  const productId = resolveProductId(rawItem);
  if (!productId) return null;

  const unit = resolveItemUnit(rawItem);

  const price = toNumber(
    rawItem.price ??
      rawItem.unit_price ??
      rawItem.unitPrice ??
      rawItem.product?.price ??
      0,
    0
  );

  const availableStockRaw =
    rawItem.available_stock ??
    rawItem.stock ??
    rawItem.quantity_available ??
    rawItem.product?.stock ??
    null;

  const availableStock =
    availableStockRaw === null || availableStockRaw === undefined
      ? null
      : normalizeQuantity(availableStockRaw, unit, 0);

  const image =
    rawItem.image ??
    rawItem.image_url ??
    rawItem.product?.image ??
    rawItem.product?.image_url ??
    null;

  const name =
    rawItem.name ??
    rawItem.product_name ??
    rawItem.product?.name ??
    "Unnamed product";

  const quantity = normalizeQuantity(
    quantityOverride ?? rawItem.quantity ?? rawItem.qty ?? 1,
    unit,
    1
  );

  const packSize = rawItem.pack_size ?? rawItem.product?.pack_size ?? null;
  const packUnit = rawItem.pack_unit ?? rawItem.product?.pack_unit ?? null;

  const farmerId =
    rawItem.farmer_id ??
    rawItem.farmerId ??
    rawItem.product?.farmer_id ??
    rawItem.product?.farmerId ??
    null;

  const itemDeliveryLocation =
    rawItem.item_delivery_location ??
    rawItem.delivery_location ??
    rawItem.itemDeliveryLocation ??
    null;

  return {
    id: productId,
    product_id: productId,
    name,
    image,
    price,
    quantity,
    available_stock: availableStock,
    unit,
    pack_size: packSize,
    pack_unit: packUnit,
    farmer_id: farmerId,
    item_delivery_location: itemDeliveryLocation,
  };
}

function mergeItemWithExisting(existing, incoming) {
  const unit = normalizeUnit(incoming?.unit ?? existing?.unit ?? "each");

  const nextQty = normalizeQuantity(
    toNumber(existing?.quantity, 0) + toNumber(incoming?.quantity, 0),
    unit,
    1
  );

  const stockCandidate =
    incoming?.available_stock !== null && incoming?.available_stock !== undefined
      ? incoming.available_stock
      : existing?.available_stock;

  const maxQty =
    stockCandidate === null || stockCandidate === undefined
      ? Infinity
      : normalizeQuantity(stockCandidate, unit, 1);

  return {
    ...existing,
    ...incoming,
    unit,
    available_stock: stockCandidate,
    quantity: clampQuantity(nextQty, 1, maxQty, unit),
  };
}

function lineTotal(item) {
  return roundTo(toNumber(item?.price, 0) * toNumber(item?.quantity, 0), 2);
}

// ----------------------------------------------------------------------------
// Checkout / policy helpers
// ----------------------------------------------------------------------------
function resolveCheckoutApiCaller(defaultModule, namespaceModule) {
  const candidates = [];

  if (isObject(defaultModule)) candidates.push(defaultModule);
  if (isObject(namespaceModule)) candidates.push(namespaceModule);

  for (const apiModule of candidates) {
    if (typeof apiModule.checkoutOrder === "function") return apiModule.checkoutOrder;
    if (typeof apiModule.checkout === "function") return apiModule.checkout;
    if (typeof apiModule.placeOrder === "function") return apiModule.placeOrder;
    if (typeof apiModule.createOrder === "function") return apiModule.createOrder;
  }

  return null;
}

function inferDefaultPaymentMethod(settings) {
  if (settings?.payments?.eft_enabled) return "eft";
  if (settings?.payments?.cash_on_delivery_enabled) return "cash_on_delivery";
  return "eft";
}

function normalizePaymentMethod(value, settings) {
  const raw = safeTrim(value, "").toLowerCase();

  if (raw.includes("cash") || raw.includes("cod") || raw.includes("delivery")) {
    return "cash_on_delivery";
  }

  if (raw.includes("eft") || raw.includes("bank") || raw.includes("transfer")) {
    return "eft";
  }

  return inferDefaultPaymentMethod(settings);
}

function normalizeDeliveryMethod(value, settings) {
  const raw = safeTrim(value, "").toLowerCase();

  if (raw === "pickup" || raw === "collection" || raw === "collect") {
    return "pickup";
  }

  if (raw === "delivery") {
    return "delivery";
  }

  if (settings?.checkout?.allow_delivery) return "delivery";
  if (settings?.checkout?.allow_pickup) return "pickup";
  return "delivery";
}

function buildCheckoutItemsFromCart(
  cartItems = [],
  fallbackDeliveryLocation = "",
  deliveryMethod = "delivery"
) {
  return cartItems.map((item) => {
    const payloadItem = {
      product_id: item.product_id,
      quantity: normalizeQuantity(item.quantity, item.unit ?? "each", 1),
    };

    if (item.price !== undefined && item.price !== null) {
      payloadItem.unit_price = toNumber(item.price, 0);
    }

    if (deliveryMethod === "delivery") {
      const itemLocation = item.item_delivery_location || fallbackDeliveryLocation;
      if (itemLocation) {
        payloadItem.delivery_location = String(itemLocation);
      }
    }

    return payloadItem;
  });
}

function estimateDeliveryFee(subtotal, deliveryMethod, settings) {
  if (deliveryMethod !== "delivery") return 0;

  const threshold = toNumber(settings?.checkout?.free_delivery_threshold, 500);
  const defaultFee = toNumber(settings?.checkout?.default_delivery_fee, 30);

  if (threshold > 0 && subtotal >= threshold) return 0;
  return Math.max(0, defaultFee);
}

function estimateVat(amountBeforeVat, settings) {
  const vatPercent = Math.max(0, toNumber(settings?.marketplace?.vat_percent, 15));
  return roundTo((amountBeforeVat * vatPercent) / 100, 2);
}

function validateCheckoutPolicy({
  items,
  settings,
  deliveryMethod,
  paymentMethod,
  deliveryLocation,
  paymentProofFile,
}) {
  if (!Array.isArray(items) || !items.length) {
    throw new Error("Your cart is empty.");
  }

  // ------------------------------------------------------------------------
  // IMPORTANT:
  // Maintenance is advisory now, so it should not hard-block checkout.
  // Read-only mode is the true operational restriction.
  // ------------------------------------------------------------------------
  if (settings?.platform?.read_only_mode) {
    throw new Error(
      "Checkout is temporarily unavailable because the marketplace is in read-only mode."
    );
  }

  const maxOrderLines = Math.max(
    1,
    Math.floor(toNumber(settings?.checkout?.max_order_lines_per_checkout, 20))
  );

  if (items.length > maxOrderLines) {
    throw new Error(
      `Checkout is limited to ${maxOrderLines} order lines by marketplace policy.`
    );
  }

  for (const item of items) {
    if (!item?.product_id) {
      throw new Error("One or more cart items are missing a product id.");
    }

    const qty = normalizeQuantity(item.quantity, item.unit ?? "each", 0);
    if (!(qty > 0)) {
      throw new Error(
        `Invalid quantity detected for ${safeTrim(item?.name, "a cart item")}.`
      );
    }
  }

  if (deliveryMethod === "delivery" && !settings?.checkout?.allow_delivery) {
    throw new Error("Delivery checkout is disabled in system settings.");
  }

  if (deliveryMethod === "pickup" && !settings?.checkout?.allow_pickup) {
    throw new Error("Pickup checkout is disabled in system settings.");
  }

  if (deliveryMethod === "delivery" && !safeTrim(deliveryLocation, "")) {
    throw new Error("Delivery location is required for delivery checkout.");
  }

  if (paymentMethod === "eft" && !settings?.payments?.eft_enabled) {
    throw new Error("EFT / bank transfer is disabled in system settings.");
  }

  if (
    paymentMethod === "cash_on_delivery" &&
    !settings?.payments?.cash_on_delivery_enabled
  ) {
    throw new Error("Cash on delivery is disabled in system settings.");
  }

  // ------------------------------------------------------------------------
  // Initial checkout should not upload proof yet.
  // We still validate file size here so older screens can show a meaningful
  // warning instead of silently failing.
  // ------------------------------------------------------------------------
  if (paymentProofFile) {
    const maxMb = Math.max(
      1,
      Math.floor(toNumber(settings?.payments?.max_payment_proof_mb, 5))
    );
    const maxBytes = maxMb * 1024 * 1024;
    const actualBytes = fileSizeBytes(paymentProofFile);

    if (actualBytes > maxBytes) {
      throw new Error(`Payment proof exceeds the ${maxMb} MB system limit.`);
    }
  }
}

// ----------------------------------------------------------------------------
// Hook
// ----------------------------------------------------------------------------
export function useCart() {
  const {
    settings: publicSettings,
    loading: settingsLoading,
    error: settingsError,
  } = usePublicSystemSettings({
    autoLoad: true,
    initialSettings: DEFAULT_PUBLIC_SYSTEM_SETTINGS,
  });

  // --------------------------------------------------------------------------
  // IMPORTANT FIX:
  // The shared helper exported by usePublicSystemSettings is
  // mergePublicSystemSettings(...), not mergePublicSettings(...).
  // Using the wrong name caused the runtime ReferenceError on mount.
  // --------------------------------------------------------------------------
  const runtimeSettings = useMemo(
    () => mergePublicSystemSettings(publicSettings),
    [publicSettings]
  );

  const [items, setItems] = useState(() =>
    readCartFromStorage()
      .map((x) => normalizeCartItem(x))
      .filter(Boolean)
  );

  // --------------------------------------------------------------------------
  // Persist local cart state after every mutation.
  // --------------------------------------------------------------------------
  useEffect(() => {
    writeCartToStorage(items);
    cleanupLegacyCartStorage();
  }, [items]);

  // --------------------------------------------------------------------------
  // Replace the full cart in one call.
  // Useful for restoring cart state from another screen.
  // --------------------------------------------------------------------------
  const setCartItems = useCallback((nextItems) => {
    const normalized = Array.isArray(nextItems)
      ? nextItems.map((x) => normalizeCartItem(x)).filter(Boolean)
      : [];

    setItems(normalized);
  }, []);

  // --------------------------------------------------------------------------
  // Add or merge an item into the cart.
  // NOTE:
  // Read-only mode is respected for write-heavy commerce actions.
  // --------------------------------------------------------------------------
  const addToCart = useCallback(
    (rawItem, quantity = 1) => {
      if (runtimeSettings?.platform?.read_only_mode) {
        throw new Error(
          "Cart updates are temporarily unavailable because the marketplace is in read-only mode."
        );
      }

      const maxCartItems = Math.max(
        1,
        Math.floor(toNumber(runtimeSettings?.checkout?.max_cart_items, 50))
      );

      const incoming = normalizeCartItem(rawItem, quantity);
      if (!incoming) return;

      setItems((prev) => {
        const idx = prev.findIndex(
          (x) => String(x.product_id) === String(incoming.product_id)
        );

        if (idx < 0) {
          if (prev.length >= maxCartItems) {
            throw new Error(
              `Cart size is limited to ${maxCartItems} items by marketplace policy.`
            );
          }
          return [...prev, incoming];
        }

        const next = [...prev];
        next[idx] = mergeItemWithExisting(next[idx], incoming);
        return next;
      });
    },
    [runtimeSettings]
  );

  const removeFromCart = useCallback(
    (productId) => {
      if (!productId) return;

      if (runtimeSettings?.platform?.read_only_mode) {
        throw new Error(
          "Cart updates are temporarily unavailable because the marketplace is in read-only mode."
        );
      }

      setItems((prev) =>
        prev.filter((x) => String(x.product_id) !== String(productId))
      );
    },
    [runtimeSettings]
  );

  // --------------------------------------------------------------------------
  // Update quantity with unit-aware normalization:
  //   • each/pack -> integer
  //   • kg/g/l/ml -> decimal up to 3dp
  // qty <= 0 removes the item
  // --------------------------------------------------------------------------
  const updateQuantity = useCallback(
    (productId, quantity) => {
      if (!productId) return;

      if (runtimeSettings?.platform?.read_only_mode) {
        throw new Error(
          "Cart updates are temporarily unavailable because the marketplace is in read-only mode."
        );
      }

      setItems((prev) => {
        const existing = prev.find(
          (x) => String(x.product_id) === String(productId)
        );
        if (!existing) return prev;

        const normalizedQty = normalizeQuantity(
          quantity,
          existing.unit ?? "each",
          0
        );

        if (!(normalizedQty > 0)) {
          return prev.filter((x) => String(x.product_id) !== String(productId));
        }

        return prev.map((x) => {
          if (String(x.product_id) !== String(productId)) return x;

          const maxQty =
            x.available_stock === null || x.available_stock === undefined
              ? Infinity
              : normalizeQuantity(x.available_stock, x.unit ?? "each", 1);

          return {
            ...x,
            quantity: clampQuantity(
              normalizedQty,
              0.001,
              maxQty,
              x.unit ?? "each"
            ),
          };
        });
      });
    },
    [runtimeSettings]
  );

  const updateItemDeliveryLocation = useCallback(
    (productId, location) => {
      if (!productId) return;

      if (runtimeSettings?.platform?.read_only_mode) {
        throw new Error(
          "Cart updates are temporarily unavailable because the marketplace is in read-only mode."
        );
      }

      setItems((prev) =>
        prev.map((x) =>
          String(x.product_id) !== String(productId)
            ? x
            : {
                ...x,
                item_delivery_location:
                  location === undefined || location === null || location === ""
                    ? null
                    : String(location),
              }
        )
      );
    },
    [runtimeSettings]
  );

  const clearCart = useCallback(() => {
    setItems([]);
  }, []);

  // --------------------------------------------------------------------------
  // Derived line items with line totals.
  // --------------------------------------------------------------------------
  const lineItems = useMemo(() => {
    return items.map((item) => ({
      ...item,
      line_total: lineTotal(item),
    }));
  }, [items]);

  // --------------------------------------------------------------------------
  // Core cart metrics
  // --------------------------------------------------------------------------
  const subtotal = useMemo(() => {
    return roundTo(
      items.reduce((sum, item) => sum + lineTotal(item), 0),
      2
    );
  }, [items]);

  const totalItems = useMemo(() => {
    return roundTo(
      items.reduce((sum, item) => sum + toNumber(item.quantity, 0), 0),
      DEFAULT_QTY_PRECISION
    );
  }, [items]);

  const totalUniqueItems = items.length;

  // --------------------------------------------------------------------------
  // UI-friendly policy summary
  // --------------------------------------------------------------------------
  const policy = useMemo(() => {
    const canUseDelivery = Boolean(runtimeSettings?.checkout?.allow_delivery);
    const canUsePickup = Boolean(runtimeSettings?.checkout?.allow_pickup);
    const defaultPaymentMethod = inferDefaultPaymentMethod(runtimeSettings);

    return {
      currencyCode: safeTrim(
        runtimeSettings?.marketplace?.currency_code,
        "NAD"
      ).toUpperCase(),
      vatPercent: Math.max(
        0,
        toNumber(runtimeSettings?.marketplace?.vat_percent, 15)
      ),
      canUseDelivery,
      canUsePickup,
      eftEnabled: Boolean(runtimeSettings?.payments?.eft_enabled),
      cashOnDeliveryEnabled: Boolean(
        runtimeSettings?.payments?.cash_on_delivery_enabled
      ),
      proofOfPaymentRequiredForEft: Boolean(
        runtimeSettings?.payments?.proof_of_payment_required_for_eft
      ),
      maxPaymentProofMb: Math.max(
        1,
        Math.floor(toNumber(runtimeSettings?.payments?.max_payment_proof_mb, 5))
      ),
      maxCartItems: Math.max(
        1,
        Math.floor(toNumber(runtimeSettings?.checkout?.max_cart_items, 50))
      ),
      maxOrderLinesPerCheckout: Math.max(
        1,
        Math.floor(
          toNumber(runtimeSettings?.checkout?.max_order_lines_per_checkout, 20)
        )
      ),
      defaultDeliveryFee: Math.max(
        0,
        toNumber(runtimeSettings?.checkout?.default_delivery_fee, 30)
      ),
      freeDeliveryThreshold: Math.max(
        0,
        toNumber(runtimeSettings?.checkout?.free_delivery_threshold, 500)
      ),
      defaultPaymentMethod,
      maintenance: Boolean(runtimeSettings?.maintenance),
      maintenanceMessage:
        safeTrim(runtimeSettings?.platform?.maintenance_message, "") ||
        "Scheduled maintenance in progress. Please try again shortly.",
      readOnlyMode: Boolean(runtimeSettings?.platform?.read_only_mode),
      settingsLoading,
      settingsError,
    };
  }, [runtimeSettings, settingsLoading, settingsError]);

  // --------------------------------------------------------------------------
  // Default estimates for a delivery checkout.
  // --------------------------------------------------------------------------
  const estimatedDeliveryFee = useMemo(() => {
    return roundTo(
      estimateDeliveryFee(subtotal, "delivery", runtimeSettings),
      2
    );
  }, [subtotal, runtimeSettings]);

  const estimatedVat = useMemo(() => {
    return estimateVat(subtotal + estimatedDeliveryFee, runtimeSettings);
  }, [subtotal, estimatedDeliveryFee, runtimeSettings]);

  const estimatedGrandTotal = useMemo(() => {
    return roundTo(subtotal + estimatedDeliveryFee + estimatedVat, 2);
  }, [subtotal, estimatedDeliveryFee, estimatedVat]);

  // --------------------------------------------------------------------------
  // Checkout action
  // --------------------------------------------------------------------------
  const checkoutOrder = useCallback(
    async (options = {}) => {
      const checkoutCaller = resolveCheckoutApiCaller(
        customerApiDefault,
        customerApiNS
      );

      if (!checkoutCaller) {
        throw new Error(
          "Checkout service is unavailable. Missing checkoutOrder/checkout/placeOrder/createOrder export."
        );
      }

      const deliveryMethod = normalizeDeliveryMethod(
        options.delivery_method ?? options.deliveryMethod,
        runtimeSettings
      );

      const paymentMethod = normalizePaymentMethod(
        options.payment_method ?? options.paymentMethod,
        runtimeSettings
      );

      const deliveryLocation =
        safeTrim(
          options.delivery_location ??
            options.deliveryLocation ??
            options.customer_location ??
            options.customerLocation ??
            options.defaultDeliveryLocation,
          ""
        ) || "";

      const paymentProofFile =
        options.payment_proof ??
        options.paymentProof ??
        options.paymentProofFile ??
        null;

      const paymentProofReference = safeTrim(
        options.payment_proof_reference ??
          options.paymentReference ??
          options.payment_reference ??
          options.proof_reference,
        ""
      );

      validateCheckoutPolicy({
        items,
        settings: runtimeSettings,
        deliveryMethod,
        paymentMethod,
        deliveryLocation,
        paymentProofFile,
      });

      // ----------------------------------------------------------------------
      // Initial checkout must not transmit payment proof/reference.
      // Those belong to the later payment-proof upload workflow.
      // ----------------------------------------------------------------------
      if (paymentProofFile || paymentProofReference) {
        // eslint-disable-next-line no-console
        console.warn(
          "[useCart] payment proof/reference is ignored during initial checkout. Upload it later after the order is ready for payment."
        );
      }

      const payload = {
        items: buildCheckoutItemsFromCart(
          items,
          deliveryLocation,
          deliveryMethod
        ),
        delivery_method: deliveryMethod,
        delivery_location:
          deliveryMethod === "delivery" ? deliveryLocation || undefined : undefined,
        customer_location:
          deliveryMethod === "delivery" ? deliveryLocation || undefined : undefined,
        payment_method: paymentMethod,
        notes: safeTrim(options.notes ?? options.orderNotes, ""),
      };

      const response = await checkoutCaller(payload, {
        onUploadProgress: options.onUploadProgress,
        requestConfig: options.requestConfig,
      });

      if (options.clearCartOnSuccess !== false) {
        clearCart();
      }

      return response;
    },
    [items, clearCart, runtimeSettings]
  );

  // --------------------------------------------------------------------------
  // Public action bundle kept for backwards compatibility.
  // --------------------------------------------------------------------------
  const actions = useMemo(
    () => ({
      addToCart,
      addItem: addToCart,
      removeFromCart,
      removeItem: removeFromCart,
      updateQuantity,
      setQuantity: updateQuantity,
      updateItemDeliveryLocation,
      setItemDeliveryLocation: updateItemDeliveryLocation,
      setCartItems,
      clearCart,
      checkoutOrder,
      checkout: checkoutOrder,
    }),
    [
      addToCart,
      removeFromCart,
      updateQuantity,
      updateItemDeliveryLocation,
      setCartItems,
      clearCart,
      checkoutOrder,
    ]
  );

  // --------------------------------------------------------------------------
  // cartState mirror kept for legacy screens.
  // --------------------------------------------------------------------------
  const cartState = useMemo(
    () => ({
      items,
      lineItems,
      subtotal,
      totalItems,
      totalUniqueItems,
      estimatedDeliveryFee,
      estimatedVat,
      estimatedGrandTotal,
      runtimeSettings,
      policy,
      actions,
    }),
    [
      items,
      lineItems,
      subtotal,
      totalItems,
      totalUniqueItems,
      estimatedDeliveryFee,
      estimatedVat,
      estimatedGrandTotal,
      runtimeSettings,
      policy,
      actions,
    ]
  );

  return {
    items,
    lineItems,
    subtotal,
    totalItems,
    totalUniqueItems,
    estimatedDeliveryFee,
    estimatedVat,
    estimatedGrandTotal,
    runtimeSettings,
    policy,
    actions,
    cartState,

    addToCart,
    addItem: addToCart,
    removeFromCart,
    removeItem: removeFromCart,
    updateQuantity,
    setQuantity: updateQuantity,
    updateItemDeliveryLocation,
    setItemDeliveryLocation: updateItemDeliveryLocation,
    setCartItems,
    clearCart,
    checkoutOrder,
    checkout: checkoutOrder,
  };
}

export default useCart;