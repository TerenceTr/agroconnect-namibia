// ============================================================================
// frontend/src/components/modals/EditProductModal.jsx — AgroConnect Namibia
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Farmer product edit modal.
//   • Prefills ProductForm with current product values
//   • Sends multipart/form-data to PUT /products/:id (backend expects request.form + request.files)
//   • Notifies parent via onUpdated(updatedProduct)
//   • Closes via onClose()
//
// IMPORTANT (Fix for your ESLint error):
//   ✅ Do NOT call hooks after an early return.
//   This version removes the conditional-hook problem by using a static styles object
//   (no useMemo needed) and placing the early return AFTER all hooks.
// ============================================================================

import React, { useEffect, useState } from "react";
import ProductForm from "../shared/ProductForm";
import api from "../../api";
import { toast } from "react-hot-toast";

// ---------------------------------------------------------------------------
// Static styles (no hook needed → avoids "hooks called conditionally" entirely)
// ---------------------------------------------------------------------------
const STYLES = {
  overlay:
    "fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4",
  card:
    "w-full max-w-2xl rounded-2xl shadow-2xl border border-black/10 bg-white text-slate-900 overflow-hidden",
  header:
    "px-6 py-4 border-b border-black/10 bg-white/70 backdrop-blur-md flex items-center justify-between",
  body: "px-6 py-5",
  title: "text-lg font-semibold tracking-tight",
  hint: "text-sm text-slate-600",
  closeBtn:
    "rounded-lg px-3 py-2 text-slate-700 hover:bg-black/5 transition disabled:opacity-50 disabled:cursor-not-allowed",
};

export default function EditProductModal({ open, onClose, product, onUpdated }) {
  // -------------------------------------------------------------------------
  // Local state
  // -------------------------------------------------------------------------
  const [initial, setInitial] = useState(null);
  const [saving, setSaving] = useState(false);
  const busy = saving;

  // Support both shapes: { id } or { product_id }
  const productId = product?.id || product?.product_id || null;

  // -------------------------------------------------------------------------
  // Lock scroll while modal is open
  // -------------------------------------------------------------------------
  useEffect(() => {
    if (!open) return;

    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";

    return () => {
      document.body.style.overflow = prev;
    };
  }, [open]);

  // -------------------------------------------------------------------------
  // ESC to close (disabled while saving)
  // -------------------------------------------------------------------------
  useEffect(() => {
    if (!open) return;

    const onKey = (e) => {
      if (e.key === "Escape" && !busy) onClose?.();
    };

    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, busy, onClose]);

  // -------------------------------------------------------------------------
  // Build initial form values whenever product changes
  // -------------------------------------------------------------------------
  useEffect(() => {
    if (!product) {
      setInitial(null);
      return;
    }

    setInitial({
      // ProductForm expects: { name, description, price, category, unit, quantity, image_url }
      name: product.product_name || product.name || "",
      description: product.description || "",
      price: product.price ?? "",
      category: product.category || "",
      unit: product.unit || "",
      quantity: product.quantity ?? 1,
      image_url: product.image_url || null,
    });
  }, [product]);

  // -------------------------------------------------------------------------
  // IMPORTANT: early return MUST come AFTER hooks to satisfy react-hooks rules
  // -------------------------------------------------------------------------
  if (!open || !product) return null;

  // Close when clicking the backdrop (but not while saving)
  const onBackdropMouseDown = (e) => {
    if (busy) return;
    if (e.target === e.currentTarget) onClose?.();
  };

  // -------------------------------------------------------------------------
  // Submit: multipart/form-data (backend update route reads request.form/files)
  // -------------------------------------------------------------------------
  const handleUpdate = async (values, file) => {
    if (!productId) {
      toast.error("Missing product id");
      return;
    }

    setSaving(true);
    try {
      const fd = new FormData();

      // Match backend field names used in products.py update_product()
      // (Your backend checks for keys in request.form, so sending keys is OK.)
      fd.append("product_name", values.name || "");
      fd.append("description", values.description || "");
      fd.append("price", String(values.price ?? ""));
      fd.append("quantity", String(values.quantity ?? 1));

      if (values.category) fd.append("category", values.category);
      if (values.unit) fd.append("unit", values.unit);

      // Only attach new image if user selected one
      if (file) fd.append("image", file);

      const res = await api.put(`/products/${productId}`, fd, {
        headers: { "Content-Type": "multipart/form-data" },
      });

      toast.success("Product updated");
      onUpdated?.(res.data);
      onClose?.();
    } catch (err) {
      console.error("Update product error", err);
      toast.error("Failed to update product");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div
      className={STYLES.overlay}
      role="dialog"
      aria-modal="true"
      aria-label="Edit product modal"
      onMouseDown={onBackdropMouseDown}
    >
      <div className={STYLES.card} onMouseDown={(e) => e.stopPropagation()}>
        <div className={STYLES.header}>
          <div>
            <h3 className={STYLES.title}>Edit Product</h3>
            <p className={STYLES.hint}>Update product details and save changes.</p>
          </div>

          <button
            type="button"
            onClick={() => !busy && onClose?.()}
            disabled={busy}
            className={STYLES.closeBtn}
            aria-label="Close"
          >
            ✕
          </button>
        </div>

        <div className={STYLES.body}>
          <ProductForm
            // If ProductForm can’t handle null, change to: initialValues={initial || {}}
            initialValues={initial}
            onSubmit={handleUpdate}
            onCancel={() => !busy && onClose?.()}
            submitting={busy}
            submitLabel={busy ? "Saving..." : "Save Changes"}
          />
        </div>
      </div>
    </div>
  );
}
