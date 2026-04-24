// ============================================================================
// frontend/src/components/modals/DeleteProductModal.jsx — AgroConnect Namibia
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Confirm delete modal for product removal.
//
// RESPONSIBILITIES:
//   • Confirm intent
//   • Call DELETE /products/:id
//   • Notify parent via onDeleted(deletedId)
//   • Close via onClose()
//
// DESIGN:
//   • Mostly white surface card
//   • Subtle glass blur overlay
// ============================================================================

import React, { useEffect, useState } from "react";
import api from "../../api";
import { toast } from "react-hot-toast";

export default function DeleteProductModal({ open, onClose, product, onDeleted }) {
  const [loading, setLoading] = useState(false);
  const busy = loading;

  // Lock scroll while open
  useEffect(() => {
    if (!open) return;
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.body.style.overflow = prev;
    };
  }, [open]);

  // ESC to close
  useEffect(() => {
    if (!open) return;
    const onKey = (e) => {
      if (e.key === "Escape" && !busy) onClose?.();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, busy, onClose]);

  if (!open || !product) return null;

  const onBackdropMouseDown = (e) => {
    if (busy) return;
    if (e.target === e.currentTarget) onClose?.();
  };

  // Support both shapes: {id} or {product_id}
  const productId = product?.id || product?.product_id;

  const handleDelete = async () => {
    if (!productId) return;

    setLoading(true);
    try {
      await api.delete(`/products/${productId}`);
      toast.success("Product deleted");
      onDeleted?.(productId);
      onClose?.();
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error("Delete product error:", err);
      toast.error(err?.response?.data?.message || "Failed to delete product");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm p-4"
      role="dialog"
      aria-modal="true"
      aria-label="Delete product modal"
      onMouseDown={onBackdropMouseDown}
    >
      <div
        className="w-full max-w-md rounded-2xl bg-white/90 backdrop-blur-xl border border-white/60 shadow-2xl"
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div className="px-6 pt-6 pb-4">
          <h3 className="text-lg font-semibold text-slate-900">Delete Product</h3>
          <p className="text-sm text-slate-600 mt-2">
            Are you sure you want to delete{" "}
            <strong className="text-slate-900">{product.product_name || product.name}</strong>?
            This action cannot be undone.
          </p>
        </div>

        <div className="px-6 pb-6 flex justify-end gap-3">
          <button
            onClick={() => !busy && onClose?.()}
            disabled={busy}
            className="px-4 py-2 rounded-xl border border-slate-200 bg-white hover:bg-slate-50 text-slate-800 disabled:opacity-50"
          >
            Cancel
          </button>

          <button
            onClick={handleDelete}
            disabled={busy}
            className="px-4 py-2 rounded-xl bg-rose-600 hover:bg-rose-500 text-white font-semibold disabled:opacity-50"
          >
            {busy ? "Deleting..." : "Delete"}
          </button>
        </div>
      </div>
    </div>
  );
}
