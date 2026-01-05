// ============================================================================
// frontend/src/components/modals/AddProductModal.jsx — AgroConnect Namibia
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Modal to create a new product (Farmer).
//
// RESPONSIBILITIES:
//   • Collect form input via ProductForm
//   • Submit multipart/form-data to POST /products
//   • Notify parent via onCreated(createdProduct)
//   • Close via onClose()
//
// BACKEND ALIGNMENT:
//   ✅ Your backend create route reads request.form + request.files
//      → must send multipart/form-data
//
// DESIGN:
//   • Mostly white surface card
//   • Subtle glass blur overlay
// ============================================================================

import React, { useEffect, useState } from "react";
import ProductForm from "../shared/ProductForm";
import api from "../../api";
import { toast } from "react-hot-toast";

export default function AddProductModal({ open, onClose, onCreated }) {
  const [saving, setSaving] = useState(false);
  const busy = saving;

  // Lock scroll while open (prevents background page scrolling)
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

  if (!open) return null;

  const onBackdropMouseDown = (e) => {
    if (busy) return;
    if (e.target === e.currentTarget) onClose?.();
  };

  const handleCreate = async (values, file) => {
    setSaving(true);

    try {
      const fd = new FormData();

      // Match backend field names
      fd.append("product_name", values.name);
      fd.append("description", values.description || "");
      fd.append("price", String(values.price ?? ""));
      fd.append("quantity", String(values.quantity ?? 1));

      if (values.category) fd.append("category", values.category);
      if (values.unit) fd.append("unit", values.unit);
      if (file) fd.append("image", file);

      const response = await api.post("/products", fd, {
        headers: { "Content-Type": "multipart/form-data" },
      });

      toast.success("Product created successfully");
      onCreated?.(response.data);
      onClose?.();
    } catch (err) {
      console.error("Create product error", err);
      toast.error("Failed to create product");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm p-4"
      role="dialog"
      aria-modal="true"
      aria-label="Add product modal"
      onMouseDown={onBackdropMouseDown}
    >
      <div
        className="w-full max-w-2xl rounded-2xl bg-white/85 backdrop-blur-xl border border-white/60 shadow-2xl"
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div className="px-6 pt-6 pb-4">
          <h3 className="text-lg md:text-xl font-semibold text-slate-900">Add Product</h3>
          <p className="text-sm text-slate-500 mt-1">Create a new listing for customers.</p>
        </div>

        <div className="px-6 pb-6">
          <ProductForm
            onSubmit={handleCreate}
            onCancel={() => !busy && onClose?.()}
            submitting={busy}
            submitLabel={busy ? "Saving..." : "Create Product"}
          />
        </div>
      </div>
    </div>
  );
}
