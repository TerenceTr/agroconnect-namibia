// ============================================================================
// frontend/src/components/modals/AddProductModal.jsx — Farmer Create Product
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Modal used by the Farmer dashboard to create a product listing.
//
// RESPONSIBILITIES:
//   • Collect input via ProductForm
//   • Submit to POST /products
//   • Enforce moderation workflow: status = 'pending'
//   • Close modal + notify parent when created
//
// MODERATION (OPTION 1):
//   • New products default to pending
//   • Customers only see 'available/approved/published' products
// ============================================================================

import React, { useEffect, useState } from "react";
import { toast } from "react-hot-toast";

import api from "../../api";
import ProductForm from "../shared/ProductForm";

export default function AddProductModal({ open, onClose, onCreated }) {
  const [saving, setSaving] = useState(false);
  const busy = saving;

  // Prevent background scroll while open
  useEffect(() => {
    if (!open) return;
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.body.style.overflow = prev;
    };
  }, [open]);

  // ESC closes modal (if not busy)
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
      // Use multipart to remain compatible with backends reading request.form + request.files
      const fd = new FormData();

      fd.append("product_name", values.name);
      fd.append("name", values.name); // extra compatibility for backends expecting "name"
      fd.append("description", values.description || "");
      fd.append("price", String(values.price ?? ""));
      fd.append("quantity", String(values.quantity ?? 1));
      fd.append("stock", String(values.quantity ?? 1)); // extra compatibility
      if (values.category) fd.append("category", values.category);
      if (values.unit) fd.append("unit", values.unit);

      // IMPORTANT: moderation workflow
      fd.append("status", "pending");

      if (file) fd.append("image", file);

      const response = await api.post("/products", fd, {
        headers: { "Content-Type": "multipart/form-data" },
      });

      toast.success("Product submitted for approval.");
      onCreated?.(response.data);
      onClose?.();
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error("Create product error", err);
      toast.error(err?.response?.data?.message || "Failed to submit product.");
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
        className="w-full max-w-2xl rounded-2xl bg-white/90 backdrop-blur-xl border border-white/60 shadow-2xl"
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div className="px-6 pt-6 pb-4">
          <h3 className="text-lg md:text-xl font-extrabold text-slate-900">Add Product</h3>
          <p className="text-sm text-slate-600 mt-1">
            Your listing will be reviewed by Admin before it becomes visible to customers.
          </p>
        </div>

        <div className="px-6 pb-6">
          <ProductForm
            onSubmit={handleCreate}
            onCancel={() => !busy && onClose?.()}
            submitting={busy}
            submitLabel={busy ? "Submitting..." : "Submit for approval"}
          />
        </div>
      </div>
    </div>
  );
}
