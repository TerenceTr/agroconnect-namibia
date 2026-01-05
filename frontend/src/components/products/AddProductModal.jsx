// ====================================================================
// AddProductModal.jsx — AgroConnect Namibia
// Glassmorphism Modal for Creating New Products
// Clean, unified with global index.css styling
// ====================================================================

import React, { useState } from "react";
import ProductForm from "../shared/ProductForm";
import useFileUpload from "../shared/useFileUpload";
import api from "../../api";
import { toast } from "react-hot-toast";

export default function AddProductModal({ open, onClose, onCreated, farmerId }) {
  const [saving, setSaving] = useState(false);
  const { uploadFile, uploading } = useFileUpload();

  if (!open) return null;

  const handleCreate = async (values, file) => {
    setSaving(true);

    try {
      let image_url = null;

      // Upload if file selected
      if (file) {
        const res = await uploadFile(file);
        if (!res.ok) {
          toast.error(`Upload failed: ${res.error}`);
          setSaving(false);
          return;
        }
        image_url = res.path;
      }

      const payload = {
        name: values.name,
        description: values.description,
        price: Number(values.price),
        quantity: Number(values.quantity || 1),
        farmer_id: farmerId,
        category: values.category || null,
        unit: values.unit || null,
        ...(image_url ? { image_url } : {}),
      };

      const response = await api.post("/products", payload);

      toast.success("Product created successfully");
      onCreated && onCreated(response.data);
      onClose && onClose();
    } catch (err) {
      console.error("Create product error", err);
      toast.error("Failed to create product");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-md fade-in p-4">

      {/* MODAL CARD */}
      <div className="w-full max-w-2xl glass-card rounded-2xl p-6 shadow-2xl text-white">

        <h3 className="text-xl font-semibold mb-4 tracking-wide">Add Product</h3>

        <ProductForm
          onSubmit={handleCreate}
          onCancel={onClose}
          submitting={saving || uploading}
          submitLabel={saving || uploading ? "Saving..." : "Create Product"}
        />
      </div>
    </div>
  );
}
