// ====================================================================
// EditProductModal.jsx — AgroConnect Namibia
// Glassmorphism Edit Product Modal
// Unified with global index.css styling
// ====================================================================

import React, { useState, useEffect } from "react";
import ProductForm from "../shared/ProductForm";
import useFileUpload from "../shared/useFileUpload";
import api from "../../api";
import { toast } from "react-hot-toast";

export default function EditProductModal({ open, onClose, product, onUpdated }) {
  const [initial, setInitial] = useState(null);
  const { uploadFile, uploading } = useFileUpload();

  useEffect(() => {
    if (!product) {
      setInitial(null);
      return;
    }

    setInitial({
      name: product.name || "",
      description: product.description || "",
      price: product.price || "",
      category: product.category || "",
      unit: product.unit || "",
      quantity: product.quantity || 1,
      image_url: product.image_url || null,
    });
  }, [product]);

  if (!open || !product) return null;

  const handleUpdate = async (values, file) => {
    try {
      let image_url = values.image_url || null;

      // If new image provided, upload it
      if (file) {
        const res = await uploadFile(file);
        if (!res.ok) {
          toast.error(`Upload failed: ${res.error}`);
          return;
        }
        image_url = res.path;
      }

      const payload = {
        name: values.name,
        description: values.description,
        price: Number(values.price),
        quantity: Number(values.quantity || 1),
        category: values.category || null,
        unit: values.unit || null,
        ...(image_url ? { image_url } : { image_url: null }),
      };

      const res = await api.put(`/products/${product.id}`, payload);
      toast.success("Product updated");
      onUpdated && onUpdated(res.data);
      onClose && onClose();
    } catch (err) {
      console.error("Update product error:", err);
      toast.error("Failed to update");
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-md flex items-center justify-center fade-in p-4">

      <div className="glass-card w-full max-w-2xl rounded-2xl p-6 text-white shadow-xl">

        <h3 className="text-2xl font-semibold mb-4 tracking-wide">
          Edit Product
        </h3>

        <ProductForm
          initialValues={initial}
          onSubmit={handleUpdate}
          onCancel={onClose}
          submitting={uploading}
          submitLabel="Save Changes"
        />

      </div>
    </div>
  );
}
