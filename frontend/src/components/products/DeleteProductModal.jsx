// ====================================================================
// DeleteProductModal.jsx — AgroConnect Namibia
// Glassmorphism Confirm Delete Modal
// Unified with global index.css styling
// ====================================================================

import React, { useState } from "react";
import api from "../../api";
import { toast } from "react-hot-toast";

export default function DeleteProductModal({ open, onClose, product, onDeleted }) {
  const [loading, setLoading] = useState(false);

  if (!open || !product) return null;

  const handleDelete = async () => {
    setLoading(true);

    try {
      await api.delete(`/products/${product.id}`);

      toast.success("Product deleted");
      onDeleted && onDeleted(product.id);
      onClose && onClose();
    } catch (err) {
      console.error("Delete product error:", err);
      toast.error("Failed to delete product");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-md fade-in p-4">

      {/* CARD */}
      <div className="glass-card w-full max-w-md p-6 rounded-2xl shadow-xl text-white">

        <h3 className="text-xl font-semibold mb-4 tracking-wide">Delete Product</h3>

        <p className="text-white/80 text-sm mb-6 leading-relaxed">
          Are you sure you want to delete <strong className="text-white">{product.name}</strong>?  
          This action cannot be undone.
        </p>

        {/* ACTION BUTTONS */}
        <div className="flex justify-end gap-3">

          {/* Cancel Button */}
          <button
            onClick={onClose}
            disabled={loading}
            className="
              px-4 py-2 rounded-lg border border-white/40 
              text-white/90 hover:bg-white/10 transition
            "
          >
            Cancel
          </button>

          {/* Delete Button */}
          <button
            onClick={handleDelete}
            disabled={loading}
            className="
              px-4 py-2 rounded-lg
              bg-red-600 hover:bg-red-500
              text-white font-semibold
              transition
            "
          >
            {loading ? "Deleting..." : "Delete"}
          </button>

        </div>
      </div>
    </div>
  );
}
