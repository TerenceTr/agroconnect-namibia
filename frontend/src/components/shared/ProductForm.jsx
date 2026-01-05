// frontend/src/components/shared/ProductForm.jsx
// Reusable product form used by Add and Edit modals.
// Handles local file selection and passes file + values to parent on submit.

import React, { useState, useEffect } from "react";
import ImagePreview from "./ImagePreview";

/**
 * Props:
 * - initialValues: { name, description, price, category, unit, quantity, image_url }
 * - onSubmit: async (values, file) => void
 * - onCancel: () => void
 * - submitting: boolean
 * - submitLabel: string
 */
export default function ProductForm({
  initialValues,
  onSubmit,
  onCancel,
  submitting = false,
  submitLabel = "Save",
}) {
  const initial = initialValues || {};
  const [name, setName] = useState(initial.name || "");
  const [description, setDescription] = useState(initial.description || "");
  const [price, setPrice] = useState(initial.price ?? "");
  const [category, setCategory] = useState(initial.category || "");
  const [unit, setUnit] = useState(initial.unit || "");
  const [quantity, setQuantity] = useState(initial.quantity ?? 1);
  const [file, setFile] = useState(null);
  const [previewSrc, setPreviewSrc] = useState(initial.image_url || null);

  useEffect(() => {
    // sync when initialValues change (e.g., opening edit modal)
    setName(initial.name || "");
    setDescription(initial.description || "");
    setPrice(initial.price ?? "");
    setCategory(initial.category || "");
    setUnit(initial.unit || "");
    setQuantity(initial.quantity ?? 1);
    setPreviewSrc(initial.image_url || null);
    setFile(null);
  }, [initialValues]);

  const handleFileChange = (e) => {
    const f = e.target.files?.[0] ?? null;
    setFile(f);

    if (f) {
      const reader = new FileReader();
      reader.onloadend = () => setPreviewSrc(reader.result);
      reader.readAsDataURL(f);
    } else {
      setPreviewSrc(initial.image_url || null);
    }
  };

  const handleSubmit = (ev) => {
    ev.preventDefault();
    const values = {
      name: name.trim(),
      description: description.trim(),
      price,
      category: category.trim(),
      unit: unit.trim(),
      quantity,
      image_url: previewSrc,
    };
    onSubmit && onSubmit(values, file);
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div>
        <label className="block text-sm">Name</label>
        <input required value={name} onChange={(e) => setName(e.target.value)}
               className="w-full p-2 rounded border" />
      </div>

      <div>
        <label className="block text-sm">Description</label>
        <textarea value={description} onChange={(e) => setDescription(e.target.value)}
                  className="w-full p-2 rounded border" />
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-sm">Price</label>
          <input required type="number" value={price} onChange={(e) => setPrice(e.target.value)}
                 className="w-full p-2 rounded border" />
        </div>

        <div>
          <label className="block text-sm">Quantity</label>
          <input type="number" value={quantity} onChange={(e) => setQuantity(e.target.value)}
                 className="w-full p-2 rounded border" />
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-sm">Category</label>
          <input value={category} onChange={(e) => setCategory(e.target.value)}
                 className="w-full p-2 rounded border" />
        </div>

        <div>
          <label className="block text-sm">Unit</label>
          <input value={unit} onChange={(e) => setUnit(e.target.value)}
                 className="w-full p-2 rounded border" />
        </div>
      </div>

      <div>
        <label className="block text-sm">Image (optional)</label>
        <input type="file" accept="image/*" onChange={handleFileChange} />
      </div>

      <div>
        <label className="block text-sm mb-2">Preview</label>
        <ImagePreview src={previewSrc} alt="product preview" />
      </div>

      <div className="flex justify-end gap-2 pt-2">
        <button type="button" onClick={onCancel} disabled={submitting}
                className="px-4 py-2 rounded border">
          Cancel
        </button>
        <button type="submit" disabled={submitting} className="px-4 py-2 rounded bg-green-600 text-white">
          {submitting ? "Saving..." : submitLabel}
        </button>
      </div>
    </form>
  );
}
