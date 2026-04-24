// ============================================================================
// frontend/src/components/shared/ProductForm.jsx — Reusable Product Form
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Shared form UI used by AddProductModal and EditProductModal (if desired).
//
// RESPONSIBILITIES:
//   • Controlled inputs: name, description, category, unit, price, quantity
//   • Optional image file selection + preview
//   • Pass (values, file) to parent on submit
//
// ESLINT FIX (THIS UPDATE):
//   • Avoid referencing nested `initial.*` in useEffect dependencies
//   • Use `useMemo` to build stable `init` from initialValues
//   • Depend on `init` only (stable snapshot)
// ============================================================================

import React, { useEffect, useMemo, useState } from "react";
import ImagePreview from "./ImagePreview";

// You can share the same list used elsewhere for consistency
const NAMIBIA_TOP_CATEGORIES = [
  "Fresh Produce",
  "Animal Products",
  "Fish & Seafood",
  "Staples",
  "Nuts, Seeds & Oils",
  "Honey & Sweeteners",
  "Value-Added & Processed (Farm-made)",
  "Farm Supplies",
  "Wild Harvest",
];

export default function ProductForm({
  initialValues,
  onSubmit,
  onCancel,
  submitting = false,
  submitLabel = "Save",
}) {
  // Build a stable initial snapshot for controlled fields.
  const init = useMemo(() => {
    const v = initialValues || {};
    return {
      name: v.name || v.product_name || "",
      description: v.description || "",
      price: v.price ?? "",
      category: v.category || "Fresh Produce",
      unit: v.unit || "each",
      quantity: v.quantity ?? 1,
      image_url: v.image_url || v.imageUrl || "",
    };
  }, [initialValues]);

  const [name, setName] = useState(init.name);
  const [description, setDescription] = useState(init.description);
  const [price, setPrice] = useState(init.price);
  const [category, setCategory] = useState(init.category);
  const [unit, setUnit] = useState(init.unit);
  const [quantity, setQuantity] = useState(init.quantity);

  const [file, setFile] = useState(null);
  const [previewSrc, setPreviewSrc] = useState(init.image_url || "");

  // Sync when modal opens with a new product (edit) or clears (add)
  useEffect(() => {
    setName(init.name);
    setDescription(init.description);
    setPrice(init.price);
    setCategory(init.category);
    setUnit(init.unit);
    setQuantity(init.quantity);
    setPreviewSrc(init.image_url || "");
    setFile(null);
  }, [init]);

  const handleFileChange = (e) => {
    const f = e.target.files?.[0] ?? null;
    setFile(f);

    if (!f) {
      setPreviewSrc(init.image_url || "");
      return;
    }

    const reader = new FileReader();
    reader.onloadend = () => setPreviewSrc(String(reader.result || ""));
    reader.readAsDataURL(f);
  };

  const handleSubmit = (ev) => {
    ev.preventDefault();

    const values = {
      name: name.trim(),
      description: description.trim(),
      price,
      category: String(category || "").trim(),
      unit: String(unit || "").trim(),
      quantity,
      image_url: previewSrc,
    };

    onSubmit?.(values, file);
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      {/* Name */}
      <div>
        <label className="block text-xs font-extrabold text-slate-900 mb-1">Product name</label>
        <input
          required
          value={name}
          onChange={(e) => setName(e.target.value)}
          className="h-11 w-full rounded-2xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-900 outline-none"
          placeholder="e.g. Sweet Melon (Cantaloupe)"
        />
      </div>

      {/* Description */}
      <div>
        <label className="block text-xs font-extrabold text-slate-900 mb-1">Description</label>
        <textarea
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          className="min-h-[88px] w-full rounded-2xl border border-slate-200 bg-white px-3 py-2 text-sm text-slate-900 outline-none"
          placeholder="Short notes: farming method, freshness, harvest date..."
        />
      </div>

      {/* Price + Quantity */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <div>
          <label className="block text-xs font-extrabold text-slate-900 mb-1">Price (N$)</label>
          <input
            required
            type="number"
            step="0.01"
            inputMode="decimal"
            value={price}
            onChange={(e) => setPrice(e.target.value)}
            className="h-11 w-full rounded-2xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-900 outline-none"
            placeholder="0.00"
          />
        </div>

        <div>
          <label className="block text-xs font-extrabold text-slate-900 mb-1">Quantity / Stock</label>
          <input
            type="number"
            step="0.01"
            inputMode="decimal"
            value={quantity}
            onChange={(e) => setQuantity(e.target.value)}
            className="h-11 w-full rounded-2xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-900 outline-none"
            placeholder="1"
          />
        </div>
      </div>

      {/* Category + Unit */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <div>
          <label className="block text-xs font-extrabold text-slate-900 mb-1">Category</label>
          <select
            value={category}
            onChange={(e) => setCategory(e.target.value)}
            className="h-11 w-full rounded-2xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-900 outline-none"
          >
            {NAMIBIA_TOP_CATEGORIES.map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </select>
        </div>

        <div>
          <label className="block text-xs font-extrabold text-slate-900 mb-1">Unit</label>
          <select
            value={unit}
            onChange={(e) => setUnit(e.target.value)}
            className="h-11 w-full rounded-2xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-900 outline-none"
          >
            <option value="each">each</option>
            <option value="kg">kg</option>
            <option value="g">g</option>
            <option value="l">l</option>
            <option value="ml">ml</option>
            <option value="pack">pack</option>
          </select>
        </div>
      </div>

      {/* Image file */}
      <div className="rounded-2xl border border-slate-200 bg-white p-3">
        <label className="block text-xs font-extrabold text-slate-900 mb-2">Image (optional)</label>
        <input type="file" accept="image/*" onChange={handleFileChange} />
        <div className="mt-3">
          <ImagePreview src={previewSrc} alt="Product preview" />
        </div>
        <div className="mt-2 text-xs text-slate-500">
          Tip: if your backend does not persist uploads yet, the listing will still be created and your UI will fall back to local assets.
        </div>
      </div>

      {/* Actions */}
      <div className="flex justify-end gap-2 pt-2">
        <button
          type="button"
          onClick={onCancel}
          disabled={submitting}
          className="h-11 px-4 rounded-2xl border border-slate-200 bg-white hover:bg-slate-50 text-slate-800 font-bold disabled:opacity-60"
        >
          Cancel
        </button>
        <button
          type="submit"
          disabled={submitting}
          className="h-11 px-4 rounded-2xl bg-emerald-600 hover:bg-emerald-700 text-white font-extrabold disabled:opacity-60"
        >
          {submitting ? "Saving..." : submitLabel}
        </button>
      </div>
    </form>
  );
}
