// ====================================================================
// ImageUploader.jsx — AgroConnect Namibia
// Reusable image upload component (unified styling)
// ====================================================================

import React, { useState } from "react";
import api from "../../api";

export default function ImageUploader({ onUpload }) {
  const [loading, setLoading] = useState(false);

  const handleUpload = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const form = new FormData();
    form.append("image", file);

    setLoading(true);

    try {
      const res = await api.post("/api/upload/image", form, {
        headers: { "Content-Type": "multipart/form-data" },
      });

      onUpload && onUpload(res.data.url);
    } catch (err) {
      console.error("Upload failed:", err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-2">
      <label className="block text-sm font-medium text-white/90">
        Upload Image
      </label>

      <input
        type="file"
        accept=".jpg,.jpeg,.png,.webp"
        onChange={handleUpload}
        className="
          w-full
          text-sm
          rounded-md
          border border-white/30
          bg-white/10
          backdrop-blur
          p-2
          text-white
          file:bg-white/20
          file:border-0
          file:px-3
          file:py-1
          file:rounded-md
          file:text-white
          file:mr-3
          hover:bg-white/20
          transition
        "
      />

      {loading && (
        <p className="text-sm text-white/80 fade-in">Uploading...</p>
      )}
    </div>
  );
}
