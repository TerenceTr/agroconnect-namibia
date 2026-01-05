// frontend/src/components/shared/ImagePreview.jsx
// Small component that renders an image preview or a placeholder.

import React from "react";

export default function ImagePreview({ src, alt }) {
  if (!src) {
    return (
      <div className="h-40 w-full rounded border bg-gray-100 flex items-center justify-center">
        <p className="text-gray-500">No image</p>
      </div>
    );
  }

  // If src looks like an absolute or relative path, render directly.
  // The src may already include a leading slash ("/uploads/...") or be a data URL.
  return (
    <div className="h-40 w-full rounded border bg-gray-100 flex items-center justify-center overflow-hidden">
      <img src={src} alt={alt || "preview"} className="h-full object-contain" />
    </div>
  );
}
