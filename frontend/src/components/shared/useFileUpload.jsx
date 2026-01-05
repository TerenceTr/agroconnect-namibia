// frontend/src/components/shared/useFileUpload.jsx
// Hook to upload a single file to backend /upload endpoint.
// Returns: { uploadFile(file) => { ok, path, error }, uploading }

import { useState } from "react";
import api from "../../api";

/**
 * Assumes backend exposes POST /upload
 * Request: multipart/form-data field name "file"
 * Response: { path: "/uploads/..." } on success
 */
export default function useFileUpload() {
  const [uploading, setUploading] = useState(false);

  const uploadFile = async (file) => {
    if (!file) return { ok: false, error: "No file" };
    const form = new FormData();
    // Some older components used "file" or "image"; backend usually accepts the field name "file"
    form.append("file", file);

    setUploading(true);
    try {
      const res = await api.post("/upload", form, {
        headers: { "Content-Type": "multipart/form-data" },
      });

      // Accept either res.data.path or res.data.url
      const path = res?.data?.path || res?.data?.url || null;
      if (!path) {
        return { ok: false, error: "Invalid upload response" };
      }

      return { ok: true, path };
    } catch (err) {
      console.error("Upload error:", err);
      const msg = err?.message || "Upload failed";
      return { ok: false, error: msg };
    } finally {
      setUploading(false);
    }
  };

  return { uploadFile, uploading };
}
