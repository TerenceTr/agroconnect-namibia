// frontend/src/components/ui/FileUploader.jsx
import React from "react";

export function FileUploader({ onChange }) {
  return (
    <label className="block p-6 text-center border border-white/30 rounded-xl bg-white/10 backdrop-blur-md text-white cursor-pointer hover:bg-white/20 transition">
      <p className="text-sm">Click to upload file</p>
      <input type="file" className="hidden" onChange={onChange} />
    </label>
  );
}

export default FileUploader;
