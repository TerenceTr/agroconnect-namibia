// frontend/src/components/ui/Modal.jsx
import React from "react";
import { X } from "lucide-react";

export function Modal({ open, onClose, title, children, actions }) {
  if (!open) return null;

  return (
    <div className="fixed inset-0 bg-black/40 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="bg-white/10 backdrop-blur-xl border border-white/20 shadow-glass rounded-2xl w-full max-w-lg p-6 relative">
        <button
          aria-label="Close"
          className="absolute right-4 top-4 text-white/70 hover:text-white"
          onClick={onClose}
        >
          <X size={22} />
        </button>

        {title && <h2 className="text-xl font-semibold text-white mb-4">{title}</h2>}

        <div className="text-white">{children}</div>

        {actions && <div className="mt-6 flex justify-end gap-3">{actions}</div>}
      </div>
    </div>
  );
}

export default Modal;
