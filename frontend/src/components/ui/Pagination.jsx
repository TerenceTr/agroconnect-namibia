// frontend/src/components/ui/Pagination.jsx
import React from "react";

export function Pagination({ page = 1, totalPages = 1, onChange }) {
  return (
    <div className="flex items-center justify-center gap-3 mt-4">
      <button
        onClick={() => onChange?.(Math.max(1, page - 1))}
        disabled={page === 1}
        className={`px-3 py-1 rounded ${
          page === 1 ? "bg-gray-200 text-gray-400" : "bg-namibia-green text-white"
        }`}
      >
        Prev
      </button>

      <div className="text-white/80 text-sm">
        Page <span className="font-medium">{page}</span> of{" "}
        <span className="font-medium">{totalPages}</span>
      </div>

      <button
        onClick={() => onChange?.(Math.min(totalPages, page + 1))}
        disabled={page === totalPages}
        className={`px-3 py-1 rounded ${
          page === totalPages
            ? "bg-gray-200 text-gray-400"
            : "bg-namibia-green text-white"
        }`}
      >
        Next
      </button>
    </div>
  );
}

export default Pagination;
