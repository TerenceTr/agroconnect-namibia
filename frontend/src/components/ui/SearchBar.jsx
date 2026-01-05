// frontend/src/components/ui/SearchBar.jsx
import React from "react";
import { Search, X } from "lucide-react";

export function SearchBar({ value, onChange, placeholder = "Search..." }) {
  return (
    <div className="flex items-center gap-2 bg-white/10 rounded-md px-3 py-2">
      <Search className="w-4 h-4 text-white/80" />
      <input
        value={value}
        onChange={(e) => onChange?.(e.target.value)}
        placeholder={placeholder}
        className="bg-transparent outline-none text-white placeholder-white/60 flex-1"
      />
      {value && (
        <button onClick={() => onChange?.("")} className="text-white/80 p-1 rounded">
          <X className="w-4 h-4" />
        </button>
      )}
    </div>
  );
}

export default SearchBar;
