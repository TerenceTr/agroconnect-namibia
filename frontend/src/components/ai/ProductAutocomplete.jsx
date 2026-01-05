// src/components/ai/ProductAutocomplete.jsx
import React, { useState, useEffect, useRef } from "react";
import { Search } from "lucide-react";
import debounce from "lodash.debounce";
import apiClient from "../../api"; // centralized axios wrapper

export default function ProductAutocomplete({ value, onChange, placeholder = "Search product..." }) {
  const [q, setQ] = useState(value ? (value.name || value) : "");
  const [items, setItems] = useState([]);
  const [open, setOpen] = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    const onClick = (e) => {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false);
    };
    document.addEventListener("click", onClick);
    return () => document.removeEventListener("click", onClick);
  }, []);

  const searchAPI = async (term) => {
    try {
      if (!term || term.length < 2) {
        setItems([]);
        return;
      }
      // use centralized axios instance (it injects token and uses REACT_APP_API_URL)
      const res = await apiClient.api.get("/products", { params: { q: term } });
      setItems(res.data || []);
      setOpen(true);
    } catch (err) {
      setItems([]);
    }
  };

  const debounced = useRef(debounce((t) => searchAPI(t), 300)).current;

  useEffect(() => {
    debounced(q);
  }, [q, debounced]);

  return (
    <div className="relative" ref={ref}>
      <div className="flex items-center bg-white/10 p-2 rounded-md">
        <Search className="w-4 h-4 text-white/60 mr-2" />
        <input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          onFocus={() => q.length >= 2 && setOpen(true)}
          placeholder={placeholder}
          className="bg-transparent outline-none text-white w-full"
        />
      </div>

      {open && items.length > 0 && (
        <ul className="absolute z-50 mt-1 w-full bg-white/6 backdrop-blur-md rounded-md border border-white/10 max-h-56 overflow-auto">
          {items.map((p) => (
            <li
              key={p.id}
              className="px-3 py-2 hover:bg-white/10 cursor-pointer text-white/90"
              onClick={() => {
                onChange && onChange(p);
                setQ(p.name);
                setOpen(false);
              }}
            >
              <div className="font-medium">{p.name}</div>
              <div className="text-xs text-white/60">{p.location || "—"}</div>
            </li>
          ))}
        </ul>
      )}

      {open && items.length === 0 && q.length >= 2 && (
        <div className="absolute z-50 mt-1 w-full bg-white/6 backdrop-blur-md rounded-md border border-white/10 p-2 text-white/60">
          No products found
        </div>
      )}
    </div>
  );
}
