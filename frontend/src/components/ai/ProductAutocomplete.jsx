// ============================================================================
// src/components/ai/ProductAutocomplete.jsx
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Reusable product autocomplete input for search / AI-assisted selection
//   surfaces in AgroConnect.
//
// WHAT THIS VERSION IMPROVES:
//   ✅ Respects public system settings from usePublicSystemSettings
//   ✅ Disables live autocomplete when search.autocomplete_enabled = false
//   ✅ Respects search.search_suggestions_limit
//   ✅ Keeps graceful fallback to plain text input behavior
//   ✅ Uses debounced API search to reduce noisy requests
//   ✅ Safely supports different axios wrapper shapes:
//        - apiClient.get(...)
//        - apiClient.api.get(...)
//   ✅ Synchronizes internal display text with external value changes
//   ✅ Adds clearer loading / empty / disabled UI states
// ============================================================================

import React, { useEffect, useMemo, useRef, useState } from "react";
import { Search } from "lucide-react";
import debounce from "lodash.debounce";

import apiClient from "../../api";
import usePublicSystemSettings from "../../hooks/usePublicSystemSettings";

// ----------------------------------------------------------------------------
// Small helpers
// ----------------------------------------------------------------------------
function safeText(value, fallback = "") {
  const text = String(value ?? "").trim();
  return text || fallback;
}

function resolveApiGetter(client) {
  if (client && typeof client.get === "function") return client.get.bind(client);
  if (client?.api && typeof client.api.get === "function") return client.api.get.bind(client.api);
  return null;
}

function normalizeProductArray(payload) {
  // Supports multiple response shapes safely.
  if (Array.isArray(payload)) return payload;
  if (Array.isArray(payload?.data)) return payload.data;
  if (Array.isArray(payload?.items)) return payload.items;
  if (Array.isArray(payload?.products)) return payload.products;
  return [];
}

function resolveProductId(product, index) {
  return (
    product?.id ??
    product?.product_id ??
    product?.productId ??
    `${safeText(product?.name, "product")}-${index}`
  );
}

function resolveProductName(product) {
  return safeText(product?.name ?? product?.product_name ?? product?.title, "Unnamed product");
}

function resolveProductLocation(product) {
  return safeText(
    product?.location ??
      product?.farmer_location ??
      product?.origin ??
      product?.region,
    "—"
  );
}

// ----------------------------------------------------------------------------
// Component
// ----------------------------------------------------------------------------
export default function ProductAutocomplete({
  value,
  onChange,
  placeholder = "Search product...",
  minChars = 2,
}) {
  const { helpers, loading: settingsLoading } = usePublicSystemSettings();

  const autocompleteEnabled = helpers?.autocompleteEnabled ?? true;
  const suggestionLimit = Math.max(1, Number(helpers?.suggestionLimit ?? 8) || 8);

  const [q, setQ] = useState(value ? safeText(value?.name ?? value, "") : "");
  const [items, setItems] = useState([]);
  const [open, setOpen] = useState(false);
  const [searching, setSearching] = useState(false);

  const ref = useRef(null);
  const lastRequestIdRef = useRef(0);

  // --------------------------------------------------------------------------
  // Keep internal input text in sync with incoming value changes.
  // --------------------------------------------------------------------------
  useEffect(() => {
    const nextText = value ? safeText(value?.name ?? value, "") : "";
    setQ(nextText);
  }, [value]);

  // --------------------------------------------------------------------------
  // Close dropdown on outside click.
  // --------------------------------------------------------------------------
  useEffect(() => {
    const onClick = (e) => {
      if (ref.current && !ref.current.contains(e.target)) {
        setOpen(false);
      }
    };

    document.addEventListener("click", onClick);
    return () => document.removeEventListener("click", onClick);
  }, []);

  // --------------------------------------------------------------------------
  // Main API search.
  // Respects admin-controlled autocomplete policy.
  // --------------------------------------------------------------------------
  const searchAPI = async (term) => {
    const trimmed = safeText(term, "");

    if (!autocompleteEnabled) {
      setItems([]);
      setSearching(false);
      setOpen(false);
      return;
    }

    if (!trimmed || trimmed.length < minChars) {
      setItems([]);
      setSearching(false);
      setOpen(false);
      return;
    }

    const get = resolveApiGetter(apiClient);
    if (!get) {
      setItems([]);
      setSearching(false);
      setOpen(false);
      return;
    }

    const requestId = ++lastRequestIdRef.current;
    setSearching(true);

    try {
      // ----------------------------------------------------------------------
      // Keep request broad but lightweight. We trim locally to the policy limit.
      // ----------------------------------------------------------------------
      const res = await get("/products", {
        params: { q: trimmed, limit: suggestionLimit },
      });

      if (requestId !== lastRequestIdRef.current) return;

      const normalized = normalizeProductArray(res?.data).slice(0, suggestionLimit);
      setItems(normalized);
      setOpen(true);
    } catch (err) {
      if (requestId !== lastRequestIdRef.current) return;
      setItems([]);
      setOpen(true);
    } finally {
      if (requestId === lastRequestIdRef.current) {
        setSearching(false);
      }
    }
  };

  // --------------------------------------------------------------------------
  // Debounce search calls to reduce API chatter while typing.
  // --------------------------------------------------------------------------
  const debouncedSearch = useMemo(
    () =>
      debounce((term) => {
        searchAPI(term);
      }, 300),
    [autocompleteEnabled, minChars, suggestionLimit]
  );

  useEffect(() => {
    debouncedSearch(q);

    return () => {
      debouncedSearch.cancel();
    };
  }, [q, debouncedSearch]);

  const disabledMessage = !autocompleteEnabled
    ? "Autocomplete is turned off in system settings."
    : "";

  const showDropdown =
    open &&
    autocompleteEnabled &&
    q.length >= minChars &&
    !settingsLoading;

  return (
    <div className="relative" ref={ref}>
      <div
        className={[
          "flex items-center rounded-md border p-2 transition",
          autocompleteEnabled
            ? "border-white/10 bg-white/10"
            : "border-white/10 bg-white/5 opacity-80",
        ].join(" ")}
      >
        <Search className="mr-2 h-4 w-4 shrink-0 text-white/60" />

        <input
          value={q}
          onChange={(e) => {
            const next = e.target.value;
            setQ(next);

            // ----------------------------------------------------------------
            // Fallback behavior:
            // Even when autocomplete is disabled, parent forms can still use
            // the typed string as plain input.
            // ----------------------------------------------------------------
            if (!autocompleteEnabled && typeof onChange === "function") {
              onChange(next);
            }
          }}
          onFocus={() => {
            if (autocompleteEnabled && q.length >= minChars) {
              setOpen(true);
            }
          }}
          placeholder={placeholder}
          className="w-full bg-transparent text-white outline-none placeholder:text-white/45"
        />
      </div>

      {!settingsLoading && !autocompleteEnabled && (
        <div className="mt-1 rounded-md border border-white/10 bg-white/6 p-2 text-xs text-white/60">
          {disabledMessage}
        </div>
      )}

      {showDropdown && searching && (
        <div className="absolute z-50 mt-1 w-full rounded-md border border-white/10 bg-white/6 p-2 text-white/70 backdrop-blur-md">
          Searching products…
        </div>
      )}

      {showDropdown && !searching && items.length > 0 && (
        <ul className="absolute z-50 mt-1 max-h-56 w-full overflow-auto rounded-md border border-white/10 bg-white/6 backdrop-blur-md">
          {items.map((p, index) => (
            <li
              key={resolveProductId(p, index)}
              className="cursor-pointer px-3 py-2 text-white/90 hover:bg-white/10"
              onClick={() => {
                if (typeof onChange === "function") {
                  onChange(p);
                }
                setQ(resolveProductName(p));
                setOpen(false);
              }}
            >
              <div className="font-medium">{resolveProductName(p)}</div>
              <div className="text-xs text-white/60">{resolveProductLocation(p)}</div>
            </li>
          ))}
        </ul>
      )}

      {showDropdown && !searching && items.length === 0 && (
        <div className="absolute z-50 mt-1 w-full rounded-md border border-white/10 bg-white/6 p-2 text-white/60 backdrop-blur-md">
          No products found
        </div>
      )}
    </div>
  );
}