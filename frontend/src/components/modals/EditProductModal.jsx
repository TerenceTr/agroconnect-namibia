// ============================================================================
// frontend/src/components/modals/EditProductModal.jsx — Edit Product (Farmer)
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Modal dialog that allows a farmer to update product fields safely.
//
// WHAT THIS UPDATE ADDS:
//   ✅ Keeps Namibia top-level category dropdown
//   ✅ Keeps optional image update flow
//   ✅ Aligns selling units with the real DB/product model
//   ✅ Removes invalid legacy selling units (box / crate / bag) from edit UI
//   ✅ Adds pack_size + pack_unit support when unit = "pack"
//   ✅ Makes quantity meaning clearer for each unit type
//   ✅ Normalizes legacy unit aliases in the editor BEFORE save:
//        box/crate/bag/tray/packet -> pack
//        piece/items/unit -> each
//        litre/liter -> l
//
// CANONICAL UNIT RULES:
//   • each -> sold per single item
//   • kg/g/l/ml -> sold per selected measurement unit
//   • pack -> sold per pack
//       - price = price per pack
//       - quantity = number of packs in stock
//       - pack_size + pack_unit describe what one pack contains
//
// EXAMPLE:
//   Cream cheese sold per tub:
//     unit = each
//     price = 35
//     quantity = 34
//
//   Droëwors sold per 250 g pack:
//     unit = pack
//     price = 58
//     quantity = 70
//     pack_size = 250
//     pack_unit = g
//
// API NOTES:
//   - Uses PATCH first, falls back to PUT
//   - Sends numeric fields as strings to support Decimal/Numeric columns
// ============================================================================

import React, { useEffect, useMemo, useState } from "react";
import { X, Save, Image as ImageIcon, Link2 } from "lucide-react";

import api from "../../api";
import Card, { CardHeader, CardTitle, CardContent } from "../ui/Card";
import { PLACEHOLDER_IMG, resolveProductImageCandidates } from "../../utils/productImage";

// ----------------------------------------------------------------------------
// Namibia top-level categories
// ----------------------------------------------------------------------------
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

// ----------------------------------------------------------------------------
// Canonical selling units
// IMPORTANT:
//   These should match the backend/database-supported product units.
// ----------------------------------------------------------------------------
const UNIT_OPTIONS = [
  { value: "each", label: "each" },
  { value: "kg", label: "kg" },
  { value: "g", label: "g" },
  { value: "l", label: "L" },
  { value: "ml", label: "ml" },
  { value: "pack", label: "pack" },
];

// When selling by pack, this describes what one pack contains.
const PACK_UNIT_OPTIONS = [
  { value: "each", label: "each" },
  { value: "kg", label: "kg" },
  { value: "g", label: "g" },
  { value: "l", label: "L" },
  { value: "ml", label: "ml" },
];

const MAX_IMAGE_MB = 5;

// ----------------------------------------------------------------------------
// Backend-aligned legacy aliases
// These are normalized in the UI so farmers see the canonical unit immediately
// instead of only seeing it change after save.
// ----------------------------------------------------------------------------
const UNIT_ALIASES = {
  piece: "each",
  pieces: "each",
  item: "each",
  items: "each",
  unit: "each",
  litre: "l",
  litres: "l",
  liter: "l",
  liters: "l",
  box: "pack",
  crate: "pack",
  bag: "pack",
  tray: "pack",
  packet: "pack",
  packets: "pack",
};

// ----------------------------------------------------------------------------
// Small helpers
// ----------------------------------------------------------------------------
function safeStr(v, fallback = "") {
  if (typeof v === "string") return v;
  if (v == null) return fallback;
  return String(v);
}

function toNumber(v, fallback = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

function getProductId(p) {
  return p?.id || p?.product_id || p?.productId || null;
}

function getName(p) {
  return p?.product_name || p?.name || "Product";
}

function getCategory(p) {
  return p?.category || p?.product_category || p?.productCategory || p?.type || p?.group || "";
}

function isTopCategory(cat) {
  const s = safeStr(cat).trim().toLowerCase();
  return NAMIBIA_TOP_CATEGORIES.some((c) => c.toLowerCase() === s);
}

function normalizeCategory(rawCategory, productName = "") {
  const raw = safeStr(rawCategory).trim();
  if (!raw) return "Fresh Produce";

  if (isTopCategory(raw)) {
    const match = NAMIBIA_TOP_CATEGORIES.find((c) => c.toLowerCase() === raw.toLowerCase());
    return match || raw;
  }

  const s = `${raw} ${safeStr(productName)}`.toLowerCase();

  if (/(wild|!nara|mopane|mushroom|veld)/.test(s)) return "Wild Harvest";
  if (
    /(feed|forage|lucerne|hay|bran|seedling|nursery|fiber|fibre|hide|skin|wool|mohair|supply|supplies)/.test(
      s
    )
  ) {
    return "Farm Supplies";
  }
  if (/(honey|sweetener|syrup|beeswax)/.test(s)) return "Honey & Sweeteners";
  if (/(fish|seafood|hake|tilapia|oyster|prawn|shrimp|crab|smoked fish|dried fish)/.test(s)) {
    return "Fish & Seafood";
  }
  if (/(nut|seed|groundnut|peanut|sunflower|sesame|pumpkin seed|oil|olive)/.test(s)) {
    return "Nuts, Seeds & Oils";
  }
  if (/(staple|grain|cereal|mahangu|maize|corn|sorghum|rice|wheat|legume|pulse|bean|cowpea|lentil)/.test(s)) {
    return "Staples";
  }
  if (/(animal|dairy|milk|omaere|yoghurt|yogurt|cheese|butter|egg|meat|poultry|beef|goat|chicken|lamb|pork|game)/.test(s)) {
    return "Animal Products";
  }
  if (/(value|processed|farm-made|meal|flour|peanut butter|jam|dried fruit|pickle|atchar|sauce|chutney|biltong|droewors)/.test(s)) {
    return "Value-Added & Processed (Farm-made)";
  }

  return "Fresh Produce";
}

// Normalize any incoming unit into the canonical UI/backend value.
function normalizeUnit(value, defaultValue = "each") {
  const raw = safeStr(value).trim().toLowerCase();
  if (!raw) return defaultValue;
  return UNIT_ALIASES[raw] || raw;
}

// Normalize pack-unit input to canonical content units.
function normalizePackUnit(value, defaultValue = "g") {
  const raw = safeStr(value).trim().toLowerCase();
  if (!raw) return defaultValue;
  return UNIT_ALIASES[raw] || raw;
}

function legacyUnitInfo(value) {
  const raw = safeStr(value).trim().toLowerCase();
  if (!raw) return null;

  const normalized = normalizeUnit(raw, "each");
  if (raw === normalized) return null;

  return {
    raw,
    normalized,
  };
}

function legacyPackUnitInfo(value) {
  const raw = safeStr(value).trim().toLowerCase();
  if (!raw) return null;

  const normalized = normalizePackUnit(raw, "g");
  if (raw === normalized) return null;

  return {
    raw,
    normalized,
  };
}

function isPackUnit(unit) {
  return normalizeUnit(unit, "each") === "pack";
}

function quantityLabelForUnit(unit) {
  const u = normalizeUnit(unit, "each");

  if (u === "each") return "Quantity in stock (items)";
  if (u === "kg") return "Quantity in stock (kg)";
  if (u === "g") return "Quantity in stock (g)";
  if (u === "l") return "Quantity in stock (L)";
  if (u === "ml") return "Quantity in stock (ml)";
  if (u === "pack") return "Quantity in stock (number of packs)";
  return "Quantity in stock";
}

function quantityPlaceholderForUnit(unit) {
  const u = normalizeUnit(unit, "each");

  if (u === "each") return "e.g. 34";
  if (u === "kg") return "e.g. 34";
  if (u === "g") return "e.g. 34000";
  if (u === "l") return "e.g. 20";
  if (u === "ml") return "e.g. 20000";
  if (u === "pack") return "e.g. 34";
  return "0";
}

function quantityHelpForUnit(unit) {
  const u = normalizeUnit(unit, "each");

  if (u === "each") {
    return "Use this when you sell one item at a time. Quantity means number of items in stock.";
  }
  if (u === "kg") {
    return "Quantity means total stock available in kilograms.";
  }
  if (u === "g") {
    return "Quantity means total stock available in grams.";
  }
  if (u === "l") {
    return "Quantity means total stock available in litres.";
  }
  if (u === "ml") {
    return "Quantity means total stock available in millilitres.";
  }
  if (u === "pack") {
    return "Quantity means how many packs are in stock. Then enter the size of one pack below.";
  }
  return "";
}

// ----------------------------------------------------------------------------
// Best-effort upload helpers
// ----------------------------------------------------------------------------

/**
 * Preferred image save path:
 * PATCH/PUT /products/:id as multipart/form-data with field "image".
 * This matches current backend behavior and updates product.image_url directly.
 */
async function tryUploadViaProductUpdate({ file, productId }) {
  if (!file || !productId) return null;

  const form = new FormData();
  form.append("image", file);
  form.append("file", file);
  form.append("photo", file);
  form.append("product_id", String(productId));

  const endpoints = [`/products/${productId}`, `/api/products/${productId}`];

  for (const ep of endpoints) {
    try {
      const res = await api.patch(ep, form, {
        headers: { "Content-Type": "multipart/form-data" },
      });
      const d = res?.data;
      const item = d?.item ?? d?.product ?? d;
      const url =
        item?.image_url ||
        item?.imageUrl ||
        d?.image_url ||
        d?.url ||
        d?.file_url ||
        d?.path ||
        d?.location ||
        d?.public_url ||
        (d?.filename ? `/uploads/products/${d.filename}` : null);

      if (typeof url === "string" && url.trim()) return url.trim();
      return "__uploaded__";
    } catch {
      try {
        const res = await api.put(ep, form, {
          headers: { "Content-Type": "multipart/form-data" },
        });
        const d = res?.data;
        const item = d?.item ?? d?.product ?? d;
        const url =
          item?.image_url ||
          item?.imageUrl ||
          d?.image_url ||
          d?.url ||
          d?.file_url ||
          d?.path ||
          d?.location ||
          d?.public_url ||
          (d?.filename ? `/uploads/products/${d.filename}` : null);

        if (typeof url === "string" && url.trim()) return url.trim();
        return "__uploaded__";
      } catch {
        // keep trying next endpoint
      }
    }
  }

  return null;
}

/**
 * Fallback uploader for legacy/non-standard endpoints.
 * Won't block save if endpoint does not exist.
 */
async function tryUploadImageBestEffort({ file, productId }) {
  if (!file) return null;

  const form = new FormData();
  form.append("image", file);
  form.append("file", file);
  form.append("photo", file);
  if (productId) form.append("product_id", String(productId));

  const endpoints = [
    productId ? `/products/${productId}/image` : null,
    productId ? `/products/${productId}/upload-image` : null,
    "/products/upload-image",
    "/uploads",
    "/upload",
    "/uploads/public_images",
  ].filter(Boolean);

  for (const ep of endpoints) {
    try {
      const res = await api.post(ep, form, {
        headers: { "Content-Type": "multipart/form-data" },
      });

      const d = res?.data;
      const url =
        d?.image_url ||
        d?.url ||
        d?.file_url ||
        d?.path ||
        d?.location ||
        d?.public_url ||
        (d?.filename ? `/uploads/public_images/${d.filename}` : null);

      if (typeof url === "string" && url.trim()) return url.trim();
      return "__uploaded__";
    } catch {
      // ignore 404/405/etc
    }
  }

  return null;
}

export default function EditProductModal({ open, onClose, product, onUpdated }) {
  const pid = getProductId(product);

  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [ok, setOk] = useState("");

  const [form, setForm] = useState({
    product_name: "",
    category: "Fresh Produce",
    unit: "each",
    price: "",
    quantity: "",
    pack_size: "",
    pack_unit: "g",
    description: "",
    image_url: "",
  });

  const [imageFile, setImageFile] = useState(null);
  const [imagePreview, setImagePreview] = useState("");

  // Current image (from resolver) for fallback preview
  const currentImageCandidates = useMemo(
    () => resolveProductImageCandidates(product || {}),
    [product]
  );
  const currentImage = currentImageCandidates?.[0] || PLACEHOLDER_IMG;

  // Show a soft info message when a legacy value was normalized immediately in the editor.
  const originalUnitInfo = useMemo(
    () => legacyUnitInfo(product?.unit),
    [product?.unit]
  );

  const originalPackUnitInfo = useMemo(
    () => legacyPackUnitInfo(product?.pack_unit),
    [product?.pack_unit]
  );

  useEffect(() => {
    if (!open) return;

    const name = getName(product);
    const cat = normalizeCategory(getCategory(product), name);

    setForm({
      product_name: safeStr(product?.product_name ?? product?.name ?? ""),
      category: cat,
      unit: normalizeUnit(product?.unit ?? "each", "each"),
      price: safeStr(product?.price ?? ""),
      quantity: safeStr(product?.quantity ?? product?.stock ?? ""),
      pack_size: safeStr(product?.pack_size ?? ""),
      pack_unit: normalizePackUnit(product?.pack_unit ?? "g", "g"),
      description: safeStr(product?.description ?? ""),
      image_url: safeStr(
        product?.image_url ??
          product?.imageUrl ??
          product?.image_src ??
          product?.imageSrc ??
          ""
      ),
    });

    setImageFile(null);
    setImagePreview("");
    setError("");
    setOk("");
  }, [open, product]);

  useEffect(() => {
    if (!imageFile) {
      setImagePreview("");
      return;
    }

    const url = URL.createObjectURL(imageFile);
    setImagePreview(url);

    return () => URL.revokeObjectURL(url);
  }, [imageFile]);

  // ESC close
  useEffect(() => {
    if (!open) return;

    const onKey = (e) => {
      if (e.key === "Escape") onClose?.();
    };

    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  if (!open) return null;

  const save = async (e) => {
    e?.preventDefault?.();
    setError("");
    setOk("");

    const name = safeStr(form.product_name).trim();
    if (!name) {
      setError("Product name is required.");
      return;
    }

    const price = toNumber(form.price, NaN);
    if (!Number.isFinite(price) || price <= 0) {
      setError("Price must be a valid number greater than 0.");
      return;
    }

    const qty = toNumber(form.quantity, NaN);
    if (!Number.isFinite(qty) || qty < 0) {
      setError("Quantity must be a valid non-negative number.");
      return;
    }

    // Normalize again at save time so the payload always matches backend rules.
    const unit = normalizeUnit(form.unit, "each");
    const validUnits = new Set(UNIT_OPTIONS.map((u) => u.value));
    if (!validUnits.has(unit)) {
      setError("Unit is invalid.");
      return;
    }

    // Pack-specific validation:
    // unit='pack' means:
    //   - price = price per pack
    //   - quantity = number of packs in stock
    //   - pack_size + pack_unit describe what one pack contains
    let packSizeValue = null;
    let packUnitValue = "";

    if (unit === "pack") {
      const ps = toNumber(form.pack_size, NaN);
      if (!Number.isFinite(ps) || ps <= 0) {
        setError("Pack size must be a valid number greater than 0 when unit is 'pack'.");
        return;
      }

      const validPackUnits = new Set(PACK_UNIT_OPTIONS.map((u) => u.value));
      packUnitValue = normalizePackUnit(form.pack_unit, "g");

      if (!validPackUnits.has(packUnitValue)) {
        setError("Pack unit must be one of: each, kg, g, l, ml.");
        return;
      }

      packSizeValue = ps;
    }

    const cat = normalizeCategory(form.category, name);

    // Optional image validation
    if (imageFile) {
      const sizeMb = imageFile.size / (1024 * 1024);
      if (sizeMb > MAX_IMAGE_MB) {
        setError(`Image is too large. Max ${MAX_IMAGE_MB}MB.`);
        return;
      }
      if (!String(imageFile.type || "").startsWith("image/")) {
        setError("Please select a valid image file.");
        return;
      }
    }

    setSaving(true);

    try {
      // 1) Update base fields first
      const payload = {
        product_name: name,
        name, // compatibility
        category: cat,
        unit,
        price: String(price),
        quantity: String(qty),
        stock: String(qty), // compatibility
        description: safeStr(form.description).trim() || "",
        image_url: safeStr(form.image_url).trim() || undefined,

        // Clear pack metadata by default when not using pack
        pack_size: unit === "pack" ? String(packSizeValue) : null,
        pack_unit: unit === "pack" ? packUnitValue : null,
      };

      try {
        await api.patch(`/products/${pid}`, payload);
      } catch {
        await api.put(`/products/${pid}`, payload);
      }

      // 2) Optional image update
      //    a) Try multipart directly on /products/:id
      //    b) Fallback to legacy upload endpoints
      //    c) If a URL is returned, patch it back explicitly
      let imageSaved = false;

      if (imageFile && pid) {
        let uploadedUrl = await tryUploadViaProductUpdate({
          file: imageFile,
          productId: pid,
        });

        if (!uploadedUrl) {
          uploadedUrl = await tryUploadImageBestEffort({
            file: imageFile,
            productId: pid,
          });
        }

        if (uploadedUrl) {
          if (uploadedUrl !== "__uploaded__") {
            try {
              const imgPayload = {
                image_url: uploadedUrl,
                imageUrl: uploadedUrl,
              };

              try {
                await api.patch(`/products/${pid}`, imgPayload);
              } catch {
                await api.put(`/products/${pid}`, imgPayload);
              }
            } catch {
              // Keep success true if upload itself worked
            }
          }

          imageSaved = true;
        }
      }

      setOk(
        imageFile
          ? imageSaved
            ? "Saved (image updated)."
            : "Saved (image not updated)."
          : "Saved."
      );

      setTimeout(() => setOk(""), 1600);

      await onUpdated?.();
    } catch (err) {
      console.error("Edit product failed", err);
      setError(
        err?.response?.data?.message ||
          "Couldn’t save changes right now. Please try again."
      );
    } finally {
      setSaving(false);
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4"
      onMouseDown={(e) => {
        // Overlay click closes the modal
        if (e.target === e.currentTarget) onClose?.();
      }}
    >
      <div className="w-full max-w-2xl">
        <Card className="overflow-hidden rounded-3xl">
          <CardHeader className="flex flex-row items-center justify-between gap-3">
            <div className="min-w-0">
              <CardTitle>Edit Product</CardTitle>
              <p className="mt-1 truncate text-xs text-slate-500">
                {safeStr(getName(product))}
              </p>
            </div>

            <button
              type="button"
              onClick={onClose}
              className="inline-flex h-10 w-10 items-center justify-center rounded-2xl border border-slate-200 bg-white hover:bg-slate-50"
              title="Close"
            >
              <X className="h-5 w-5 text-slate-700" />
            </button>
          </CardHeader>

          <CardContent>
            {error ? (
              <div className="mb-3 rounded-xl border border-rose-200 bg-rose-50 p-3 text-sm text-rose-700">
                {error}
              </div>
            ) : null}

            {ok ? (
              <div className="mb-3 rounded-xl border border-emerald-200 bg-emerald-50 p-3 text-sm text-emerald-800">
                {ok}
              </div>
            ) : null}

            {originalUnitInfo || originalPackUnitInfo ? (
              <div className="mb-3 rounded-xl border border-sky-200 bg-sky-50 p-3 text-sm text-sky-800">
                {originalUnitInfo ? (
                  <div>
                    Legacy selling unit <span className="font-bold">"{originalUnitInfo.raw}"</span> is shown here as{" "}
                    <span className="font-bold">"{originalUnitInfo.normalized}"</span>.
                  </div>
                ) : null}
                {originalPackUnitInfo ? (
                  <div className={originalUnitInfo ? "mt-1" : ""}>
                    Legacy pack content unit <span className="font-bold">"{originalPackUnitInfo.raw}"</span> is shown here as{" "}
                    <span className="font-bold">"{originalPackUnitInfo.normalized}"</span>.
                  </div>
                ) : null}
              </div>
            ) : null}

            <form onSubmit={save} className="space-y-4">
              <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
                <div>
                  <label className="text-xs font-extrabold text-slate-700">
                    Product name
                  </label>
                  <input
                    className="mt-1 h-11 w-full rounded-2xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-900 outline-none"
                    value={form.product_name}
                    onChange={(e) =>
                      setForm((s) => ({ ...s, product_name: e.target.value }))
                    }
                    placeholder="Product name"
                  />
                </div>

                <div>
                  <label className="text-xs font-extrabold text-slate-700">
                    Category
                  </label>
                  <select
                    className="mt-1 h-11 w-full rounded-2xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-900 outline-none"
                    value={form.category}
                    onChange={(e) =>
                      setForm((s) => ({ ...s, category: e.target.value }))
                    }
                  >
                    {NAMIBIA_TOP_CATEGORIES.map((c) => (
                      <option key={c} value={c}>
                        {c}
                      </option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="text-xs font-extrabold text-slate-700">
                    Selling unit
                  </label>
                  <select
                    className="mt-1 h-11 w-full rounded-2xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-900 outline-none"
                    value={form.unit}
                    onChange={(e) => {
                      const nextUnit = normalizeUnit(e.target.value, "each");
                      setForm((s) => ({
                        ...s,
                        unit: nextUnit,
                        ...(nextUnit === "pack"
                          ? {}
                          : {
                              pack_size: "",
                              pack_unit: "g",
                            }),
                      }));
                    }}
                  >
                    {UNIT_OPTIONS.map((u) => (
                      <option key={u.value} value={u.value}>
                        {u.label}
                      </option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="text-xs font-extrabold text-slate-700">
                    Price (N$)
                  </label>
                  <input
                    className="mt-1 h-11 w-full rounded-2xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-900 outline-none"
                    inputMode="decimal"
                    value={form.price}
                    onChange={(e) =>
                      setForm((s) => ({ ...s, price: e.target.value }))
                    }
                    placeholder="0.00"
                  />
                </div>

                <div className="md:col-span-2">
                  <label className="text-xs font-extrabold text-slate-700">
                    {quantityLabelForUnit(form.unit)}
                  </label>
                  <input
                    className="mt-1 h-11 w-full rounded-2xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-900 outline-none"
                    inputMode="decimal"
                    value={form.quantity}
                    onChange={(e) =>
                      setForm((s) => ({ ...s, quantity: e.target.value }))
                    }
                    placeholder={quantityPlaceholderForUnit(form.unit)}
                  />
                  <div className="mt-1 text-[11px] text-slate-500">
                    {quantityHelpForUnit(form.unit)}
                  </div>
                </div>

                {isPackUnit(form.unit) ? (
                  <>
                    <div>
                      <label className="text-xs font-extrabold text-slate-700">
                        Pack size
                      </label>
                      <input
                        className="mt-1 h-11 w-full rounded-2xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-900 outline-none"
                        inputMode="decimal"
                        value={form.pack_size}
                        onChange={(e) =>
                          setForm((s) => ({ ...s, pack_size: e.target.value }))
                        }
                        placeholder="e.g. 250"
                      />
                    </div>

                    <div>
                      <label className="text-xs font-extrabold text-slate-700">
                        Pack content unit
                      </label>
                      <select
                        className="mt-1 h-11 w-full rounded-2xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-900 outline-none"
                        value={form.pack_unit}
                        onChange={(e) =>
                          setForm((s) => ({
                            ...s,
                            pack_unit: normalizePackUnit(e.target.value, "g"),
                          }))
                        }
                      >
                        {PACK_UNIT_OPTIONS.map((u) => (
                          <option key={u.value} value={u.value}>
                            {u.label}
                          </option>
                        ))}
                      </select>
                    </div>

                    <div className="md:col-span-2 -mt-1 text-[11px] text-sky-700">
                      Example: price = N$35, quantity = 34, unit = pack, pack size = 250,
                      pack content unit = g means “N$35 per pack, 34 packs in stock, each
                      pack contains 250 g”.
                    </div>
                  </>
                ) : null}
              </div>

              <div>
                <label className="text-xs font-extrabold text-slate-700">
                  Description
                </label>
                <textarea
                  className="mt-1 min-h-[84px] w-full rounded-2xl border border-slate-200 bg-white px-3 py-2 text-sm text-slate-900 outline-none"
                  value={form.description}
                  onChange={(e) =>
                    setForm((s) => ({ ...s, description: e.target.value }))
                  }
                  placeholder="Description (optional)"
                />
              </div>

              {/* Image controls */}
              <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
                <div className="rounded-2xl border border-slate-200 bg-white p-3">
                  <div className="mb-2 flex items-center gap-2 text-xs font-extrabold text-slate-800">
                    <ImageIcon className="h-4 w-4 text-slate-500" />
                    Replace image (optional)
                  </div>

                  <input
                    type="file"
                    accept="image/*"
                    onChange={(e) => setImageFile(e.target.files?.[0] || null)}
                    className="block w-full text-sm text-slate-700"
                  />

                  <div className="mt-3 overflow-hidden rounded-xl border border-slate-200 bg-slate-50">
                    <img
                      src={imagePreview || form.image_url || currentImage}
                      alt="Product"
                      className="h-40 w-full object-cover"
                    />
                  </div>

                  <div className="mt-2 text-xs text-slate-500">
                    Save always proceeds. If upload endpoints are unavailable, other
                    product fields still save.
                  </div>
                </div>

                <div className="rounded-2xl border border-slate-200 bg-white p-3">
                  <div className="mb-2 flex items-center gap-2 text-xs font-extrabold text-slate-800">
                    <Link2 className="h-4 w-4 text-slate-500" />
                    Image URL (optional)
                  </div>

                  <input
                    className="h-11 w-full rounded-2xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-900 outline-none"
                    value={form.image_url}
                    onChange={(e) =>
                      setForm((s) => ({ ...s, image_url: e.target.value }))
                    }
                    placeholder="https://... or /Assets/product_images/example.jpg"
                  />

                  <div className="mt-2 text-xs text-slate-500">
                    Use a URL/path if uploads aren’t enabled on the backend.
                  </div>
                </div>
              </div>

              <div className="flex items-center justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={onClose}
                  className="h-11 rounded-2xl border border-slate-200 bg-white px-4 text-sm font-extrabold text-slate-800 hover:bg-slate-50"
                >
                  Cancel
                </button>

                <button
                  type="submit"
                  disabled={saving}
                  className="inline-flex h-11 items-center gap-2 rounded-2xl bg-emerald-600 px-4 text-sm font-extrabold text-white hover:bg-emerald-700 disabled:opacity-60"
                >
                  <Save className="h-4 w-4" />
                  {saving ? "Saving…" : "Save changes"}
                </button>
              </div>
            </form>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}