// ============================================================================
// frontend/src/components/customer/marketplace/cart/CartItemRow.jsx
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Single cart line item row with qty controls + remove.
//   Safe against different item shapes.
// ============================================================================

import React, { useMemo } from "react";
import { Minus, Plus, Trash2 } from "lucide-react";
import { resolveProductImageCandidates } from "../../../../utils/productImage";
import { clampQty, money } from "./cartUtils";

export default function CartItemRow({ item, placing, onUpdateQty, onRemoveItem }) {
  const product = item?.product || item;
  const productId = item?.productId ?? item?.product_id ?? product?.id ?? product?.product_id ?? item?.id;

  const name = product?.name ?? product?.product_name ?? item?.product_name ?? "Item";
  const farmer = product?.farmer_name ?? product?.farmerName ?? item?.farmer_name ?? "";
  const unit = product?.unit ?? item?.unit ?? "each";

  const price = Number(product?.price ?? item?.price ?? item?.unit_price ?? 0);
  const qty = Number(item?.qty ?? item?.quantity ?? 1);

  const candidates = useMemo(() => resolveProductImageCandidates(product), [product]);
  const src = candidates[0];

  const lineTotal = price * qty;

  return (
    <div className="rounded-2xl border border-slate-200 bg-white p-3 flex gap-3">
      <div className="h-14 w-14 rounded-xl overflow-hidden bg-slate-50 border border-slate-200 shrink-0">
        <img src={src} alt={name} className="h-full w-full object-cover" />
      </div>

      <div className="min-w-0 flex-1">
        <div className="flex items-start justify-between gap-2">
          <div className="min-w-0">
            <div className="text-sm font-extrabold text-slate-900 truncate" title={name}>
              {name}
            </div>
            <div className="text-xs text-slate-500 mt-0.5">
              {farmer ? <span className="font-semibold text-slate-700">{farmer}</span> : "Farmer —"}{" "}
              <span className="text-slate-400">•</span> Unit:{" "}
              <span className="font-semibold">{`N$ ${money(price)} / ${unit}`}</span>
            </div>
          </div>

          <button
            type="button"
            className="h-9 w-9 rounded-xl border border-slate-200 bg-white hover:bg-slate-50 inline-flex items-center justify-center disabled:opacity-60"
            onClick={() => onRemoveItem?.(productId)}
            disabled={placing}
            aria-label="Remove item"
          >
            <Trash2 className="h-4 w-4 text-rose-600" />
          </button>
        </div>

        <div className="mt-2 flex items-center justify-between">
          <div className="inline-flex items-center rounded-2xl border border-slate-200 bg-white overflow-hidden">
            <button
              type="button"
              className="h-9 w-10 inline-flex items-center justify-center hover:bg-slate-50 disabled:opacity-60"
              disabled={placing}
              onClick={() => onUpdateQty?.(productId, clampQty(qty - 1))}
              aria-label="Decrease quantity"
            >
              <Minus className="h-4 w-4 text-slate-700" />
            </button>

            <div className="h-9 px-3 min-w-[56px] inline-flex items-center justify-center text-sm font-extrabold text-slate-900">
              {Number.isFinite(qty) ? qty : 1}
            </div>

            <button
              type="button"
              className="h-9 w-10 inline-flex items-center justify-center hover:bg-slate-50 disabled:opacity-60"
              disabled={placing}
              onClick={() => onUpdateQty?.(productId, clampQty(qty + 1))}
              aria-label="Increase quantity"
            >
              <Plus className="h-4 w-4 text-slate-700" />
            </button>
          </div>

          <div className="text-sm font-extrabold text-slate-900">N$ {money(lineTotal)}</div>
        </div>
      </div>
    </div>
  );
}
