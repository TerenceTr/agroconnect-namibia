// ============================================================================
// frontend/src/components/customer/marketplace/CartSummaryPanel.jsx
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Right-column sticky "Cart Summary" panel + premium secondary actions.
//
// RESPONSIBILITIES:
//   • Show item count badge + subtotal
//   • Primary CTA: Open Cart drawer
//   • Secondary CTA: View Orders drawer
//   • Neutral styling; green as accent only
// ============================================================================

import React from "react";
import { ShoppingCart, ClipboardList } from "lucide-react";
import Card, { CardHeader, CardTitle, CardContent } from "../../ui/Card";

export default function CartSummaryPanel({
  itemCount,
  subtotal,
  onOpenCart,
  onOpenOrders,
}) {
  return (
    <Card className="rounded-2xl border border-[#E6E8EF] bg-white shadow-sm">
      <CardHeader>
        <CardTitle>
          <div className="flex items-center justify-between">
            <div className="text-sm font-extrabold text-[#111827]">Cart Summary</div>
            <span className="px-2 py-1 rounded-2xl border border-[#E6E8EF] bg-[#F7F8FA] text-xs font-semibold text-slate-700">
              {itemCount} item(s)
            </span>
          </div>
        </CardTitle>
      </CardHeader>

      <CardContent className="space-y-3">
        <div className="rounded-2xl border border-[#E6E8EF] bg-[#F7F8FA] p-4">
          <div className="text-xs font-semibold text-[#6B7280]">Subtotal</div>
          <div className="text-2xl font-extrabold text-[#111827] mt-1">
            N$ {Number(subtotal || 0).toFixed(2)}
          </div>
          <div className="text-xs text-[#6B7280] mt-2">
            Delivery + VAT are computed at checkout.
          </div>
        </div>

        <button
          type="button"
          onClick={onOpenCart}
          className="h-11 w-full rounded-2xl bg-[#1F7A4D] hover:brightness-95 text-white text-sm font-extrabold inline-flex items-center justify-center gap-2"
        >
          <ShoppingCart className="h-4 w-4" />
          Open Cart
        </button>

        <button
          type="button"
          onClick={onOpenOrders}
          className="h-11 w-full rounded-2xl border border-[#E6E8EF] bg-white hover:bg-[#F7F8FA] text-sm font-extrabold inline-flex items-center justify-center gap-2"
        >
          <ClipboardList className="h-4 w-4 text-slate-700" />
          View Orders
        </button>

        <div className="text-xs text-[#6B7280]">
          Checkout uses the real API. Your order appears in Orders after success.
        </div>
      </CardContent>
    </Card>
  );
}
