// ============================================================================
// frontend/src/components/customer/marketplace/OrdersDrawer.jsx
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Customer orders slide-over drawer (premium, neutral).
//
// RESPONSIBILITIES:
//   • Fetch & display recent orders via real API: customerApi.fetchOrders
//   • Show status + total + created date (null-safe)
//   • Accessibility: focus trap, ESC close, overlay click close, ARIA
// ============================================================================

import React, { useEffect, useRef, useState } from "react";
import { X, ClipboardList, RefreshCw } from "lucide-react";
import * as customerApi from "../../../services/customerApi";

function useFocusTrap(open, onClose) {
  const rootRef = useRef(null);
  const lastActiveRef = useRef(null);

  useEffect(() => {
    if (!open) return;

    lastActiveRef.current = document.activeElement;

    const root = rootRef.current;
    if (!root) return;

    const focusables = root.querySelectorAll(
      'button,[href],input,select,textarea,[tabindex]:not([tabindex="-1"])'
    );
    const first = focusables[0];
    if (first) first.focus();

    function onKeyDown(e) {
      if (e.key === "Escape") {
        e.preventDefault();
        onClose?.();
        return;
      }
      if (e.key !== "Tab") return;

      const list = Array.from(focusables).filter((el) => !el.hasAttribute("disabled"));
      if (!list.length) return;

      const firstEl = list[0];
      const lastEl = list[list.length - 1];

      if (e.shiftKey && document.activeElement === firstEl) {
        e.preventDefault();
        lastEl.focus();
      } else if (!e.shiftKey && document.activeElement === lastEl) {
        e.preventDefault();
        firstEl.focus();
      }
    }

    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      const last = lastActiveRef.current;
      if (last && last.focus) last.focus();
    };
  }, [open, onClose]);

  return rootRef;
}

function pickList(res) {
  if (!res) return [];
  if (Array.isArray(res)) return res;
  if (Array.isArray(res?.data)) return res.data;
  if (Array.isArray(res?.orders)) return res.orders;
  return [];
}

function money(n) {
  const x = Number(n || 0);
  return (Number.isFinite(x) ? x : 0).toFixed(2);
}

function fmtDate(d) {
  if (!d) return "—";
  const dt = new Date(d);
  if (Number.isNaN(dt.getTime())) return "—";
  return dt.toLocaleString();
}

export default function OrdersDrawer({ open, onClose, customerId }) {
  const rootRef = useFocusTrap(open, onClose);
  const [loading, setLoading] = useState(false);
  const [orders, setOrders] = useState([]);
  const [err, setErr] = useState(null);

  async function load() {
    if (!customerId) return;
    setLoading(true);
    setErr(null);
    try {
      const res = await customerApi.fetchOrders(customerId);
      setOrders(pickList(res));
    } catch (e) {
      setOrders([]);
      setErr(e?.response?.data?.message || e?.response?.data?.error || e?.message || "Failed to load orders");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    if (open) load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, customerId]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-[70]">
      <button type="button" className="absolute inset-0 bg-black/40" aria-label="Close orders" onClick={onClose} />

      <div className="absolute right-0 top-0 bottom-0 w-full max-w-md bg-white border-l border-[#E6E8EF] shadow-2xl">
        <div ref={rootRef} className="h-full flex flex-col" role="dialog" aria-modal="true" aria-label="Orders drawer">
          <div className="px-5 py-4 border-b border-[#E6E8EF] flex items-center justify-between">
            <div>
              <div className="text-sm font-extrabold text-[#111827] inline-flex items-center gap-2">
                <ClipboardList className="h-4 w-4 text-[#1F7A4D]" />
                Orders
              </div>
              <div className="text-xs font-semibold text-[#6B7280]">Your recent purchases</div>
            </div>

            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={load}
                className="h-10 w-10 rounded-2xl border border-[#E6E8EF] bg-white hover:bg-[#F7F8FA] inline-flex items-center justify-center"
                aria-label="Refresh orders"
              >
                <RefreshCw className="h-4 w-4 text-slate-700" />
              </button>

              <button
                type="button"
                onClick={onClose}
                className="h-10 w-10 rounded-2xl border border-[#E6E8EF] bg-white hover:bg-[#F7F8FA] inline-flex items-center justify-center"
                aria-label="Close orders"
              >
                <X className="h-4 w-4 text-slate-700" />
              </button>
            </div>
          </div>

          <div className="flex-1 overflow-auto p-5">
            {!customerId ? (
              <div className="rounded-2xl border border-[#E6E8EF] bg-[#F7F8FA] p-8 text-center">
                <div className="text-sm font-extrabold text-[#111827]">Login required</div>
                <div className="text-xs text-[#6B7280] mt-1">Please login to view your orders.</div>
              </div>
            ) : loading ? (
              <div className="space-y-3">
                {Array.from({ length: 6 }).map((_, i) => (
                  <div key={i} className="h-20 rounded-2xl border border-[#E6E8EF] bg-[#F7F8FA] animate-pulse" />
                ))}
              </div>
            ) : err ? (
              <div className="rounded-2xl border border-[#E6E8EF] bg-[#F7F8FA] p-6 text-sm font-semibold text-rose-700">
                {err}
              </div>
            ) : orders.length === 0 ? (
              <div className="rounded-2xl border border-[#E6E8EF] bg-[#F7F8FA] p-8 text-center">
                <div className="text-sm font-extrabold text-[#111827]">No orders yet</div>
                <div className="text-xs text-[#6B7280] mt-1">Checkout from your cart to create an order.</div>
              </div>
            ) : (
              <div className="space-y-3">
                {orders.slice(0, 20).map((o) => (
                  <div key={String(o?.id || o?.order_id || Math.random())} className="rounded-2xl border border-[#E6E8EF] bg-white p-4">
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <div className="text-sm font-extrabold text-[#111827]">
                          Order #{o?.id || o?.order_id || "—"}
                        </div>
                        <div className="text-xs text-[#6B7280] mt-1">
                          {fmtDate(o?.created_at || o?.createdAt || o?.date)}
                        </div>
                      </div>

                      <span className="px-3 py-2 rounded-2xl border border-[#E6E8EF] bg-[#F7F8FA] text-xs font-extrabold text-slate-700">
                        {o?.status || "pending"}
                      </span>
                    </div>

                    <div className="mt-3 text-xs text-[#6B7280]">
                      Total: <span className="font-extrabold text-[#111827]">N$ {money(o?.total || o?.grand_total || o?.amount)}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="border-t border-[#E6E8EF] p-5 bg-[#F7F8FA] text-[11px] text-[#6B7280]">
            Tip: Press <span className="font-extrabold text-[#111827]">ESC</span> to close.
          </div>
        </div>
      </div>
    </div>
  );
}
