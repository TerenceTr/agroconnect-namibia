// ============================================================================
// frontend/src/pages/dashboards/admin/AdminOrderDetailPage.jsx
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Admin read-only order detail view.
//
// THIS UPDATE:
//   ✅ Uses the dedicated admin detail endpoint first: /admin/orders/<id>
//   ✅ Falls back to /orders/<id> only if needed for compatibility
//   ✅ Supports more backend payload shapes (ok/data, success/data, direct order)
//   ✅ Normalizes customer + items defensively
//   ✅ Handles missing history by falling back to /dashboard/admin
//   ✅ Shows cleaner financial, delivery, payment, and item details
//   ✅ Adds optional proof link when a payment proof URL exists
// ============================================================================

import React, { useEffect, useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import {
  ArrowLeft,
  RefreshCw,
  ShoppingBasket,
  UserRound,
  Truck,
  CreditCard,
  Package,
  ExternalLink,
} from "lucide-react";

import api from "../../../api";
import AdminLayout from "../../../components/AdminLayout";
import Card from "../../../components/ui/Card";
import EmptyState from "../../../components/ui/EmptyState";

// ----------------------------------------------------------------------------
// Safe helpers
// ----------------------------------------------------------------------------
function safeObj(v) {
  return v && typeof v === "object" ? v : {};
}

function safeArray(v) {
  return Array.isArray(v) ? v : [];
}

function safeStr(v, fallback = "") {
  if (typeof v === "string") return v;
  if (v == null) return fallback;
  return String(v);
}

function safeNumber(v, fallback = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

function firstDefined(...values) {
  for (const v of values) {
    if (v !== undefined && v !== null && v !== "") return v;
  }
  return undefined;
}

function fmtDateTime(v) {
  try {
    if (!v) return "—";
    const d = new Date(v);
    if (Number.isNaN(d.getTime())) return "—";
    return d.toLocaleString();
  } catch {
    return "—";
  }
}

function fmtNAD(v) {
  const n = safeNumber(v, 0);
  try {
    return new Intl.NumberFormat(undefined, {
      style: "currency",
      currency: "NAD",
      maximumFractionDigits: 2,
    }).format(n);
  } catch {
    return `N$ ${n.toFixed(2)}`;
  }
}

function shortId(id) {
  const s = safeStr(id, "");
  if (!s) return "—";
  return s.length <= 12 ? s : `${s.slice(0, 8)}…${s.slice(-4)}`;
}

function titleCaseWords(v) {
  return safeStr(v)
    .replace(/[_-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/\b\w/g, (m) => m.toUpperCase());
}

function normalizeOrderPayload(raw) {
  const d = safeObj(raw);

  if (d.ok === true && d.data && typeof d.data === "object") {
    const order = safeObj(d.data);

    return {
      order,
      customer: {
        full_name: safeStr(
          firstDefined(order.buyer_name, order.customer_name, order.customer_full_name, "Customer")
        ),
        email: safeStr(firstDefined(order.buyer_email, order.customer_email, "—")),
        phone: safeStr(firstDefined(order.buyer_phone, order.customer_phone, "—")),
        location: safeStr(firstDefined(order.buyer_location, order.customer_location, "—")),
        address: safeStr(
          firstDefined(
            order.buyer_address,
            order.customer_address,
            order.delivery_address,
            "—"
          )
        ),
      },
      items: safeArray(order.items),
    };
  }

  if (d.success === true) {
    const rootData = safeObj(d.data);
    const order = safeObj(d.order || rootData.order || rootData);
    const customer = safeObj(d.customer || rootData.customer || {});
    const items = safeArray(d.items || rootData.items || order.items);

    return {
      order,
      customer: {
        full_name: safeStr(
          firstDefined(
            customer.full_name,
            customer.name,
            order.buyer_name,
            order.customer_name,
            "Customer"
          )
        ),
        email: safeStr(firstDefined(customer.email, order.buyer_email, order.customer_email, "—")),
        phone: safeStr(firstDefined(customer.phone, order.buyer_phone, order.customer_phone, "—")),
        location: safeStr(
          firstDefined(customer.location, order.buyer_location, order.customer_location, "—")
        ),
        address: safeStr(
          firstDefined(
            customer.address,
            order.buyer_address,
            order.customer_address,
            order.delivery_address,
            "—"
          )
        ),
      },
      items,
    };
  }

  if (d.order_id || d.id || d.items || d.customer_name || d.buyer_name) {
    const order = d;
    return {
      order,
      customer: {
        full_name: safeStr(
          firstDefined(order.buyer_name, order.customer_name, "Customer")
        ),
        email: safeStr(firstDefined(order.buyer_email, order.customer_email, "—")),
        phone: safeStr(firstDefined(order.buyer_phone, order.customer_phone, "—")),
        location: safeStr(firstDefined(order.buyer_location, order.customer_location, "—")),
        address: safeStr(
          firstDefined(order.buyer_address, order.customer_address, order.delivery_address, "—")
        ),
      },
      items: safeArray(order.items),
    };
  }

  return null;
}

function StatusPill({ tone = "neutral", children }) {
  const cls =
    tone === "success"
      ? "border-emerald-200 bg-emerald-50 text-emerald-700"
      : tone === "warn"
      ? "border-amber-200 bg-amber-50 text-amber-800"
      : tone === "danger"
      ? "border-rose-200 bg-rose-50 text-rose-700"
      : "border-slate-200 bg-slate-50 text-slate-700";

  return (
    <span
      className={[
        "inline-flex items-center rounded-full border px-3 py-1.5",
        "text-xs font-bold whitespace-nowrap",
        cls,
      ].join(" ")}
    >
      {children}
    </span>
  );
}

function SummaryStat({ label, value, sub }) {
  return (
    <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
      <div className="text-[11px] font-bold uppercase tracking-wide text-slate-500">
        {label}
      </div>
      <div className="mt-1 text-xl font-extrabold text-slate-900">{value}</div>
      {sub ? <div className="mt-1 text-xs font-semibold text-slate-500">{sub}</div> : null}
    </div>
  );
}

function KV({ label, value }) {
  return (
    <div>
      <div className="text-[11px] font-bold uppercase tracking-wide text-slate-500">
        {label}
      </div>
      <div className="mt-1 text-sm font-semibold text-slate-900 break-words">
        {value || "—"}
      </div>
    </div>
  );
}

export default function AdminOrderDetailPage() {
  const navigate = useNavigate();
  const { orderId } = useParams();

  const [loading, setLoading] = useState(true);
  const [detail, setDetail] = useState(null);
  const [err, setErr] = useState("");

  const fetchDetail = async () => {
    if (!orderId) return;

    setLoading(true);
    setErr("");

    try {
      let res;
      try {
        res = await api.get(`/admin/orders/${orderId}`, {
          params: { include_items: 1, include_payments: 1 },
        });
      } catch (_primaryErr) {
        res = await api.get(`/orders/${orderId}`);
      }

      const normalized = normalizeOrderPayload(res.data);

      if (!normalized) {
        throw new Error("Order data could not be interpreted.");
      }

      setDetail(normalized);
    } catch (e) {
      setDetail(null);
      setErr(String(e?.message || e || "Failed to load order"));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDetail();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [orderId]);

  const order = useMemo(() => safeObj(detail?.order), [detail]);
  const customer = useMemo(() => safeObj(detail?.customer), [detail]);
  const items = useMemo(() => safeArray(detail?.items), [detail]);

  const bankDetails = useMemo(() => {
    const bd = safeObj(order.bank_details);
    return {
      bank_name: safeStr(firstDefined(order.bank_name, bd.bank_name, "—")),
      account_name: safeStr(firstDefined(order.account_name, bd.account_name, "—")),
      account_number: safeStr(firstDefined(order.account_number, bd.account_number, "—")),
      branch_code: safeStr(firstDefined(order.branch_code, bd.branch_code, "—")),
      payment_instructions: safeStr(
        firstDefined(order.payment_instructions, bd.payment_instructions, "—")
      ),
    };
  }, [order]);

  const proofUrl = safeStr(
    firstDefined(order.payment_proof_url, order.proof_url, order.payment_proof, "")
  );

  const orderStatus = safeStr(order.order_status || order.status || "pending").toLowerCase();
  const paymentStatus = safeStr(
    order.payment_status || order.payment_visibility_status || "unpaid"
  ).toLowerCase();
  const deliveryStatus = safeStr(order.delivery_status || "pending").toLowerCase();

  const statusTone =
    orderStatus === "completed"
      ? "success"
      : orderStatus === "cancelled"
      ? "danger"
      : "warn";

  const paymentTone =
    paymentStatus === "paid"
      ? "success"
      : paymentStatus === "pending"
      ? "warn"
      : "neutral";

  const deliveryTone =
    deliveryStatus === "delivered"
      ? "success"
      : deliveryStatus === "partial"
      ? "warn"
      : "neutral";

  const handleBack = () => {
    if (window.history.length > 1) {
      navigate(-1);
      return;
    }
    navigate("/dashboard/admin");
  };

  return (
    <AdminLayout>
      <div className="space-y-5">
        <Card className="rounded-3xl border border-slate-200 bg-white p-5 shadow-sm">
          <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
            <div className="space-y-4">
              <button
                type="button"
                onClick={handleBack}
                className="inline-flex items-center gap-2 rounded-2xl border border-slate-200 bg-white px-4 py-2 text-sm font-semibold text-slate-700 shadow-sm hover:bg-slate-50"
              >
                <ArrowLeft className="h-4 w-4" />
                Back
              </button>

              <div className="flex items-start gap-3">
                <div className="grid h-12 w-12 place-items-center rounded-2xl border border-emerald-200 bg-emerald-50 text-emerald-700">
                  <ShoppingBasket className="h-5 w-5" />
                </div>
                <div>
                  <div className="text-3xl font-black tracking-tight text-slate-900">
                    Order Detail
                  </div>
                  <div className="mt-1 text-sm font-semibold text-slate-500">
                    {safeStr(firstDefined(order.order_id, order.id, orderId), "—")}
                  </div>
                </div>
              </div>
            </div>

            <button
              type="button"
              onClick={fetchDetail}
              className="inline-flex items-center gap-2 rounded-2xl border border-slate-200 bg-white px-4 py-2 text-sm font-semibold text-slate-700 shadow-sm hover:bg-slate-50"
            >
              <RefreshCw className="h-4 w-4" />
              Refresh
            </button>
          </div>
        </Card>

        {loading ? (
          <Card className="rounded-3xl border border-slate-200 bg-white p-8 shadow-sm">
            <div className="text-sm font-semibold text-slate-500">Loading order…</div>
          </Card>
        ) : err ? (
          <Card className="rounded-3xl border border-slate-200 bg-white p-8 shadow-sm">
            <div className="text-sm font-semibold text-rose-600">{err}</div>
          </Card>
        ) : !detail ? (
          <Card className="rounded-3xl border border-slate-200 bg-white p-8 shadow-sm">
            <EmptyState message="Order could not be found." />
          </Card>
        ) : (
          <>
            <div className="grid grid-cols-1 gap-4 lg:grid-cols-4">
              <SummaryStat
                label="Total"
                value={fmtNAD(firstDefined(order.grand_total, order.total, order.order_total, 0))}
                sub="Grand total"
              />
              <SummaryStat
                label="Order status"
                value={titleCaseWords(orderStatus)}
                sub="Current order lifecycle"
              />
              <SummaryStat
                label="Payment"
                value={titleCaseWords(paymentStatus)}
                sub={safeStr(firstDefined(order.payment_method, "—"), "—")}
              />
              <SummaryStat
                label="Delivery"
                value={titleCaseWords(deliveryStatus)}
                sub={fmtDateTime(firstDefined(order.expected_delivery_date, order.delivered_at))}
              />
            </div>

            <div className="grid grid-cols-1 gap-5 xl:grid-cols-2">
              <Card className="rounded-3xl border border-slate-200 bg-white p-5 shadow-sm">
                <div className="mb-4 flex items-center gap-2 text-sm font-black text-slate-900">
                  <UserRound className="h-4 w-4 text-slate-700" />
                  Customer Details
                </div>

                <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                  <KV label="Full name" value={safeStr(customer.full_name, "—")} />
                  <KV label="Email" value={safeStr(customer.email, "—")} />
                  <KV label="Phone" value={safeStr(customer.phone, "—")} />
                  <KV label="Location" value={safeStr(customer.location, "—")} />
                  <div className="sm:col-span-2">
                    <KV label="Address" value={safeStr(customer.address, "—")} />
                  </div>
                </div>
              </Card>

              <Card className="rounded-3xl border border-slate-200 bg-white p-5 shadow-sm">
                <div className="mb-4 flex items-center gap-2 text-sm font-black text-slate-900">
                  <Truck className="h-4 w-4 text-slate-700" />
                  Fulfilment & Delivery
                </div>

                <div className="space-y-4">
                  <div className="flex flex-wrap gap-2">
                    <StatusPill tone={statusTone}>Order: {titleCaseWords(orderStatus)}</StatusPill>
                    <StatusPill tone={paymentTone}>Payment: {titleCaseWords(paymentStatus)}</StatusPill>
                    <StatusPill tone={deliveryTone}>Delivery: {titleCaseWords(deliveryStatus)}</StatusPill>
                  </div>

                  <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                    <KV label="Delivery method" value={safeStr(order.delivery_method, "—")} />
                    <KV
                      label="Expected delivery"
                      value={fmtDateTime(order.expected_delivery_date)}
                    />
                    <KV label="Delivered at" value={fmtDateTime(order.delivered_at)} />
                    <KV
                      label="Delivery fee"
                      value={fmtNAD(firstDefined(order.delivery_fee, 0))}
                    />
                  </div>

                  <KV
                    label="Delivery address"
                    value={safeStr(firstDefined(order.delivery_address, customer.address), "—")}
                  />
                </div>
              </Card>
            </div>

            <div className="grid grid-cols-1 gap-5 xl:grid-cols-2">
              <Card className="rounded-3xl border border-slate-200 bg-white p-5 shadow-sm">
                <div className="mb-4 flex items-center gap-2 text-sm font-black text-slate-900">
                  <CreditCard className="h-4 w-4 text-slate-700" />
                  Payment Overview
                </div>

                <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                  <KV label="Payment status" value={titleCaseWords(paymentStatus)} />
                  <KV
                    label="Payment method"
                    value={safeStr(firstDefined(order.payment_method, "—"), "—")}
                  />
                  <KV
                    label="Reference"
                    value={safeStr(firstDefined(order.payment_reference, order.reference), "—")}
                  />
                  <KV label="Paid at" value={fmtDateTime(firstDefined(order.paid_at, order.payment_date))} />
                  <KV
                    label="Subtotal"
                    value={fmtNAD(firstDefined(order.subtotal, order.products_subtotal, 0))}
                  />
                  <KV label="VAT" value={fmtNAD(firstDefined(order.vat_amount, 0))} />
                  <KV label="Grand total" value={fmtNAD(firstDefined(order.grand_total, order.total, 0))} />
                  <KV label="Paid total" value={fmtNAD(firstDefined(order.paid_total, 0))} />
                </div>

                {proofUrl ? (
                  <div className="mt-4">
                    <a
                      href={proofUrl}
                      target="_blank"
                      rel="noreferrer"
                      className="inline-flex items-center gap-2 rounded-2xl border border-slate-200 bg-slate-50 px-4 py-2 text-sm font-semibold text-slate-700 hover:bg-slate-100"
                    >
                      View payment proof
                      <ExternalLink className="h-4 w-4" />
                    </a>
                  </div>
                ) : null}
              </Card>

              <Card className="rounded-3xl border border-slate-200 bg-white p-5 shadow-sm">
                <div className="mb-4 flex items-center gap-2 text-sm font-black text-slate-900">
                  <CreditCard className="h-4 w-4 text-slate-700" />
                  Bank Details
                </div>

                <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                  <KV label="Bank name" value={bankDetails.bank_name} />
                  <KV label="Account name" value={bankDetails.account_name} />
                  <KV label="Account number" value={bankDetails.account_number} />
                  <KV label="Branch code" value={bankDetails.branch_code} />
                  <div className="sm:col-span-2">
                    <KV label="Instructions" value={bankDetails.payment_instructions} />
                  </div>
                </div>
              </Card>
            </div>

            <Card className="rounded-3xl border border-slate-200 bg-white p-5 shadow-sm">
              <div className="mb-4 flex items-center gap-2 text-sm font-black text-slate-900">
                <Package className="h-4 w-4 text-slate-700" />
                Order Items ({items.length})
              </div>

              {!items.length ? (
                <EmptyState message="No order items available." />
              ) : (
                <div className="overflow-x-auto">
                  <table className="min-w-full text-sm">
                    <thead className="border-b border-slate-200 text-slate-500">
                      <tr>
                        <th className="px-3 py-3 text-left text-xs font-black uppercase tracking-wide">Product</th>
                        <th className="px-3 py-3 text-left text-xs font-black uppercase tracking-wide">Product ID</th>
                        <th className="px-3 py-3 text-left text-xs font-black uppercase tracking-wide">Qty</th>
                        <th className="px-3 py-3 text-left text-xs font-black uppercase tracking-wide">Unit price</th>
                        <th className="px-3 py-3 text-left text-xs font-black uppercase tracking-wide">Line total</th>
                        <th className="px-3 py-3 text-left text-xs font-black uppercase tracking-wide">Unit</th>
                        <th className="px-3 py-3 text-left text-xs font-black uppercase tracking-wide">Delivery</th>
                      </tr>
                    </thead>
                    <tbody>
                      {items.map((item, idx) => {
                        const productName = safeStr(
                          firstDefined(item.product_name, item.name, "Product"),
                          "Product"
                        );
                        const productId = safeStr(
                          firstDefined(item.product_id, item.id, ""),
                          ""
                        );

                        return (
                          <tr key={`${productId || "item"}-${idx}`} className="border-b border-slate-100 hover:bg-slate-50/70">
                            <td className="px-3 py-3 font-semibold text-slate-900">{productName}</td>
                            <td className="px-3 py-3 text-slate-600">{shortId(productId)}</td>
                            <td className="px-3 py-3 text-slate-700">
                              {safeStr(firstDefined(item.quantity, item.qty), "—")}
                            </td>
                            <td className="px-3 py-3 text-slate-700">
                              {fmtNAD(firstDefined(item.unit_price, 0))}
                            </td>
                            <td className="px-3 py-3 font-semibold text-slate-900">
                              {fmtNAD(firstDefined(item.line_total, 0))}
                            </td>
                            <td className="px-3 py-3 text-slate-700">
                              {safeStr(firstDefined(item.unit, "each"), "each")}
                            </td>
                            <td className="px-3 py-3 text-slate-700">
                              {titleCaseWords(firstDefined(item.delivery_status, item.item_delivery_status, "pending"))}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </Card>
          </>
        )}
      </div>
    </AdminLayout>
  );
}