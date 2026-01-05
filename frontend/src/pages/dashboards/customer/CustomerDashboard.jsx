// ============================================================================
// CustomerDashboard.jsx — Customer Journey Orchestrator (Neutral + Thesis UI)
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Customer “container” dashboard that orchestrates the journey:
//   • browsing, product details, cart, checkout, order history, ratings
//   • children contain business logic; this page wires flows together
//
// DESIGN UPDATE:
//   ✅ Remove dark/white-text styling
//   ✅ Use calm green base from DashboardLayout
//   ✅ Keep content on white cards
//
// ADDITION:
//   ✅ Logout button (calls useAuth().logout() then navigates to /login)
// ============================================================================

import React, { useState } from "react";
import { motion } from "framer-motion";
import toast from "react-hot-toast";
import { LogOut } from "lucide-react";
import { useNavigate } from "react-router-dom";

import DashboardLayout from "../../../components/layout/DashboardLayout";
import { useAuth } from "../../../components/auth/AuthProvider";

import CustomerBrowse from "./CustomerBrowse";
import CartDrawer from "../../../components/customer/CartDrawer";
import CheckoutPanel from "../../../components/customer/CheckoutPanel";
import ProductDetailsPanel from "../../../components/customer/ProductDetailsPanel";
import OrderHistory from "../../../components/customer/OrderHistory";
import RatingsPanel from "../../../components/customer/RatingsPanel";
import OrderConfirmation from "../../../components/customer/OrderConfirmation";

import useCart from "../../../hooks/useCart";
import useCustomerOrders from "../../../hooks/useCustomerOrders";
import useCustomerFollowed from "../../../hooks/useCustomerFollowed";
import useLastViewed from "../../../hooks/useLastViewed";

import { placeOrder } from "../../../services/customerApi";

export default function CustomerDashboard() {
  const navigate = useNavigate();
  const { user, logout } = useAuth();

  const cart = useCart();
  const orders = useCustomerOrders();
  const followed = useCustomerFollowed();
  const lastViewed = useLastViewed();

  const [selected, setSelected] = useState(null);
  const [confirmedOrder, setConfirmedOrder] = useState(null);

  // Product selection
  const onSelectProduct = (product) => {
    setSelected(product);
    lastViewed.setLastViewed(product);
  };

  // Checkout → Order placement
  const onPlaceOrder = async (payload) => {
    try {
      const res = await placeOrder(payload);

      await cart.reload();
      await orders.reload();

      setConfirmedOrder(res);
      toast.success("Order placed successfully");

      return res;
    } catch (err) {
      console.error(err);
      toast.error("Failed to place order");
      throw err;
    }
  };

  // Logout handler (AuthProvider does NOT navigate by design)
  const onLogout = () => {
    logout();
    navigate("/login", { replace: true });
  };

  return (
    <DashboardLayout>
      <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-6 text-slate-900">
        {/* Header row with Logout */}
        <div className="rounded-3xl bg-white border border-slate-200 shadow-sm p-6 flex items-center justify-between gap-4">
          <div className="min-w-0">
            <div className="text-xs text-slate-500">Customer</div>
            <h2 className="text-xl md:text-2xl font-extrabold text-slate-900">Customer Dashboard</h2>
            <p className="text-sm text-slate-600 mt-1">
              Welcome{user?.name ? `, ${user.name}` : ""}. Browse products and place orders.
            </p>
          </div>

          <button type="button" onClick={onLogout} className="btn-secondary px-4 py-2 flex items-center gap-2">
            <LogOut className="w-4 h-4" />
            Logout
          </button>
        </div>

        {/* Browse */}
        <div className="rounded-3xl bg-white border border-slate-200 shadow-sm p-4 md:p-6">
          <CustomerBrowse onSelect={onSelectProduct} />
        </div>

        {/* Last viewed */}
        {lastViewed.lastViewed && (
          <div className="rounded-2xl bg-[#EAF7F0] border border-[#B7E4C7] px-4 py-3 text-sm text-[#1B4332]">
            Last checked: <strong>{lastViewed.lastViewed.name}</strong>
          </div>
        )}

        {/* Details + Cart */}
        <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
          <div className="xl:col-span-2 space-y-6">
            <div className="rounded-3xl bg-white border border-slate-200 shadow-sm p-4 md:p-6">
              <ProductDetailsPanel
                product={selected}
                customerId={user?.id}
                isFollowed={selected && followed.isFollowed(selected.id)}
                onFollow={() => selected && followed.follow(selected.id)}
                onUnfollow={() => selected && followed.unfollow(selected.id)}
                onAddToCart={(id, qty) => cart.add(id, qty)}
              />
            </div>

            <div className="rounded-3xl bg-white border border-slate-200 shadow-sm p-4 md:p-6">
              <RatingsPanel product={selected} />
            </div>
          </div>

          <div className="space-y-6">
            <div className="rounded-3xl bg-white border border-slate-200 shadow-sm p-4 md:p-6">
              <CartDrawer
                cart={cart.cart}
                totals={cart.totals}
                onInc={cart.inc}
                onDec={cart.dec}
                onRemove={cart.remove}
                onClear={cart.clear}
              />
            </div>

            <div className="rounded-3xl bg-white border border-slate-200 shadow-sm p-4 md:p-6">
              <CheckoutPanel cart={cart.cart} totals={cart.totals} onPlaceOrder={onPlaceOrder} />
            </div>
          </div>
        </div>

        {/* Confirmation */}
        {confirmedOrder && (
          <div className="rounded-3xl bg-white border border-slate-200 shadow-sm p-4 md:p-6">
            <OrderConfirmation order={confirmedOrder} />
          </div>
        )}

        {/* Orders */}
        <div className="rounded-3xl bg-white border border-slate-200 shadow-sm p-4 md:p-6">
          <OrderHistory orders={orders.orders} loading={orders.loading} onRefresh={orders.reload} />
        </div>
      </motion.div>
    </DashboardLayout>
  );
}
