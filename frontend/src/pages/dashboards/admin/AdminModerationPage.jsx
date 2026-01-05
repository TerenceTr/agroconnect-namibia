// ============================================================================
// AdminModerationPage.jsx — Product Listing Governance (Admin)
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Admin decision gate for farmer product listings.
//   • Approve / reject pending products
//   • Enforces: submit → review → publish/reject
//
// API (RELATIVE; api.js already ends with "/api"):
//   GET  /admin/products/pending
//   POST /admin/products/:id/approve
//   POST /admin/products/:id/reject
// ============================================================================

import React, { useEffect, useState } from "react";
import { toast } from "react-hot-toast";
import api from "../../../api";

import AdminLayout from "../../../components/AdminLayout";
import Card from "../../../components/ui/Card";

export default function AdminModerationPage() {
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);

  const load = async () => {
    try {
      setLoading(true);
      const res = await api.get("/admin/products/pending");
      setItems(Array.isArray(res.data) ? res.data : []);
    } catch (e) {
      console.error(e);
      toast.error("Failed to load pending products");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const act = async (id, action) => {
    try {
      await api.post(`/admin/products/${id}/${action}`);
      toast.success(`Product ${action}ed`);
      load();
    } catch (e) {
      console.error(e);
      toast.error("Action failed");
    }
  };

  return (
    <AdminLayout>
      <div className="space-y-6">
        <div className="bg-white rounded-2xl border border-gray-200 shadow-sm p-6">
          <h2 className="text-xl font-bold text-gray-800">Moderation</h2>
          <p className="text-sm text-gray-600 mt-1">
            Approve or reject product listings before they are published.
          </p>
        </div>

        <Card className="bg-white border border-gray-200">
          <h3 className="text-lg font-semibold text-gray-800 mb-4">
            Pending Product Listings
          </h3>

          {loading ? (
            <p className="text-gray-600">Loading…</p>
          ) : items.length === 0 ? (
            <p className="text-gray-500">No pending listings.</p>
          ) : (
            <div className="space-y-3">
              {items.map((p) => (
                <div
                  key={p.id}
                  className="p-4 rounded-2xl bg-[#F4FBF7] border border-[#B7E4C7] flex flex-col md:flex-row md:items-center md:justify-between gap-3"
                >
                  <div className="min-w-0">
                    <div className="font-semibold text-gray-800 truncate">
                      {p.name}
                    </div>
                    <div className="text-sm text-gray-600">
                      Farmer: {p.farmer_name || "—"}
                    </div>
                  </div>

                  <div className="flex gap-2">
                    <button
                      type="button"
                      onClick={() => act(p.id, "approve")}
                      className="px-4 py-2 rounded-xl bg-[#40916C] text-white font-semibold hover:bg-[#2D6A4F] transition"
                    >
                      Approve
                    </button>
                    <button
                      type="button"
                      onClick={() => act(p.id, "reject")}
                      className="px-4 py-2 rounded-xl bg-white border border-gray-300 text-gray-800 font-semibold hover:bg-gray-50 transition"
                    >
                      Reject
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </Card>
      </div>
    </AdminLayout>
  );
}
