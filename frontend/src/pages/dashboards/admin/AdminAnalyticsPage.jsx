// ============================================================================
// AdminAnalyticsPage.jsx — Admin Analytics Comparison Dashboard
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Admin comparison dashboard (read-only).
//   • Fetches compact analytics summary from backend
//   • Renders charts via AdminAnalyticsCharts
// ============================================================================

import React, { useEffect, useState } from "react";
import { toast } from "react-hot-toast";

import AdminLayout from "../../../components/AdminLayout";
import AdminAnalyticsCharts from "../../../components/analytics/AdminAnalyticsCharts";
import { fetchAdminAnalyticsSummary } from "../../../analytics/analyticsApi";

export default function AdminAnalyticsPage() {
  const [loading, setLoading] = useState(true);
  const [summary, setSummary] = useState(null);

  useEffect(() => {
    let alive = true;

    (async () => {
      try {
        setLoading(true);
        const data = await fetchAdminAnalyticsSummary();
        if (alive) setSummary(data);
      } catch (e) {
        console.error(e);
        toast.error("Admin analytics unavailable (missing endpoint?)");
      } finally {
        if (alive) setLoading(false);
      }
    })();

    return () => {
      alive = false;
    };
  }, []);

  return (
    <AdminLayout>
      <div className="space-y-6">
        <div className="bg-white rounded-2xl border border-gray-200 shadow-sm p-6">
          <h2 className="text-xl font-bold text-gray-800">Admin Analytics</h2>
          <p className="text-sm text-gray-600 mt-1">
            Governance and monitoring summary (orders, products, statuses).
          </p>
        </div>

        {loading ? (
          <div className="bg-white rounded-2xl border border-gray-200 shadow-sm p-6 text-gray-600">
            Loading…
          </div>
        ) : (
          <AdminAnalyticsCharts summary={summary || {}} />
        )}
      </div>
    </AdminLayout>
  );
}
