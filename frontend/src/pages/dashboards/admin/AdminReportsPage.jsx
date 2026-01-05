// ====================================================================
// AdminReportsPage.jsx — Reports & Analytics (Admin)
// --------------------------------------------------------------------
// FILE ROLE:
//   Visualizes user growth, deletions, role distribution using Chart.js.
//   • Supports refresh (backend sync)
//   • Supports exports (CSV/PDF) using authenticated blob downloads
//
// IMPORTANT FIXES:
//   ✅ Correct relative imports for dashboards/admin folder
//   ✅ Uses api (Axios instance) and RELATIVE endpoints (no "/api" prefix)
//   ✅ Export uses responseType="blob" (so Authorization header is included)
// ====================================================================

import React, { useEffect, useMemo, useState } from "react";
import { motion } from "framer-motion";
import { toast } from "react-hot-toast";
import { Line, Doughnut } from "react-chartjs-2";
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  ArcElement,
} from "chart.js";
import { RefreshCw, FileDown, FileText, TrendingUp, Trash2, Users } from "lucide-react";

import api from "../../../api";
import AdminLayout from "../../../components/AdminLayout";
import ProtectedRoute from "../../../components/auth/ProtectedRoute";

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Title, Tooltip, Legend, ArcElement);

export default function AdminReportsPage() {
  const [growth, setGrowth] = useState([]);
  const [deletions, setDeletions] = useState([]);
  const [roles, setRoles] = useState([]);
  const [loading, setLoading] = useState(true);

  const fetchReports = async () => {
    try {
      setLoading(true);

      // Endpoints are RELATIVE to baseURL ".../api"
      const [g, d, r] = await Promise.all([
        api.get("/admin/reports/user-growth"),
        api.get("/admin/reports/deletions"),
        api.get("/admin/reports/roles"),
      ]);

      setGrowth(Array.isArray(g.data) ? g.data : []);
      setDeletions(Array.isArray(d.data) ? d.data : []);
      setRoles(Array.isArray(r.data) ? r.data : []);
    } catch (err) {
      console.error("❌ Error fetching reports:", err);
      toast.error("Failed to load analytics data.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchReports();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const refreshReports = async () => {
    const toastId = toast.loading("Refreshing analytics...");
    try {
      await api.post("/admin/reports/refresh", {});
      toast.success("✅ Analytics refreshed successfully");
      fetchReports();
    } catch (err) {
      console.error("❌ Refresh failed:", err);
      toast.error("Failed to refresh analytics");
    } finally {
      toast.dismiss(toastId);
    }
  };

  const exportReports = async (type) => {
    const toastId = toast.loading(`Exporting ${type.toUpperCase()}…`);
    try {
      const res = await api.get(`/admin/reports/export?type=${encodeURIComponent(type)}`, {
        responseType: "blob",
      });

      const blob = new Blob([res.data]);
      const url = window.URL.createObjectURL(blob);

      const a = document.createElement("a");
      a.href = url;
      a.download = `agroconnect-admin-report.${type === "pdf" ? "pdf" : "csv"}`;
      document.body.appendChild(a);
      a.click();
      a.remove();

      window.URL.revokeObjectURL(url);
      toast.success("Export downloaded");
    } catch (err) {
      console.error("❌ Export failed:", err);
      toast.error("Export failed");
    } finally {
      toast.dismiss(toastId);
    }
  };

  const growthChart = useMemo(
    () => ({
      labels: growth.map((g) => g.date),
      datasets: [
        {
          label: "User Registrations",
          data: growth.map((g) => g.count),
          borderColor: "#10B981",
          backgroundColor: "rgba(16,185,129,0.2)",
          tension: 0.4,
        },
      ],
    }),
    [growth]
  );

  const deletionChart = useMemo(
    () => ({
      labels: deletions.map((d) => d.date),
      datasets: [
        {
          label: "Account Deletions",
          data: deletions.map((d) => d.count),
          borderColor: "#EF4444",
          backgroundColor: "rgba(239,68,68,0.2)",
          tension: 0.4,
        },
      ],
    }),
    [deletions]
  );

  const roleChart = useMemo(
    () => ({
      labels: roles.map((r) => r.role),
      datasets: [
        {
          label: "Users per Role",
          data: roles.map((r) => r.count),
          backgroundColor: ["#10B981", "#3B82F6", "#F59E0B"],
        },
      ],
    }),
    [roles]
  );

  if (loading) {
    return (
      <AdminLayout>
        <div className="flex justify-center items-center h-64 text-gray-600">
          <div className="animate-spin mr-3 border-2 border-green-600 rounded-full w-6 h-6 border-t-transparent" />
          Loading analytics data...
        </div>
      </AdminLayout>
    );
  }

  return (
    <ProtectedRoute roles={["admin"]}>
      <AdminLayout>
        <motion.div
          initial={{ opacity: 0, y: 15 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
          className="bg-white rounded-2xl shadow p-6 border border-gray-100 relative z-10"
        >
          <div className="flex flex-col md:flex-row justify-between items-start md:items-center mb-6 gap-4">
            <h1 className="text-2xl font-semibold text-gray-800 flex items-center gap-2">
              <TrendingUp className="w-6 h-6 text-green-600" />
              Reports & Analytics
            </h1>

            <div className="flex flex-wrap gap-2">
              <button
                onClick={refreshReports}
                className="flex items-center bg-green-600 text-white px-4 py-2 rounded-md hover:bg-green-700 transition"
              >
                <RefreshCw className="w-4 h-4 mr-2" /> Refresh
              </button>

              <button
                onClick={() => exportReports("csv")}
                className="flex items-center bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700 transition"
              >
                <FileText className="w-4 h-4 mr-2" /> Export CSV
              </button>

              <button
                onClick={() => exportReports("pdf")}
                className="flex items-center bg-red-600 text-white px-4 py-2 rounded-md hover:bg-red-700 transition"
              >
                <FileDown className="w-4 h-4 mr-2" /> Export PDF
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
            <div className="p-4 bg-gray-50 rounded-lg border border-gray-200">
              <h3 className="font-semibold mb-2 text-gray-700 flex items-center gap-1">
                <Users className="w-4 h-4 text-green-600" /> User Growth
              </h3>
              <Line data={growthChart} options={{ responsive: true }} />
            </div>

            <div className="p-4 bg-gray-50 rounded-lg border border-gray-200">
              <h3 className="font-semibold mb-2 text-gray-700 flex items-center gap-1">
                <Trash2 className="w-4 h-4 text-red-500" /> Deletion Trends
              </h3>
              <Line data={deletionChart} options={{ responsive: true }} />
            </div>

            <div className="md:col-span-2 p-4 bg-gray-50 rounded-lg border border-gray-200">
              <h3 className="font-semibold mb-3 text-gray-700 flex items-center gap-1">
                <Users className="w-4 h-4 text-blue-500" /> Role Distribution
              </h3>
              <div className="w-full md:w-1/2 mx-auto">
                <Doughnut data={roleChart} options={{ responsive: true }} />
              </div>
            </div>
          </div>
        </motion.div>
      </AdminLayout>
    </ProtectedRoute>
  );
}
