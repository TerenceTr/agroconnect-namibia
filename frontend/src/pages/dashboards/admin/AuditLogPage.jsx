// ============================================================================
// AuditLogPage.jsx — Admin Audit Dashboard (Governance + Analytics)
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Admin audit logs + basic governance analytics.
//   • Fetches audit log events
//   • Visualizes deletions over time
//   • Visualizes actions grouped by role
//
// API (RELATIVE):
//   GET /admin/audit-log
//
// UI NOTES:
//   • Uses dark "glass" cards for consistency with admin theme
//   • Chart.js defaults tuned for dark backgrounds
// ============================================================================

import React, { useEffect, useMemo, useState } from "react";
import { toast } from "react-hot-toast";
import { format } from "date-fns";

import api from "../../../api";
import AdminLayout from "../../../components/AdminLayout";
import Card from "../../../components/ui/Card";
import EmptyState from "../../../components/ui/EmptyState";
import SkeletonChart from "../../../components/ui/SkeletonChart";

import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  LineElement,
  BarElement,
  PointElement,
  Tooltip,
  Legend,
} from "chart.js";
import { Line, Bar } from "react-chartjs-2";

ChartJS.register(CategoryScale, LinearScale, LineElement, BarElement, PointElement, Tooltip, Legend);

// Dark-theme Chart defaults
ChartJS.defaults.color = "rgba(255,255,255,0.75)";
ChartJS.defaults.borderColor = "rgba(255,255,255,0.10)";

export default function AuditLogPage() {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);

  // Fetch audit logs
  useEffect(() => {
    (async () => {
      try {
        setLoading(true);
        const res = await api.get("/admin/audit-log");
        setLogs(res.data?.logs || []);
      } catch (e) {
        console.error(e);
        toast.error("Failed to load audit logs");
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  // Deletions over time
  const deletionsByDate = useMemo(() => {
    if (!logs.length) return null;

    const map = {};
    for (const l of logs) {
      const d = l?.deleted_at?.slice(0, 10);
      if (!d) continue;
      map[d] = (map[d] || 0) + 1;
    }

    const labels = Object.keys(map).sort();
    if (!labels.length) return null;

    return {
      labels,
      datasets: [
        {
          label: "Account Deletions",
          data: labels.map((k) => map[k]),
          borderColor: "#EF4444",
          backgroundColor: "rgba(239,68,68,0.20)",
          tension: 0.3,
        },
      ],
    };
  }, [logs]);

  // Actions by role
  const actionsByRole = useMemo(() => {
    if (!logs.length) return null;

    const map = {};
    for (const l of logs) {
      const role = l?.actor_role || "unknown";
      map[role] = (map[role] || 0) + 1;
    }

    const labels = Object.keys(map);
    if (!labels.length) return null;

    return {
      labels,
      datasets: [
        {
          label: "Actions",
          data: labels.map((k) => map[k]),
          backgroundColor: ["#52B788", "#3B82F6", "#F59E0B", "#EF4444"],
        },
      ],
    };
  }, [logs]);

  const chartOptions = useMemo(
    () => ({
      responsive: true,
      plugins: {
        legend: { labels: { color: "rgba(255,255,255,0.75)" } },
        tooltip: { enabled: true },
      },
      scales: {
        x: { grid: { color: "rgba(255,255,255,0.06)" } },
        y: { grid: { color: "rgba(255,255,255,0.06)" } },
      },
    }),
    []
  );

  return (
    <AdminLayout>
      <div className="space-y-6">
        {/* Charts */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <Card>
            <h3 className="font-semibold mb-3 text-white">Deletions Over Time</h3>
            {loading ? (
              <SkeletonChart />
            ) : deletionsByDate ? (
              <Line data={deletionsByDate} options={chartOptions} />
            ) : (
              <EmptyState message="No deletion activity." />
            )}
          </Card>

          <Card>
            <h3 className="font-semibold mb-3 text-white">Actions by Role</h3>
            {loading ? (
              <SkeletonChart />
            ) : actionsByRole ? (
              <Bar data={actionsByRole} options={chartOptions} />
            ) : (
              <EmptyState message="No role data available." />
            )}
          </Card>
        </div>

        {/* Table */}
        <Card>
          <h3 className="font-semibold mb-3 text-white">Audit Records</h3>

          {loading ? (
            <p className="text-white/60">Loading logs…</p>
          ) : logs.length === 0 ? (
            <EmptyState message="No audit records found." />
          ) : (
            <div className="overflow-x-auto">
              <table className="min-w-full text-sm">
                <thead className="border-b border-white/10 text-white/70">
                  <tr>
                    <th className="py-2 px-2 text-left">Email</th>
                    <th className="py-2 px-2 text-left">Role</th>
                    <th className="py-2 px-2 text-left">Reason</th>
                    <th className="py-2 px-2 text-left">Date</th>
                  </tr>
                </thead>
                <tbody>
                  {logs.map((l) => (
                    <tr key={l.id} className="border-b border-white/5 hover:bg-white/5">
                      <td className="py-2 px-2 text-white">{l.deleted_email}</td>
                      <td className="py-2 px-2 text-white/70 capitalize">{l.actor_role}</td>
                      <td className="py-2 px-2 text-white/70">{l.reason || "—"}</td>
                      <td className="py-2 px-2 text-white/60">
                        {l.deleted_at ? format(new Date(l.deleted_at), "dd MMM yyyy HH:mm") : "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </div>
    </AdminLayout>
  );
}
