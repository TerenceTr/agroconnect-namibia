// ============================================================================
// frontend/src/pages/dashboards/admin/AdminUsersPage.jsx
// ----------------------------------------------------------------------------
// 🌾 AgroConnect Namibia — Admin Users (Readable + Production UI)
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Admin UI for managing users.
//   • Search + role/status filters
//   • Export CSV/PDF (NOW placed at bottom of table per request)
//   • Activate/Deactivate users
//
// UI FIXES INCLUDED:
//   • Light-theme tokens (no more text-white/white/10 on white background)
//   • Clearer table grid lines (stronger borders + column separators)
//   • Export moved to table footer (bottom-right)
// ============================================================================

import React, { useEffect, useMemo, useRef, useState } from "react";
import { toast } from "react-hot-toast";
import { format } from "date-fns";
import {
  Users,
  Search,
  ChevronDown,
  UserCheck,
  UserX,
  FileDown,
  FileText,
} from "lucide-react";

import api from "../../../api";
import AdminLayout from "../../../components/AdminLayout";
import ProtectedRoute from "../../../components/auth/ProtectedRoute";
import Card from "../../../components/ui/Card";
import EmptyState from "../../../components/ui/EmptyState";

// ---------------------------------------------------------------------------
// Null-safe helpers
// ---------------------------------------------------------------------------
function safeArray(v) {
  return Array.isArray(v) ? v : [];
}

function safeStr(v, fallback = "") {
  if (typeof v === "string") return v;
  if (v == null) return fallback;
  return String(v);
}

function safeLower(v) {
  return safeStr(v).toLowerCase();
}

function normalizeRole(u) {
  const rn = safeStr(u?.role_name).trim();
  if (rn) return rn;
  const r = safeStr(u?.role).trim();
  return r || "unknown";
}

function normalizeStatus(u) {
  const s = safeLower(u?.status);
  if (s === "active" || s === "inactive") return s;
  if (typeof u?.is_active === "boolean") return u.is_active ? "active" : "inactive";
  return "active";
}

// ---------------------------------------------------------------------------
// Small UI utility: close dropdown on outside click
// ---------------------------------------------------------------------------
function useOutsideClick(ref, handler) {
  useEffect(() => {
    function onDown(e) {
      const el = ref.current;
      if (!el) return;
      if (el.contains(e.target)) return;
      handler();
    }
    document.addEventListener("mousedown", onDown);
    return () => document.removeEventListener("mousedown", onDown);
  }, [ref, handler]);
}

export default function AdminUsersPage() {
  const [users, setUsers] = useState([]);
  const [query, setQuery] = useState("");
  const [roleFilter, setRoleFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [loading, setLoading] = useState(true);

  // Export dropdown (now in table footer)
  const [showExport, setShowExport] = useState(false);
  const exportRef = useRef(null);
  useOutsideClick(exportRef, () => setShowExport(false));

  // Build query params (only non-empty)
  const params = useMemo(() => {
    const p = new URLSearchParams({
      ...(query && { q: query }),
      ...(roleFilter && { role: roleFilter }),
      ...(statusFilter && { status: statusFilter }),
    });
    return p.toString();
  }, [query, roleFilter, statusFilter]);

  async function fetchUsers() {
    try {
      setLoading(true);
      const res = await api.get(`/admin/users?${params}`);
      const raw = res?.data;
      const list = Array.isArray(raw) ? raw : safeArray(raw?.users);
      setUsers(list);
    } catch (err) {
      console.error(err);
      toast.error("Failed to load users");
      setUsers([]);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    fetchUsers();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function toggleUserStatus(userId, currentStatus) {
    try {
      const curr = safeLower(currentStatus) || "active";
      const newStatus = curr === "active" ? "inactive" : "active";

      await api.patch(`/admin/users/${userId}/status`, { status: newStatus });

      toast.success(`User ${newStatus === "active" ? "activated" : "deactivated"}`);
      fetchUsers();
    } catch (err) {
      console.error(err);
      toast.error("Failed to update user status");
    }
  }

  async function exportUsers(type) {
    const t = type === "pdf" ? "pdf" : "csv";
    const toastId = toast.loading(`Exporting ${t.toUpperCase()}…`);

    try {
      const res = await api.get(
        `/admin/users/export?${params}&type=${encodeURIComponent(t)}`,
        { responseType: "blob" }
      );

      const blob = new Blob([res.data]);
      const url = window.URL.createObjectURL(blob);

      const a = document.createElement("a");
      a.href = url;
      a.download = `agroconnect-users.${t}`;
      document.body.appendChild(a);
      a.click();
      a.remove();

      window.URL.revokeObjectURL(url);
      toast.success("Export downloaded");
    } catch (err) {
      console.error(err);
      toast.error("Export failed");
    } finally {
      toast.dismiss(toastId);
      setShowExport(false);
    }
  }

  const rows = useMemo(() => {
    return safeArray(users).map((u) => ({
      ...u,
      role_name: normalizeRole(u),
      status: normalizeStatus(u),
    }));
  }, [users]);

  // Helper for consistent grid lines (vertical separators)
  const thBase =
    "px-4 py-3 text-left font-semibold text-slate-700 border-b border-slate-200 bg-slate-50";
  const tdBase =
    "px-4 py-3 text-slate-700 border-b border-slate-200";
  const vSep = "border-r border-slate-200 last:border-r-0";

  return (
    <ProtectedRoute roles={["admin"]}>
      <AdminLayout>
        <div className="space-y-6">
          {/* Header + Filters */}
          <Card className="p-6">
            <div className="flex items-center gap-2">
              <Users className="w-5 h-5 text-emerald-700" />
              <h2 className="text-xl font-semibold text-slate-900">User Management</h2>
            </div>

            <form
              onSubmit={(e) => {
                e.preventDefault();
                fetchUsers();
              }}
              className="mt-5 grid grid-cols-1 md:grid-cols-4 gap-3"
            >
              <div className="md:col-span-2">
                <label className="block text-xs font-medium text-slate-600 mb-1">
                  Search
                </label>
                <div className="flex items-center gap-2 px-3 py-2 rounded-xl bg-white border border-slate-200 focus-within:ring-2 focus-within:ring-emerald-200">
                  <Search className="w-4 h-4 text-slate-500" />
                  <input
                    value={query}
                    onChange={(e) => setQuery(e.target.value)}
                    placeholder="Email or name…"
                    className="w-full bg-transparent outline-none text-slate-900 placeholder:text-slate-400"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-600 mb-1">
                  Role
                </label>
                <select
                  value={roleFilter}
                  onChange={(e) => setRoleFilter(e.target.value)}
                  className="w-full px-3 py-2 rounded-xl bg-white border border-slate-200 text-slate-900 outline-none focus:ring-2 focus:ring-emerald-200"
                >
                  <option value="">All</option>
                  <option value="admin">Admin</option>
                  <option value="farmer">Farmer</option>
                  <option value="customer">Customer</option>
                </select>
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-600 mb-1">
                  Status
                </label>
                <select
                  value={statusFilter}
                  onChange={(e) => setStatusFilter(e.target.value)}
                  className="w-full px-3 py-2 rounded-xl bg-white border border-slate-200 text-slate-900 outline-none focus:ring-2 focus:ring-emerald-200"
                >
                  <option value="">All</option>
                  <option value="active">Active</option>
                  <option value="inactive">Inactive</option>
                </select>
              </div>

              <div className="md:col-span-4 flex justify-end">
                <button
                  type="submit"
                  className="inline-flex items-center justify-center rounded-xl px-4 py-2 text-sm font-semibold bg-emerald-600 text-white hover:bg-emerald-700 shadow-sm focus:outline-none focus:ring-2 focus:ring-emerald-300"
                >
                  Apply Filters
                </button>
              </div>
            </form>
          </Card>

          {/* Table */}
          <Card className="p-0">
            {loading ? (
              <div className="p-6 text-slate-600">Loading users…</div>
            ) : rows.length === 0 ? (
              <div className="p-6">
                <EmptyState message="No users found." />
              </div>
            ) : (
              <>
                <div className="overflow-x-auto">
                  {/* Clear grid lines: border + column separators */}
                  <div className="min-w-[900px] border border-slate-200 rounded-2xl overflow-hidden">
                    <table className="min-w-full text-sm bg-white">
                      <thead>
                        <tr>
                          <th className={[thBase, vSep].join(" ")}>Full Name</th>
                          <th className={[thBase, vSep].join(" ")}>Email</th>
                          <th className={[thBase, vSep].join(" ")}>Role</th>
                          <th className={[thBase, vSep].join(" ")}>Status</th>
                          <th className={[thBase, vSep].join(" ")}>Created</th>
                          <th className={[thBase, "text-right"].join(" ")}>Actions</th>
                        </tr>
                      </thead>

                      <tbody>
                        {rows.map((u) => {
                          const status = normalizeStatus(u);
                          const roleName = normalizeRole(u);

                          return (
                            <tr key={u.id} className="hover:bg-slate-50">
                              <td className={[tdBase, vSep, "font-semibold text-slate-900"].join(" ")}>
                                {safeStr(u.full_name, "—") || "—"}
                              </td>

                              <td className={[tdBase, vSep].join(" ")}>
                                {safeStr(u.email, "—") || "—"}
                              </td>

                              <td className={[tdBase, vSep, "capitalize"].join(" ")}>
                                {roleName || "—"}
                              </td>

                              <td className={[tdBase, vSep].join(" ")}>
                                <span
                                  className={[
                                    "text-xs px-2 py-1 rounded-full border inline-flex items-center",
                                    status === "active"
                                      ? "text-emerald-700 border-emerald-200 bg-emerald-50"
                                      : "text-red-700 border-red-200 bg-red-50",
                                  ].join(" ")}
                                >
                                  {status}
                                </span>
                              </td>

                              <td className={[tdBase, vSep, "text-slate-600"].join(" ")}>
                                {u.created_at
                                  ? format(new Date(u.created_at), "dd MMM yyyy")
                                  : "—"}
                              </td>

                              <td className={[tdBase, "text-right"].join(" ")}>
                                {status === "active" ? (
                                  <button
                                    type="button"
                                    onClick={() => toggleUserStatus(u.id, status)}
                                    className="inline-flex items-center gap-1 text-red-600 hover:text-red-700 font-semibold"
                                  >
                                    <UserX className="w-4 h-4" />
                                    Deactivate
                                  </button>
                                ) : (
                                  <button
                                    type="button"
                                    onClick={() => toggleUserStatus(u.id, status)}
                                    className="inline-flex items-center gap-1 text-emerald-700 hover:text-emerald-800 font-semibold"
                                  >
                                    <UserCheck className="w-4 h-4" />
                                    Activate
                                  </button>
                                )}
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                </div>

                {/* Footer bar (BOTTOM): count + Export dropdown */}
                <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3 px-6 py-4 border-t border-slate-200 bg-slate-50 rounded-b-2xl">
                  <div className="text-xs text-slate-600">
                    Showing <span className="font-semibold">{rows.length}</span> user
                    {rows.length === 1 ? "" : "s"} (max 2000 per query).
                  </div>

                  <div className="relative" ref={exportRef}>
                    <button
                      type="button"
                      onClick={() => setShowExport((v) => !v)}
                      className="inline-flex items-center gap-2 rounded-xl px-4 py-2 text-sm font-semibold bg-emerald-600 text-white hover:bg-emerald-700 shadow-sm focus:outline-none focus:ring-2 focus:ring-emerald-300"
                    >
                      <FileDown className="w-4 h-4" />
                      Export
                      <ChevronDown className="w-4 h-4" />
                    </button>

                    {showExport && (
                      <div className="absolute right-0 mt-2 w-52 rounded-xl bg-white border border-slate-200 shadow-lg z-50 overflow-hidden">
                        <button
                          type="button"
                          onClick={() => exportUsers("csv")}
                          className="w-full px-4 py-3 text-left text-sm text-slate-800 hover:bg-slate-50 flex items-center gap-2"
                        >
                          <FileText className="w-4 h-4 text-slate-600" />
                          Export CSV
                        </button>
                        <button
                          type="button"
                          onClick={() => exportUsers("pdf")}
                          className="w-full px-4 py-3 text-left text-sm text-slate-800 hover:bg-slate-50 flex items-center gap-2"
                        >
                          <FileDown className="w-4 h-4 text-slate-600" />
                          Export PDF
                        </button>
                      </div>
                    )}
                  </div>
                </div>
              </>
            )}
          </Card>
        </div>
      </AdminLayout>
    </ProtectedRoute>
  );
}
