// ============================================================================
// frontend/src/pages/dashboards/admin/AdminUsersPage.jsx
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Admin UI for managing users.
//
// THIS UPDATE:
//   ✅ Uses page space better with responsive user cards
//   ✅ Adds client-side pagination to reduce long scrolling
//   ✅ Keeps search + role/status filters
//   ✅ Keeps activate/deactivate actions
//   ✅ Keeps CSV/PDF export
//   ✅ Presents a cleaner master's-level admin workspace
// ============================================================================

import React, { useEffect, useMemo, useRef, useState } from "react";
import { format } from "date-fns";
import toast from "react-hot-toast";
import {
  Users,
  Search,
  ChevronDown,
  UserCheck,
  UserX,
  FileDown,
  FileText,
  RefreshCw,
  ChevronLeft,
  ChevronRight,
  ShieldCheck,
  UserRound,
} from "lucide-react";

import api from "../../../api";
import AdminLayout from "../../../components/AdminLayout";
import ProtectedRoute from "../../../components/auth/ProtectedRoute";
import Card from "../../../components/ui/Card";
import EmptyState from "../../../components/ui/EmptyState";

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------
const PAGE_SIZE = 8;

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

function titleCaseWords(v) {
  return safeStr(v)
    .replace(/[_-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/\b\w/g, (m) => m.toUpperCase());
}

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

function StatCard({ title, value, subtext, tone = "slate" }) {
  const accent =
    tone === "emerald"
      ? "border-emerald-200 bg-emerald-50/70"
      : tone === "amber"
      ? "border-amber-200 bg-amber-50/70"
      : tone === "rose"
      ? "border-rose-200 bg-rose-50/70"
      : "border-slate-200 bg-white";

  return (
    <Card className={`rounded-2xl border p-4 shadow-sm ${accent}`}>
      <div className="text-xs font-bold uppercase tracking-wide text-slate-500">{title}</div>
      <div className="mt-2 text-2xl font-black text-slate-900">{value}</div>
      <div className="mt-1 text-xs font-semibold text-slate-600">{subtext}</div>
    </Card>
  );
}

function PaginationBar({ page, totalPages, totalItems, onPageChange }) {
  if (totalPages <= 1) return null;

  const pages = [];
  const start = Math.max(1, page - 2);
  const end = Math.min(totalPages, page + 2);

  for (let p = start; p <= end; p += 1) pages.push(p);

  return (
    <div className="flex flex-col gap-3 rounded-2xl border border-slate-200 bg-white px-4 py-3 shadow-sm md:flex-row md:items-center md:justify-between">
      <div className="text-sm font-semibold text-slate-600">
        Page <span className="font-extrabold text-slate-900">{page}</span> of{" "}
        <span className="font-extrabold text-slate-900">{totalPages}</span> •{" "}
        <span className="font-extrabold text-slate-900">{totalItems}</span> users
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <button
          type="button"
          onClick={() => onPageChange(Math.max(1, page - 1))}
          disabled={page === 1}
          className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm font-extrabold text-slate-800 hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-50"
        >
          <ChevronLeft className="h-4 w-4" />
          Prev
        </button>

        {pages.map((p) => (
          <button
            key={p}
            type="button"
            onClick={() => onPageChange(p)}
            className={[
              "rounded-xl border px-3 py-2 text-sm font-extrabold transition",
              p === page
                ? "border-slate-900 bg-slate-900 text-white"
                : "border-slate-200 bg-white text-slate-700 hover:bg-slate-50",
            ].join(" ")}
          >
            {p}
          </button>
        ))}

        <button
          type="button"
          onClick={() => onPageChange(Math.min(totalPages, page + 1))}
          disabled={page === totalPages}
          className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm font-extrabold text-slate-800 hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-50"
        >
          Next
          <ChevronRight className="h-4 w-4" />
        </button>
      </div>
    </div>
  );
}

export default function AdminUsersPage() {
  const [users, setUsers] = useState([]);
  const [query, setQuery] = useState("");
  const [roleFilter, setRoleFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);

  const [showExport, setShowExport] = useState(false);
  const exportRef = useRef(null);
  useOutsideClick(exportRef, () => setShowExport(false));

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

  useEffect(() => {
    setPage(1);
  }, [query, roleFilter, statusFilter]);

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

  const summary = useMemo(() => {
    const total = rows.length;
    const active = rows.filter((u) => normalizeStatus(u) === "active").length;
    const inactive = rows.filter((u) => normalizeStatus(u) === "inactive").length;
    const admins = rows.filter((u) => normalizeRole(u).toLowerCase() === "admin").length;
    const farmers = rows.filter((u) => normalizeRole(u).toLowerCase() === "farmer").length;
    const customers = rows.filter((u) => normalizeRole(u).toLowerCase() === "customer").length;

    return { total, active, inactive, admins, farmers, customers };
  }, [rows]);

  const totalPages = Math.max(1, Math.ceil(rows.length / PAGE_SIZE));
  const safePage = Math.min(page, totalPages);

  const pagedRows = useMemo(() => {
    const start = (safePage - 1) * PAGE_SIZE;
    return rows.slice(start, start + PAGE_SIZE);
  }, [rows, safePage]);

  return (
    <ProtectedRoute roles={["admin"]}>
      <AdminLayout>
        <div className="space-y-6">
          {/* Header */}
          <div className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1fr)_auto] xl:items-start">
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <Users className="h-5 w-5 text-emerald-700" />
                <h2 className="text-2xl font-extrabold text-slate-900">User Management</h2>
              </div>
              <p className="mt-1 max-w-3xl text-sm text-slate-600">
                Manage platform accounts, review role distribution, and activate or deactivate users
                from a compact administrative workspace.
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <button
                type="button"
                onClick={fetchUsers}
                className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-4 py-2 text-sm font-extrabold text-slate-800 hover:bg-slate-50"
              >
                <RefreshCw className="h-4 w-4" />
                Refresh
              </button>

              <div className="relative" ref={exportRef}>
                <button
                  type="button"
                  onClick={() => setShowExport((v) => !v)}
                  className="inline-flex items-center gap-2 rounded-xl bg-emerald-600 px-4 py-2 text-sm font-extrabold text-white shadow-sm hover:bg-emerald-700"
                >
                  <FileDown className="h-4 w-4" />
                  Export
                  <ChevronDown className="h-4 w-4" />
                </button>

                {showExport && (
                  <div className="absolute right-0 z-50 mt-2 w-52 overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-lg">
                    <button
                      type="button"
                      onClick={() => exportUsers("csv")}
                      className="flex w-full items-center gap-2 px-4 py-3 text-left text-sm font-semibold text-slate-800 hover:bg-slate-50"
                    >
                      <FileText className="h-4 w-4 text-slate-600" />
                      Export CSV
                    </button>
                    <button
                      type="button"
                      onClick={() => exportUsers("pdf")}
                      className="flex w-full items-center gap-2 px-4 py-3 text-left text-sm font-semibold text-slate-800 hover:bg-slate-50"
                    >
                      <FileDown className="h-4 w-4 text-slate-600" />
                      Export PDF
                    </button>
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Summary cards */}
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2 2xl:grid-cols-4">
            <StatCard
              title="Total users"
              value={summary.total}
              subtext="Accounts currently returned by the active filter set."
              tone="slate"
            />
            <StatCard
              title="Active users"
              value={summary.active}
              subtext="Accounts currently available for login and use."
              tone="emerald"
            />
            <StatCard
              title="Inactive users"
              value={summary.inactive}
              subtext="Accounts currently disabled by admin status control."
              tone="rose"
            />
            <StatCard
              title="Role distribution"
              value={`${summary.admins}/${summary.farmers}/${summary.customers}`}
              subtext="Admin / Farmer / Customer"
              tone="amber"
            />
          </div>

          {/* Filters */}
          <Card className="rounded-2xl border border-slate-200 p-5 shadow-sm">
            <form
              onSubmit={(e) => {
                e.preventDefault();
                fetchUsers();
              }}
              className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,2fr)_220px_220px_auto]"
            >
              <div>
                <label className="mb-1 block text-xs font-bold uppercase tracking-wide text-slate-500">
                  Search
                </label>
                <div className="flex items-center gap-2 rounded-2xl border border-slate-200 bg-white px-3 py-2 focus-within:ring-2 focus-within:ring-emerald-200">
                  <Search className="h-4 w-4 text-slate-500" />
                  <input
                    value={query}
                    onChange={(e) => setQuery(e.target.value)}
                    placeholder="Search by full name or email"
                    className="w-full bg-transparent text-sm text-slate-900 outline-none placeholder:text-slate-400"
                  />
                </div>
              </div>

              <div>
                <label className="mb-1 block text-xs font-bold uppercase tracking-wide text-slate-500">
                  Role
                </label>
                <select
                  value={roleFilter}
                  onChange={(e) => setRoleFilter(e.target.value)}
                  className="h-[44px] w-full rounded-2xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-900 outline-none focus:ring-2 focus:ring-emerald-200"
                >
                  <option value="">All roles</option>
                  <option value="admin">Admin</option>
                  <option value="farmer">Farmer</option>
                  <option value="customer">Customer</option>
                </select>
              </div>

              <div>
                <label className="mb-1 block text-xs font-bold uppercase tracking-wide text-slate-500">
                  Status
                </label>
                <select
                  value={statusFilter}
                  onChange={(e) => setStatusFilter(e.target.value)}
                  className="h-[44px] w-full rounded-2xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-900 outline-none focus:ring-2 focus:ring-emerald-200"
                >
                  <option value="">All statuses</option>
                  <option value="active">Active</option>
                  <option value="inactive">Inactive</option>
                </select>
              </div>

              <div className="flex items-end">
                <button
                  type="submit"
                  className="inline-flex h-[44px] items-center justify-center rounded-2xl bg-emerald-600 px-5 text-sm font-extrabold text-white shadow-sm hover:bg-emerald-700"
                >
                  Apply filters
                </button>
              </div>
            </form>
          </Card>

          {/* Users grid */}
          <Card className="rounded-2xl border border-slate-200 p-4 shadow-sm">
            {loading ? (
              <div className="p-4 text-sm font-semibold text-slate-600">Loading users…</div>
            ) : rows.length === 0 ? (
              <div className="p-4">
                <EmptyState message="No users found." />
              </div>
            ) : (
              <>
                <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <div className="text-sm font-extrabold text-slate-900">User directory</div>
                    <div className="mt-1 text-xs font-semibold text-slate-500">
                      Showing {pagedRows.length} users on this page • {rows.length} total matches
                    </div>
                  </div>

                  <div className="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-slate-50 px-3 py-2 text-xs font-bold text-slate-600">
                    <ShieldCheck className="h-3.5 w-3.5" />
                    Status changes are applied immediately
                  </div>
                </div>

                <div className="grid grid-cols-1 gap-4 2xl:grid-cols-2">
                  {pagedRows.map((u) => {
                    const status = normalizeStatus(u);
                    const roleName = normalizeRole(u);
                    const createdLabel = u.created_at
                      ? format(new Date(u.created_at), "dd MMM yyyy")
                      : "—";

                    return (
                      <div
                        key={u.id}
                        className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm transition hover:shadow-md"
                      >
                        <div className="flex items-start gap-4">
                          <div className="grid h-14 w-14 shrink-0 place-items-center rounded-2xl border border-slate-200 bg-slate-50">
                            <UserRound className="h-6 w-6 text-slate-600" />
                          </div>

                          <div className="min-w-0 flex-1">
                            <div className="flex flex-wrap items-center gap-2">
                              <div className="truncate text-sm font-extrabold text-slate-900">
                                {safeStr(u.full_name, "—") || "—"}
                              </div>

                              <span
                                className={[
                                  "inline-flex items-center rounded-full border px-2.5 py-1 text-[11px] font-extrabold",
                                  status === "active"
                                    ? "border-emerald-200 bg-emerald-50 text-emerald-800"
                                    : "border-rose-200 bg-rose-50 text-rose-800",
                                ].join(" ")}
                              >
                                {titleCaseWords(status)}
                              </span>

                              <span className="inline-flex items-center rounded-full border border-slate-200 bg-slate-50 px-2.5 py-1 text-[11px] font-extrabold text-slate-700">
                                {titleCaseWords(roleName)}
                              </span>
                            </div>

                            <div className="mt-1 truncate text-sm font-semibold text-slate-600">
                              {safeStr(u.email, "—") || "—"}
                            </div>

                            <div className="mt-3 grid grid-cols-2 gap-3 text-xs text-slate-600 sm:grid-cols-4">
                              <div>
                                <div className="font-bold uppercase tracking-wide text-slate-500">Role</div>
                                <div className="mt-1 font-semibold text-slate-800">{titleCaseWords(roleName)}</div>
                              </div>
                              <div>
                                <div className="font-bold uppercase tracking-wide text-slate-500">Status</div>
                                <div className="mt-1 font-semibold text-slate-800">{titleCaseWords(status)}</div>
                              </div>
                              <div>
                                <div className="font-bold uppercase tracking-wide text-slate-500">Created</div>
                                <div className="mt-1 font-semibold text-slate-800">{createdLabel}</div>
                              </div>
                              <div>
                                <div className="font-bold uppercase tracking-wide text-slate-500">User ID</div>
                                <div className="mt-1 truncate font-mono text-[11px] text-slate-700">{safeStr(u.id, "—")}</div>
                              </div>
                            </div>
                          </div>

                          <div className="shrink-0">
                            {status === "active" ? (
                              <button
                                type="button"
                                onClick={() => toggleUserStatus(u.id, status)}
                                className="inline-flex items-center gap-2 rounded-xl border border-rose-200 bg-rose-50 px-4 py-2 text-sm font-extrabold text-rose-800 hover:bg-rose-100"
                              >
                                <UserX className="h-4 w-4" />
                                Deactivate
                              </button>
                            ) : (
                              <button
                                type="button"
                                onClick={() => toggleUserStatus(u.id, status)}
                                className="inline-flex items-center gap-2 rounded-xl border border-emerald-200 bg-emerald-50 px-4 py-2 text-sm font-extrabold text-emerald-800 hover:bg-emerald-100"
                              >
                                <UserCheck className="h-4 w-4" />
                                Activate
                              </button>
                            )}
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>

                <div className="mt-5">
                  <PaginationBar
                    page={safePage}
                    totalPages={totalPages}
                    totalItems={rows.length}
                    onPageChange={setPage}
                  />
                </div>
              </>
            )}
          </Card>
        </div>
      </AdminLayout>
    </ProtectedRoute>
  );
}