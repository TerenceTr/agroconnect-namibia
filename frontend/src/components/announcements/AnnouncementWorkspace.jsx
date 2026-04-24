// ============================================================================
// frontend/src/components/announcements/AnnouncementWorkspace.jsx
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Shared announcement history workspace for customer and farmer dashboards.
//
// PURPOSE:
//   • Shows admin announcements sent through the governance messaging workspace
//   • Keeps announcements separate from customer ↔ farmer conversations
//   • Lets users review, mark read, and clear announcement history
// ============================================================================

import React, { useCallback, useEffect, useMemo, useState } from "react";
import { Bell, CheckCheck, Megaphone, RefreshCw, Trash2 } from "lucide-react";
import { useLocation, useNavigate } from "react-router-dom";

import api from "../../api";
import { connectNotificationsSocket } from "../../services/notificationsSocket";

const MAX_ROWS = 50;

function safeStr(value, fallback = "") {
  const s = String(value ?? "").trim();
  return s || fallback;
}

function safeNumber(value, fallback = 0) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function formatWhen(value) {
  const raw = safeStr(value, "");
  if (!raw) return "just now";
  const dt = new Date(raw);
  if (Number.isNaN(dt.getTime())) return raw;
  return dt.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

function normalizeNotification(raw = {}) {
  const payload = raw?.data_json && typeof raw.data_json === "object" ? raw.data_json : {};
  return {
    notification_id: safeStr(raw?.notification_id || raw?.id, ""),
    title: safeStr(raw?.title || payload?.subject || "Announcement"),
    message: safeStr(raw?.message || payload?.message || ""),
    is_read: Boolean(raw?.is_read),
    created_at: safeStr(raw?.created_at || raw?.updated_at, ""),
    action_url: safeStr(payload?.action_url || raw?.action_url, ""),
    action_label: safeStr(payload?.action_label || raw?.action_label, "Open related area"),
    channels: Array.isArray(payload?.channels) ? payload.channels : [],
    audience_role: safeStr(payload?.audience_role, ""),
    subject: safeStr(payload?.subject, ""),
  };
}

async function listAnnouncements() {
  const resp = await api.get("/api/notifications", { params: { category: "announcements", limit: MAX_ROWS } });
  const root = resp?.data || {};
  const rows = Array.isArray(root?.data) ? root.data : [];
  return {
    rows: rows.map(normalizeNotification).filter((row) => !!row.notification_id),
    unreadCount: safeNumber(root?.unread_by_category?.announcements ?? root?.unread_count, 0),
  };
}

async function markAnnouncementRead(notificationId) {
  if (!safeStr(notificationId, "")) return;
  await api.post("/api/notifications/mark-read", { notification_ids: [notificationId] });
}

async function markAllAnnouncementsRead() {
  await api.post("/api/notifications/mark-read", { mark_all: true, category: "announcements" });
}

async function clearAnnouncementHistory() {
  await api.post("/api/notifications/clear", { clear_all: true, category: "announcements" });
}

export default function AnnouncementWorkspace({
  role = "customer",
  eyebrow = "Platform announcements",
  title = "Announcements",
  description = "Review administrative notices, service updates, and governance announcements in one place.",
}) {
  const navigate = useNavigate();
  const location = useLocation();

  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [unreadCount, setUnreadCount] = useState(0);
  const [selectedId, setSelectedId] = useState("");

  const refresh = useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true);
    setError("");
    try {
      const next = await listAnnouncements();
      setRows(next.rows);
      setUnreadCount(next.unreadCount);
      setSelectedId((current) => {
        const focusId = safeStr(location?.state?.focusNotificationId, "");
        if (focusId && next.rows.some((row) => row.notification_id === focusId)) return focusId;
        if (current && next.rows.some((row) => row.notification_id === current)) return current;
        return safeStr(next.rows?.[0]?.notification_id, "");
      });
    } catch (err) {
      setError(err?.response?.data?.message || err?.message || "Failed to load announcements.");
    } finally {
      if (!quiet) setLoading(false);
    }
  }, [location?.state?.focusNotificationId]);

  useEffect(() => {
    void refresh(false);
  }, [refresh]);

  useEffect(() => {
    const socket = connectNotificationsSocket();
    if (!socket) return () => {};
    const handleChanged = () => { void refresh(true); };
    socket.on("notifications:changed", handleChanged);
    return () => {
      socket.off("notifications:changed", handleChanged);
      socket.disconnect();
    };
  }, [refresh]);

  const selected = useMemo(
    () => rows.find((row) => row.notification_id === selectedId) || rows[0] || null,
    [rows, selectedId]
  );

  const selectRow = useCallback(async (row) => {
    setSelectedId(row.notification_id);
    if (!row?.is_read) {
      try {
        await markAnnouncementRead(row.notification_id);
        setRows((prev) => prev.map((item) => item.notification_id === row.notification_id ? { ...item, is_read: true } : item));
        setUnreadCount((prev) => Math.max(0, prev - 1));
      } catch {
        // Keep selection even if read sync fails.
      }
    }
  }, []);

  const emptyHint = role === "farmer"
    ? "Administrative broadcasts to your seller account will appear here."
    : "Administrative broadcasts to your customer account will appear here.";

  return (
    <div className="space-y-5">
      <section className="rounded-[28px] border border-[#D8F3DC] bg-white px-6 py-5 shadow-sm">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
          <div>
            <div className="text-[11px] font-semibold uppercase tracking-[0.18em] text-[#2D6A4F]">{eyebrow}</div>
            <h1 className="mt-1 text-2xl font-extrabold tracking-tight text-slate-900">{title}</h1>
            <p className="mt-2 max-w-3xl text-sm text-slate-600">{description}</p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <div className="rounded-2xl border border-[#D8F3DC] bg-[#F7FCF9] px-4 py-2 text-sm font-semibold text-slate-700">
              {unreadCount} unread
            </div>
            <button
              type="button"
              onClick={() => refresh(false)}
              className="inline-flex h-11 items-center gap-2 rounded-xl border border-[#D8F3DC] bg-white px-4 text-sm font-semibold text-slate-700 shadow-sm hover:bg-slate-50"
            >
              <RefreshCw className="h-4 w-4" />
              Refresh
            </button>
            <button
              type="button"
              onClick={async () => { await markAllAnnouncementsRead(); await refresh(true); }}
              className="inline-flex h-11 items-center gap-2 rounded-xl border border-[#D8F3DC] bg-white px-4 text-sm font-semibold text-slate-700 shadow-sm hover:bg-slate-50"
            >
              <CheckCheck className="h-4 w-4" />
              Read all
            </button>
            <button
              type="button"
              onClick={async () => { await clearAnnouncementHistory(); await refresh(true); }}
              className="inline-flex h-11 items-center gap-2 rounded-xl border border-slate-200 bg-white px-4 text-sm font-semibold text-slate-700 shadow-sm hover:bg-slate-50"
            >
              <Trash2 className="h-4 w-4" />
              Clear
            </button>
          </div>
        </div>
      </section>

      <div className="grid gap-5 xl:grid-cols-[360px_minmax(0,1fr)]">
        <section className="rounded-[28px] border border-[#D8F3DC] bg-white shadow-sm">
          <div className="border-b border-slate-100 px-5 py-4">
            <h2 className="text-lg font-bold text-slate-900">Announcement history</h2>
            <p className="mt-1 text-sm text-slate-500">Administrative notices, service changes, and platform-wide updates.</p>
          </div>

          <div className="max-h-[620px] overflow-auto p-4">
            {loading ? (
              <div className="rounded-2xl border border-dashed border-slate-200 bg-slate-50 px-4 py-10 text-center text-sm text-slate-500">Loading announcements…</div>
            ) : error ? (
              <div className="rounded-2xl border border-rose-200 bg-rose-50 px-4 py-6 text-sm text-rose-700">{error}</div>
            ) : rows.length ? (
              <div className="space-y-3">
                {rows.map((row) => {
                  const active = row.notification_id === selected?.notification_id;
                  return (
                    <button
                      key={row.notification_id}
                      type="button"
                      onClick={() => selectRow(row)}
                      className={[
                        "w-full rounded-2xl border px-4 py-4 text-left transition",
                        active
                          ? "border-[#95D5B2] bg-[#F7FCF9] shadow-sm"
                          : "border-slate-200 bg-white hover:border-[#D8F3DC] hover:bg-slate-50",
                      ].join(" ")}
                    >
                      <div className="flex items-start justify-between gap-3">
                        <div className="min-w-0">
                          <div className="flex items-center gap-2">
                            <Megaphone className="h-4 w-4 text-[#2D6A4F]" />
                            <div className="truncate text-sm font-bold text-slate-900">{row.title}</div>
                            {!row.is_read ? <span className="rounded-full bg-emerald-100 px-2 py-0.5 text-[10px] font-bold uppercase tracking-wide text-emerald-700">New</span> : null}
                          </div>
                          <div className="mt-2 line-clamp-2 text-sm text-slate-600">{row.message || row.subject || "Administrative announcement"}</div>
                        </div>
                        <div className="whitespace-nowrap text-xs text-slate-400">{formatWhen(row.created_at)}</div>
                      </div>
                    </button>
                  );
                })}
              </div>
            ) : (
              <div className="rounded-2xl border border-dashed border-[#D8F3DC] bg-[#F7FCF9] px-4 py-10 text-center">
                <div className="mx-auto mb-3 grid h-12 w-12 place-items-center rounded-2xl border border-[#D8F3DC] bg-white">
                  <Bell className="h-5 w-5 text-[#2D6A4F]" />
                </div>
                <div className="text-sm font-semibold text-slate-800">No announcements yet</div>
                <div className="mt-1 text-sm text-slate-500">{emptyHint}</div>
              </div>
            )}
          </div>
        </section>

        <section className="rounded-[28px] border border-[#D8F3DC] bg-white shadow-sm">
          <div className="border-b border-slate-100 px-5 py-4">
            <h2 className="text-lg font-bold text-slate-900">Announcement detail</h2>
            <p className="mt-1 text-sm text-slate-500">Read the full notice and follow the linked workspace when action is required.</p>
          </div>

          <div className="p-5">
            {selected ? (
              <div className="space-y-4">
                <div className="rounded-3xl border border-[#D8F3DC] bg-[#F7FCF9] p-5">
                  <div className="text-[11px] font-semibold uppercase tracking-[0.18em] text-[#2D6A4F]">AgroConnect notice</div>
                  <h3 className="mt-2 text-2xl font-extrabold tracking-tight text-slate-900">{selected.title}</h3>
                  <div className="mt-2 text-sm text-slate-500">Received {formatWhen(selected.created_at)}</div>
                </div>

                <div className="rounded-3xl border border-slate-200 bg-white p-5">
                  <div className="whitespace-pre-wrap text-sm leading-7 text-slate-700">{selected.message || "No message body was stored for this announcement."}</div>
                </div>

                <div className="grid gap-4 md:grid-cols-3">
                  <div className="rounded-2xl border border-slate-200 bg-white p-4">
                    <div className="text-[11px] font-semibold uppercase tracking-[0.16em] text-slate-500">Delivery channels</div>
                    <div className="mt-2 text-sm font-semibold text-slate-900">{selected.channels.length ? selected.channels.join(", ") : "In-app"}</div>
                  </div>
                  <div className="rounded-2xl border border-slate-200 bg-white p-4">
                    <div className="text-[11px] font-semibold uppercase tracking-[0.16em] text-slate-500">Audience</div>
                    <div className="mt-2 text-sm font-semibold text-slate-900">{safeStr(selected.audience_role, "Direct recipient")}</div>
                  </div>
                  <div className="rounded-2xl border border-slate-200 bg-white p-4">
                    <div className="text-[11px] font-semibold uppercase tracking-[0.16em] text-slate-500">Action</div>
                    <button
                      type="button"
                      onClick={() => {
                        if (selected.action_url) navigate(selected.action_url);
                      }}
                      disabled={!selected.action_url}
                      className="mt-2 inline-flex h-10 items-center rounded-xl border border-[#D8F3DC] bg-white px-4 text-sm font-semibold text-slate-800 disabled:cursor-not-allowed disabled:opacity-50 hover:bg-slate-50"
                    >
                      {safeStr(selected.action_label, "Open related area")}
                    </button>
                  </div>
                </div>
              </div>
            ) : (
              <div className="rounded-2xl border border-dashed border-slate-200 bg-slate-50 px-4 py-16 text-center text-sm text-slate-500">Select an announcement from the left panel.</div>
            )}
          </div>
        </section>
      </div>
    </div>
  );
}
