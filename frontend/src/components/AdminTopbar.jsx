// ============================================================================
// frontend/src/components/AdminTopbar.jsx
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Fixed admin header for all admin pages.
//   • Mobile drawer trigger
//   • Route-aware page title
//   • Server-backed admin notifications bell
//   • Admin account menu
//
// THIS UPDATE:
//   ✅ Adds an admin notification bell with unread badge
//   ✅ Uses backend notifications endpoints already present in the system
//   ✅ Routes product notifications to Moderation and order notifications to
//      the Admin order detail page when possible
//   ✅ Keeps the header clean, compact, and professional
// ============================================================================

import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import {
  Menu,
  ChevronDown,
  LogOut,
  Bell,
  CheckCheck,
  Trash2,
  Package,
  FileText,
  ShieldAlert,
  ShoppingBasket,
} from "lucide-react";

import api from "../api";

const POLL_MS = 30000;
const MAX_NOTIFICATIONS = 8;

const titleMap = [
  { match: "/dashboard/admin/users", title: "Users" },
  { match: "/dashboard/admin/moderation", title: "Moderation" },
  { match: "/dashboard/admin/analytics", title: "Analytics" },
  { match: "/dashboard/admin/audit-log", title: "Audit Log" },
  { match: "/dashboard/admin/reports", title: "Reports & Analytics" },
  { match: "/dashboard/admin/messaging", title: "Messaging & Broadcasts" },
  { match: "/dashboard/admin/settings", title: "System Settings" },
  { match: "/dashboard/admin", title: "Admin Dashboard" },
];

function safeStr(v, fallback = "") {
  if (typeof v === "string") return v;
  if (v == null) return fallback;
  return String(v);
}

function safeNumber(v, fallback = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

function safeObj(v) {
  return v && typeof v === "object" ? v : {};
}

function initials(name) {
  const s = String(name || "").trim();
  if (!s) return "AD";
  const parts = s.split(/\s+/).slice(0, 2);
  return parts.map((p) => p[0]?.toUpperCase()).join("") || "AD";
}

function fmtRelative(iso) {
  try {
    if (!iso) return "";
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return "";
    const diffMs = Date.now() - d.getTime();
    const mins = Math.max(0, Math.round(diffMs / 60000));
    if (mins < 1) return "Just now";
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.round(mins / 60);
    if (hrs < 24) return `${hrs}h ago`;
    const days = Math.round(hrs / 24);
    return `${days}d ago`;
  } catch {
    return "";
  }
}

function normalizeNotificationEntry(raw) {
  const row = safeObj(raw);
  const data = safeObj(row.data || row.data_json);

  return {
    notification_id: safeStr(row.notification_id || row.id, ""),
    type: safeStr(row.type || row.notification_type, "system"),
    title: safeStr(row.title, "Notification"),
    message: safeStr(row.message, ""),
    event_key: safeStr(row.event_key, ""),
    order_id: safeStr(row.order_id || data.order_id || data.oid, ""),
    product_id: safeStr(row.product_id || data.product_id, ""),
    is_read: Boolean(row.is_read),
    created_at: safeStr(row.created_at || row.received_at || row.updated_at, ""),
    data,
  };
}

function parseNotificationsResponse(resp) {
  const root = safeObj(resp?.data);
  const data = safeObj(root.data || root.items || root.rows || root);

  const rows = Array.isArray(data.notifications)
    ? data.notifications
    : Array.isArray(root.notifications)
      ? root.notifications
      : Array.isArray(data)
        ? data
        : [];

  return {
    notifications: rows.map(normalizeNotificationEntry).filter((x) => !!x.notification_id),
    unread_count: safeNumber(root.unread_count ?? data.unread_count ?? root.meta?.unread_count ?? 0, 0),
  };
}

function notificationIcon(n) {
  const type = safeStr(n?.type, "system").toLowerCase();
  if (type.includes("payment") || type.includes("proof")) return FileText;
  if (type.includes("product") || type.includes("listing") || type.includes("moderation")) return ShieldAlert;
  if (type.includes("order")) return ShoppingBasket;
  return Package;
}

function notificationTitle(n) {
  if (n?.title) return n.title;
  const type = safeStr(n?.type, "system").toLowerCase();
  if (type.includes("product") && type.includes("rejected")) return "Product listing rejected";
  if (type.includes("product") && type.includes("approved")) return "Product listing approved";
  if (type.includes("product") || type.includes("listing")) return "Product listing update";
  if (type.includes("payment") || type.includes("proof")) return "Payment evidence notification";
  if (type.includes("order")) return "Order notification";
  return "Notification";
}

function notificationSubtitle(n) {
  if (n?.message) return n.message;

  const data = safeObj(n?.data);
  const productName = safeStr(data.product_name || data.name, "");
  const buyer = safeStr(data.buyer || data.customer_name, "");
  const oid = safeStr(n?.order_id || data.oid, "");

  if (productName) return productName;
  if (buyer) return `Buyer: ${buyer}`;
  if (oid) return `Order: ${oid}`;
  return "Open notification";
}

function notificationActionText(n) {
  const type = safeStr(n?.type, "system").toLowerCase();
  if (type.includes("product") || type.includes("listing") || type.includes("moderation")) {
    return "Opens moderation";
  }
  if (type.includes("order") || type.includes("payment") || type.includes("proof")) {
    return "Opens order detail";
  }
  return "Open notification";
}

async function getNotificationsFromServer(limit = MAX_NOTIFICATIONS) {
  const candidates = [
    "/notifications/me",
    "/notifications",
  ];

  let lastErr = null;
  for (const path of candidates) {
    try {
      const resp = await api.get(path, {
        params: {
          limit,
          unread_only: 0,
        },
      });
      return parseNotificationsResponse(resp);
    } catch (err) {
      lastErr = err;
      const status = err?.response?.status;
      if (status && ![404, 405].includes(status)) break;
    }
  }

  throw lastErr;
}

async function markNotificationsReadServer(notificationIds = [], markAll = false) {
  const ids = Array.isArray(notificationIds)
    ? notificationIds.map((x) => safeStr(x, "")).filter(Boolean)
    : [];

  const candidates = [
    "/notifications/mark-read",
    "/notifications/mark_read",
  ];

  let lastErr = null;
  for (const path of candidates) {
    try {
      const resp = await api.post(path, {
        notification_ids: ids,
        mark_all: Boolean(markAll),
      });
      return resp?.data ?? {};
    } catch (err) {
      lastErr = err;
      const status = err?.response?.status;
      if (status && ![404, 405].includes(status)) break;
    }
  }

  throw lastErr;
}

async function clearNotificationsServer(notificationIds = [], clearAll = false) {
  const ids = Array.isArray(notificationIds)
    ? notificationIds.map((x) => safeStr(x, "")).filter(Boolean)
    : [];

  const candidates = [
    "/notifications/clear",
  ];

  let lastErr = null;
  for (const path of candidates) {
    try {
      const resp = await api.post(path, {
        notification_ids: ids,
        clear_all: Boolean(clearAll),
      });
      return resp?.data ?? {};
    } catch (err) {
      lastErr = err;
      const status = err?.response?.status;
      if (status && ![404, 405].includes(status)) break;
    }
  }

  throw lastErr;
}

export default function AdminTopbar({
  adminName = "Admin",
  onOpenDrawer,
  onLogout,
}) {
  const { pathname } = useLocation();
  const navigate = useNavigate();

  const [openUserMenu, setOpenUserMenu] = useState(false);
  const [openNotifMenu, setOpenNotifMenu] = useState(false);
  const [notifications, setNotifications] = useState([]);
  const [unreadCount, setUnreadCount] = useState(0);
  const [loadingNotifications, setLoadingNotifications] = useState(false);
  const [notificationsError, setNotificationsError] = useState("");

  const ref = useRef(null);

  const pageTitle = useMemo(() => {
    const hit = titleMap.find((t) => pathname.startsWith(t.match));
    return hit?.title || "Admin";
  }, [pathname]);

  const hasUnread = unreadCount > 0;
  const hasNotifications = Array.isArray(notifications) && notifications.length > 0;

  const closeMenus = useCallback(() => {
    setOpenNotifMenu(false);
    setOpenUserMenu(false);
  }, []);

  const refreshNotifications = useCallback(async (silent = false) => {
    if (!silent) setLoadingNotifications(true);
    setNotificationsError("");

    try {
      const payload = await getNotificationsFromServer(MAX_NOTIFICATIONS);
      setNotifications(Array.isArray(payload.notifications) ? payload.notifications : []);
      setUnreadCount(safeNumber(payload.unread_count, 0));
    } catch (err) {
      setNotificationsError(
        err?.response?.data?.message ||
          err?.message ||
          "Failed to load notifications."
      );
    } finally {
      if (!silent) setLoadingNotifications(false);
    }
  }, []);

  const markAllRead = useCallback(async () => {
    try {
      await markNotificationsReadServer([], true);
      setNotifications((prev) => (Array.isArray(prev) ? prev.map((n) => ({ ...n, is_read: true })) : []));
      setUnreadCount(0);
    } catch (err) {
      setNotificationsError(
        err?.response?.data?.message ||
          err?.message ||
          "Failed to mark notifications as read."
      );
    }
  }, []);

  const clearNotifications = useCallback(async () => {
    try {
      await clearNotificationsServer([], true);
      setNotifications([]);
      setUnreadCount(0);
    } catch (err) {
      setNotificationsError(
        err?.response?.data?.message ||
          err?.message ||
          "Failed to clear notifications."
      );
    }
  }, []);

  const handleNotificationClick = useCallback(
    async (n) => {
      const type = safeStr(n?.type, "system").toLowerCase();
      const oid = safeStr(n?.order_id || n?.data?.order_id || n?.data?.oid, "");

      try {
        if (safeStr(n?.notification_id, "")) {
          await markNotificationsReadServer([n.notification_id], false);
        }
      } catch {
        // Do not block navigation.
      }

      setNotifications((prev) =>
        Array.isArray(prev)
          ? prev.map((row) =>
              row.notification_id === n.notification_id ? { ...row, is_read: true } : row
            )
          : []
      );
      setUnreadCount((prev) => Math.max(0, prev - (n?.is_read ? 0 : 1)));
      closeMenus();

      if ((type.includes("product") || type.includes("listing") || type.includes("moderation")) && !pathname.includes("/dashboard/admin/moderation")) {
        navigate("/dashboard/admin/moderation");
        return;
      }

      if ((type.includes("order") || type.includes("payment") || type.includes("proof")) && oid) {
        navigate(`/dashboard/admin/orders/${oid}`);
        return;
      }

      navigate("/dashboard/admin/analytics");
    },
    [closeMenus, navigate, pathname]
  );

  useEffect(() => {
    const onDoc = (e) => {
      if (!ref.current) return;
      if (!ref.current.contains(e.target)) closeMenus();
    };

    const onKey = (e) => {
      if (e.key === "Escape") closeMenus();
    };

    document.addEventListener("mousedown", onDoc);
    document.addEventListener("keydown", onKey);

    return () => {
      document.removeEventListener("mousedown", onDoc);
      document.removeEventListener("keydown", onKey);
    };
  }, [closeMenus]);

  useEffect(() => {
    let alive = true;
    let timerId = null;

    const run = async () => {
      if (!alive) return;
      await refreshNotifications(true);
    };

    refreshNotifications(false);
    timerId = window.setInterval(run, POLL_MS);

    return () => {
      alive = false;
      if (timerId) window.clearInterval(timerId);
    };
  }, [refreshNotifications]);

  return (
    <header className="border-b border-[#D8F3DC] bg-white/90 backdrop-blur-md shadow-[0_8px_24px_rgba(15,23,42,0.05)]">
      <div className="mx-auto flex w-full max-w-[1400px] items-center justify-between gap-3 px-4 py-3 md:px-6">
        <div className="flex min-w-0 items-center gap-3">
          <button
            type="button"
            onClick={onOpenDrawer}
            className="grid h-10 w-10 place-items-center rounded-xl border border-[#D8F3DC] bg-white transition hover:bg-slate-50 lg:hidden"
            aria-label="Open menu"
          >
            <Menu className="h-5 w-5 text-slate-700" />
          </button>

          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <span className="inline-block h-6 w-1.5 rounded-full bg-[#40916C]" />
              <div className="text-sm text-slate-500">AgroConnect Namibia</div>
            </div>

            <h1 className="truncate text-lg font-bold text-slate-800 md:text-xl">
              {pageTitle}
            </h1>
          </div>
        </div>

        <div className="relative flex items-center gap-2" ref={ref}>
          <div className="relative">
            <button
              type="button"
              onClick={() => {
                setOpenUserMenu(false);
                setOpenNotifMenu((v) => !v);
              }}
              className="relative grid h-10 w-10 place-items-center rounded-xl border border-[#D8F3DC] bg-white transition hover:bg-slate-50"
              aria-label="Admin notifications"
              aria-haspopup="menu"
              aria-expanded={openNotifMenu}
              title={hasUnread ? `${unreadCount} new notification(s)` : "Admin notifications"}
            >
              <Bell className="h-5 w-5 text-slate-700" />
              {hasUnread ? (
                <span className="absolute -right-1 -top-1 grid h-5 min-w-[20px] place-items-center rounded-full border border-white bg-rose-500 px-1 text-[10px] font-bold text-white">
                  {unreadCount > 99 ? "99+" : unreadCount}
                </span>
              ) : null}
            </button>

            {openNotifMenu ? (
              <div className="absolute right-0 mt-2 w-[400px] max-w-[92vw] overflow-hidden rounded-2xl border border-[#D8F3DC] bg-white shadow-lg">
                <div className="flex items-center justify-between border-b border-slate-100 px-4 py-3">
                  <div>
                    <div className="text-sm font-bold text-slate-800">Admin notifications</div>
                    <div className="text-xs text-slate-500">
                      {hasUnread ? `${unreadCount} unread` : "No unread notifications"}
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={markAllRead}
                      className="inline-flex items-center gap-1 rounded-lg border border-slate-200 px-2 py-1 text-xs font-semibold text-slate-700 hover:bg-slate-50"
                      title="Mark all as read"
                    >
                      <CheckCheck className="h-3.5 w-3.5" />
                      Read
                    </button>

                    <button
                      type="button"
                      onClick={clearNotifications}
                      className="inline-flex items-center gap-1 rounded-lg border border-slate-200 px-2 py-1 text-xs font-semibold text-slate-700 hover:bg-slate-50"
                      title="Clear notification items"
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                      Clear
                    </button>
                  </div>
                </div>

                <div className="max-h-[380px] overflow-auto">
                  {loadingNotifications ? (
                    <div className="px-4 py-6 text-sm font-semibold text-slate-500">Loading notifications…</div>
                  ) : notificationsError ? (
                    <div className="px-4 py-6 text-sm font-semibold text-rose-600">{notificationsError}</div>
                  ) : hasNotifications ? (
                    notifications.map((n, idx) => {
                      const Icon = notificationIcon(n);
                      const type = safeStr(n?.type, "system").toLowerCase();
                      const isProduct = type.includes("product") || type.includes("listing") || type.includes("moderation");

                      return (
                        <button
                          key={`${safeStr(n?.event_key, idx)}-${idx}`}
                          type="button"
                          onClick={() => handleNotificationClick(n)}
                          className="w-full border-b border-slate-100 px-4 py-3 text-left hover:bg-slate-50"
                          title={notificationActionText(n)}
                        >
                          <div className="flex items-start gap-3">
                            <div
                              className={`mt-0.5 grid h-9 w-9 shrink-0 place-items-center rounded-xl border ${
                                isProduct
                                  ? "border-amber-200 bg-amber-50 text-amber-700"
                                  : "border-emerald-200 bg-emerald-50 text-emerald-700"
                              }`}
                            >
                              <Icon className="h-4 w-4" />
                            </div>

                            <div className="min-w-0 flex-1">
                              <div className="flex items-start justify-between gap-3">
                                <div className="min-w-0">
                                  <div className="truncate text-sm font-bold text-slate-900">
                                    {notificationTitle(n)}
                                  </div>
                                  <div className="mt-1 text-xs text-slate-500 line-clamp-2">
                                    {notificationSubtitle(n)}
                                  </div>
                                </div>

                                <div className="shrink-0 text-[11px] font-bold text-slate-400">
                                  {fmtRelative(n?.created_at)}
                                </div>
                              </div>

                              <div className="mt-2 flex items-center gap-2">
                                {!n?.is_read ? (
                                  <span className="inline-flex rounded-full bg-rose-50 px-2 py-0.5 text-[10px] font-bold text-rose-700 ring-1 ring-rose-200">
                                    New
                                  </span>
                                ) : null}
                                <span className="text-[11px] font-semibold text-slate-500">
                                  {notificationActionText(n)}
                                </span>
                              </div>
                            </div>
                          </div>
                        </button>
                      );
                    })
                  ) : (
                    <div className="px-4 py-8 text-center text-sm text-slate-500">
                      No notifications yet.
                    </div>
                  )}
                </div>
              </div>
            ) : null}
          </div>

          <div className="relative">
            <button
              type="button"
              onClick={() => {
                setOpenNotifMenu(false);
                setOpenUserMenu((v) => !v);
              }}
              className="flex items-center gap-3 rounded-2xl border border-[#D8F3DC] bg-white px-3 py-2 transition hover:bg-slate-50"
              aria-haspopup="menu"
              aria-expanded={openUserMenu}
            >
              <div className="grid h-10 w-10 place-items-center rounded-full border border-[#B7E4C7] bg-[#EAF7F0] font-bold text-[#2D6A4F]">
                {initials(adminName)}
              </div>

              <div className="hidden text-left sm:block">
                <div className="max-w-[220px] truncate text-sm font-semibold text-slate-800">
                  {adminName}
                </div>
                <div className="text-xs text-slate-500">Administrator</div>
              </div>

              <ChevronDown className="h-4 w-4 text-slate-600" />
            </button>

            {openUserMenu ? (
              <div className="absolute right-0 mt-2 w-52 overflow-hidden rounded-2xl border border-[#D8F3DC] bg-white shadow-lg">
                <button
                  type="button"
                  onClick={() => {
                    setOpenUserMenu(false);
                    onLogout?.();
                  }}
                  className="flex w-full items-center gap-2 px-4 py-3 text-left text-sm text-slate-700 hover:bg-slate-50"
                >
                  <LogOut className="h-4 w-4 text-slate-600" />
                  Logout
                </button>
              </div>
            ) : null}
          </div>
        </div>
      </div>
    </header>
  );
}