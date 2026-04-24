// ============================================================================
// src/components/FarmerTopbar.jsx — Header Bar for Farmer Console
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Farmer top navigation bar.
//   • Mobile drawer trigger
//   • Brand label
//   • User dropdown with logout action
//   • Server-persisted farmer notification bell + dropdown
//
// THIS VERSION:
//   ✅ Splits farmer notifications into Orders / Messages / Moderation
//   ✅ Keeps one clean bell with tabbed filtering instead of cluttering the bar
//   ✅ Uses unread counts by category from the backend when available
//   ✅ Marks page-relevant categories as read when the farmer is already there
//   ✅ Respects communications.in_app_notifications_enabled
//   ✅ Routes order/payment notifications to Orders
//   ✅ Routes seller/admin communication notifications to Messages
//   ✅ Routes product moderation notifications to Products
// ============================================================================

import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Menu,
  User,
  LogOut,
  ChevronDown,
  Bell,
  BellOff,
  CheckCheck,
  Trash2,
  Package,
  FileText,
  ArrowRight,
  Loader2,
  Megaphone,
  MessageSquareText,
  ShieldCheck,
  ClipboardList,
} from "lucide-react";
import { useLocation, useNavigate } from "react-router-dom";
import api from "../api";
import usePublicSystemSettings from "../hooks/usePublicSystemSettings";
import { connectNotificationsSocket } from "../services/notificationsSocket";

// -----------------------------------------------------------------------------
// Shared routes + focus routing constants
// -----------------------------------------------------------------------------
const FARMER_ORDERS_ROUTE = "/dashboard/farmer/orders";
const FARMER_PRODUCTS_ROUTE = "/dashboard/farmer/products";
const FARMER_MESSAGES_ROUTE = "/dashboard/farmer/messages";
const FARMER_ANNOUNCEMENTS_ROUTE = "/dashboard/farmer/announcements";
const FARMER_NOTIFICATION_FOCUS_EVENT = "agroconnect:farmer-notification-focus";
const FOCUS_SECTION_ORDER_SUMMARY = "order_summary";
const FOCUS_SECTION_PAYMENT_EVIDENCE = "payment_evidence";

const STORAGE_KEYS = {
  focusOrderId: "agroconnect_farmer_focus_order_id",
  focusContext: "agroconnect_farmer_focus_order_context",
};

const POLL_MS = 30000;
const MAX_NOTIFICATIONS = 30;
const NOTIFICATION_TABS = [
  { key: "all", label: "All", icon: Bell },
  { key: "orders", label: "Orders", icon: ClipboardList },
  { key: "announcements", label: "Admin", icon: Megaphone },
  { key: "messages", label: "Messages", icon: MessageSquareText },
  { key: "moderation", label: "Moderation", icon: ShieldCheck },
];

// -----------------------------------------------------------------------------
// Generic helpers
// -----------------------------------------------------------------------------
function safeStr(v, fallback = "") {
  const s = String(v ?? "").trim();
  return s || fallback;
}

function safeNumber(v, fallback = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

function ensureLeadingSlash(p) {
  const s = String(p || "").trim();
  if (!s) return "";
  return s.startsWith("/") ? s : `/${s}`;
}

function apiPath(p) {
  const path = ensureLeadingSlash(p);
  if (!path) return path;

  const base = String(api?.defaults?.baseURL || "");
  const baseEndsWithApi = /\/api\/?$/.test(base);

  if (baseEndsWithApi && path.startsWith("/api/")) return path.replace(/^\/api/, "");
  return path;
}

function tryParseJson(raw, fallback = null) {
  try {
    return JSON.parse(String(raw));
  } catch {
    return fallback;
  }
}

function hasMeaningfulMoney(v) {
  return Number.isFinite(Number(v)) && Number(v) > 0;
}

function formatMoney(v) {
  const n = safeNumber(v, 0);
  return `N$ ${n.toFixed(2)}`;
}

function formatWhen(v) {
  const raw = safeStr(v, "");
  if (!raw) return "just now";

  const dt = new Date(raw);
  if (Number.isNaN(dt.getTime())) return "just now";

  const diffMs = Date.now() - dt.getTime();
  const diffMin = Math.floor(diffMs / 60000);

  if (diffMin < 1) return "just now";
  if (diffMin < 60) return `${diffMin}m ago`;

  const diffHr = Math.floor(diffMin / 60);
  if (diffHr < 24) return `${diffHr}h ago`;

  const diffDay = Math.floor(diffHr / 24);
  if (diffDay < 7) return `${diffDay}d ago`;

  return dt.toLocaleDateString();
}

// -----------------------------------------------------------------------------
// Backend-origin helper
// -----------------------------------------------------------------------------
function getBackendRoot() {
  const base =
    safeStr(api?.defaults?.baseURL, "") ||
    safeStr(process.env.REACT_APP_API_BASE_URL, "") ||
    safeStr(process.env.REACT_APP_API_URL, "") ||
    safeStr(process.env.REACT_APP_BACKEND_URL, "");

  if (!base) return "";
  return base.replace(/\/api\/?$/i, "").replace(/\/+$/, "");
}

function normalizeProofHref(url) {
  const raw = safeStr(url, "").trim();
  if (!raw) return "";

  if (/^(https?:)?\/\//i.test(raw) || raw.startsWith("blob:") || raw.startsWith("data:")) {
    return raw;
  }

  const backendRoot = getBackendRoot();
  const path = (raw.startsWith("/") ? raw : `/${raw}`).replace(/^\/api\/api\//, "/api/");

  if (backendRoot && (path.startsWith("/api/") || path.startsWith("/uploads/"))) {
    return `${backendRoot}${path}`;
  }

  return path;
}

// -----------------------------------------------------------------------------
// Notification normalization
// -----------------------------------------------------------------------------
function extractNotificationPayload(raw = {}) {
  const candidates = [raw?.data_json, raw?.data, raw?.metadata, raw?.meta, null];

  for (const value of candidates) {
    if (value && typeof value === "object" && !Array.isArray(value)) return value;
    if (typeof value === "string") {
      const parsed = tryParseJson(value, null);
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) return parsed;
    }
  }

  return {};
}

function normalizeNotificationCategory(type, explicitCategory = "") {
  const explicit = safeStr(explicitCategory, "").toLowerCase();
  if (["orders", "messages", "moderation", "announcements", "announcement"].includes(explicit)) return explicit.startsWith("announcement") ? "announcements" : explicit;

  const t = safeStr(type, "system").toLowerCase();
  if (["product_review", "product_approved", "product_rejected", "product_edit_required", "policy_flagged"].includes(t)) {
    return "moderation";
  }
  if (["admin_message", "admin_announcement", "announcement", "broadcast"].includes(t)) {
    return "announcements";
  }
  if (["support_reply", "customer_message_received"].includes(t)) {
    return "messages";
  }
  return "orders";
}

function normalizeNotificationEntry(raw = {}) {
  const payload = extractNotificationPayload(raw);
  const type = safeStr(raw?.notification_type || raw?.type || payload?.type, "system");

  return {
    notification_id: safeStr(raw?.notification_id || raw?.id || raw?.notificationId, ""),
    event_key: safeStr(raw?.event_key || payload?.event_key, safeStr(raw?.notification_id || raw?.id, "")),
    type,
    category: normalizeNotificationCategory(type, raw?.category || payload?.category),
    oid: safeStr(raw?.order_id || raw?.orderId || payload?.order_id || payload?.orderId || payload?.oid, ""),
    title: safeStr(raw?.title || payload?.title, ""),
    message: safeStr(raw?.message || payload?.message, ""),
    buyer: safeStr(payload?.buyer || payload?.buyer_name || payload?.customer_name || "Customer"),
    total: safeNumber(payload?.total ?? payload?.grand_total ?? payload?.order_total ?? payload?.total_amount, 0),
    proof_name: safeStr(payload?.proof_name || payload?.payment_proof_name, ""),
    payment_reference: safeStr(payload?.payment_reference || payload?.reference, ""),
    payment_proof_url: normalizeProofHref(payload?.payment_proof_url || payload?.proof_url || ""),
    product_id: safeStr(payload?.product_id, ""),
    product_name: safeStr(payload?.product_name, ""),
    action_url: safeStr(payload?.action_url || payload?.route || payload?.href, ""),
    action_label: safeStr(payload?.action_label, ""),
    show_total: payload?.show_total,
    is_read: Boolean(raw?.is_read),
    received_at: safeStr(raw?.created_at || raw?.received_at || raw?.updated_at, ""),
  };
}

function parseNotificationsResponse(resp) {
  const root = resp?.data ?? {};
  const data = root?.data ?? root?.items ?? root?.rows ?? root ?? {};
  const rows = Array.isArray(data)
    ? data
    : Array.isArray(data?.notifications)
      ? data.notifications
      : Array.isArray(root?.notifications)
        ? root.notifications
        : [];

  const unreadByCategory = root?.unread_by_category ?? data?.unread_by_category ?? {};

  return {
    notifications: rows.map(normalizeNotificationEntry).filter((x) => !!x.notification_id),
    unread_count: safeNumber(root?.unread_count ?? data?.unread_count ?? root?.meta?.unread_count ?? 0, 0),
    unread_by_category: {
      orders: safeNumber(unreadByCategory?.orders, 0),
      messages: safeNumber(unreadByCategory?.messages, 0),
      moderation: safeNumber(unreadByCategory?.moderation, 0),
      announcements: safeNumber(unreadByCategory?.announcements, 0),
    },
  };
}

function isAnnouncementType(type) {
  const t = safeStr(type, "system");
  return ["admin_announcement", "admin_message", "announcement", "broadcast"].includes(t);
}

function shouldShowTotal(n) {
  if (typeof n?.show_total === "boolean") return n.show_total && hasMeaningfulMoney(n?.total);
  if (n?.category !== "orders") return false;
  return hasMeaningfulMoney(n?.total);
}

function notificationTitleText(n) {
  if (n?.title) return n.title;

  const type = safeStr(n?.type, "system");
  if (type === "payment_proof") return `Payment evidence uploaded for ${safeStr(n?.oid, "order")}`;
  if (type === "new_order") return `New order ${safeStr(n?.oid, "—")}`;
  if (type === "order_ready_for_payment") return `Order ${safeStr(n?.oid, "—")} ready for payment`;
  if (type === "product_approved") return "Product listing approved";
  if (type === "product_rejected") return "Product listing rejected";
  if (type === "product_review") return "Product review update";
  if (n?.category === "messages") return "New message received";
  return "Notification";
}

function notificationSubtitleText(n) {
  if (n?.message) return n.message;
  const type = safeStr(n?.type, "system");

  if (type === "payment_proof") {
    const ref = safeStr(n?.payment_reference, "");
    const proofName = safeStr(n?.proof_name, "");
    if (proofName && ref) return `Customer uploaded ${proofName} • Ref: ${ref}`;
    if (proofName) return `Customer uploaded ${proofName}`;
    if (ref) return `Customer uploaded proof • Ref: ${ref}`;
    return "Customer uploaded proof of payment";
  }

  if (type === "new_order") return `Buyer: ${safeStr(n?.buyer, "Customer")}`;
  if (n?.category === "moderation") return "Opens your product management workspace";
  if (n?.category === "messages") return "Opens your farmer inbox";
  if (isAnnouncementType(type)) return "Administrative platform communication";
  return `Order: ${safeStr(n?.oid, "—")}`;
}

function notificationActionText(n) {
  if (n?.category === "messages") return "Open inbox";
  if (n?.category === "moderation") return "Open product moderation";
  if (safeStr(n?.type, "") === "payment_proof") return "Open payment evidence";
  return "Open order details";
}

function notificationIcon(n) {
  if (n?.category === "messages") return MessageSquareText;
  if (n?.category === "moderation") return ShieldCheck;
  if (safeStr(n?.type, "") === "payment_proof") return FileText;
  if (isAnnouncementType(n?.type)) return Megaphone;
  return Package;
}

function categoryTone(category) {
  if (category === "messages") return "border-indigo-200 bg-indigo-50 text-indigo-700";
  if (category === "moderation") return "border-amber-200 bg-amber-50 text-amber-700";
  return "border-emerald-200 bg-emerald-50 text-emerald-700";
}

// -----------------------------------------------------------------------------
// Backend API helpers
// -----------------------------------------------------------------------------
async function getNotificationsFromServer(limit = MAX_NOTIFICATIONS, category = "") {
  const candidates = ["/api/notifications/me", "/notifications/me", "/api/notifications", "/notifications"];
  let lastErr = null;

  for (const path of candidates) {
    try {
      const resp = await api.get(apiPath(path), {
        params: {
          limit,
          unread_only: 0,
          ...(category && category !== "all" ? { category } : {}),
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

async function markNotificationsReadServer(notificationIds = [], markAll = false, category = "") {
  const ids = Array.isArray(notificationIds) ? notificationIds.map((x) => safeStr(x, "")).filter(Boolean) : [];
  const candidates = ["/api/notifications/mark-read", "/notifications/mark-read", "/api/notifications/mark_read", "/notifications/mark_read"];
  let lastErr = null;

  for (const path of candidates) {
    try {
      const resp = await api.post(apiPath(path), {
        notification_ids: ids,
        mark_all: Boolean(markAll),
        ...(category && category !== "all" ? { category } : {}),
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

async function clearNotificationsServer(notificationIds = [], clearAll = false, category = "") {
  const ids = Array.isArray(notificationIds) ? notificationIds.map((x) => safeStr(x, "")).filter(Boolean) : [];
  const candidates = ["/api/notifications/clear", "/notifications/clear"];
  let lastErr = null;

  for (const path of candidates) {
    try {
      const resp = await api.post(apiPath(path), {
        notification_ids: ids,
        clear_all: Boolean(clearAll),
        ...(category && category !== "all" ? { category } : {}),
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

export default function FarmerTopbar({ farmerName = "Farmer", onOpenDrawer, onLogout }) {
  const navigate = useNavigate();
  const location = useLocation();
  const rootRef = useRef(null);

  const { helpers, loading: settingsLoading } = usePublicSystemSettings();
  const notificationsEnabled = helpers?.notificationsEnabled ?? true;

  const [openUserMenu, setOpenUserMenu] = useState(false);
  const [openNotifMenu, setOpenNotifMenu] = useState(false);
  const [activeNotifTab, setActiveNotifTab] = useState("all");

  const [loadingNotifications, setLoadingNotifications] = useState(false);
  const [notificationsError, setNotificationsError] = useState("");
  const [unreadCount, setUnreadCount] = useState(0);
  const [unreadByCategory, setUnreadByCategory] = useState({ orders: 0, messages: 0, moderation: 0, announcements: 0 });
  const [notifications, setNotifications] = useState([]);

  const onOrdersPage = useMemo(() => safeStr(location?.pathname, "").includes(FARMER_ORDERS_ROUTE), [location?.pathname]);
  const onProductsPage = useMemo(() => safeStr(location?.pathname, "").includes(FARMER_PRODUCTS_ROUTE), [location?.pathname]);
  const onMessagesPage = useMemo(() => safeStr(location?.pathname, "").includes(FARMER_MESSAGES_ROUTE), [location?.pathname]);
  const onAnnouncementsPage = useMemo(() => safeStr(location?.pathname, "").includes(FARMER_ANNOUNCEMENTS_ROUTE), [location?.pathname]);

  const initials = useMemo(() => {
    const parts = String(farmerName || "Farmer").trim().split(/\s+/);
    return parts.slice(0, 2).map((p) => p[0]?.toUpperCase()).join("") || "FR";
  }, [farmerName]);

  const closeMenus = useCallback(() => {
    setOpenNotifMenu(false);
    setOpenUserMenu(false);
  }, []);

  const refreshNotifications = useCallback(async (silent = false) => {
    if (!notificationsEnabled) {
      setNotifications([]);
      setUnreadCount(0);
      setUnreadByCategory({ orders: 0, messages: 0, moderation: 0, announcements: 0 });
      setNotificationsError("");
      setLoadingNotifications(false);
      return;
    }

    if (!silent) setLoadingNotifications(true);
    setNotificationsError("");

    try {
      const payload = await getNotificationsFromServer(MAX_NOTIFICATIONS);
      setNotifications(Array.isArray(payload.notifications) ? payload.notifications : []);
      setUnreadCount(safeNumber(payload.unread_count, 0));
      setUnreadByCategory({
        orders: safeNumber(payload?.unread_by_category?.orders, 0),
        messages: safeNumber(payload?.unread_by_category?.messages, 0),
        moderation: safeNumber(payload?.unread_by_category?.moderation, 0),
        announcements: safeNumber(payload?.unread_by_category?.announcements, 0),
      });
    } catch (err) {
      setNotificationsError(err?.response?.data?.message || err?.message || "Failed to load notifications.");
    } finally {
      if (!silent) setLoadingNotifications(false);
    }
  }, [notificationsEnabled]);

  const activeCategoryParam = activeNotifTab === "all" ? "" : activeNotifTab;

  const markCurrentTabRead = useCallback(async () => {
    if (!notificationsEnabled) return;

    try {
      await markNotificationsReadServer([], true, activeCategoryParam);
      setNotifications((prev) =>
        Array.isArray(prev)
          ? prev.map((n) => (activeNotifTab === "all" || n.category === activeNotifTab ? { ...n, is_read: true } : n))
          : []
      );
      await refreshNotifications(true);
    } catch (err) {
      setNotificationsError(err?.response?.data?.message || err?.message || "Failed to mark notifications as read.");
    }
  }, [activeCategoryParam, activeNotifTab, notificationsEnabled, refreshNotifications]);

  const clearCurrentTab = useCallback(async () => {
    if (!notificationsEnabled) return;

    try {
      await clearNotificationsServer([], true, activeCategoryParam);
      setNotifications((prev) =>
        Array.isArray(prev) ? prev.filter((n) => !(activeNotifTab === "all" || n.category === activeNotifTab)) : []
      );
      await refreshNotifications(true);
    } catch (err) {
      setNotificationsError(err?.response?.data?.message || err?.message || "Failed to clear notifications.");
    }
  }, [activeCategoryParam, activeNotifTab, notificationsEnabled, refreshNotifications]);

  const navigateByCategory = useCallback((category) => {
    closeMenus();
    if (category === "messages") {
      navigate(FARMER_MESSAGES_ROUTE);
      return;
    }
    if (category === "announcements") {
      navigate(FARMER_ANNOUNCEMENTS_ROUTE);
      return;
    }
    if (category === "moderation") {
      navigate(FARMER_PRODUCTS_ROUTE);
      return;
    }
    navigate(FARMER_ORDERS_ROUTE);
  }, [closeMenus, navigate]);

  const handleNotificationClick = useCallback(async (n) => {
    const oid = safeStr(n?.oid, "");
    const type = safeStr(n?.type, "new_order");
    const category = safeStr(n?.category, "orders");

    if (notificationsEnabled) {
      try {
        if (safeStr(n?.notification_id, "")) {
          await markNotificationsReadServer([n.notification_id], false);
        }
      } catch {
        // do not block navigation
      }
    }

    setNotifications((prev) =>
      Array.isArray(prev)
        ? prev.map((row) => (row.notification_id === n.notification_id ? { ...row, is_read: true } : row))
        : []
    );

    await refreshNotifications(true);

    if (category === "messages") {
      closeMenus();
      navigate(FARMER_MESSAGES_ROUTE);
      return;
    }

    if (category === "announcements") {
      closeMenus();
      navigate(FARMER_ANNOUNCEMENTS_ROUTE, { state: { focusNotificationId: n?.notification_id } });
      return;
    }

    if (category === "moderation") {
      closeMenus();
      navigate(FARMER_PRODUCTS_ROUTE);
      return;
    }

    const focusPayload = {
      orderId: oid,
      section: type === "payment_proof" ? FOCUS_SECTION_PAYMENT_EVIDENCE : FOCUS_SECTION_ORDER_SUMMARY,
      notificationType: type,
      eventKey: safeStr(n?.event_key, ""),
      createdAt: new Date().toISOString(),
    };

    if (typeof window !== "undefined" && oid) {
      try {
        window.localStorage.setItem(STORAGE_KEYS.focusOrderId, oid);
        window.localStorage.setItem(STORAGE_KEYS.focusContext, JSON.stringify(focusPayload));
        window.dispatchEvent(new CustomEvent(FARMER_NOTIFICATION_FOCUS_EVENT, { detail: focusPayload }));
      } catch {
        // ignore storage/custom event failures
      }
    }

    closeMenus();
    navigate(FARMER_ORDERS_ROUTE);
  }, [closeMenus, navigate, notificationsEnabled, refreshNotifications]);

  useEffect(() => {
    let alive = true;
    let timerId = null;

    if (!notificationsEnabled) {
      setNotifications([]);
      setUnreadCount(0);
      setUnreadByCategory({ orders: 0, messages: 0, moderation: 0, announcements: 0 });
      setLoadingNotifications(false);
      return () => {};
    }

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
  }, [refreshNotifications, notificationsEnabled]);

  useEffect(() => {
    const pageCategory = onOrdersPage ? "orders" : onProductsPage ? "moderation" : onMessagesPage ? "messages" : onAnnouncementsPage ? "announcements" : "";
    if (!notificationsEnabled || !pageCategory) return;

    const count = safeNumber(unreadByCategory?.[pageCategory], 0);
    if (count <= 0) return;
    void markNotificationsReadServer([], true, pageCategory).then(() => refreshNotifications(true)).catch(() => {});
  }, [notificationsEnabled, onOrdersPage, onProductsPage, onMessagesPage, onAnnouncementsPage, unreadByCategory, refreshNotifications]);

  useEffect(() => {
    if (!notificationsEnabled) return () => {};

    const socket = connectNotificationsSocket();
    if (!socket) return () => {};

    const handleChanged = () => {
      void refreshNotifications(true);
    };

    socket.on("notifications:changed", handleChanged);

    return () => {
      socket.off("notifications:changed", handleChanged);
      socket.disconnect();
    };
  }, [notificationsEnabled, refreshNotifications]);

  useEffect(() => {
    const onDoc = (e) => {
      if (!rootRef.current) return;
      if (!rootRef.current.contains(e.target)) closeMenus();
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

  const filteredNotifications = useMemo(() => {
    if (!Array.isArray(notifications)) return [];
    if (activeNotifTab === "all") return notifications;
    return notifications.filter((n) => n.category === activeNotifTab);
  }, [activeNotifTab, notifications]);

  const hasNotifications = filteredNotifications.length > 0;
  const hasUnread = unreadCount > 0;
  const activeTabUnread = activeNotifTab === "all" ? unreadCount : safeNumber(unreadByCategory?.[activeNotifTab], 0);

  const notificationMenuSubtitle = useMemo(() => {
    if (settingsLoading) return "Checking notification policy…";
    if (!notificationsEnabled) return "In-app notifications are currently off";
    if (activeNotifTab === "all") return hasUnread ? `${unreadCount} unread across all categories` : "No unread notifications";
    return activeTabUnread > 0 ? `${activeTabUnread} unread in ${activeNotifTab}` : `No unread ${activeNotifTab}`;
  }, [settingsLoading, notificationsEnabled, hasUnread, unreadCount, activeNotifTab, activeTabUnread]);

  const footerActionLabel = activeNotifTab === "messages" ? "Open Messages" : activeNotifTab === "announcements" ? "Open Announcements" : activeNotifTab === "moderation" ? "Open Products" : "Open Orders";

  return (
    <header className="sticky top-0 z-30 border-b border-[#D8F3DC] bg-white/95 backdrop-blur">
      <div className="mx-auto flex h-[72px] w-full items-center justify-between px-4 sm:px-6 lg:px-8">
        <div className="flex min-w-0 items-center gap-3">
          <button
            type="button"
            onClick={onOpenDrawer}
            className="inline-flex h-10 w-10 items-center justify-center rounded-xl border border-[#D8F3DC] bg-white text-slate-700 transition hover:bg-[#F7FCF9] lg:hidden"
            aria-label="Open menu"
          >
            <Menu className="h-5 w-5" />
          </button>

          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <span className="inline-block h-6 w-1.5 rounded-full bg-[#40916C]" />
              <h2 className="truncate text-base font-semibold tracking-tight text-slate-800 md:text-lg">AgroConnect Namibia</h2>
            </div>
          </div>
        </div>

        <div className="relative flex items-center gap-2" ref={rootRef}>
          <div className="relative">
            <button
              type="button"
              onClick={() => {
                setOpenUserMenu(false);
                setOpenNotifMenu((v) => !v);
              }}
              className={`relative grid h-10 w-10 place-items-center rounded-xl border transition ${
                notificationsEnabled ? "border-[#D8F3DC] bg-white hover:bg-slate-50" : "border-slate-200 bg-slate-50 hover:bg-slate-100"
              }`}
              aria-label="Farmer notifications"
              aria-haspopup="menu"
              aria-expanded={openNotifMenu}
              title={notificationsEnabled ? (hasUnread ? `${unreadCount} new notification(s)` : "Farmer notifications") : "In-app notifications are off"}
            >
              {notificationsEnabled ? <Bell className="h-5 w-5 text-slate-700" /> : <BellOff className="h-5 w-5 text-slate-500" />}
              {notificationsEnabled && hasUnread ? (
                <span className="absolute -right-1 -top-1 grid h-5 min-w-[20px] place-items-center rounded-full border border-white bg-rose-500 px-1 text-[10px] font-bold text-white">
                  {unreadCount > 99 ? "99+" : unreadCount}
                </span>
              ) : null}
            </button>

            {openNotifMenu ? (
              <div className="absolute right-0 mt-2 w-[430px] max-w-[95vw] overflow-hidden rounded-2xl border border-[#D8F3DC] bg-white shadow-lg">
                <div className="border-b border-slate-100 px-4 py-3">
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <div className="text-sm font-bold text-slate-800">Farmer notifications</div>
                      <div className="text-xs text-slate-500">{notificationMenuSubtitle}</div>
                    </div>
                    <div className="flex items-center gap-2">
                      <button
                        type="button"
                        onClick={markCurrentTabRead}
                        disabled={!notificationsEnabled || activeTabUnread <= 0}
                        className="inline-flex items-center gap-1 rounded-lg border border-slate-200 px-2 py-1 text-xs font-semibold text-slate-700 hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-50"
                        title="Mark current tab as read"
                      >
                        <CheckCheck className="h-3.5 w-3.5" />
                        Read
                      </button>
                      <button
                        type="button"
                        onClick={clearCurrentTab}
                        disabled={!notificationsEnabled || !hasNotifications}
                        className="inline-flex items-center gap-1 rounded-lg border border-slate-200 px-2 py-1 text-xs font-semibold text-slate-700 hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-50"
                        title="Clear current tab"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                        Clear
                      </button>
                    </div>
                  </div>

                  <div className="mt-3 flex flex-wrap gap-2">
                    {NOTIFICATION_TABS.map((tab) => {
                      const Icon = tab.icon;
                      const count = tab.key === "all" ? unreadCount : safeNumber(unreadByCategory?.[tab.key], 0);
                      const active = activeNotifTab === tab.key;
                      return (
                        <button
                          key={tab.key}
                          type="button"
                          onClick={() => setActiveNotifTab(tab.key)}
                          className={[
                            "inline-flex items-center gap-2 rounded-full border px-3 py-1.5 text-xs font-semibold transition",
                            active ? "border-green-200 bg-green-50 text-green-700" : "border-slate-200 bg-white text-slate-700 hover:bg-slate-50",
                          ].join(" ")}
                        >
                          <Icon className="h-3.5 w-3.5" />
                          {tab.label}
                          {count > 0 ? <span className="rounded-full bg-white/80 px-1.5 py-0.5 text-[10px] font-bold">{count}</span> : null}
                        </button>
                      );
                    })}
                  </div>
                </div>

                <div className="max-h-[420px] overflow-auto">
                  {settingsLoading ? (
                    <div className="px-4 py-6 text-center text-sm text-slate-500">
                      <div className="mx-auto mb-2 grid h-9 w-9 place-items-center rounded-lg border border-slate-200 bg-slate-50">
                        <Loader2 className="h-4 w-4 animate-spin text-slate-500" />
                      </div>
                      Checking notification policy…
                    </div>
                  ) : !notificationsEnabled ? (
                    <div className="px-4 py-6 text-center text-sm text-slate-500">
                      <div className="mx-auto mb-2 grid h-9 w-9 place-items-center rounded-lg border border-slate-200 bg-slate-50">
                        <BellOff className="h-4 w-4 text-slate-500" />
                      </div>
                      In-app notifications are currently turned off by system policy.
                    </div>
                  ) : loadingNotifications ? (
                    <div className="px-4 py-6 text-center text-sm text-slate-500">
                      <div className="mx-auto mb-2 grid h-9 w-9 place-items-center rounded-lg border border-slate-200 bg-slate-50">
                        <Loader2 className="h-4 w-4 animate-spin text-slate-500" />
                      </div>
                      Loading notifications…
                    </div>
                  ) : notificationsError ? (
                    <div className="px-4 py-6 text-center text-sm text-rose-600">{notificationsError}</div>
                  ) : hasNotifications ? (
                    filteredNotifications.map((n, idx) => {
                      const Icon = notificationIcon(n);
                      return (
                        <button
                          key={`${safeStr(n?.notification_id || n?.event_key, idx)}-${idx}`}
                          type="button"
                          onClick={() => handleNotificationClick(n)}
                          className={`w-full border-b border-slate-100 px-4 py-3 text-left hover:bg-slate-50 ${n?.is_read ? "opacity-70" : ""}`}
                          title={notificationActionText(n)}
                        >
                          <div className="flex items-start gap-3">
                            <div className={`mt-0.5 grid h-9 w-9 shrink-0 place-items-center rounded-xl border ${categoryTone(n?.category)}`}>
                              <Icon className="h-4 w-4" />
                            </div>

                            <div className="min-w-0 flex-1">
                              <div className="flex items-start justify-between gap-2">
                                <div className="min-w-0">
                                  <div className="flex flex-wrap items-center gap-2">
                                    <div className="truncate text-sm font-semibold text-slate-900">{notificationTitleText(n)}</div>
                                    <span className={`rounded-full border px-2 py-0.5 text-[10px] font-bold uppercase tracking-wide ${categoryTone(n?.category)}`}>
                                      {safeStr(n?.category, "orders")}
                                    </span>
                                  </div>

                                  <div className="mt-1 whitespace-pre-wrap text-xs leading-5 text-slate-600">{notificationSubtitleText(n)}</div>

                                  {shouldShowTotal(n) ? <div className="mt-1 text-xs text-slate-500">Total: {formatMoney(n?.total)}</div> : null}

                                  <div className="mt-2 inline-flex items-center gap-1 rounded-full border border-slate-200 bg-slate-50 px-2 py-1 text-[11px] font-semibold text-slate-700">
                                    <ArrowRight className="h-3 w-3" />
                                    {notificationActionText(n)}
                                  </div>
                                </div>

                                <div className="shrink-0 text-[11px] text-slate-400">{formatWhen(n?.received_at)}</div>
                              </div>
                            </div>
                          </div>
                        </button>
                      );
                    })
                  ) : (
                    <div className="px-4 py-6 text-center text-sm text-slate-500">
                      <div className="mx-auto mb-2 grid h-9 w-9 place-items-center rounded-lg border border-slate-200 bg-slate-50">
                        <Bell className="h-4 w-4 text-slate-500" />
                      </div>
                      No {activeNotifTab === "all" ? "notifications" : activeNotifTab} right now.
                    </div>
                  )}
                </div>

                <div className="border-t border-slate-100 p-3">
                  <button
                    type="button"
                    onClick={() => navigateByCategory(activeNotifTab === "all" ? "orders" : activeNotifTab)}
                    className="h-10 w-full rounded-xl border border-slate-200 bg-white text-sm font-semibold text-slate-800 hover:bg-slate-50"
                  >
                    {footerActionLabel}
                  </button>
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
              className="flex items-center gap-3 rounded-2xl border border-[#D8F3DC] bg-white px-2 py-1.5 transition hover:bg-slate-50"
              aria-haspopup="menu"
              aria-expanded={openUserMenu}
            >
              <div className="flex h-9 w-9 items-center justify-center rounded-xl border border-[#B7E4C7] bg-[#EAF7F0] font-semibold text-[#1B4332]">
                {initials ? initials : <User className="h-5 w-5" />}
              </div>
              <div className="hidden text-left sm:block">
                <div className="max-w-[220px] truncate text-sm font-semibold text-slate-800">{farmerName}</div>
                <div className="text-xs text-slate-500">Farmer</div>
              </div>
              <ChevronDown className="h-4 w-4 text-slate-600" />
            </button>

            {openUserMenu ? (
              <div className="absolute right-0 mt-2 w-48 overflow-hidden rounded-2xl border border-[#D8F3DC] bg-white shadow-lg">
                <button
                  type="button"
                  onClick={() => {
                    setOpenUserMenu(false);
                    onLogout?.();
                  }}
                  className="flex w-full items-center gap-2 px-4 py-3 text-sm text-slate-700 hover:bg-slate-50"
                >
                  <LogOut className="h-4 w-4 text-slate-700" />
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
