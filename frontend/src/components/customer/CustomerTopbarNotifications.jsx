// ============================================================================
// frontend/src/components/customer/CustomerTopbarNotifications.jsx
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Server-persisted customer notification bell used on the customer dashboard.
//
// WHAT THIS SHOWS:
//   • Order-ready notifications
//   • Direct customer message notifications
//   • Announcements / broadcasts
//   • Payment method and EFT details when relevant
//
// IMPORTANT FIXES IN THIS VERSION:
//   ✅ Fixes the parser-breaking setUnreadCount typo
//   ✅ Restores the full component so default export exists again
//   ✅ Fixes "openLabel is not defined"
//   ✅ Correctly routes message notifications to customer messages
//   ✅ Keeps cash vs EFT wording correct for payment-ready notifications
// ============================================================================

import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Bell,
  BellOff,
  CheckCheck,
  Trash2,
  Loader2,
  CreditCard,
  ArrowRight,
  Package,
  MessageSquareText,
  Megaphone,
} from "lucide-react";
import { useNavigate } from "react-router-dom";
import api from "../../api";
import usePublicSystemSettings from "../../hooks/usePublicSystemSettings";
import { connectNotificationsSocket } from "../../services/notificationsSocket";

const CUSTOMER_ORDERS_ROUTE = "/dashboard/customer/orders";
const CUSTOMER_ANNOUNCEMENTS_ROUTE = "/dashboard/customer/announcements";
const CUSTOMER_MESSAGES_ROUTE = "/dashboard/customer/messages";
const MAX_NOTIFICATIONS = 30;
const POLL_MS = 30000;

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

  if (baseEndsWithApi && path.startsWith("/api/")) {
    return path.replace(/^\/api/, "");
  }
  return path;
}

function tryParseJson(raw, fallback = null) {
  try {
    return JSON.parse(String(raw));
  } catch {
    return fallback;
  }
}

function formatMoney(v) {
  return `N$ ${safeNumber(v, 0).toFixed(2)}`;
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

function titleCaseWords(v) {
  const s = safeStr(v, "");
  if (!s) return "—";
  return s
    .replace(/_/g, " ")
    .toLowerCase()
    .replace(/\b([a-z])/g, (m) => m.toUpperCase());
}

function normalizePaymentMethod(value) {
  const raw = safeStr(value, "").toLowerCase();
  if (!raw) return "";

  if (["cash", "cod", "cash_on_delivery", "cash-on-delivery", "cash on delivery"].includes(raw)) {
    return "cash_on_delivery";
  }

  if (["eft", "bank_transfer", "bank-transfer", "bank transfer", "electronic transfer"].includes(raw)) {
    return "eft";
  }

  return raw;
}

function paymentMethodIsCash(value) {
  return normalizePaymentMethod(value) === "cash_on_delivery";
}

function paymentMethodIsEft(value) {
  return normalizePaymentMethod(value) === "eft";
}

function isBankLikeMethod(methodRaw) {
  const m = safeStr(methodRaw, "").toLowerCase();
  return (
    paymentMethodIsEft(methodRaw) ||
    m.includes("bank") ||
    m.includes("transfer") ||
    m.includes("wire")
  );
}

function normalizeBankDetails(raw = {}) {
  const bank = raw && typeof raw === "object" ? raw : {};
  return {
    bank_name: safeStr(bank.bank_name),
    account_name: safeStr(bank.account_name),
    account_number: safeStr(bank.account_number),
    branch_code: safeStr(bank.branch_code),
    payment_instructions: safeStr(bank.payment_instructions),
    is_complete: Boolean(
      safeStr(bank.bank_name) &&
        safeStr(bank.account_name) &&
        safeStr(bank.account_number)
    ),
  };
}

function extractNotificationPayload(raw = {}) {
  const candidates = [raw?.data_json, raw?.data, raw?.metadata, raw?.meta, null];

  for (const value of candidates) {
    if (value && typeof value === "object" && !Array.isArray(value)) {
      return value;
    }
    if (typeof value === "string") {
      const parsed = tryParseJson(value, null);
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        return parsed;
      }
    }
  }

  return {};
}

function isAnnouncementType(type) {
  const t = safeStr(type, "system").toLowerCase();
  return ["admin_message", "admin_announcement", "announcement", "broadcast"].includes(t);
}

function normalizeNotificationCategory(type, explicitCategory = "") {
  const explicit = safeStr(explicitCategory, "").toLowerCase();

  if (
    ["orders", "messages", "moderation", "announcements", "announcement"].includes(explicit)
  ) {
    return explicit.startsWith("announcement") ? "announcements" : explicit;
  }

  const normalizedType = safeStr(type, "system").toLowerCase();

  if (
    [
      "support_reply",
      "customer_message_received",
      "message",
      "message_received",
      "farmer_message",
      "farmer_message_received",
      "chat_message",
      "conversation_reply",
    ].includes(normalizedType)
  ) {
    return "messages";
  }

  return isAnnouncementType(type) ? "announcements" : "orders";
}

function normalizeNotificationEntry(raw = {}) {
  const payload = extractNotificationPayload(raw);

  const notificationId = safeStr(
    raw?.notification_id || raw?.id || raw?.notificationId,
    ""
  );

  const type = safeStr(raw?.notification_type || raw?.type || payload?.type, "system");

  const oid = safeStr(
    raw?.order_id ||
      raw?.orderId ||
      payload?.order_id ||
      payload?.orderId ||
      payload?.oid,
    ""
  );

  const paymentMethod = safeStr(
    payload?.payment_method_label || payload?.payment_method || "",
    ""
  );

  const bankDetails = normalizeBankDetails(payload?.bank_details || {});
  const productsSubtotal = safeNumber(payload?.products_subtotal, 0);
  const deliveryFee = safeNumber(payload?.delivery_fee, 0);
  const vatAmount = safeNumber(payload?.vat_amount, 0);
  const grandTotal = safeNumber(payload?.grand_total, 0);

  return {
    notification_id: notificationId,
    event_key: safeStr(raw?.event_key || payload?.event_key, notificationId),
    type,
    category: normalizeNotificationCategory(type, raw?.category || payload?.category),
    oid,
    title: safeStr(raw?.title || payload?.title || ""),
    message: safeStr(raw?.message || payload?.message || ""),
    is_read: Boolean(raw?.is_read),
    received_at: safeStr(raw?.created_at || raw?.received_at || raw?.updated_at, ""),
    payment_method: paymentMethod,
    payment_method_key: normalizePaymentMethod(paymentMethod),
    payment_method_is_eft:
      Boolean(payload?.payment_method_is_eft) || isBankLikeMethod(paymentMethod),
    payment_method_is_cash:
      Boolean(payload?.payment_method_is_cash) || paymentMethodIsCash(paymentMethod),
    products_subtotal: productsSubtotal,
    delivery_fee: deliveryFee,
    vat_amount: vatAmount,
    grand_total: grandTotal,
    checkout_stage: safeStr(payload?.checkout_stage, ""),
    bank_details: bankDetails,
    thread_id: safeStr(payload?.thread_id || payload?.threadId, ""),
    product_id: safeStr(payload?.product_id || payload?.productId, ""),
    product_name: safeStr(payload?.product_name || payload?.productName, ""),
    action_url: safeStr(payload?.action_url || payload?.route || payload?.href, ""),
    action_label: safeStr(payload?.action_label, ""),
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

  return {
    notifications: rows
      .map(normalizeNotificationEntry)
      .filter((x) => !!x.notification_id),
    unread_count: safeNumber(
      root?.unread_count ?? data?.unread_count ?? root?.meta?.unread_count ?? 0,
      0
    ),
  };
}
async function getNotificationsFromServer(limit = MAX_NOTIFICATIONS) {
  const candidates = [
    "/api/notifications/me",
    "/notifications/me",
    "/api/notifications",
    "/notifications",
  ];

  let lastErr = null;

  for (const path of candidates) {
    try {
      const resp = await api.get(apiPath(path), {
        params: { limit, unread_only: 0 },
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
  const ids = Array.isArray(notificationIds)
    ? notificationIds.map((x) => safeStr(x, "")).filter(Boolean)
    : [];

  const candidates = [
    "/api/notifications/mark-read",
    "/notifications/mark-read",
    "/api/notifications/mark_read",
    "/notifications/mark_read",
  ];

  let lastErr = null;

  for (const path of candidates) {
    try {
      const resp = await api.post(apiPath(path), {
        notification_ids: ids,
        mark_all: Boolean(markAll),
        category: safeStr(category, ""),
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
  const ids = Array.isArray(notificationIds)
    ? notificationIds.map((x) => safeStr(x, "")).filter(Boolean)
    : [];

  const candidates = ["/api/notifications/clear", "/notifications/clear"];

  let lastErr = null;

  for (const path of candidates) {
    try {
      const resp = await api.post(apiPath(path), {
        notification_ids: ids,
        clear_all: Boolean(clearAll),
        category: safeStr(category, ""),
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

function buildCustomerMessageRoute(notification = {}) {
  const params = new URLSearchParams();

  const threadId = safeStr(notification?.thread_id, "");
  const orderId = safeStr(notification?.oid, "");
  const productId = safeStr(notification?.product_id, "");
  const productName = safeStr(notification?.product_name, "");

  if (threadId) params.set("threadId", threadId);
  if (orderId) params.set("orderId", orderId);
  if (productId) params.set("productId", productId);
  if (productName) params.set("productName", productName);

  const query = params.toString();
  return query ? `${CUSTOMER_MESSAGES_ROUTE}?${query}` : CUSTOMER_MESSAGES_ROUTE;
}

function customerRouteForCategory(category, notification = {}) {
  const normalizedCategory = safeStr(category, "orders");

  if (normalizedCategory === "messages") {
    return buildCustomerMessageRoute(notification);
  }

  if (normalizedCategory === "announcements") {
    return CUSTOMER_ANNOUNCEMENTS_ROUTE;
  }

  return CUSTOMER_ORDERS_ROUTE;
}

function footerLabelForCategory(category) {
  const normalizedCategory = safeStr(category, "orders");

  if (normalizedCategory === "messages") return "Open Messages";
  if (normalizedCategory === "announcements") return "Open Announcements";
  return "Open Orders";
}

function NotificationCard({ notification, onOpen }) {
  const notificationType = safeStr(notification?.type, "");
  const isReadyForPayment = notificationType === "order_ready_for_payment";

  const bankDetails = notification?.bank_details || {};
  const isEftReadyCard =
    isReadyForPayment &&
    notification?.payment_method_is_eft &&
    Boolean(bankDetails?.is_complete);

  const isCashReadyCard =
    isReadyForPayment &&
    notification?.payment_method_is_cash;

  const notificationCategory = safeStr(notification?.category, "orders");
  const isMessageNotification = notificationCategory === "messages";
  const isAnnouncementNotification = notificationCategory === "announcements";

  const openLabel =
    notificationCategory === "messages"
      ? "Open Messages"
      : notificationCategory === "announcements"
        ? "Open Announcements"
        : "Open Orders";

  const paymentPanelTitle = isCashReadyCard ? "Cash on delivery ready" : "Payment ready";

  const paymentMethodLabel = notification?.payment_method
    ? titleCaseWords(notification.payment_method)
    : "—";

  return (
    <button
      type="button"
      onClick={onOpen}
      className={`w-full border-b border-slate-100 px-4 py-3 text-left hover:bg-slate-50 ${
        notification?.is_read ? "opacity-75" : ""
      }`}
      title={openLabel}
    >
      <div className="flex items-start gap-3">
        <div
          className={`mt-0.5 grid h-9 w-9 shrink-0 place-items-center rounded-xl border ${
            isReadyForPayment
              ? "border-emerald-200 bg-emerald-50 text-emerald-700"
              : isMessageNotification
                ? "border-indigo-200 bg-indigo-50 text-indigo-700"
                : isAnnouncementNotification
                  ? "border-amber-200 bg-amber-50 text-amber-700"
                  : "border-slate-200 bg-slate-50 text-slate-700"
          }`}
        >
          {isReadyForPayment ? (
            <CreditCard className="h-4 w-4" />
          ) : isMessageNotification ? (
            <MessageSquareText className="h-4 w-4" />
          ) : isAnnouncementNotification ? (
            <Megaphone className="h-4 w-4" />
          ) : (
            <Package className="h-4 w-4" />
          )}
        </div>

        <div className="min-w-0 flex-1">
          <div className="flex items-start justify-between gap-2">
            <div className="min-w-0">
              <div className="truncate text-sm font-semibold text-slate-900">
                {notification?.title || "Notification"}
              </div>

              <div className="mt-0.5 text-xs text-slate-600">
                {notification?.message || `Order ${safeStr(notification?.oid, "—")}`}
              </div>
              {isReadyForPayment ? (
                <div
                  className={`mt-2 rounded-xl border p-3 ${
                    isCashReadyCard
                      ? "border-amber-200 bg-amber-50"
                      : "border-sky-200 bg-sky-50"
                  }`}
                >
                  <div
                    className={`text-xs font-bold uppercase tracking-wide ${
                      isCashReadyCard ? "text-amber-800" : "text-sky-800"
                    }`}
                  >
                    {paymentPanelTitle}
                  </div>

                  <div className="mt-2 grid grid-cols-2 gap-2 text-xs">
                    <div>
                      <div className="text-slate-500">Method</div>
                      <div className="font-semibold text-slate-900">
                        {paymentMethodLabel}
                      </div>
                    </div>

                    <div>
                      <div className="text-slate-500">Order</div>
                      <div className="font-semibold text-slate-900">
                        {safeStr(notification?.oid, "—")}
                      </div>
                    </div>

                    <div>
                      <div className="text-slate-500">Products</div>
                      <div className="font-semibold text-slate-900">
                        {formatMoney(notification?.products_subtotal)}
                      </div>
                    </div>

                    <div>
                      <div className="text-slate-500">Delivery</div>
                      <div className="font-semibold text-slate-900">
                        {formatMoney(notification?.delivery_fee)}
                      </div>
                    </div>

                    <div>
                      <div className="text-slate-500">VAT</div>
                      <div className="font-semibold text-slate-900">
                        {formatMoney(notification?.vat_amount)}
                      </div>
                    </div>

                    <div>
                      <div className="text-slate-500">Total</div>
                      <div className="font-bold text-slate-900">
                        {formatMoney(notification?.grand_total)}
                      </div>
                    </div>
                  </div>

                  {isCashReadyCard ? (
                    <div className="mt-3 rounded-lg border border-amber-200 bg-white p-3">
                      <div className="text-xs font-bold uppercase tracking-wide text-amber-800">
                        Cash on delivery
                      </div>
                      <div className="mt-2 text-xs text-slate-700">
                        No proof of payment is required. Your farmer will collect payment on
                        delivery or pickup after the final total is confirmed.
                      </div>
                    </div>
                  ) : null}

                  {isEftReadyCard ? (
                    <div className="mt-3 rounded-lg border border-emerald-200 bg-white p-3">
                      <div className="text-xs font-bold uppercase tracking-wide text-emerald-800">
                        EFT / bank details
                      </div>

                      <div className="mt-2 grid grid-cols-1 gap-2 text-xs sm:grid-cols-2">
                        <div>
                          <div className="text-slate-500">Bank</div>
                          <div className="font-semibold text-slate-900">
                            {bankDetails.bank_name || "—"}
                          </div>
                        </div>

                        <div>
                          <div className="text-slate-500">Account name</div>
                          <div className="font-semibold text-slate-900">
                            {bankDetails.account_name || "—"}
                          </div>
                        </div>

                        <div>
                          <div className="text-slate-500">Account number</div>
                          <div className="font-semibold text-slate-900">
                            {bankDetails.account_number || "—"}
                          </div>
                        </div>

                        <div>
                          <div className="text-slate-500">Branch code</div>
                          <div className="font-semibold text-slate-900">
                            {bankDetails.branch_code || "—"}
                          </div>
                        </div>

                        {bankDetails.payment_instructions ? (
                          <div className="sm:col-span-2">
                            <div className="text-slate-500">Instructions</div>
                            <div className="font-semibold text-slate-900">
                              {bankDetails.payment_instructions}
                            </div>
                          </div>
                        ) : null}
                      </div>
                    </div>
                  ) : null}
                </div>
              ) : null}

              <div className="mt-2 inline-flex items-center gap-1 rounded-full border border-slate-200 bg-slate-50 px-2 py-1 text-[11px] font-semibold text-slate-700">
                <ArrowRight className="h-3 w-3" />
                {openLabel}
              </div>
            </div>

            <div className="shrink-0 text-[11px] text-slate-400">
              {formatWhen(notification?.received_at)}
            </div>
          </div>
        </div>
      </div>
    </button>
  );
}

export default function CustomerTopbarNotifications() {
  const navigate = useNavigate();
  const rootRef = useRef(null);

  const { helpers, loading: settingsLoading } = usePublicSystemSettings();
  const notificationsEnabled = helpers?.notificationsEnabled ?? true;

  const [open, setOpen] = useState(false);
  const [loadingNotifications, setLoadingNotifications] = useState(false);
  const [notificationsError, setNotificationsError] = useState("");
  const [unreadCount, setUnreadCount] = useState(0);
  const [notifications, setNotifications] = useState([]);

  const refreshNotifications = useCallback(
    async (silent = false) => {
      if (!notificationsEnabled) {
        setNotifications([]);
        setUnreadCount(0);
        setNotificationsError("");
        setLoadingNotifications(false);
        return;
      }

      if (!silent) setLoadingNotifications(true);
      setNotificationsError("");

      try {
        const payload = await getNotificationsFromServer(MAX_NOTIFICATIONS);
        setNotifications(
          Array.isArray(payload.notifications) ? payload.notifications : []
        );
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
    },
    [notificationsEnabled]
  );

  const markAllRead = useCallback(async () => {
    if (!notificationsEnabled) return;

    try {
      await markNotificationsReadServer([], true);
      setNotifications((prev) =>
        Array.isArray(prev) ? prev.map((n) => ({ ...n, is_read: true })) : []
      );
      setUnreadCount(0);
    } catch (err) {
      setNotificationsError(
        err?.response?.data?.message ||
          err?.message ||
          "Failed to mark notifications as read."
      );
    }
  }, [notificationsEnabled]);

  const clearNotifications = useCallback(async () => {
    if (!notificationsEnabled) return;

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
  }, [notificationsEnabled]);

  const openCategoryPage = useCallback(
    async (category, notification = null) => {
      const normalizedCategory = safeStr(category, "orders");

      try {
        if (notificationsEnabled && unreadCount > 0) {
          await markNotificationsReadServer([], true, normalizedCategory);

          setNotifications((prev) =>
            Array.isArray(prev)
              ? prev.map((row) =>
                  safeStr(row?.category, "orders") === normalizedCategory
                    ? { ...row, is_read: true }
                    : row
                )
              : []
          );

          setUnreadCount((prev) => {
            const unreadInCategory = Array.isArray(notifications)
              ? notifications.filter(
                  (row) =>
                    safeStr(row?.category, "orders") === normalizedCategory &&
                    !row?.is_read
                ).length
              : 0;

            return Math.max(0, prev - unreadInCategory);
          });
        }
      } catch {
        // Navigation should still continue even if mark-read fails.
      }

      setOpen(false);
      navigate(customerRouteForCategory(normalizedCategory, notification || {}));
    },
    [navigate, notificationsEnabled, notifications, unreadCount]
  );

  const openAnnouncementsPage = useCallback(() => {
    void openCategoryPage("announcements");
  }, [openCategoryPage]);

  const openOrdersPage = useCallback(() => {
    void openCategoryPage("orders");
  }, [openCategoryPage]);

  const openMessagesPage = useCallback(() => {
    void openCategoryPage("messages");
  }, [openCategoryPage]);
  const handleNotificationClick = useCallback(
    async (notification) => {
      if (notificationsEnabled) {
        try {
          if (safeStr(notification?.notification_id, "")) {
            await markNotificationsReadServer([notification.notification_id], false);
          }
        } catch {
          // Ignore read errors and still navigate.
        }

        setNotifications((prev) =>
          Array.isArray(prev)
            ? prev.map((row) =>
                row.notification_id === notification.notification_id
                  ? { ...row, is_read: true }
                  : row
              )
            : []
        );

        setUnreadCount((prev) =>
          Math.max(0, prev - (notification?.is_read ? 0 : 1))
        );
      }

      setOpen(false);

      const target =
        safeStr(notification?.action_url, "") ||
        customerRouteForCategory(notification?.category, notification);

      navigate(target, {
        state: {
          focusNotificationId: notification?.notification_id,
          focusThreadId: notification?.thread_id,
        },
      });
    },
    [navigate, notificationsEnabled]
  );

  useEffect(() => {
    let alive = true;
    let timerId = null;

    if (!notificationsEnabled) {
      setNotifications([]);
      setUnreadCount(0);
      setNotificationsError("");
      setLoadingNotifications(false);
      return () => {};
    }

    const run = async () => {
      if (!alive) return;
      await refreshNotifications(true);
    };

    void refreshNotifications(false);
    timerId = window.setInterval(run, POLL_MS);

    return () => {
      alive = false;
      if (timerId) window.clearInterval(timerId);
    };
  }, [refreshNotifications, notificationsEnabled]);

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
      if (!rootRef.current.contains(e.target)) setOpen(false);
    };

    const onKey = (e) => {
      if (e.key === "Escape") setOpen(false);
    };

    document.addEventListener("mousedown", onDoc);
    document.addEventListener("keydown", onKey);

    return () => {
      document.removeEventListener("mousedown", onDoc);
      document.removeEventListener("keydown", onKey);
    };
  }, []);

  const hasUnread = unreadCount > 0;
  const hasNotifications = Array.isArray(notifications) && notifications.length > 0;
  const latestCategory = safeStr(notifications?.[0]?.category, "orders");

  const headerSubtitle = useMemo(() => {
    if (settingsLoading) return "Checking notification policy…";
    if (!notificationsEnabled) return "In-app notifications are currently off";
    return hasUnread ? `${unreadCount} unread` : "No unread notifications";
  }, [settingsLoading, notificationsEnabled, hasUnread, unreadCount]);

  const openLabel = footerLabelForCategory(latestCategory);

  const footerAction =
    latestCategory === "messages"
      ? openMessagesPage
      : latestCategory === "announcements"
        ? openAnnouncementsPage
        : openOrdersPage;

  return (
    <div className="relative" ref={rootRef}>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className={`relative inline-flex h-11 w-11 items-center justify-center rounded-xl border shadow-sm transition duration-200 hover:-translate-y-[1px] hover:shadow ${
          notificationsEnabled
            ? "border-[#D8F3DC] bg-white text-slate-700 hover:bg-slate-50"
            : "border-slate-200 bg-slate-50 text-slate-500 hover:bg-slate-100"
        }`}
        aria-label="Customer notifications"
        title={
          notificationsEnabled
            ? hasUnread
              ? `${unreadCount} new notification(s)`
              : "Customer notifications"
            : "In-app notifications are off"
        }
      >
        {notificationsEnabled ? (
          <Bell className="h-4 w-4" />
        ) : (
          <BellOff className="h-4 w-4" />
        )}

        {notificationsEnabled && hasUnread ? (
          <span className="absolute -right-1 -top-1 grid h-5 min-w-[20px] place-items-center rounded-full border border-white bg-rose-500 px-1 text-[10px] font-bold text-white">
            {unreadCount > 99 ? "99+" : unreadCount}
          </span>
        ) : null}
      </button>

      {open ? (
        <div className="absolute right-0 z-40 mt-2 w-[420px] max-w-[94vw] overflow-hidden rounded-2xl border border-[#D8F3DC] bg-white shadow-lg">
          <div className="flex items-center justify-between border-b border-slate-100 px-4 py-3">
            <div>
              <div className="text-sm font-bold text-slate-800">
                Customer notifications
              </div>
              <div className="text-xs text-slate-500">{headerSubtitle}</div>
            </div>

            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={markAllRead}
                disabled={!notificationsEnabled}
                className="inline-flex items-center gap-1 rounded-lg border border-slate-200 px-2 py-1 text-xs font-semibold text-slate-700 hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-50"
                title="Mark all as read"
              >
                <CheckCheck className="h-3.5 w-3.5" />
                Read
              </button>

              <button
                type="button"
                onClick={clearNotifications}
                disabled={!notificationsEnabled}
                className="inline-flex items-center gap-1 rounded-lg border border-slate-200 px-2 py-1 text-xs font-semibold text-slate-700 hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-50"
                title="Clear notification items"
              >
                <Trash2 className="h-3.5 w-3.5" />
                Clear
              </button>
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
              <div className="px-4 py-6 text-center text-sm text-rose-600">
                {notificationsError}
              </div>
            ) : hasNotifications ? (
              notifications.map((notification, idx) => (
                <NotificationCard
                  key={`${safeStr(
                    notification?.notification_id || notification?.event_key,
                    idx
                  )}-${idx}`}
                  notification={notification}
                  onOpen={() => handleNotificationClick(notification)}
                />
              ))
            ) : (
              <div className="px-4 py-6 text-center text-sm text-slate-500">
                <div className="mx-auto mb-2 grid h-9 w-9 place-items-center rounded-lg border border-slate-200 bg-slate-50">
                  <Package className="h-4 w-4 text-slate-500" />
                </div>
                No new notifications right now.
              </div>
            )}
          </div>

          <div className="border-t border-slate-100 p-3">
            <button
              type="button"
              onClick={footerAction}
              className="h-10 w-full rounded-xl border border-slate-200 bg-white text-sm font-semibold text-slate-800 hover:bg-slate-50"
            >
              {openLabel}
            </button>
          </div>
        </div>
      ) : null}
    </div>
  );
}