// ============================================================================
// frontend/src/components/messaging/MessagingWorkspace.jsx — Shared Inbox UI
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Reusable conversation workspace for farmer and customer dashboards.
//
// CURRENT SCOPE:
//   • Conversation list
//   • Thread reader
//   • Send/reply composer
//   • Customer / farmer auto-start from query params
//   • Direct thread opening from notification query param (?threadId=...)
//
// IMPORTANT IMPROVEMENTS IN THIS VERSION:
//   ✅ Supports opening a specific thread directly from notification links
//   ✅ Keeps existing conversation-start seeding logic intact
//   ✅ Clears threadId from the URL after the thread is opened
//   ✅ Preserves search, socket refresh, and conversation reload flow
// ============================================================================

import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import {
  Loader2,
  Mail,
  MessageSquareText,
  RefreshCcw,
  Search,
  SendHorizonal,
  ShoppingBasket,
  UserRound,
  ArrowRight,
} from "lucide-react";

import Card, { CardContent, CardHeader, CardTitle } from "../ui/Card";
import * as messagingApi from "../../services/messagingApi";
import { connectMessagingSocket } from "../../services/messagingSocket";

function safeStr(value, fallback = "") {
  const text = String(value ?? "").trim();
  return text || fallback;
}

function safeNumber(value, fallback = 0) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function formatRelativeDate(value) {
  const raw = safeStr(value);
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

function normalizeConversation(raw = {}) {
  return {
    thread_id: safeStr(raw?.thread_id || raw?.id),
    subject: safeStr(raw?.subject, "Conversation"),
    last_message_preview: safeStr(raw?.last_message_preview, "No messages yet."),
    last_message_at: safeStr(raw?.last_message_at || raw?.updated_at),
    unread_count: safeNumber(raw?.unread_count, 0),
    counterpart: raw?.counterpart || {},
    product: raw?.product || null,
    status: safeStr(raw?.status, "open"),
  };
}

function normalizeMessage(raw = {}) {
  return {
    message_id: safeStr(raw?.message_id || raw?.id),
    sender_user_id: safeStr(raw?.sender_user_id),
    sender_name: safeStr(raw?.sender_name, "User"),
    sender_role_name: safeStr(raw?.sender_role_name),
    body: safeStr(raw?.body),
    created_at: safeStr(raw?.created_at),
    is_system: Boolean(raw?.is_system),
  };
}

function EmptyState({ title, text }) {
  return (
    <div className="rounded-2xl border border-slate-200 bg-slate-50 px-5 py-10 text-center">
      <MessageSquareText className="mx-auto mb-3 h-5 w-5 text-slate-400" />
      <div className="text-sm font-bold text-slate-900">{title}</div>
      <div className="mt-1 text-sm text-slate-600">{text}</div>
    </div>
  );
}

export default function MessagingWorkspace({
  role = "farmer",
  eyebrow = "Messaging",
  title = "Messages",
  description = "Stay connected inside AgroConnect.",
}) {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();

  const [search, setSearch] = useState("");
  const [loadingList, setLoadingList] = useState(true);
  const [loadingThread, setLoadingThread] = useState(false);
  const [busySend, setBusySend] = useState(false);
  const [busySeed, setBusySeed] = useState(false);
  const [error, setError] = useState("");
  const [conversations, setConversations] = useState([]);
  const [selectedThreadId, setSelectedThreadId] = useState("");
  const [activeThread, setActiveThread] = useState(null);
  const [messages, setMessages] = useState([]);
  const [draft, setDraft] = useState("");

  const scrollerRef = useRef(null);
  const seededRef = useRef("");
  const selectedThreadRef = useRef("");
  const socketRef = useRef(null);
  const realtimeReloadTimerRef = useRef(null);

  // --------------------------------------------------------------------------
  // Query param seeds:
  //   • direct thread open from notifications
  //   • new conversation start from marketplace/order context
  // --------------------------------------------------------------------------
  const seedThreadId = safeStr(
    searchParams.get("threadId") || searchParams.get("thread_id")
  );

  const seedRecipientId = safeStr(
    searchParams.get("recipient") ||
      searchParams.get("recipientId") ||
      searchParams.get("userId") ||
      searchParams.get("farmerId") ||
      searchParams.get("customerId")
  );

  const seedProductId = safeStr(searchParams.get("productId"));
  const seedOrderId = safeStr(searchParams.get("orderId"));
  const seedProductName = safeStr(searchParams.get("productName"));
  const seedSubject = safeStr(searchParams.get("subject"));
  const seedPrefill = safeStr(searchParams.get("message"));

  const seedKey = useMemo(
    () =>
      [
        role,
        seedThreadId,
        seedRecipientId,
        seedProductId,
        seedOrderId,
        seedProductName,
        seedSubject,
        seedPrefill,
      ].join("|"),
    [
      role,
      seedThreadId,
      seedRecipientId,
      seedProductId,
      seedOrderId,
      seedProductName,
      seedSubject,
      seedPrefill,
    ]
  );

  const loadConversations = useCallback(
    async (preferredThreadId = "") => {
      setLoadingList(true);
      setError("");

      try {
        const payload = await messagingApi.listConversations({ search, limit: 80 });

        const rows = Array.isArray(payload?.conversations)
          ? payload.conversations.map(normalizeConversation)
          : [];

        setConversations(rows);

        const nextId =
          safeStr(preferredThreadId) ||
          safeStr(seedThreadId) ||
          safeStr(selectedThreadRef.current) ||
          safeStr(rows?.[0]?.thread_id);

        setSelectedThreadId(nextId);
      } catch (err) {
        setError(
          err?.response?.data?.message ||
            err?.message ||
            "Failed to load conversations."
        );
      } finally {
        setLoadingList(false);
      }
    },
    [search, seedThreadId]
  );

  const loadThread = useCallback(async (threadId) => {
    const id = safeStr(threadId);

    if (!id) {
      setActiveThread(null);
      setMessages([]);
      return;
    }

    setLoadingThread(true);
    setError("");

    try {
      const payload = await messagingApi.getConversation(id, {
        mark_read: 1,
        limit: 200,
      });

      setActiveThread(normalizeConversation(payload?.thread || {}));
      setMessages(
        Array.isArray(payload?.messages)
          ? payload.messages.map(normalizeMessage)
          : []
      );

      // Clear unread count for the open thread in the sidebar.
      setConversations((prev) =>
        prev.map((row) => (row.thread_id === id ? { ...row, unread_count: 0 } : row))
      );
    } catch (err) {
      setError(
        err?.response?.data?.message ||
          err?.message ||
          "Failed to load conversation."
      );
    } finally {
      setLoadingThread(false);
    }
  }, []);

  const scheduleRealtimeRefresh = useCallback(
    (threadId = "") => {
      if (realtimeReloadTimerRef.current) {
        window.clearTimeout(realtimeReloadTimerRef.current);
      }

      realtimeReloadTimerRef.current = window.setTimeout(async () => {
        const preferredThreadId = safeStr(threadId) || safeStr(selectedThreadRef.current);

        await loadConversations(preferredThreadId);

        if (preferredThreadId && preferredThreadId === safeStr(selectedThreadRef.current)) {
          await loadThread(preferredThreadId);
        }
      }, 120);
    },
    [loadConversations, loadThread]
  );

  useEffect(() => {
    loadConversations();
  }, [loadConversations]);

  useEffect(() => {
    selectedThreadRef.current = selectedThreadId;
    loadThread(selectedThreadId);
  }, [selectedThreadId, loadThread]);

  useEffect(() => {
    if (!messages.length || !scrollerRef.current) return;
    const el = scrollerRef.current;
    el.scrollTop = el.scrollHeight;
  }, [messages]);

  // --------------------------------------------------------------------------
  // Realtime socket updates
  // --------------------------------------------------------------------------
  useEffect(() => {
    const socket = connectMessagingSocket();
    socketRef.current = socket;

    if (!socket) {
      return undefined;
    }

    const handleThreadUpdated = (payload = {}) => {
      const threadId = safeStr(payload?.thread_id);
      if (!threadId) return;
      scheduleRealtimeRefresh(threadId);
    };

    socket.on("messages:thread-updated", handleThreadUpdated);

    return () => {
      socket.off("messages:thread-updated", handleThreadUpdated);
      socket.disconnect();
      socketRef.current = null;

      if (realtimeReloadTimerRef.current) {
        window.clearTimeout(realtimeReloadTimerRef.current);
        realtimeReloadTimerRef.current = null;
      }
    };
  }, [scheduleRealtimeRefresh]);

  // --------------------------------------------------------------------------
  // Direct thread selection from notification query param.
  // Example: /dashboard/customer/messages?threadId=abc123
  // --------------------------------------------------------------------------
  useEffect(() => {
    if (!seedThreadId) return;
    if (selectedThreadRef.current === seedThreadId) return;

    setSelectedThreadId(seedThreadId);
  }, [seedThreadId]);

  // --------------------------------------------------------------------------
  // Conversation auto-start when recipient/product/order seed params exist.
  // --------------------------------------------------------------------------
  useEffect(() => {
    if (!seedRecipientId) return;
    if (seededRef.current === seedKey) return;

    let cancelled = false;
    seededRef.current = seedKey;

    async function ensureSeededThread() {
      setBusySeed(true);
      setError("");

      try {
        const payload = await messagingApi.startConversation({
          recipient_user_id: seedRecipientId,
          product_id: seedProductId || undefined,
          order_id: seedOrderId || undefined,
          subject:
            seedSubject ||
            (seedProductName ? `Question about ${seedProductName}` : undefined) ||
            (seedOrderId ? `Order ${seedOrderId}` : undefined),
        });

        const nextThreadId = safeStr(payload?.thread_id);

        if (!cancelled && nextThreadId) {
          setSelectedThreadId(nextThreadId);

          if (seedPrefill) {
            setDraft(seedPrefill);
          }

          await loadConversations(nextThreadId);

          const next = new URLSearchParams(searchParams);
          [
            "farmerId",
            "customerId",
            "recipient",
            "recipientId",
            "userId",
            "productId",
            "orderId",
            "productName",
            "subject",
            "message",
          ].forEach((key) => next.delete(key));

          setSearchParams(next, { replace: true });
        }
      } catch (err) {
        if (!cancelled) {
          setError(
            err?.response?.data?.message ||
              err?.message ||
              "Could not prepare the conversation."
          );
        }
      } finally {
        if (!cancelled) setBusySeed(false);
      }
    }

    ensureSeededThread();

    return () => {
      cancelled = true;
    };
  }, [
    role,
    seedRecipientId,
    seedProductId,
    seedOrderId,
    seedProductName,
    seedSubject,
    seedPrefill,
    seedKey,
    loadConversations,
    searchParams,
    setSearchParams,
  ]);

  // --------------------------------------------------------------------------
  // Once the requested thread is fully active, remove threadId from the URL.
  // This keeps refresh/share behavior clean after opening from notifications.
  // --------------------------------------------------------------------------
  useEffect(() => {
    if (!seedThreadId) return;
    if (safeStr(activeThread?.thread_id) !== seedThreadId) return;

    const next = new URLSearchParams(searchParams);
    next.delete("threadId");
    next.delete("thread_id");
    setSearchParams(next, { replace: true });
  }, [activeThread?.thread_id, searchParams, seedThreadId, setSearchParams]);

  const activeCounterpart = activeThread?.counterpart || {};
  const activeProduct = activeThread?.product || null;

  const summaryStats = useMemo(() => {
    const unread = conversations.reduce(
      (sum, row) => sum + safeNumber(row.unread_count, 0),
      0
    );
    return { unread, total: conversations.length };
  }, [conversations]);

  const roleGuide =
    role === "customer"
      ? {
          title: "Start by choosing a farmer from the marketplace",
          text: "Open a product, use Message Farmer, and AgroConnect will prepare the conversation for that listing.",
          actionLabel: "Browse products",
          action: () => navigate("/dashboard/customer"),
        }
      : {
          title: "Start from a real order or reply from your inbox",
          text: "Farmers should message customers from order context so the conversation stays linked to the correct transaction.",
          actionLabel: "Open orders",
          action: () => navigate("/dashboard/farmer/orders"),
        };

  const emptyConversationHint =
    role === "customer"
      ? "Open a product and choose Message Farmer to begin."
      : "Open an order and choose Message Customer to start a buyer conversation.";

  const handleSend = async () => {
    const threadId = safeStr(selectedThreadId);
    const body = safeStr(draft);

    if (!threadId || !body) return;

    setBusySend(true);
    setError("");

    try {
      await messagingApi.sendMessage(threadId, body);
      setDraft("");
      await loadThread(threadId);
      await loadConversations(threadId);
    } catch (err) {
      setError(
        err?.response?.data?.message ||
          err?.message ||
          "Failed to send message."
      );
    } finally {
      setBusySend(false);
    }
  };

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <div className="text-xs font-semibold uppercase tracking-wide text-emerald-700">
              {eyebrow}
            </div>
            <CardTitle>{title}</CardTitle>
            <p className="mt-1 text-sm text-slate-600">{description}</p>
            <p className="mt-1 text-xs text-slate-500">
              Administrative broadcasts appear in the notification bell. This workspace
              is for direct marketplace conversations only.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <div className="relative w-full min-w-[220px] sm:w-[280px]">
              <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
              <input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search conversations"
                className="h-11 w-full rounded-2xl border border-slate-200 bg-white pl-9 pr-3 text-sm outline-none transition focus:border-slate-400"
              />
            </div>

            <button
              type="button"
              onClick={() => loadConversations(selectedThreadId)}
              className="inline-flex h-11 items-center gap-2 rounded-2xl border border-slate-200 bg-white px-4 text-sm font-semibold text-slate-800 hover:bg-slate-50"
              disabled={loadingList || busySeed}
            >
              {loadingList || busySeed ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <RefreshCcw className="h-4 w-4" />
              )}
              Refresh
            </button>
          </div>
        </CardHeader>
      </Card>

      {error ? (
        <div className="rounded-2xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">
          {error}
        </div>
      ) : null}

      <div className="grid gap-6 xl:grid-cols-[360px_minmax(0,1fr)]">
        <div className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Inbox summary</CardTitle>
            </CardHeader>
            <CardContent className="grid grid-cols-2 gap-3">
              <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                <div className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                  Unread
                </div>
                <div className="mt-2 text-2xl font-black text-slate-900">
                  {summaryStats.unread}
                </div>
              </div>
              <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                <div className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                  Threads
                </div>
                <div className="mt-2 text-2xl font-black text-slate-900">
                  {summaryStats.total}
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Conversations</CardTitle>
            </CardHeader>
            <CardContent>
              {loadingList ? (
                <div className="flex items-center gap-2 text-sm text-slate-500">
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Loading conversations…
                </div>
              ) : conversations.length === 0 ? (
                <div className="space-y-4">
                  <EmptyState title="No conversations yet" text={emptyConversationHint} />
                  <div className="rounded-2xl border border-emerald-100 bg-emerald-50/70 p-4">
                    <div className="text-sm font-bold text-slate-900">
                      {roleGuide.title}
                    </div>
                    <div className="mt-1 text-sm text-slate-600">{roleGuide.text}</div>
                    <button
                      type="button"
                      onClick={roleGuide.action}
                      className="mt-3 inline-flex items-center gap-2 rounded-2xl border border-emerald-200 bg-white px-4 py-2 text-sm font-semibold text-emerald-700 hover:bg-emerald-50"
                    >
                      {roleGuide.actionLabel}
                      <ArrowRight className="h-4 w-4" />
                    </button>
                  </div>
                </div>
              ) : (
                <div className="space-y-3">
                  {conversations.map((row) => {
                    const active = row.thread_id === selectedThreadId;

                    return (
                      <button
                        key={row.thread_id}
                        type="button"
                        onClick={() => setSelectedThreadId(row.thread_id)}
                        className={[
                          "w-full rounded-2xl border p-4 text-left transition",
                          active
                            ? "border-emerald-200 bg-emerald-50/40"
                            : "border-slate-200 bg-white hover:bg-slate-50",
                        ].join(" ")}
                      >
                        <div className="flex items-start justify-between gap-3">
                          <div className="min-w-0">
                            <div className="truncate text-sm font-bold text-slate-900">
                              {safeStr(row?.counterpart?.full_name, "Conversation")}
                            </div>
                            <div className="mt-0.5 truncate text-xs font-semibold uppercase tracking-wide text-slate-500">
                              {row.subject}
                            </div>
                          </div>

                          <div className="shrink-0 text-right">
                            <div className="text-[11px] text-slate-400">
                              {formatRelativeDate(row.last_message_at)}
                            </div>
                            {row.unread_count > 0 ? (
                              <span className="mt-2 inline-flex min-w-[28px] items-center justify-center rounded-full bg-emerald-600 px-2 py-1 text-[11px] font-bold text-white">
                                {row.unread_count}
                              </span>
                            ) : null}
                          </div>
                        </div>

                        <div className="mt-3 line-clamp-2 text-sm leading-6 text-slate-600">
                          {row.last_message_preview}
                        </div>

                        {row.product?.name ? (
                          <div className="mt-3 inline-flex items-center gap-1 rounded-full border border-slate-200 bg-slate-50 px-3 py-1 text-[11px] font-semibold text-slate-700">
                            <ShoppingBasket className="h-3.5 w-3.5" />
                            {row.product.name}
                          </div>
                        ) : null}
                      </button>
                    );
                  })}
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        <Card className="min-h-[680px]">
          <CardHeader className="space-y-4">
            {activeThread ? (
              <>
                <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                  <div>
                    <div className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                      Active conversation
                    </div>
                    <div className="mt-1 text-lg font-black text-slate-900">
                      {safeStr(activeCounterpart.full_name, "AgroConnect user")}
                    </div>
                    <div className="mt-1 text-sm text-slate-600">
                      {activeThread.subject}
                    </div>
                  </div>

                  <div className="flex flex-wrap items-center gap-2 text-xs text-slate-500">
                    <span className="inline-flex items-center gap-1 rounded-full border border-slate-200 bg-slate-50 px-3 py-1.5">
                      <UserRound className="h-3.5 w-3.5" />
                      {safeStr(activeCounterpart.role_name, "user")}
                    </span>
                    <span className="inline-flex items-center gap-1 rounded-full border border-slate-200 bg-slate-50 px-3 py-1.5">
                      <Mail className="h-3.5 w-3.5" />
                      {safeStr(activeCounterpart.email, "No email shared")}
                    </span>
                  </div>
                </div>

                {activeProduct?.name ? (
                  <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4 text-sm text-slate-700">
                    <div className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                      Product context
                    </div>
                    <div className="mt-1 font-bold text-slate-900">
                      {activeProduct.name}
                    </div>
                    <div className="mt-1 text-xs text-slate-500">
                      Keep the conversation focused on this listing for faster support
                      and order clarity.
                    </div>
                  </div>
                ) : null}
              </>
            ) : (
              <div>
                <CardTitle>Select a conversation</CardTitle>
                <p className="mt-1 text-sm text-slate-600">
                  Choose a thread from the inbox to read and reply.
                </p>
              </div>
            )}
          </CardHeader>

          <CardContent className="space-y-4">
            {!selectedThreadId ? (
              <EmptyState
                title="No thread selected"
                text="Select a conversation from the left panel."
              />
            ) : loadingThread ? (
              <div className="flex items-center gap-2 text-sm text-slate-500">
                <Loader2 className="h-4 w-4 animate-spin" />
                Loading conversation…
              </div>
            ) : (
              <>
                <div
                  ref={scrollerRef}
                  className="max-h-[420px] space-y-3 overflow-y-auto rounded-2xl border border-slate-200 bg-slate-50 p-4"
                >
                  {messages.length === 0 ? (
                    <EmptyState
                      title="No messages yet"
                      text="Use the composer below to start the conversation."
                    />
                  ) : (
                    messages.map((row) => {
                      const mine = safeStr(row.sender_role_name) === role;

                      return (
                        <div
                          key={row.message_id}
                          className={`flex ${mine ? "justify-end" : "justify-start"}`}
                        >
                          <div
                            className={[
                              "max-w-[85%] rounded-2xl px-4 py-3 text-sm shadow-sm",
                              mine
                                ? "bg-emerald-600 text-white"
                                : "border border-slate-200 bg-white text-slate-800",
                            ].join(" ")}
                          >
                            <div
                              className={`text-[11px] font-semibold ${
                                mine ? "text-emerald-50" : "text-slate-500"
                              }`}
                            >
                              {row.sender_name}
                            </div>
                            <div className="mt-1 whitespace-pre-wrap leading-6">
                              {row.body}
                            </div>
                            <div
                              className={`mt-2 text-[11px] ${
                                mine ? "text-emerald-100" : "text-slate-400"
                              }`}
                            >
                              {formatRelativeDate(row.created_at)}
                            </div>
                          </div>
                        </div>
                      );
                    })
                  )}
                </div>

                <div className="rounded-2xl border border-slate-200 bg-white p-4">
                  <label className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                    Reply
                  </label>
                  <textarea
                    value={draft}
                    onChange={(e) => setDraft(e.target.value)}
                    rows={4}
                    placeholder={
                      role === "customer"
                        ? "Ask about stock, delivery, freshness, or order details..."
                        : "Reply to the customer here..."
                    }
                    className="mt-2 w-full rounded-2xl border border-slate-200 px-4 py-3 text-sm outline-none transition focus:border-slate-400"
                  />

                  <div className="mt-3 flex flex-wrap items-center justify-between gap-3">
                    <div className="text-xs text-slate-500">
                      Messages stay inside AgroConnect so both sides have one clean
                      record.
                    </div>
                    <button
                      type="button"
                      onClick={handleSend}
                      disabled={!safeStr(draft) || !selectedThreadId || busySend}
                      className="inline-flex h-11 items-center gap-2 rounded-2xl bg-emerald-600 px-4 text-sm font-bold text-white hover:brightness-95 disabled:cursor-not-allowed disabled:bg-slate-300"
                    >
                      {busySend ? (
                        <Loader2 className="h-4 w-4 animate-spin" />
                      ) : (
                        <SendHorizonal className="h-4 w-4" />
                      )}
                      Send message
                    </button>
                  </div>
                </div>
              </>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}