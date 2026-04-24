// ============================================================================
// frontend/src/pages/dashboards/admin/AdminMessagingPage.jsx
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Professional admin messaging workspace for:
//     • direct one-to-one recipient communication
//     • audience broadcasts
//     • multi-channel dispatch (SMS, Email, or both)
//
// THIS UPDATE:
//   ✅ Admin can choose between a direct recipient and a broadcast audience
//   ✅ Adds searchable recipient directory for intended-recipient delivery
//   ✅ Adds audience coverage insight for professional broadcast planning
//   ✅ Strengthens delivery preview, contact readiness, and governance cues
//   ✅ Keeps the UI aligned with a master's-level administrative system
// ============================================================================

import React, { useEffect, useMemo, useState } from "react";
import toast from "react-hot-toast";
import {
  CheckCircle2,
  Layers3,
  Mail,
  Megaphone,
  MessageSquare,
  Search,
  Send,
  ShieldCheck,
  Smartphone,
  MessageCircleMore,
  Lock,
  Sparkles,
  UserRound,
  Users,
} from "lucide-react";

import AdminLayout from "../../../components/AdminLayout";
import ProtectedRoute from "../../../components/auth/ProtectedRoute";
import Card from "../../../components/ui/Card";
import api from "../../../api";

// ----------------------------------------------------------------------------
// Templates
// ----------------------------------------------------------------------------
const MESSAGE_TEMPLATES = [
  {
    key: "system_maintenance",
    label: "System maintenance",
    subject: "Scheduled platform maintenance",
    audienceRole: "all",
    message:
      "AgroConnect Namibia will undergo scheduled maintenance during the stated service window. Some platform functions may be temporarily unavailable. We appreciate your patience as we complete this operational improvement.",
  },
  {
    key: "farmer_operations",
    label: "Farmer operations notice",
    subject: "Farmer operations update",
    audienceRole: "farmers",
    message:
      "Please review your listings, stock quantities, delivery settings, and payment profile details. Keeping operational data current improves fulfilment quality and reduces transaction delays.",
  },
  {
    key: "customer_service",
    label: "Customer service notice",
    subject: "Marketplace service update",
    audienceRole: "customers",
    message:
      "Thank you for using AgroConnect Namibia. We are sharing an important marketplace update related to ordering, service quality, or platform availability. Please review this notice carefully.",
  },
  {
    key: "policy_compliance",
    label: "Policy / compliance notice",
    subject: "Policy and compliance reminder",
    audienceRole: "all",
    message:
      "This is an administrative reminder to review current platform policy requirements. Continued platform participation depends on compliance with listing, communication, and account governance standards.",
  },
];

const ROLE_OPTIONS = [
  { value: "all", label: "All Users" },
  { value: "farmers", label: "Farmers" },
  { value: "customers", label: "Customers" },
  { value: "admins", label: "Administrators" },
];

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------
function safeStr(v, fallback = "") {
  if (typeof v === "string") return v;
  if (v == null) return fallback;
  return String(v);
}

function titleCaseWords(v) {
  return safeStr(v)
    .replace(/[_-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/\b\w/g, (m) => m.toUpperCase());
}

function roleLabel(role) {
  const key = safeStr(role).toLowerCase();
  if (key === "farmers" || key === "farmer") return "Farmers";
  if (key === "customers" || key === "customer") return "Customers";
  if (key === "admins" || key === "admin") return "Administrators";
  return "All Users";
}

function compactNumber(value) {
  const n = Number(value || 0);
  if (!Number.isFinite(n)) return "0";
  return new Intl.NumberFormat().format(n);
}

function contactSummaryLabel(recipient) {
  if (!recipient) return "No recipient selected";
  return recipient.full_name || recipient.email || recipient.phone || "Selected recipient";
}

function fallbackSubject(subject, message) {
  const cleanSubject = safeStr(subject).trim();
  if (cleanSubject) return cleanSubject;

  const cleanMessage = safeStr(message).replace(/\s+/g, " ").trim();
  if (!cleanMessage) return "AgroConnect Notice";

  return `AgroConnect Notice — ${cleanMessage.slice(0, 72).trim()}`;
}

function StatCard({ title, value, subtext, tone = "slate" }) {
  const accent =
    tone === "emerald"
      ? "border-emerald-200 bg-emerald-50/70"
      : tone === "amber"
      ? "border-amber-200 bg-amber-50/70"
      : tone === "sky"
      ? "border-sky-200 bg-sky-50/70"
      : "border-slate-200 bg-white";

  return (
    <Card className={`rounded-2xl border p-4 shadow-sm ${accent}`}>
      <div className="text-xs font-bold uppercase tracking-wide text-slate-500">{title}</div>
      <div className="mt-2 text-2xl font-black text-slate-900">{value}</div>
      <div className="mt-1 text-xs font-semibold text-slate-600">{subtext}</div>
    </Card>
  );
}

function ModeButton({ active, icon: Icon, title, subtitle, onClick }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={[
        "w-full rounded-2xl border p-4 text-left shadow-sm transition",
        active
          ? "border-emerald-300 bg-emerald-50/70"
          : "border-slate-200 bg-white hover:border-emerald-200 hover:bg-emerald-50/30",
      ].join(" ")}
    >
      <div className="flex items-start gap-3">
        <div
          className={[
            "mt-0.5 rounded-xl p-2",
            active ? "bg-emerald-100 text-emerald-700" : "bg-slate-100 text-slate-700",
          ].join(" ")}
        >
          <Icon className="h-4 w-4" />
        </div>
        <div className="min-w-0">
          <div className="text-sm font-extrabold text-slate-900">{title}</div>
          <div className="mt-1 text-xs leading-5 text-slate-600">{subtitle}</div>
        </div>
      </div>
    </button>
  );
}

export default function AdminMessagingPage() {
  const [deliveryMode, setDeliveryMode] = useState("broadcast");
  const [channels, setChannels] = useState({ sms: true, email: true });
  const [subject, setSubject] = useState("");
  const [message, setMessage] = useState("");
  const [audienceRole, setAudienceRole] = useState("all");
  const [sending, setSending] = useState(false);

  const [audienceSummary, setAudienceSummary] = useState(null);
  const [loadingAudienceSummary, setLoadingAudienceSummary] = useState(false);

  const [recipientSearch, setRecipientSearch] = useState("");
  const [recipientResults, setRecipientResults] = useState([]);
  const [recipientRoleFilter, setRecipientRoleFilter] = useState("all");
  const [searchingRecipients, setSearchingRecipients] = useState(false);
  const [selectedRecipient, setSelectedRecipient] = useState(null);

  const [lastDispatch, setLastDispatch] = useState(null);

  const selectedChannels = useMemo(
    () => Object.keys(channels).filter((k) => channels[k]),
    [channels]
  );

  const charCount = message.length;
  const resolvedSubject = useMemo(
    () => fallbackSubject(subject, message),
    [subject, message]
  );

  const isSingleMode = deliveryMode === "single";

  const audienceLabel = useMemo(() => {
    if (isSingleMode) return "Individual Recipient";
    return roleLabel(audienceRole);
  }, [audienceRole, isSingleMode]);

  const channelSummary = useMemo(() => {
    if (!selectedChannels.length) return "No delivery channel selected";
    if (selectedChannels.length === 2) return "SMS and Email";
    if (selectedChannels[0] === "sms") return "SMS";
    return "Email";
  }, [selectedChannels]);

  const smsLikelyLong = useMemo(() => charCount > 160, [charCount]);

  const currentCoverage = useMemo(() => {
    if (isSingleMode) {
      return {
        label: selectedRecipient ? "Selected recipient" : "No recipient selected",
        total: selectedRecipient ? 1 : 0,
        sms_reachable: selectedRecipient?.has_sms ? 1 : 0,
        email_reachable: selectedRecipient?.has_email ? 1 : 0,
      };
    }

    return (
      audienceSummary?.[audienceRole] || {
        label: roleLabel(audienceRole),
        total: 0,
        sms_reachable: 0,
        email_reachable: 0,
      }
    );
  }, [audienceRole, audienceSummary, isSingleMode, selectedRecipient]);

  const canSend = useMemo(() => {
    if (!message.trim()) return false;
    if (!selectedChannels.length) return false;
    if (isSingleMode && !selectedRecipient) return false;
    return true;
  }, [isSingleMode, message, selectedChannels.length, selectedRecipient]);

  // --------------------------------------------------------------------------
  // Load broadcast audience coverage once and refresh after dispatch.
  // --------------------------------------------------------------------------
  const loadAudienceSummary = async () => {
    try {
      setLoadingAudienceSummary(true);
      const { data } = await api.get("/admin/notifications/audience-summary");
      setAudienceSummary(data?.data || null);
    } catch (err) {
      console.error("Failed to load audience summary", err);
    } finally {
      setLoadingAudienceSummary(false);
    }
  };

  useEffect(() => {
    loadAudienceSummary();
  }, []);

  // --------------------------------------------------------------------------
  // Search recipient directory for direct one-to-one delivery.
  // --------------------------------------------------------------------------
  useEffect(() => {
    if (!isSingleMode) return;

    let cancelled = false;
    const timer = setTimeout(async () => {
      try {
        setSearchingRecipients(true);
        const { data } = await api.get("/admin/notifications/recipients", {
          params: {
            q: recipientSearch.trim(),
            role: recipientRoleFilter,
            limit: 8,
          },
        });
        if (!cancelled) {
          setRecipientResults(Array.isArray(data?.data?.items) ? data.data.items : []);
        }
      } catch (err) {
        if (!cancelled) {
          console.error("Recipient search failed", err);
          setRecipientResults([]);
        }
      } finally {
        if (!cancelled) setSearchingRecipients(false);
      }
    }, 250);

    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [isSingleMode, recipientRoleFilter, recipientSearch]);

  const applyTemplate = (tpl) => {
    setSubject(tpl.subject || "");
    setMessage(tpl.message || "");
    if (!isSingleMode && tpl.audienceRole) {
      setAudienceRole(tpl.audienceRole);
    }
  };

  const clearComposer = () => {
    setSubject("");
    setMessage("");
    setLastDispatch(null);
  };

  const submitDispatch = async (e) => {
    e?.preventDefault();

    if (!message.trim()) return toast.error("Message required");
    if (selectedChannels.length === 0) return toast.error("Select at least one delivery channel");
    if (isSingleMode && !selectedRecipient) {
      return toast.error("Select an intended recipient before sending");
    }

    try {
      setSending(true);

      const payload = {
        mode: deliveryMode,
        channels: selectedChannels,
        subject: subject.trim(),
        message: message.trim(),
        audience: {
          role: audienceRole,
          user_id: selectedRecipient?.id || null,
        },
      };

      const { data } = await api.post("/admin/notifications/broadcast", payload);
      setLastDispatch(data?.meta || null);
      toast.success(data?.message || (isSingleMode ? "Message sent" : "Broadcast dispatched"));
      setSubject("");
      setMessage("");
      await loadAudienceSummary();
    } catch (err) {
      console.error("Dispatch failed", err);
      const fallback = err?.response?.data?.message || "Failed to send dispatch";
      toast.error(fallback);
    } finally {
      setSending(false);
    }
  };

  return (
    <ProtectedRoute roles={["admin"]}>
      <AdminLayout>
        <div className="space-y-6">
          {/* Header */}
          <div className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1fr)_auto] xl:items-start">
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <MessageSquare className="h-5 w-5 text-emerald-700" />
                <h2 className="text-2xl font-extrabold text-slate-900">
                  Messaging & Broadcasts
                </h2>
              </div>
              <p className="mt-1 max-w-5xl text-sm text-slate-600">
                Send structured administrative communication through a professional workspace that
                supports direct intended recipients, admin-only audience broadcasts, and controlled
                multi-channel delivery.
              </p>
            </div>
          </div>

          <Card className="rounded-2xl border border-emerald-200 bg-emerald-50/70 p-5 shadow-sm">
            <div className="flex items-start gap-3">
              <div className="mt-0.5 rounded-2xl bg-white p-2 text-emerald-700 shadow-sm">
                <Lock className="h-5 w-5" />
              </div>
              <div className="min-w-0">
                <div className="text-sm font-extrabold text-slate-900">Administrative communication rules</div>
                <div className="mt-1 text-sm leading-6 text-slate-700">
                  Only administrators can send role-wide or all-user broadcasts. Customers and farmers do not use this workspace for marketplace conversations.
                </div>
                <div className="mt-4 grid gap-3 md:grid-cols-3">
                  <div className="rounded-2xl border border-white/70 bg-white/80 p-4">
                    <div className="flex items-center gap-2 text-sm font-bold text-slate-900"><Megaphone className="h-4 w-4 text-emerald-700" /> Admin</div>
                    <div className="mt-1 text-xs leading-5 text-slate-600">Can send direct notices to one user or approved broadcasts to role audiences and all users.</div>
                  </div>
                  <div className="rounded-2xl border border-white/70 bg-white/80 p-4">
                    <div className="flex items-center gap-2 text-sm font-bold text-slate-900"><MessageCircleMore className="h-4 w-4 text-emerald-700" /> Customer</div>
                    <div className="mt-1 text-xs leading-5 text-slate-600">Starts a conversation from the marketplace by choosing <span className="font-semibold">Message Farmer</span> on a product.</div>
                  </div>
                  <div className="rounded-2xl border border-white/70 bg-white/80 p-4">
                    <div className="flex items-center gap-2 text-sm font-bold text-slate-900"><MessageSquare className="h-4 w-4 text-emerald-700" /> Farmer</div>
                    <div className="mt-1 text-xs leading-5 text-slate-600">Replies in the inbox or starts from an order by choosing <span className="font-semibold">Message customer</span>.</div>
                  </div>
                </div>
              </div>
            </div>
          </Card>

          {/* Summary cards */}
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2 2xl:grid-cols-4">
            <StatCard
              title="Dispatch Mode"
              value={isSingleMode ? "Direct Recipient" : "Broadcast"}
              subtext="Choose one user or a role-based audience segment."
              tone="sky"
            />
            <StatCard
              title="Recipient Scope"
              value={isSingleMode ? contactSummaryLabel(selectedRecipient) : audienceLabel}
              subtext={
                isSingleMode
                  ? "Current intended recipient selected for this message."
                  : "Current broadcast audience selected for this dispatch."
              }
              tone="emerald"
            />
            <StatCard
              title="Channels"
              value={channelSummary}
              subtext="SMS, Email, or dual-channel delivery."
              tone="amber"
            />
            <StatCard
              title="Characters"
              value={compactNumber(charCount)}
              subtext={smsLikelyLong ? "Longer SMS content detected." : "SMS-friendly content length."}
              tone="slate"
            />
          </div>

          {/* Main workspace */}
          <div className="grid grid-cols-1 gap-6 2xl:grid-cols-[minmax(0,1fr)_380px]">
            {/* Compose side */}
            <div className="space-y-6">
              {/* Quick templates */}
              <Card className="rounded-2xl border border-slate-200 p-5 shadow-sm">
                <div className="flex items-center gap-2 text-sm font-extrabold text-slate-900">
                  <Sparkles className="h-4 w-4 text-amber-600" />
                  Quick templates
                </div>

                <div className="mt-4 grid grid-cols-1 gap-3 md:grid-cols-2">
                  {MESSAGE_TEMPLATES.map((tpl) => (
                    <button
                      key={tpl.key}
                      type="button"
                      onClick={() => applyTemplate(tpl)}
                      className="rounded-2xl border border-slate-200 bg-white p-4 text-left shadow-sm transition hover:border-emerald-200 hover:bg-emerald-50/40"
                    >
                      <div className="text-sm font-extrabold text-slate-900">{tpl.label}</div>
                      <div className="mt-1 text-xs leading-5 text-slate-600">{tpl.subject}</div>
                      <div className="mt-2 text-[11px] font-bold uppercase tracking-wide text-slate-400">
                        Recommended audience: {roleLabel(tpl.audienceRole)}
                      </div>
                    </button>
                  ))}
                </div>
              </Card>

              {/* Dispatch form */}
              <Card className="rounded-2xl border border-slate-200 p-6 shadow-sm">
                <form onSubmit={submitDispatch} className="space-y-6">
                  {/* Dispatch mode */}
                  <div>
                    <label className="mb-3 block text-sm font-semibold text-slate-700">
                      Dispatch mode
                    </label>
                    <div className="grid grid-cols-1 gap-3 xl:grid-cols-2">
                      <ModeButton
                        active={isSingleMode}
                        icon={UserRound}
                        title="Direct recipient"
                        subtitle="Send a case-specific administrative notice to one selected user from the directory."
                        onClick={() => setDeliveryMode("single")}
                      />
                      <ModeButton
                        active={!isSingleMode}
                        icon={Layers3}
                        title="Admin-only broadcast audience"
                        subtitle="Distribute a governed announcement to a role audience or all users. This mode is reserved for administrators only."
                        onClick={() => setDeliveryMode("broadcast")}
                      />
                    </div>
                  </div>

                  <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4 text-sm text-slate-700">
                    {isSingleMode
                      ? "Direct-recipient mode sends one administrative message to one selected user only."
                      : "Broadcast mode is the only place where all-user and role-wide administrative messaging is allowed."}
                  </div>

                  {/* Recipient / audience selection */}
                  {isSingleMode ? (
                    <div className="space-y-4 rounded-2xl border border-slate-200 bg-slate-50/70 p-4">
                      <div className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1fr)_220px]">
                        <div>
                          <label className="mb-2 block text-sm font-semibold text-slate-700">
                            Search intended recipient
                          </label>
                          <div className="flex items-center gap-2 rounded-2xl border border-slate-200 bg-white px-3 py-2.5">
                            <Search className="h-4 w-4 text-slate-400" />
                            <input
                              value={recipientSearch}
                              onChange={(e) => setRecipientSearch(e.target.value)}
                              className="w-full border-0 bg-transparent text-sm text-slate-900 outline-none"
                              placeholder="Search by full name, email, or phone…"
                            />
                          </div>
                        </div>

                        <div>
                          <label className="mb-2 block text-sm font-semibold text-slate-700">
                            Directory filter
                          </label>
                          <select
                            value={recipientRoleFilter}
                            onChange={(e) => setRecipientRoleFilter(e.target.value)}
                            className="h-[44px] w-full rounded-2xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-900 outline-none focus:ring-2 focus:ring-emerald-200"
                          >
                            {ROLE_OPTIONS.map((opt) => (
                              <option key={opt.value} value={opt.value}>
                                {opt.label}
                              </option>
                            ))}
                          </select>
                        </div>
                      </div>

                      <div>
                        <div className="mb-2 flex items-center justify-between">
                          <div className="text-sm font-semibold text-slate-700">Recipient results</div>
                          <div className="text-xs font-semibold text-slate-500">
                            {searchingRecipients ? "Searching…" : `${recipientResults.length} found`}
                          </div>
                        </div>

                        <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
                          {recipientResults.map((item) => {
                            const active = selectedRecipient?.id === item.id;
                            return (
                              <button
                                key={item.id}
                                type="button"
                                onClick={() => setSelectedRecipient(item)}
                                className={[
                                  "rounded-2xl border p-4 text-left shadow-sm transition",
                                  active
                                    ? "border-emerald-300 bg-emerald-50/80"
                                    : "border-slate-200 bg-white hover:border-emerald-200 hover:bg-emerald-50/30",
                                ].join(" ")}
                              >
                                <div className="flex items-start justify-between gap-3">
                                  <div className="min-w-0">
                                    <div className="truncate text-sm font-extrabold text-slate-900">
                                      {item.full_name || "Unnamed user"}
                                    </div>
                                    <div className="mt-1 text-xs font-semibold uppercase tracking-wide text-slate-500">
                                      {titleCaseWords(item.role_name || item.role)}
                                    </div>
                                  </div>
                                  {active ? (
                                    <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-600" />
                                  ) : null}
                                </div>

                                <div className="mt-3 space-y-1 text-xs text-slate-600">
                                  <div>{item.email || "No email address"}</div>
                                  <div>{item.phone || "No phone number"}</div>
                                </div>
                              </button>
                            );
                          })}
                        </div>

                        {!searchingRecipients && recipientResults.length === 0 ? (
                          <div className="mt-3 rounded-2xl border border-dashed border-slate-200 bg-white p-4 text-sm text-slate-500">
                            No matching recipients found in the active user directory.
                          </div>
                        ) : null}
                      </div>

                      <div className="rounded-2xl border border-slate-200 bg-white p-4">
                        <div className="text-xs font-bold uppercase tracking-wide text-slate-500">
                          Selected recipient
                        </div>
                        <div className="mt-2 text-sm font-extrabold text-slate-900">
                          {contactSummaryLabel(selectedRecipient)}
                        </div>
                        <div className="mt-2 grid grid-cols-1 gap-2 text-xs text-slate-600 md:grid-cols-3">
                          <div>
                            <span className="font-semibold text-slate-700">Role:</span>{" "}
                            {selectedRecipient ? titleCaseWords(selectedRecipient.role_name || selectedRecipient.role) : "—"}
                          </div>
                          <div>
                            <span className="font-semibold text-slate-700">Email:</span>{" "}
                            {selectedRecipient?.email || "—"}
                          </div>
                          <div>
                            <span className="font-semibold text-slate-700">Phone:</span>{" "}
                            {selectedRecipient?.phone || "—"}
                          </div>
                        </div>
                      </div>
                    </div>
                  ) : (
                    <div className="space-y-4 rounded-2xl border border-slate-200 bg-slate-50/70 p-4">
                      <div>
                        <label className="mb-2 block text-sm font-semibold text-slate-700">
                          Broadcast audience
                        </label>
                        <select
                          value={audienceRole}
                          onChange={(e) => setAudienceRole(e.target.value)}
                          className="h-[44px] w-full rounded-2xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-900 outline-none focus:ring-2 focus:ring-emerald-200"
                        >
                          {ROLE_OPTIONS.map((opt) => (
                            <option key={opt.value} value={opt.value}>
                              {opt.label}
                            </option>
                          ))}
                        </select>
                        <p className="mt-2 text-xs text-slate-500">
                          Use role-based audiences for formal operational notices, service updates,
                          or governance-wide communication.
                        </p>
                      </div>

                      <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
                        <div className="rounded-2xl border border-slate-200 bg-white p-4">
                          <div className="text-xs font-bold uppercase tracking-wide text-slate-500">
                            Eligible users
                          </div>
                          <div className="mt-2 text-xl font-black text-slate-900">
                            {loadingAudienceSummary ? "…" : compactNumber(currentCoverage.total)}
                          </div>
                        </div>

                        <div className="rounded-2xl border border-slate-200 bg-white p-4">
                          <div className="text-xs font-bold uppercase tracking-wide text-slate-500">
                            SMS reachable
                          </div>
                          <div className="mt-2 text-xl font-black text-slate-900">
                            {loadingAudienceSummary ? "…" : compactNumber(currentCoverage.sms_reachable)}
                          </div>
                        </div>

                        <div className="rounded-2xl border border-slate-200 bg-white p-4">
                          <div className="text-xs font-bold uppercase tracking-wide text-slate-500">
                            Email reachable
                          </div>
                          <div className="mt-2 text-xl font-black text-slate-900">
                            {loadingAudienceSummary ? "…" : compactNumber(currentCoverage.email_reachable)}
                          </div>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Channel selection */}
                  <div>
                    <label className="mb-2 block text-sm font-semibold text-slate-700">
                      Delivery channels
                    </label>

                    <div className="flex flex-wrap gap-3">
                      <label className="flex items-center gap-2 rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3">
                        <input
                          type="checkbox"
                          checked={channels.sms}
                          onChange={(e) => setChannels((s) => ({ ...s, sms: e.target.checked }))}
                        />
                        <Smartphone className="h-4 w-4 text-slate-700" />
                        <span className="text-sm font-semibold text-slate-900">SMS</span>
                      </label>

                      <label className="flex items-center gap-2 rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3">
                        <input
                          type="checkbox"
                          checked={channels.email}
                          onChange={(e) => setChannels((s) => ({ ...s, email: e.target.checked }))}
                        />
                        <Mail className="h-4 w-4 text-slate-700" />
                        <span className="text-sm font-semibold text-slate-900">Email</span>
                      </label>
                    </div>

                    <div className="mt-2 text-xs text-slate-500">
                      Selected channels:{" "}
                      <span className="font-semibold text-slate-700">
                        {selectedChannels.join(", ") || "none"}
                      </span>
                    </div>
                  </div>

                  {/* Subject */}
                  <div>
                    <label className="mb-2 block text-sm font-semibold text-slate-700">
                      Subject
                    </label>
                    <input
                      value={subject}
                      onChange={(e) => setSubject(e.target.value)}
                      className="w-full rounded-2xl border border-slate-200 bg-white px-3 py-2.5 text-sm text-slate-900 outline-none focus:ring-2 focus:ring-emerald-200"
                      placeholder="e.g., Service notice, platform governance update…"
                    />
                    <div className="mt-2 text-xs text-slate-500">
                      If left blank, the system generates a professional fallback subject for email delivery.
                    </div>
                  </div>

                  {/* Message */}
                  <div>
                    <div className="mb-2 flex items-center justify-between">
                      <label className="text-sm font-semibold text-slate-700">Message</label>
                      <div className="text-xs font-semibold text-slate-500">{compactNumber(charCount)} chars</div>
                    </div>

                    <textarea
                      value={message}
                      onChange={(e) => setMessage(e.target.value)}
                      rows={8}
                      className="w-full rounded-2xl border border-slate-200 bg-white px-3 py-3 text-sm text-slate-900 outline-none focus:ring-2 focus:ring-emerald-200"
                      placeholder="Write your administrative message…"
                    />

                    <div className="mt-2 text-xs text-slate-500">
                      Keep SMS content concise. Email can carry additional structure, context, and formal wording.
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="flex flex-wrap justify-end gap-3">
                    <button
                      type="button"
                      className="inline-flex items-center justify-center rounded-2xl border border-slate-200 bg-white px-4 py-2 text-sm font-extrabold text-slate-800 hover:bg-slate-50"
                      onClick={clearComposer}
                    >
                      Clear
                    </button>

                    <button
                      type="submit"
                      className="inline-flex items-center gap-2 rounded-2xl bg-emerald-600 px-4 py-2 text-sm font-extrabold text-white shadow-sm hover:bg-emerald-700 disabled:opacity-60"
                      disabled={sending || !canSend}
                    >
                      <Send className="h-4 w-4" />
                      {sending
                        ? "Sending…"
                        : isSingleMode
                        ? "Send to Recipient"
                        : "Send Broadcast"}
                    </button>
                  </div>
                </form>
              </Card>
            </div>

            {/* Right panel */}
            <div className="space-y-6">
              {/* Preview */}
              <Card className="rounded-2xl border border-slate-200 p-5 shadow-sm">
                <div className="flex items-center gap-2 text-sm font-extrabold text-slate-900">
                  <Megaphone className="h-4 w-4 text-slate-700" />
                  Dispatch preview
                </div>

                <div className="mt-4 rounded-2xl border border-slate-200 bg-slate-50 p-4">
                  <div className="text-xs font-bold uppercase tracking-wide text-slate-500">
                    Delivery mode
                  </div>
                  <div className="mt-1 text-sm font-extrabold text-slate-900">
                    {isSingleMode ? "Direct intended recipient" : "Broadcast audience"}
                  </div>

                  <div className="mt-4 text-xs font-bold uppercase tracking-wide text-slate-500">
                    Recipient scope
                  </div>
                  <div className="mt-1 text-sm font-semibold text-slate-800">
                    {isSingleMode ? contactSummaryLabel(selectedRecipient) : audienceLabel}
                  </div>

                  <div className="mt-4 text-xs font-bold uppercase tracking-wide text-slate-500">
                    Delivery channels
                  </div>
                  <div className="mt-1 text-sm font-semibold text-slate-800">
                    {channelSummary}
                  </div>

                  <div className="mt-4 text-xs font-bold uppercase tracking-wide text-slate-500">
                    Resolved subject
                  </div>
                  <div className="mt-1 text-sm font-semibold text-slate-800">{resolvedSubject}</div>

                  <div className="mt-4 text-xs font-bold uppercase tracking-wide text-slate-500">
                    Message body
                  </div>
                  <div className="mt-1 whitespace-pre-wrap text-sm leading-6 text-slate-700">
                    {message.trim() || "Your message preview will appear here."}
                  </div>
                </div>
              </Card>

              {/* Governance guidance */}
              <Card className="rounded-2xl border border-slate-200 p-5 shadow-sm">
                <div className="flex items-center gap-2 text-sm font-extrabold text-slate-900">
                  <ShieldCheck className="h-4 w-4 text-slate-700" />
                  Governance guidance
                </div>

                <div className="mt-4 space-y-3 text-sm leading-6 text-slate-700">
                  <p>
                    Direct-recipient mode is best for case-specific communication, while broadcast mode is
                    better for structured operational or compliance-wide notices.
                  </p>
                  <p>
                    Messages remain most effective when they are concise, precise, and aligned to the selected
                    delivery channel and recipient scope.
                  </p>
                  <p>
                    Each dispatch should be reviewed carefully because administrative communication forms part
                    of the platform’s governance and accountability record.
                  </p>
                </div>
              </Card>

              {/* Delivery readiness */}
              <Card className="rounded-2xl border border-slate-200 p-5 shadow-sm">
                <div className="flex items-center gap-2 text-sm font-extrabold text-slate-900">
                  <Users className="h-4 w-4 text-slate-700" />
                  Delivery readiness
                </div>

                <div className="mt-4 space-y-3 text-sm text-slate-700">
                  <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                    <div className="text-xs font-bold uppercase tracking-wide text-slate-500">
                      Recipient coverage
                    </div>
                    <div className="mt-1 font-semibold text-slate-900">
                      {compactNumber(currentCoverage.total)} eligible target
                      {Number(currentCoverage.total || 0) === 1 ? "" : "s"}
                    </div>
                  </div>

                  <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
                    <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                      <div className="text-xs font-bold uppercase tracking-wide text-slate-500">
                        SMS reachable
                      </div>
                      <div className="mt-1 font-semibold text-slate-900">
                        {compactNumber(currentCoverage.sms_reachable)}
                      </div>
                    </div>

                    <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                      <div className="text-xs font-bold uppercase tracking-wide text-slate-500">
                        Email reachable
                      </div>
                      <div className="mt-1 font-semibold text-slate-900">
                        {compactNumber(currentCoverage.email_reachable)}
                      </div>
                    </div>
                  </div>

                  <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
                    <div className="text-xs font-bold uppercase tracking-wide text-slate-500">
                      SMS length assessment
                    </div>
                    <div className="mt-1 font-semibold text-slate-900">
                      {smsLikelyLong ? "Long-format SMS content" : "Compact SMS-friendly content"}
                    </div>
                  </div>
                </div>
              </Card>

              {/* Last dispatch */}
              <Card className="rounded-2xl border border-slate-200 p-5 shadow-sm">
                <div className="flex items-center gap-2 text-sm font-extrabold text-slate-900">
                  <CheckCircle2 className="h-4 w-4 text-emerald-600" />
                  Last dispatch result
                </div>

                <div className="mt-4 rounded-2xl border border-slate-200 bg-slate-50 p-4 text-sm text-slate-700">
                  {lastDispatch ? (
                    <div className="space-y-3">
                      <div>
                        <div className="text-xs font-bold uppercase tracking-wide text-slate-500">
                          Dispatch ID
                        </div>
                        <div className="mt-1 break-all font-semibold text-slate-900">
                          {lastDispatch.dispatch_id || "—"}
                        </div>
                      </div>

                      <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
                        <div>
                          <div className="text-xs font-bold uppercase tracking-wide text-slate-500">
                            Recipient count
                          </div>
                          <div className="mt-1 font-semibold text-slate-900">
                            {compactNumber(lastDispatch.recipient_count)}
                          </div>
                        </div>
                        <div>
                          <div className="text-xs font-bold uppercase tracking-wide text-slate-500">
                            In-app notifications
                          </div>
                          <div className="mt-1 font-semibold text-slate-900">
                            {compactNumber(lastDispatch.in_app_created)}
                          </div>
                        </div>
                      </div>

                      <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
                        <div>
                          <div className="text-xs font-bold uppercase tracking-wide text-slate-500">
                            SMS sent / failed
                          </div>
                          <div className="mt-1 font-semibold text-slate-900">
                            {compactNumber(lastDispatch.sms_sent)} / {compactNumber(lastDispatch.sms_failed)}
                          </div>
                        </div>
                        <div>
                          <div className="text-xs font-bold uppercase tracking-wide text-slate-500">
                            Email sent / failed
                          </div>
                          <div className="mt-1 font-semibold text-slate-900">
                            {compactNumber(lastDispatch.email_sent)} / {compactNumber(lastDispatch.email_failed)}
                          </div>
                        </div>
                      </div>
                    </div>
                  ) : (
                    <div>No administrative dispatch has been sent in this session yet.</div>
                  )}
                </div>
              </Card>
            </div>
          </div>
        </div>
      </AdminLayout>
    </ProtectedRoute>
  );
}
