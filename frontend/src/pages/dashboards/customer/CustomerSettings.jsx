// ============================================================================
// frontend/src/pages/dashboards/customer/CustomerSettings.jsx
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Customer-facing My Account workspace.
//   • Editable profile details
//   • Editable delivery profile
//   • Simple communication & privacy view
//   • Simple support & guidance view
//
// DESIGN GOALS IN THIS UPDATE:
//   ✅ Removes Recent Activity from the customer view
//   ✅ Keeps the page customer-focused and easier to understand
//   ✅ Uses available screen width more effectively
//   ✅ Makes profile details and delivery profile clearly editable
//   ✅ Simplifies communication, privacy, and support language
//   ✅ Keeps existing backend contracts and profile update flow intact
// ============================================================================

import React, { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import {
  Save,
  RefreshCcw,
  UserCircle2,
  Bell,
  LifeBuoy,
  MapPin,
  Mail,
  Smartphone,
  ChevronRight,
  Sparkles,
  Wallet,
  ShieldCheck,
  Home,
} from "lucide-react";

import { useAuth } from "../../../components/auth/AuthProvider";
import {
  fetchMyProfile,
  updateMyProfile,
  fetchCustomerAccountWorkspace,
} from "../../../services/customerApi";

function safeArray(value) {
  return Array.isArray(value) ? value : [];
}

function safeStr(value, fallback = "") {
  const s = String(value ?? "").trim();
  return s || fallback;
}

function safeNumber(value, fallback = 0) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function when(value) {
  const raw = safeStr(value, "");
  if (!raw) return "—";

  const dt = new Date(raw);
  if (Number.isNaN(dt.getTime())) return raw;

  return dt.toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

function relativeWhen(value) {
  const raw = safeStr(value, "");
  if (!raw) return "—";

  const dt = new Date(raw);
  if (Number.isNaN(dt.getTime())) return when(value);

  const diffMs = Date.now() - dt.getTime();
  const diffMin = Math.floor(diffMs / 60000);

  if (diffMin < 1) return "just now";
  if (diffMin < 60) return `${diffMin}m ago`;

  const diffHr = Math.floor(diffMin / 60);
  if (diffHr < 24) return `${diffHr}h ago`;

  const diffDay = Math.floor(diffHr / 24);
  if (diffDay < 7) return `${diffDay}d ago`;

  return when(value);
}

function titleize(value) {
  return safeStr(value, "—")
    .replace(/_/g, " ")
    .replace(/\b([a-z])/gi, (m) => m.toUpperCase());
}

function completionPct(values = []) {
  if (!values.length) return 0;
  const done = values.filter(Boolean).length;
  return Math.round((done / values.length) * 100);
}

function initialsFromName(value) {
  const parts = safeStr(value, "User")
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2);

  return parts.map((part) => part[0]?.toUpperCase() || "").join("") || "U";
}

function statusTone(status) {
  const s = safeStr(status, "scaffolded").toLowerCase();

  if (["live", "active", "ready", "enabled", "persisted"].includes(s)) {
    return "border-emerald-200 bg-emerald-50 text-emerald-800";
  }

  if (["planned", "scaffolded", "placeholder", "coming soon"].includes(s)) {
    return "border-amber-200 bg-amber-50 text-amber-800";
  }

  return "border-slate-200 bg-slate-50 text-slate-700";
}

function friendlyStatus(status, fallback = "Coming soon") {
  const s = safeStr(status, "").toLowerCase();

  if (!s) return fallback;
  if (s === "scaffolded") return "Coming soon";
  if (s === "placeholder") return "Placeholder";
  if (s === "planned") return "Planned";
  if (s === "persisted") return "Saved";

  return titleize(s);
}

function SectionCard({ title, subtitle, icon: Icon, children, actions = null }) {
  return (
    <section className="overflow-hidden rounded-[24px] border border-[#D8F3DC] bg-white shadow-sm">
      <div className="flex items-start justify-between gap-4 border-b border-[#EEF7F0] px-5 py-4">
        <div className="min-w-0">
          <div className="flex items-center gap-2 text-slate-900">
            {Icon ? <Icon className="h-4 w-4 text-[#2D6A4F]" /> : null}
            <h2 className="text-sm font-extrabold uppercase tracking-wide">{title}</h2>
          </div>
          {subtitle ? <p className="mt-1 text-xs text-slate-500">{subtitle}</p> : null}
        </div>
        {actions}
      </div>
      <div className="p-5">{children}</div>
    </section>
  );
}

function MetaPill({ label, value }) {
  return (
    <div className="rounded-full border border-[#D8F3DC] bg-white px-3 py-1.5 text-xs text-slate-600">
      <span className="font-semibold text-slate-500">{label}:</span>{" "}
      <span className="font-bold text-slate-800">{value}</span>
    </div>
  );
}

function MiniInfoCard({ label, value, helper, icon: Icon = null }) {
  return (
    <div className="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="text-xs font-bold uppercase tracking-wide text-slate-500">{label}</div>
          <div className="mt-1 text-sm font-black text-slate-900">{value}</div>
          {helper ? <div className="mt-1 text-xs text-slate-500">{helper}</div> : null}
        </div>
        {Icon ? (
          <div className="grid h-9 w-9 shrink-0 place-items-center rounded-2xl border border-[#D8F3DC] bg-white">
            <Icon className="h-4 w-4 text-[#2D6A4F]" />
          </div>
        ) : null}
      </div>
    </div>
  );
}

function StatusBadge({ value, fallback = "Coming soon" }) {
  return (
    <div
      className={`rounded-full border px-2.5 py-1 text-[11px] font-bold ${statusTone(value)}`}
    >
      {friendlyStatus(value, fallback)}
    </div>
  );
}

function ProgressBar({ value }) {
  const safeValue = Math.min(Math.max(safeNumber(value, 0), 0), 100);

  return (
    <div className="h-2.5 overflow-hidden rounded-full bg-white/70">
      <div
        className="h-full rounded-full bg-gradient-to-r from-[#2D6A4F] to-[#74C69D]"
        style={{ width: `${safeValue}%` }}
      />
    </div>
  );
}

function CustomerNote({ children }) {
  return (
    <div className="rounded-2xl border border-[#E7F5EA] bg-[#F7FBF8] px-4 py-3 text-sm leading-6 text-slate-700">
      {children}
    </div>
  );
}

export default function CustomerSettings() {
  const auth = useAuth();
  const { user } = auth;

  const [form, setForm] = useState({
    full_name: user?.full_name || user?.name || "",
    phone: user?.phone || "",
    location: user?.location || "",
    email: user?.email || "",
  });

  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [saving, setSaving] = useState(false);
  const [flash, setFlash] = useState(null);
  const [workspace, setWorkspace] = useState(null);

  const canSave = useMemo(() => {
    const nameOk = safeStr(form.full_name, "").length >= 2;
    const phoneOk = safeStr(form.phone, "").length >= 6;
    const locationOk = safeStr(form.location, "").length >= 2;

    return nameOk && phoneOk && locationOk && !saving;
  }, [form, saving]);

  const loadWorkspace = useCallback(async ({ silent = false } = {}) => {
    try {
      if (silent) setRefreshing(true);
      else setLoading(true);

      setFlash(null);

      const [profilePayload, workspacePayload] = await Promise.all([
        fetchMyProfile().catch(() => null),
        fetchCustomerAccountWorkspace().catch(() => null),
      ]);

      const profileData =
        profilePayload ||
        workspacePayload?.profile ||
        workspacePayload?.user ||
        workspacePayload?.data ||
        {};

      setForm((prev) => ({
        ...prev,
        full_name: profileData?.full_name || profileData?.name || prev.full_name,
        phone: profileData?.phone || prev.phone,
        location: profileData?.location || prev.location,
        email: profileData?.email || prev.email,
      }));

      setWorkspace(workspacePayload || null);
    } catch (err) {
      setFlash({
        type: "error",
        message:
          err?.response?.data?.message ||
          err?.message ||
          "Failed to load the account workspace.",
      });
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    loadWorkspace();
  }, [loadWorkspace]);

  const onChange = (key) => (e) => {
    setForm((prev) => ({ ...prev, [key]: e.target.value }));
  };

  function onReset() {
    setFlash(null);
    setForm({
      full_name: user?.full_name || user?.name || workspace?.profile?.full_name || "",
      phone: user?.phone || workspace?.profile?.phone || "",
      location: user?.location || workspace?.profile?.location || "",
      email: user?.email || workspace?.profile?.email || "",
    });
  }

  async function onSaveProfile() {
    setFlash(null);
    setSaving(true);

    try {
      await updateMyProfile({
        full_name: safeStr(form.full_name, ""),
        phone: safeStr(form.phone, ""),
        location: safeStr(form.location, ""),
      });

      setFlash({ type: "success", message: "Profile updated successfully." });
      await loadWorkspace({ silent: true });
    } catch (err) {
      setFlash({
        type: "error",
        message:
          err?.response?.data?.message ||
          err?.message ||
          "Failed to update customer profile.",
      });
    } finally {
      setSaving(false);
    }
  }

  const profile = useMemo(() => workspace?.profile || {}, [workspace]);
  const notificationOverview = useMemo(() => workspace?.notification_overview || {}, [workspace]);
  const paymentOverview = useMemo(() => workspace?.payment_overview || {}, [workspace]);
  const addresses = useMemo(() => workspace?.addresses || {}, [workspace]);
  const support = useMemo(() => workspace?.support || {}, [workspace]);
  const privacy = useMemo(() => workspace?.privacy || {}, [workspace]);
  const notes = safeArray(workspace?.notes);
  const notificationChannels = safeArray(notificationOverview?.channels);
  const supportChannels = safeArray(support?.channels);
  const addressPlaceholders = safeArray(addresses?.placeholder_items);

  const profileCompletion = useMemo(
    () =>
      completionPct([
        safeStr(form.full_name, ""),
        safeStr(form.phone, ""),
        safeStr(form.location, ""),
        safeStr(form.email || profile?.email, ""),
      ]),
    [form, profile]
  );

  const liveNotificationChannels = useMemo(
    () =>
      notificationChannels.filter((channel) =>
        ["live", "active", "enabled", "ready", "persisted"].includes(
          safeStr(channel?.status, "").toLowerCase()
        )
      ).length,
    [notificationChannels]
  );

  const accountDisplayName = safeStr(form.full_name || profile?.full_name || user?.name, "Customer");
  const accountEmail = safeStr(form.email || profile?.email || user?.email, "No email available");
  const accountLocation = safeStr(form.location || profile?.location, "Location not added yet");
  const accountInitials = initialsFromName(accountDisplayName);
  const unreadNotifications = safeNumber(notificationOverview?.unread_notifications, 0);
  const totalNotifications = safeNumber(notificationOverview?.total_notifications, 0);

  const heroNotes = useMemo(() => {
    const list = [];

    if (profileCompletion >= 100) {
      list.push("Your profile is complete and ready for orders, delivery updates, and support follow-up.");
    } else {
      list.push(`Your profile is ${profileCompletion}% complete. Add missing details for smoother service.`);
    }

    if (paymentOverview?.ready) {
      list.push("Payments history and proof-of-payment visibility are already available from your customer workspace.");
    }

    if (!addresses?.enabled) {
      list.push("Saved addresses are planned for a later update. Your current profile location is still used for delivery guidance.");
    }

    if (unreadNotifications > 0) {
      list.push(`You currently have ${unreadNotifications} unread notification(s).`);
    }

    return list.slice(0, 4);
  }, [profileCompletion, paymentOverview, addresses?.enabled, unreadNotifications]);

  const supportNotes = useMemo(() => {
    return safeArray(support?.notes)
      .concat(notes)
      .filter((item, index, arr) => safeStr(item, "") && arr.indexOf(item) === index)
      .slice(0, 3);
  }, [support, notes]);

  const deliveryAnchorText = safeStr(
    addresses?.primary_text,
    safeStr(form.location, "Add your delivery location")
  );

  if (loading) {
    return (
      <div className="space-y-4">
        <div className="rounded-[28px] border border-[#D8F3DC] bg-white/90 p-6 shadow-sm">
          <div className="text-xs font-bold uppercase tracking-[0.18em] text-[#2D6A4F]">
            My Account
          </div>
          <div className="mt-2 text-2xl font-black tracking-tight text-slate-900">
            Loading account workspace…
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-5">
      <div className="overflow-hidden rounded-[28px] border border-[#D8F3DC] bg-white/90 shadow-sm">
        <div className="bg-gradient-to-r from-[#F4FBF7] via-white to-[#F8FCF9] p-6">
          <div className="grid grid-cols-1 gap-6 xl:grid-cols-12 xl:items-start">
            <div className="min-w-0 xl:col-span-7">
              <div className="text-xs font-bold uppercase tracking-[0.18em] text-[#2D6A4F]">
                My Account
              </div>

              <div className="mt-4 flex flex-col gap-4 sm:flex-row sm:items-start">
                <div className="grid h-16 w-16 shrink-0 place-items-center rounded-[20px] border border-[#CFE9D7] bg-white text-lg font-black text-[#2D6A4F] shadow-sm">
                  {accountInitials}
                </div>

                <div className="min-w-0 flex-1">
                  <h1 className="text-[30px] font-black tracking-tight text-slate-900">
                    {accountDisplayName}
                  </h1>
                  <p className="mt-1 text-sm text-slate-600">{accountEmail}</p>

                  <div className="mt-3 flex flex-wrap gap-2">
                    <MetaPill label="Location" value={accountLocation} />
                    <MetaPill label="Member since" value={when(profile?.created_at)} />
                    <MetaPill label="Last login" value={relativeWhen(profile?.last_login_at)} />
                  </div>
                </div>
              </div>

              <div className="mt-5 rounded-[22px] border border-[#D8F3DC] bg-white/85 p-4 shadow-sm">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <div className="text-xs font-bold uppercase tracking-wide text-slate-500">
                      Profile readiness
                    </div>
                    <div className="mt-1 text-lg font-black text-slate-900">
                      {profileCompletion}% complete
                    </div>
                  </div>

                  <div className="rounded-full border border-[#D8F3DC] bg-[#F4FBF7] px-3 py-1 text-xs font-bold text-[#2D6A4F]">
                    Customer-facing
                  </div>
                </div>

                <div className="mt-3">
                  <ProgressBar value={profileCompletion} />
                </div>

                <div className="mt-3 text-sm text-slate-600">
                  Keep your name, contact number, and delivery location accurate so communication,
                  order fulfilment, and support remain smooth.
                </div>
              </div>
            </div>

            <div className="space-y-3 xl:col-span-5">
              <div className="rounded-[22px] border border-[#D8F3DC] bg-white p-4 shadow-sm">
                <div className="flex items-center gap-2 text-slate-900">
                  <Sparkles className="h-4 w-4 text-[#2D6A4F]" />
                  <div className="text-sm font-extrabold uppercase tracking-wide">Quick actions</div>
                </div>

                <div className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-1">
                  <Link
                    to="/dashboard/customer/payments"
                    className="inline-flex items-center justify-between gap-3 rounded-2xl border border-[#D8F3DC] bg-[#F7FBF8] px-4 py-3 text-sm font-semibold text-slate-800 hover:bg-white"
                  >
                    <span className="inline-flex items-center gap-2">
                      <Wallet className="h-4 w-4 text-[#2D6A4F]" />
                      Payments workspace
                    </span>
                    <ChevronRight className="h-4 w-4 text-slate-400" />
                  </Link>

                  <button
                    type="button"
                    onClick={() => loadWorkspace({ silent: true })}
                    className="inline-flex items-center justify-between gap-3 rounded-2xl border border-slate-200 bg-white px-4 py-3 text-sm font-semibold text-slate-800 hover:bg-slate-50"
                  >
                    <span className="inline-flex items-center gap-2">
                      <RefreshCcw className={`h-4 w-4 text-[#2D6A4F] ${refreshing ? "animate-spin" : ""}`} />
                      {refreshing ? "Refreshing…" : "Refresh account"}
                    </span>
                    <ChevronRight className="h-4 w-4 text-slate-400" />
                  </button>
                </div>
              </div>

              <div className="rounded-[22px] border border-[#D8F3DC] bg-white p-4 shadow-sm">
                <div className="text-xs font-bold uppercase tracking-wide text-slate-500">
                  Workspace snapshot
                </div>

                <div className="mt-3 grid grid-cols-1 gap-3 sm:grid-cols-2">
                  <MiniInfoCard
                    label="Unread alerts"
                    value={unreadNotifications}
                    helper={`${totalNotifications} total notification event(s)`}
                    icon={Bell}
                  />
                  <MiniInfoCard
                    label="Payments"
                    value={paymentOverview?.ready ? "Ready" : "Available"}
                    helper="History and proof visibility are accessible"
                    icon={Wallet}
                  />
                  <MiniInfoCard
                    label="Privacy visibility"
                    value={privacy?.activity_log_ready ? "Live" : "Limited"}
                    helper="Customer-facing visibility is active"
                    icon={ShieldCheck}
                  />
                  <MiniInfoCard
                    label="Delivery profile"
                    value={addresses?.enabled ? "Saved addresses" : "Location-based"}
                    helper={addresses?.enabled ? "Saved addresses available" : "Using your profile location for now"}
                    icon={MapPin}
                  />
                </div>
              </div>
            </div>
          </div>

          {heroNotes.length ? (
            <div className="mt-5 grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
              {heroNotes.map((note, index) => (
                <CustomerNote key={`${note}-${index}`}>{note}</CustomerNote>
              ))}
            </div>
          ) : null}
        </div>

        {flash ? (
          <div
            className={[
              "border-t px-6 py-4 text-sm",
              flash.type === "success"
                ? "border-emerald-100 bg-emerald-50 text-emerald-900"
                : "border-rose-100 bg-rose-50 text-rose-900",
            ].join(" ")}
          >
            {flash.message}
          </div>
        ) : null}
      </div>

      <div className="grid grid-cols-1 gap-5 xl:grid-cols-12 xl:items-start">
        <div className="space-y-5 xl:col-span-7">
          <SectionCard
            title="Profile details"
            subtitle="Update the core details attached to your customer account."
            icon={UserCircle2}
            actions={
              <button
                type="button"
                onClick={onSaveProfile}
                disabled={!canSave}
                className={[
                  "inline-flex items-center gap-2 rounded-2xl border px-3 py-2 text-sm font-semibold transition",
                  canSave
                    ? "border-[#B7E4C7] bg-[#2D6A4F] text-white hover:bg-[#25563f]"
                    : "cursor-not-allowed border-slate-200 bg-slate-100 text-slate-400",
                ].join(" ")}
              >
                <Save className="h-4 w-4" />
                {saving ? "Saving…" : "Save profile"}
              </button>
            }
          >
            <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
              <label className="block">
                <div className="mb-1 text-xs font-semibold text-slate-500">Full name</div>
                <input
                  value={form.full_name}
                  onChange={onChange("full_name")}
                  className="w-full rounded-2xl border border-slate-200 bg-slate-50 px-3 py-2.5 text-sm outline-none focus:border-slate-300 focus:bg-white"
                  placeholder="e.g. Nzwana Situmbeko"
                />
              </label>

              <label className="block">
                <div className="mb-1 text-xs font-semibold text-slate-500">Contact number</div>
                <input
                  value={form.phone}
                  onChange={onChange("phone")}
                  className="w-full rounded-2xl border border-slate-200 bg-slate-50 px-3 py-2.5 text-sm outline-none focus:border-slate-300 focus:bg-white"
                  placeholder="e.g. +264 81 123 4567"
                />
              </label>

              <label className="block md:col-span-2">
                <div className="mb-1 text-xs font-semibold text-slate-500">Email address</div>
                <input
                  value={form.email || profile?.email || ""}
                  readOnly
                  className="w-full rounded-2xl border border-slate-200 bg-slate-100 px-3 py-2.5 text-sm text-slate-500 outline-none"
                  placeholder="Email is managed from your registered login identity"
                />
              </label>
            </div>

            <div className="mt-4 grid grid-cols-1 gap-3 md:grid-cols-3">
              <MiniInfoCard
                label="Member since"
                value={when(profile?.created_at)}
                helper="When your customer account was created"
              />
              <MiniInfoCard
                label="Last login"
                value={relativeWhen(profile?.last_login_at)}
                helper="Your most recent sign-in"
              />
              <MiniInfoCard
                label="Profile status"
                value={profileCompletion >= 100 ? "Complete" : "Needs attention"}
                helper={`${profileCompletion}% of key profile fields completed`}
              />
            </div>
          </SectionCard>

          <SectionCard
            title="Delivery profile"
            subtitle="Set the location used for delivery coordination until the full saved-address feature is released."
            icon={MapPin}
            actions={
              <button
                type="button"
                onClick={onSaveProfile}
                disabled={!canSave}
                className={[
                  "inline-flex items-center gap-2 rounded-2xl border px-3 py-2 text-sm font-semibold transition",
                  canSave
                    ? "border-[#B7E4C7] bg-white text-[#2D6A4F] hover:bg-[#F7FBF8]"
                    : "cursor-not-allowed border-slate-200 bg-slate-100 text-slate-400",
                ].join(" ")}
              >
                <Save className="h-4 w-4" />
                {saving ? "Saving…" : "Save delivery profile"}
              </button>
            }
          >
            <div className="grid grid-cols-1 gap-4 lg:grid-cols-[1.15fr_0.85fr]">
              <div className="space-y-4">
                <label className="block">
                  <div className="mb-1 text-xs font-semibold text-slate-500">
                    Preferred delivery location
                  </div>
                  <input
                    value={form.location}
                    onChange={onChange("location")}
                    className="w-full rounded-2xl border border-slate-200 bg-slate-50 px-3 py-2.5 text-sm outline-none focus:border-slate-300 focus:bg-white"
                    placeholder="e.g. Windhoek, Khomas"
                  />
                </label>

                <CustomerNote>
                  This location helps the system and support team understand where your deliveries should normally be coordinated.
                </CustomerNote>

                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                  <MiniInfoCard
                    label="Current delivery anchor"
                    value={deliveryAnchorText}
                    helper="This is the location currently guiding delivery"
                    icon={Home}
                  />
                  <MiniInfoCard
                    label="Saved addresses"
                    value={addresses?.enabled ? safeNumber(addresses?.count, 0) : "Coming soon"}
                    helper={
                      addresses?.enabled
                        ? "Saved delivery addresses are available"
                        : "A full address book will arrive in a later update"
                    }
                    icon={MapPin}
                  />
                </div>
              </div>

              <div className="space-y-3">
                {addressPlaceholders.length ? (
                  addressPlaceholders.slice(0, 2).map((item, index) => (
                    <div
                      key={`${item.label}-${index}`}
                      className="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3"
                    >
                      <div className="flex items-start justify-between gap-3">
                        <div>
                          <div className="text-sm font-extrabold text-slate-900">
                            {safeStr(item.label, "Address placeholder")}
                          </div>
                          <div className="mt-1 text-xs text-slate-500">
                            {safeStr(
                              item.line1,
                              "Address details will appear here when saved addresses are enabled."
                            )}
                          </div>
                        </div>
                        <StatusBadge value={item.status} fallback="Placeholder" />
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-600">
                    Saved addresses are not available yet. For now, keep your delivery location above accurate.
                  </div>
                )}

                {safeArray(addresses?.notes).slice(0, 2).map((note, index) => (
                  <CustomerNote key={`${note}-${index}`}>{note}</CustomerNote>
                ))}
              </div>
            </div>

            <div className="mt-4 flex flex-wrap items-center justify-between gap-3">
              <Link
                to="/dashboard/customer/payments"
                className="inline-flex items-center gap-2 rounded-2xl border border-[#D8F3DC] bg-[#F7FBF8] px-4 py-2 text-sm font-semibold text-[#2D6A4F] hover:bg-white"
              >
                Open payments workspace
                <ChevronRight className="h-4 w-4" />
              </Link>

              <button
                type="button"
                onClick={onReset}
                className="rounded-2xl border border-slate-200 bg-white px-4 py-2 text-sm font-semibold text-slate-600 hover:bg-slate-50"
              >
                Reset
              </button>
            </div>
          </SectionCard>
        </div>

        <div className="space-y-5 xl:col-span-5 xl:sticky xl:top-24">
          <SectionCard
            title="Communication & privacy"
            subtitle="A simpler customer view of how alerts and privacy visibility currently work."
            icon={Bell}
          >
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <MiniInfoCard
                label="Unread alerts"
                value={`${unreadNotifications}`}
                helper={unreadNotifications > 0 ? "You have unread notifications to review" : "No unread notifications"}
                icon={Bell}
              />
              <MiniInfoCard
                label="Live channels"
                value={liveNotificationChannels}
                helper={`${notificationChannels.length} communication channel(s) shown`}
                icon={Mail}
              />
            </div>

            <div className="mt-4 space-y-3">
              {notificationChannels.length ? (
                notificationChannels.map((channel, index) => {
                  const Icon =
                    channel.key === "email" ? Mail : channel.key === "sms" ? Smartphone : Bell;

                  return (
                    <div
                      key={`${channel.key || channel.label || "channel"}-${index}`}
                      className="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3"
                    >
                      <div className="flex items-start justify-between gap-3">
                        <div className="flex items-start gap-3">
                          <div className="grid h-10 w-10 place-items-center rounded-2xl border border-[#D8F3DC] bg-white">
                            <Icon className="h-4 w-4 text-[#2D6A4F]" />
                          </div>
                          <div>
                            <div className="text-sm font-extrabold text-slate-900">
                              {safeStr(channel.label, "Channel")}
                            </div>
                            <div className="mt-1 text-xs text-slate-500">
                              {safeStr(channel.description, "")}
                            </div>
                          </div>
                        </div>

                        <StatusBadge value={channel.status} />
                      </div>

                      <div className="mt-3 flex flex-wrap gap-2 text-xs text-slate-600">
                        <span className="rounded-full border border-[#D8F3DC] bg-white px-2.5 py-1">
                          {channel.enabled ? "Currently enabled" : "Preference saving coming soon"}
                        </span>
                        <span className="rounded-full border border-[#D8F3DC] bg-white px-2.5 py-1">
                          {channel.last_event_at
                            ? `Last event ${relativeWhen(channel.last_event_at)}`
                            : "No recent channel event"}
                        </span>
                      </div>
                    </div>
                  );
                })
              ) : (
                <div className="text-sm text-slate-500">
                  Communication channel information is not available yet.
                </div>
              )}
            </div>

            <div className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-2">
              <MiniInfoCard
                label="Privacy visibility"
                value={privacy?.activity_log_ready ? "Live" : "Limited"}
                helper="Privacy-related customer visibility is active"
                icon={ShieldCheck}
              />
              <MiniInfoCard
                label="Preference controls"
                value={privacy?.preferences_model_ready ? "Saved" : "Coming soon"}
                helper="More personal preference controls will be added later"
                icon={UserCircle2}
              />
            </div>

            <div className="mt-4 space-y-3">
              <CustomerNote>
                In-app notifications are the clearest communication route right now.
              </CustomerNote>
              <CustomerNote>
                Email and SMS preference saving can expand later without changing your current account data.
              </CustomerNote>
            </div>
          </SectionCard>

          <SectionCard
            title="Support & guidance"
            subtitle="A simpler explanation of how customer support currently works."
            icon={LifeBuoy}
          >
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <MiniInfoCard
                label="Support mode"
                value={support?.tickets_enabled ? "Ticketing live" : "In-app support"}
                helper={safeStr(
                  support?.primary_channel,
                  "Notifications remain the main customer follow-up route."
                )}
                icon={LifeBuoy}
              />
              <MiniInfoCard
                label="Response target"
                value={`${safeNumber(support?.response_sla_hours, 72)} hours`}
                helper="Current support follow-up target"
                icon={RefreshCcw}
              />
            </div>

            <div className="mt-4 space-y-3">
              {supportChannels.length ? (
                supportChannels.slice(0, 3).map((channel, index) => (
                  <div
                    key={`${channel.name}-${index}`}
                    className="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3"
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <div className="text-sm font-extrabold text-slate-900">
                          {safeStr(channel.name, "Support channel")}
                        </div>
                        <div className="mt-1 text-xs text-slate-500">
                          {safeStr(channel.description, "")}
                        </div>
                      </div>
                      <StatusBadge value={channel.status} fallback="Planned" />
                    </div>
                  </div>
                ))
              ) : (
                <CustomerNote>
                  Customer support is available through the communication tools already visible in your workspace.
                </CustomerNote>
              )}

              {supportNotes.length ? (
                supportNotes.map((note, index) => (
                  <CustomerNote key={`${note}-${index}`}>{note}</CustomerNote>
                ))
              ) : (
                <>
                  <CustomerNote>
                    You can keep your profile details updated so delivery and support follow-up remain accurate.
                  </CustomerNote>
                  <CustomerNote>
                    Order issues, disputes, and refund handling can expand in a later system phase.
                  </CustomerNote>
                </>
              )}
            </div>
          </SectionCard>
        </div>
      </div>
    </div>
  );
}