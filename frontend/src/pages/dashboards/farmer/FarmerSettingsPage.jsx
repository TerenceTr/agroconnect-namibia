// ============================================================================
// frontend/src/pages/dashboards/farmer/FarmerSettingsPage.jsx
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Farmer commerce control centre.
//
// THIS VERSION:
//   ✅ Keeps EFT / bank details as a first-class seller setting
//   ✅ Adds seller-facing sections for:
//        - Farmer Details
//        - Storefront & Sales
//        - Fulfillment
//        - Notifications
//        - Communication
//        - Analytics
//        - Business Profile
//   ✅ Persists farmer account details to /auth/me
//   ✅ Persists EFT details to farmer_payment_profiles
//   ✅ Persists commerce settings to farmer-specific backend settings storage
//   ✅ Keeps local draft resilience via localStorage
//
// IMPORTANT DESIGN NOTE:
//   "Farmer Details" are the authenticated user profile details:
//     • full name
//     • contact number
//     • email
//     • address / town (stored as backend `location`)
//
//   "Business Profile" remains the public storefront identity layer:
//     • tagline
//     • farm story
//     • service regions
//     • pickup address
//     • operating days
//
// IMPORTANT NOTE:
//   The sale controls here persist a seller sale campaign configuration. They do
//   not automatically change customer-facing product prices until that pricing
//   flow is wired into the marketplace catalogue/order calculation pipeline.
// ============================================================================

import React, { useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  BarChart3,
  BellRing,
  Briefcase,
  CreditCard,
  Mail,
  MapPin,
  Megaphone,
  Phone,
  RefreshCcw,
  Save,
  Settings2,
  ShieldCheck,
  Store,
  Truck,
  UserRound,
} from "lucide-react";

import FarmerLayout from "../../../components/FarmerLayout";
import api from "../../../api";

// ----------------------------------------------------------------------------
// Local draft storage keys
// ----------------------------------------------------------------------------
const PROFILE_STORAGE_KEY = "agroconnect_farmer_profile_draft_v1";
const PAYMENT_STORAGE_KEY = "agroconnect_farmer_payment_profile_draft_v2";
const COMMERCE_STORAGE_KEY = "agroconnect_farmer_commerce_settings_draft_v1";

// ----------------------------------------------------------------------------
// Settings nav
// ----------------------------------------------------------------------------
const SECTION_ITEMS = [
  { key: "farmer_details", label: "Farmer Details", icon: UserRound },
  { key: "payments", label: "Payments", icon: CreditCard },
  { key: "storefront", label: "Storefront & Sales", icon: Store },
  { key: "fulfillment", label: "Fulfillment", icon: Truck },
  { key: "notifications", label: "Notifications", icon: BellRing },
  { key: "communication", label: "Communication", icon: Megaphone },
  { key: "analytics", label: "Analytics", icon: BarChart3 },
  { key: "business_profile", label: "Business Profile", icon: Briefcase },
];

// ----------------------------------------------------------------------------
// Generic helpers
// ----------------------------------------------------------------------------
function safeStr(v, fallback = "") {
  const s = String(v ?? "").trim();
  return s || fallback;
}

function safeBool(v, fallback = false) {
  if (typeof v === "boolean") return v;
  if (typeof v === "number") return v !== 0;
  const s = safeStr(v, "").toLowerCase();
  if (["1", "true", "yes", "y", "on"].includes(s)) return true;
  if (["0", "false", "no", "n", "off"].includes(s)) return false;
  return fallback;
}

function safeNumber(v, fallback = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

function apiPath(path) {
  const base = String(api?.defaults?.baseURL || "");
  const clean = path.startsWith("/") ? path : `/${path}`;
  return /\/api\/?$/.test(base) && clean.startsWith("/api/") ? clean.replace(/^\/api/, "") : clean;
}

function tryParseJson(raw, fallback) {
  try {
    return JSON.parse(raw);
  } catch {
    return fallback;
  }
}

function readLocalJson(key, fallback) {
  try {
    const raw = window.localStorage.getItem(key);
    if (!raw) return fallback;
    return tryParseJson(raw, fallback);
  } catch {
    return fallback;
  }
}

function writeLocalJson(key, value) {
  try {
    window.localStorage.setItem(key, JSON.stringify(value));
  } catch {
    // Ignore local draft write failures.
  }
}

// ----------------------------------------------------------------------------
// Farmer profile helpers
// ----------------------------------------------------------------------------
function emptyFarmerProfile() {
  return {
    full_name: "",
    phone: "",
    email: "",
    location: "",
  };
}

function normalizeFarmerProfile(raw = {}) {
  const merged = { ...emptyFarmerProfile(), ...(raw || {}) };
  merged.full_name = safeStr(merged.full_name ?? merged.name);
  merged.phone = safeStr(merged.phone ?? merged.mobile);
  merged.email = safeStr(merged.email);
  merged.location = safeStr(merged.location ?? merged.address ?? merged.town);
  return merged;
}

async function fetchMyProfile() {
  const candidates = [
    "/api/auth/me",
    "/auth/me",
  ];

  let lastErr = null;
  for (const path of candidates) {
    try {
      const res = await api.get(apiPath(path));
      return res?.data?.user ?? res?.data?.profile ?? res?.data?.data ?? res?.data ?? {};
    } catch (err) {
      lastErr = err;
      const status = err?.response?.status;
      if (status && ![404, 405].includes(status)) break;
    }
  }

  throw lastErr || new Error("Failed to load farmer profile.");
}

async function saveMyProfile(payload) {
  const candidates = [
    "/api/auth/me",
    "/auth/me",
  ];

  let lastErr = null;
  for (const path of candidates) {
    try {
      const res = await api.put(apiPath(path), payload);
      return res?.data?.user ?? res?.data?.profile ?? res?.data?.data ?? res?.data ?? {};
    } catch (err) {
      lastErr = err;
      const status = err?.response?.status;
      if (status && ![404, 405].includes(status)) break;
    }
  }

  throw lastErr || new Error("Failed to save farmer profile.");
}

// ----------------------------------------------------------------------------
// Farmer payment profile helpers
// ----------------------------------------------------------------------------
function emptyPaymentProfile() {
  return {
    profile_id: null,
    farmer_id: null,
    bank_name: "",
    account_name: "",
    account_number: "",
    branch_code: "",
    payment_instructions: "",
    use_for_eft: true,
    is_active: true,
    is_complete: false,
  };
}

function normalizePaymentProfile(raw = {}) {
  const merged = { ...emptyPaymentProfile(), ...(raw || {}) };
  merged.bank_name = safeStr(merged.bank_name);
  merged.account_name = safeStr(merged.account_name);
  merged.account_number = safeStr(merged.account_number);
  merged.branch_code = safeStr(merged.branch_code);
  merged.payment_instructions = safeStr(merged.payment_instructions);
  merged.use_for_eft = safeBool(merged.use_for_eft, true);
  merged.is_active = safeBool(merged.is_active, true);
  merged.is_complete =
    Boolean(merged.bank_name && merged.account_name && merged.account_number) ||
    !merged.use_for_eft;
  return merged;
}

async function fetchPaymentProfile() {
  const candidates = [
    "/api/farmers/payment-profile/me",
    "/farmers/payment-profile/me",
    "/api/farmers/payment-profile",
    "/farmers/payment-profile",
    "/api/farmer/payment-profile/me",
    "/farmer/payment-profile/me",
  ];

  let lastErr = null;
  for (const path of candidates) {
    try {
      const res = await api.get(apiPath(path));
      return res?.data?.data ?? res?.data ?? {};
    } catch (err) {
      lastErr = err;
      const status = err?.response?.status;
      if (status && ![404, 405].includes(status)) break;
    }
  }

  if (lastErr) throw lastErr;
  return {};
}

async function savePaymentProfile(payload) {
  const candidates = [
    "/api/farmers/payment-profile/me",
    "/farmers/payment-profile/me",
    "/api/farmers/payment-profile",
    "/farmers/payment-profile",
    "/api/farmer/payment-profile/me",
    "/farmer/payment-profile/me",
  ];

  let lastErr = null;
  for (const path of candidates) {
    try {
      const res = await api.put(apiPath(path), payload);
      return res?.data?.data ?? res?.data ?? {};
    } catch (err) {
      lastErr = err;
      const status = err?.response?.status;
      if (status && ![404, 405].includes(status)) break;
    }
  }

  throw lastErr;
}

// ----------------------------------------------------------------------------
// Farmer commerce settings helpers
// ----------------------------------------------------------------------------
function defaultCommerceSettings() {
  return {
    version: 1,
    storefront: {
      store_paused: false,
      accept_new_orders: true,
      show_low_stock_badge: true,
      hide_out_of_stock_products: false,
      featured_product_ids: [],
      sale: {
        enabled: false,
        sale_name: "",
        discount_type: "percent",
        discount_value: 0,
        start_at: "",
        end_at: "",
        apply_scope: "all",
        selected_product_ids: [],
        selected_category: "",
        banner_text: "",
        minimum_stock_threshold: 0,
        stack_with_other_promotions: false,
      },
    },
    fulfillment: {
      pickup_enabled: true,
      delivery_enabled: true,
      minimum_order_nad: 0,
      preparation_lead_hours: 24,
      same_day_cutoff_time: "12:00",
      max_daily_orders: 0,
      allow_substitutions: false,
      pickup_instructions: "",
      service_radius_km: 25,
    },
    notifications: {
      orders_in_app: true,
      orders_email: false,
      orders_sms: false,
      messages_in_app: true,
      messages_email: false,
      moderation_in_app: true,
      moderation_email: false,
      quiet_hours_enabled: false,
      quiet_hours_start: "21:00",
      quiet_hours_end: "06:00",
      urgent_override: true,
      daily_digest_enabled: false,
      instant_payment_proof_alerts: true,
    },
    communication: {
      auto_reply_enabled: false,
      auto_reply_message: "",
      display_response_time: true,
      seller_welcome_message: "",
      faq_snippets: [],
    },
    analytics: {
      show_market_trends: true,
      show_stock_alerts: true,
      show_ranking_widget: true,
      weekly_summary_email: false,
      custom_low_stock_threshold: 5,
      alert_sensitivity: "medium",
      ranking_window_days: 30,
    },
    business_profile: {
      store_tagline: "",
      farm_story: "",
      service_regions: [],
      pickup_address: "",
      business_phone: "",
      public_contact_link: "",
      operating_days: ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat"],
      opening_time: "08:00",
      closing_time: "17:00",
    },
    updated_at: null,
  };
}

function mergeDeep(base, raw) {
  const out = { ...base };
  Object.keys(raw || {}).forEach((key) => {
    const baseVal = out[key];
    const nextVal = raw[key];

    if (
      baseVal &&
      typeof baseVal === "object" &&
      !Array.isArray(baseVal) &&
      nextVal &&
      typeof nextVal === "object" &&
      !Array.isArray(nextVal)
    ) {
      out[key] = mergeDeep(baseVal, nextVal);
    } else {
      out[key] = nextVal;
    }
  });
  return out;
}

function normalizeCommerceSettings(raw = {}) {
  const merged = mergeDeep(defaultCommerceSettings(), raw || {});

  merged.storefront.store_paused = safeBool(merged.storefront.store_paused, false);
  merged.storefront.accept_new_orders = safeBool(merged.storefront.accept_new_orders, true);
  merged.storefront.show_low_stock_badge = safeBool(merged.storefront.show_low_stock_badge, true);
  merged.storefront.hide_out_of_stock_products = safeBool(
    merged.storefront.hide_out_of_stock_products,
    false
  );
  merged.storefront.sale.enabled = safeBool(merged.storefront.sale.enabled, false);
  merged.storefront.sale.discount_type =
    safeStr(merged.storefront.sale.discount_type, "percent") === "fixed"
      ? "fixed"
      : "percent";
  merged.storefront.sale.discount_value = safeNumber(merged.storefront.sale.discount_value, 0);
  merged.storefront.sale.minimum_stock_threshold = safeNumber(
    merged.storefront.sale.minimum_stock_threshold,
    0
  );
  merged.storefront.sale.stack_with_other_promotions = safeBool(
    merged.storefront.sale.stack_with_other_promotions,
    false
  );

  merged.fulfillment.pickup_enabled = safeBool(merged.fulfillment.pickup_enabled, true);
  merged.fulfillment.delivery_enabled = safeBool(merged.fulfillment.delivery_enabled, true);
  merged.fulfillment.allow_substitutions = safeBool(
    merged.fulfillment.allow_substitutions,
    false
  );
  merged.fulfillment.minimum_order_nad = safeNumber(merged.fulfillment.minimum_order_nad, 0);
  merged.fulfillment.preparation_lead_hours = safeNumber(
    merged.fulfillment.preparation_lead_hours,
    24
  );
  merged.fulfillment.max_daily_orders = safeNumber(merged.fulfillment.max_daily_orders, 0);
  merged.fulfillment.service_radius_km = safeNumber(merged.fulfillment.service_radius_km, 25);

  [
    "orders_in_app",
    "orders_email",
    "orders_sms",
    "messages_in_app",
    "messages_email",
    "moderation_in_app",
    "moderation_email",
    "quiet_hours_enabled",
    "urgent_override",
    "daily_digest_enabled",
    "instant_payment_proof_alerts",
  ].forEach((key) => {
    merged.notifications[key] = safeBool(
      merged.notifications[key],
      Boolean(defaultCommerceSettings().notifications[key])
    );
  });

  merged.communication.auto_reply_enabled = safeBool(
    merged.communication.auto_reply_enabled,
    false
  );
  merged.communication.display_response_time = safeBool(
    merged.communication.display_response_time,
    true
  );

  merged.analytics.show_market_trends = safeBool(merged.analytics.show_market_trends, true);
  merged.analytics.show_stock_alerts = safeBool(merged.analytics.show_stock_alerts, true);
  merged.analytics.show_ranking_widget = safeBool(merged.analytics.show_ranking_widget, true);
  merged.analytics.weekly_summary_email = safeBool(
    merged.analytics.weekly_summary_email,
    false
  );
  merged.analytics.custom_low_stock_threshold = safeNumber(
    merged.analytics.custom_low_stock_threshold,
    5
  );
  merged.analytics.ranking_window_days = safeNumber(merged.analytics.ranking_window_days, 30);

  merged.business_profile.service_regions = Array.isArray(
    merged.business_profile.service_regions
  )
    ? merged.business_profile.service_regions
    : [];

  merged.business_profile.operating_days =
    Array.isArray(merged.business_profile.operating_days) &&
    merged.business_profile.operating_days.length
      ? merged.business_profile.operating_days
      : defaultCommerceSettings().business_profile.operating_days;

  return merged;
}

async function fetchCommerceSettings() {
  const candidates = [
    "/api/farmers/settings/me",
    "/farmers/settings/me",
    "/api/farmers/settings",
    "/farmers/settings",
    "/api/farmer/settings/me",
    "/farmer/settings/me",
  ];

  let lastErr = null;
  for (const path of candidates) {
    try {
      const res = await api.get(apiPath(path));
      return res?.data?.data ?? res?.data ?? {};
    } catch (err) {
      lastErr = err;
      const status = err?.response?.status;
      if (status && ![404, 405].includes(status)) break;
    }
  }

  throw lastErr;
}

async function saveCommerceSettings(payload) {
  const candidates = [
    "/api/farmers/settings/me",
    "/farmers/settings/me",
    "/api/farmers/settings",
    "/farmers/settings",
    "/api/farmer/settings/me",
    "/farmer/settings/me",
  ];

  let lastErr = null;
  for (const path of candidates) {
    try {
      const res = await api.put(apiPath(path), { settings: payload });
      return res?.data?.data ?? res?.data ?? {};
    } catch (err) {
      lastErr = err;
      const status = err?.response?.status;
      if (status && ![404, 405].includes(status)) break;
    }
  }

  throw lastErr;
}

// ----------------------------------------------------------------------------
// Small UI atoms
// ----------------------------------------------------------------------------
function Toggle({ checked, onChange, label, hint = "" }) {
  return (
    <label className="flex items-start gap-3 rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-800">
      <input
        type="checkbox"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
        className="mt-0.5"
      />
      <span>
        <span className="block font-semibold text-slate-900">{label}</span>
        {hint ? <span className="mt-0.5 block text-xs text-slate-500">{hint}</span> : null}
      </span>
    </label>
  );
}

// ----------------------------------------------------------------------------
// Page
// ----------------------------------------------------------------------------
export default function FarmerSettingsPage() {
  const initialProfileDraft = normalizeFarmerProfile(
    readLocalJson(PROFILE_STORAGE_KEY, emptyFarmerProfile())
  );
  const initialPaymentDraft = normalizePaymentProfile(
    readLocalJson(PAYMENT_STORAGE_KEY, emptyPaymentProfile())
  );
  const initialCommerceDraft = normalizeCommerceSettings(
    readLocalJson(COMMERCE_STORAGE_KEY, defaultCommerceSettings())
  );

  const [activeSection, setActiveSection] = useState("farmer_details");

  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [savingProfile, setSavingProfile] = useState(false);
  const [savingPayment, setSavingPayment] = useState(false);
  const [savingCommerce, setSavingCommerce] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  const [profileForm, setProfileForm] = useState(initialProfileDraft);
  const [paymentForm, setPaymentForm] = useState(initialPaymentDraft);
  const [commerceForm, setCommerceForm] = useState(initialCommerceDraft);

  // --------------------------------------------------------------------------
  // Derived state
  // --------------------------------------------------------------------------
  const isProfileComplete = useMemo(() => {
    return Boolean(
      safeStr(profileForm.full_name) &&
        safeStr(profileForm.phone) &&
        safeStr(profileForm.email) &&
        safeStr(profileForm.location)
    );
  }, [profileForm]);

  const isPaymentComplete = useMemo(() => {
    if (!safeBool(paymentForm.use_for_eft, true)) return true;
    return Boolean(
      safeStr(paymentForm.bank_name) &&
        safeStr(paymentForm.account_name) &&
        safeStr(paymentForm.account_number)
    );
  }, [paymentForm]);

  const saleSummary = useMemo(() => {
    const sale = commerceForm.storefront.sale;
    if (!sale.enabled) return "No active sale configuration.";

    const unit =
      sale.discount_type === "fixed"
        ? `N$ ${safeNumber(sale.discount_value, 0).toFixed(2)}`
        : `${safeNumber(sale.discount_value, 0)}%`;

    return `${unit} discount • Scope: ${safeStr(sale.apply_scope, "all")}`;
  }, [commerceForm]);

  const inboxSummary = useMemo(() => {
    const n = commerceForm.notifications;
    const activeLanes = [
      n.orders_in_app,
      n.messages_in_app,
      n.moderation_in_app,
    ].filter(Boolean).length;
    return `${activeLanes} in-app notification lane(s) active`;
  }, [commerceForm]);

  const farmerIdentitySummary = useMemo(() => {
    if (!isProfileComplete) return "Profile details incomplete";
    return `${safeStr(profileForm.full_name)} • ${safeStr(profileForm.location)}`;
  }, [isProfileComplete, profileForm]);

  // --------------------------------------------------------------------------
  // Load everything
  // --------------------------------------------------------------------------
  const refreshAll = async (silent = false) => {
    if (!silent) setLoading(true);
    else setRefreshing(true);

    setError("");
    setSuccess("");

    try {
      const [profileData, paymentData, commerceData] = await Promise.all([
        fetchMyProfile(),
        fetchPaymentProfile(),
        fetchCommerceSettings(),
      ]);

      const normalizedProfile = normalizeFarmerProfile(profileData);
      const normalizedPayment = normalizePaymentProfile(paymentData);
      const normalizedCommerce = normalizeCommerceSettings(commerceData);

      setProfileForm(normalizedProfile);
      setPaymentForm(normalizedPayment);
      setCommerceForm(normalizedCommerce);

      writeLocalJson(PROFILE_STORAGE_KEY, normalizedProfile);
      writeLocalJson(PAYMENT_STORAGE_KEY, normalizedPayment);
      writeLocalJson(COMMERCE_STORAGE_KEY, normalizedCommerce);
    } catch (err) {
      setError(
        err?.response?.data?.message ||
          err?.response?.data?.details ||
          err?.message ||
          "Failed to load farmer settings."
      );
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    refreshAll(false);
  }, []);

  // --------------------------------------------------------------------------
  // Form updaters
  // --------------------------------------------------------------------------
  const updateProfile = (key, value) => {
    setProfileForm((prev) => {
      const next = normalizeFarmerProfile({ ...prev, [key]: value });
      writeLocalJson(PROFILE_STORAGE_KEY, next);
      return next;
    });
  };

  const updatePayment = (key, value) => {
    setPaymentForm((prev) => {
      const next = normalizePaymentProfile({ ...prev, [key]: value });
      writeLocalJson(PAYMENT_STORAGE_KEY, next);
      return next;
    });
  };

  const updateCommerceSection = (section, key, value) => {
    setCommerceForm((prev) => {
      const next = normalizeCommerceSettings({
        ...prev,
        [section]: {
          ...prev[section],
          [key]: value,
        },
      });
      writeLocalJson(COMMERCE_STORAGE_KEY, next);
      return next;
    });
  };

  const updateSale = (key, value) => {
    setCommerceForm((prev) => {
      const next = normalizeCommerceSettings({
        ...prev,
        storefront: {
          ...prev.storefront,
          sale: {
            ...prev.storefront.sale,
            [key]: value,
          },
        },
      });
      writeLocalJson(COMMERCE_STORAGE_KEY, next);
      return next;
    });
  };

  // --------------------------------------------------------------------------
  // Save handlers
  // --------------------------------------------------------------------------
  const saveProfile = async () => {
    setError("");
    setSuccess("");

    if (!safeStr(profileForm.full_name)) {
      setError("Full name is required.");
      return;
    }
    if (!safeStr(profileForm.phone)) {
      setError("Contact number is required.");
      return;
    }
    if (!safeStr(profileForm.email)) {
      setError("Email address is required.");
      return;
    }
    if (!safeStr(profileForm.location)) {
      setError("Address / town is required.");
      return;
    }

    setSavingProfile(true);
    try {
      const saved = normalizeFarmerProfile(await saveMyProfile(profileForm));
      setProfileForm(saved);
      writeLocalJson(PROFILE_STORAGE_KEY, saved);
      setSuccess("Farmer details updated successfully.");
    } catch (err) {
      setError(
        err?.response?.data?.message ||
          err?.response?.data?.details ||
          err?.message ||
          "Failed to save farmer details."
      );
    } finally {
      setSavingProfile(false);
    }
  };

  const savePayment = async () => {
    setError("");
    setSuccess("");

    if (safeBool(paymentForm.use_for_eft, true) && !isPaymentComplete) {
      setError(
        "Bank name, account name, and account number are required when EFT is enabled."
      );
      return;
    }

    setSavingPayment(true);
    try {
      const saved = normalizePaymentProfile(await savePaymentProfile(paymentForm));
      setPaymentForm(saved);
      writeLocalJson(PAYMENT_STORAGE_KEY, saved);
      setSuccess("Farmer EFT details saved successfully.");
    } catch (err) {
      setError(
        err?.response?.data?.message ||
          err?.response?.data?.details ||
          err?.message ||
          "Failed to save farmer EFT details."
      );
    } finally {
      setSavingPayment(false);
    }
  };

  const saveCommerce = async () => {
    setError("");
    setSuccess("");
    setSavingCommerce(true);

    try {
      const saved = normalizeCommerceSettings(await saveCommerceSettings(commerceForm));
      setCommerceForm(saved);
      writeLocalJson(COMMERCE_STORAGE_KEY, saved);
      setSuccess("Farmer commerce settings saved successfully.");
    } catch (err) {
      setError(
        err?.response?.data?.message ||
          err?.response?.data?.details ||
          err?.message ||
          "Failed to save farmer commerce settings."
      );
    } finally {
      setSavingCommerce(false);
    }
  };

  // --------------------------------------------------------------------------
  // Section renderer
  // --------------------------------------------------------------------------
  const renderSection = () => {
    if (activeSection === "farmer_details") {
      return (
        <div className="space-y-6">
          <div className="rounded-3xl border border-slate-200 bg-white p-6 shadow-sm">
            <div className="mb-4 flex items-center gap-2">
              <UserRound className="h-5 w-5 text-emerald-700" />
              <div className="text-lg font-extrabold text-slate-900">Farmer details</div>
            </div>

            <div className="mb-4 rounded-2xl border border-slate-200 bg-slate-50 p-4 text-sm text-slate-700">
              Update the farmer account identity details used across the platform.
              This is different from <span className="font-semibold">Business Profile</span>,
              which is for your storefront presentation.
            </div>

            <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
              <label className="block">
                <div className="mb-1 text-xs font-semibold text-slate-600">Full name</div>
                <input
                  value={profileForm.full_name}
                  onChange={(e) => updateProfile("full_name", e.target.value)}
                  className="h-11 w-full rounded-xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-900 outline-none focus:ring-2 focus:ring-emerald-200"
                  placeholder="e.g. Mekondjo Nuuyoma"
                />
              </label>

              <label className="block">
                <div className="mb-1 text-xs font-semibold text-slate-600">Contact number</div>
                <input
                  value={profileForm.phone}
                  onChange={(e) => updateProfile("phone", e.target.value)}
                  className="h-11 w-full rounded-xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-900 outline-none focus:ring-2 focus:ring-emerald-200"
                  placeholder="e.g. 0810123456"
                />
              </label>

              <label className="block">
                <div className="mb-1 text-xs font-semibold text-slate-600">Email address</div>
                <input
                  type="email"
                  value={profileForm.email}
                  onChange={(e) => updateProfile("email", e.target.value)}
                  className="h-11 w-full rounded-xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-900 outline-none focus:ring-2 focus:ring-emerald-200"
                  placeholder="e.g. farmer@example.com"
                />
              </label>

              <label className="block">
                <div className="mb-1 text-xs font-semibold text-slate-600">Address / town</div>
                <input
                  value={profileForm.location}
                  onChange={(e) => updateProfile("location", e.target.value)}
                  className="h-11 w-full rounded-xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-900 outline-none focus:ring-2 focus:ring-emerald-200"
                  placeholder="e.g. Etunda or Rocky Crest, Windhoek"
                />
              </label>
            </div>

            <div className="mt-4 flex flex-wrap items-center gap-3">
              <button
                type="button"
                onClick={saveProfile}
                disabled={savingProfile}
                className="inline-flex items-center gap-2 rounded-2xl bg-emerald-600 px-4 py-3 text-sm font-bold text-white hover:bg-emerald-700 disabled:cursor-not-allowed disabled:opacity-60"
              >
                <Save className="h-4 w-4" />
                {savingProfile ? "Saving details…" : "Save farmer details"}
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 gap-6 xl:grid-cols-[0.95fr_0.85fr]">
            <div className="rounded-3xl border border-slate-200 bg-white p-6 shadow-sm">
              <div className="mb-3 flex items-center gap-2">
                <ShieldCheck className="h-5 w-5 text-emerald-700" />
                <div className="text-lg font-extrabold text-slate-900">Farmer profile preview</div>
              </div>

              <dl className="space-y-3 text-sm">
                <div className="flex items-start gap-3">
                  <UserRound className="mt-0.5 h-4 w-4 text-slate-500" />
                  <div>
                    <dt className="text-xs font-semibold uppercase tracking-wide text-slate-500">Name</dt>
                    <dd className="mt-1 font-semibold text-slate-900">
                      {safeStr(profileForm.full_name, "—")}
                    </dd>
                  </div>
                </div>

                <div className="flex items-start gap-3">
                  <Phone className="mt-0.5 h-4 w-4 text-slate-500" />
                  <div>
                    <dt className="text-xs font-semibold uppercase tracking-wide text-slate-500">Contact</dt>
                    <dd className="mt-1 font-semibold text-slate-900">
                      {safeStr(profileForm.phone, "—")}
                    </dd>
                  </div>
                </div>

                <div className="flex items-start gap-3">
                  <Mail className="mt-0.5 h-4 w-4 text-slate-500" />
                  <div>
                    <dt className="text-xs font-semibold uppercase tracking-wide text-slate-500">Email</dt>
                    <dd className="mt-1 font-semibold text-slate-900">
                      {safeStr(profileForm.email, "—")}
                    </dd>
                  </div>
                </div>

                <div className="flex items-start gap-3">
                  <MapPin className="mt-0.5 h-4 w-4 text-slate-500" />
                  <div>
                    <dt className="text-xs font-semibold uppercase tracking-wide text-slate-500">Address / Town</dt>
                    <dd className="mt-1 font-semibold text-slate-900">
                      {safeStr(profileForm.location, "—")}
                    </dd>
                  </div>
                </div>
              </dl>
            </div>

            <div
              className={[
                "rounded-3xl border p-5 shadow-sm",
                isProfileComplete
                  ? "border-emerald-200 bg-emerald-50"
                  : "border-amber-200 bg-amber-50",
              ].join(" ")}
            >
              <div className="flex items-start gap-3">
                {isProfileComplete ? (
                  <ShieldCheck className="mt-0.5 h-5 w-5 text-emerald-700" />
                ) : (
                  <AlertTriangle className="mt-0.5 h-5 w-5 text-amber-700" />
                )}
                <div>
                  <div className="font-bold text-slate-900">
                    {isProfileComplete ? "Farmer profile ready" : "Farmer profile incomplete"}
                  </div>
                  <div className="mt-1 text-sm text-slate-700">
                    {isProfileComplete
                      ? "Your seller account details are complete and professionally presented."
                      : "Complete your full name, contact number, email, and address / town so your seller profile is reliable and easy to trust."}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      );
    }

    if (activeSection === "payments") {
      return (
        <div className="space-y-6">
          <div className="rounded-3xl border border-slate-200 bg-white p-6 shadow-sm">
            <div className="mb-4 flex items-center gap-2">
              <CreditCard className="h-5 w-5 text-emerald-700" />
              <div className="text-lg font-extrabold text-slate-900">EFT / bank details</div>
            </div>

            <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
              <label className="block">
                <div className="mb-1 text-xs font-semibold text-slate-600">Bank name</div>
                <input
                  value={paymentForm.bank_name}
                  onChange={(e) => updatePayment("bank_name", e.target.value)}
                  className="h-11 w-full rounded-xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-900 outline-none focus:ring-2 focus:ring-emerald-200"
                  placeholder="e.g. Bank Windhoek"
                />
              </label>

              <label className="block">
                <div className="mb-1 text-xs font-semibold text-slate-600">Account name</div>
                <input
                  value={paymentForm.account_name}
                  onChange={(e) => updatePayment("account_name", e.target.value)}
                  className="h-11 w-full rounded-xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-900 outline-none focus:ring-2 focus:ring-emerald-200"
                  placeholder="e.g. Your registered bank account name"
                />
              </label>

              <label className="block">
                <div className="mb-1 text-xs font-semibold text-slate-600">Account number</div>
                <input
                  value={paymentForm.account_number}
                  onChange={(e) => updatePayment("account_number", e.target.value)}
                  className="h-11 w-full rounded-xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-900 outline-none focus:ring-2 focus:ring-emerald-200"
                  placeholder="e.g. 1234567890"
                />
              </label>

              <label className="block">
                <div className="mb-1 text-xs font-semibold text-slate-600">Branch code</div>
                <input
                  value={paymentForm.branch_code}
                  onChange={(e) => updatePayment("branch_code", e.target.value)}
                  className="h-11 w-full rounded-xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-900 outline-none focus:ring-2 focus:ring-emerald-200"
                  placeholder="Optional"
                />
              </label>

              <label className="block md:col-span-2">
                <div className="mb-1 text-xs font-semibold text-slate-600">Payment instructions</div>
                <textarea
                  rows={4}
                  value={paymentForm.payment_instructions}
                  onChange={(e) => updatePayment("payment_instructions", e.target.value)}
                  className="w-full rounded-xl border border-slate-200 bg-white px-3 py-3 text-sm font-medium text-slate-900 outline-none focus:ring-2 focus:ring-emerald-200"
                  placeholder="Optional instructions shown to customers for EFT payments."
                />
              </label>
            </div>

            <div className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-2">
              <Toggle
                checked={safeBool(paymentForm.use_for_eft, true)}
                onChange={(v) => updatePayment("use_for_eft", v)}
                label="Use these details for EFT orders"
                hint="Expose this bank profile when an order is ready for EFT payment."
              />
              <Toggle
                checked={safeBool(paymentForm.is_active, true)}
                onChange={(v) => updatePayment("is_active", v)}
                label="Payment profile active"
                hint="Lets the platform treat this payment profile as currently usable."
              />
            </div>

            <div className="mt-4 flex flex-wrap items-center gap-3">
              <button
                type="button"
                onClick={savePayment}
                disabled={savingPayment}
                className="inline-flex items-center gap-2 rounded-2xl bg-emerald-600 px-4 py-3 text-sm font-bold text-white hover:bg-emerald-700 disabled:cursor-not-allowed disabled:opacity-60"
              >
                <Save className="h-4 w-4" />
                {savingPayment ? "Saving EFT details…" : "Save EFT details"}
              </button>
            </div>
          </div>

          <div className="grid grid-cols-1 gap-6 xl:grid-cols-[0.95fr_0.85fr]">
            <div className="rounded-3xl border border-slate-200 bg-white p-6 shadow-sm">
              <div className="mb-3 flex items-center gap-2">
                <ShieldCheck className="h-5 w-5 text-emerald-700" />
                <div className="text-lg font-extrabold text-slate-900">Customer preview</div>
              </div>

              <dl className="space-y-3 text-sm">
                <div>
                  <dt className="text-xs font-semibold uppercase tracking-wide text-slate-500">Bank</dt>
                  <dd className="mt-1 font-semibold text-slate-900">
                    {safeStr(paymentForm.bank_name, "—")}
                  </dd>
                </div>
                <div>
                  <dt className="text-xs font-semibold uppercase tracking-wide text-slate-500">Account name</dt>
                  <dd className="mt-1 font-semibold text-slate-900">
                    {safeStr(paymentForm.account_name, "—")}
                  </dd>
                </div>
                <div>
                  <dt className="text-xs font-semibold uppercase tracking-wide text-slate-500">Account number</dt>
                  <dd className="mt-1 font-semibold text-slate-900">
                    {safeStr(paymentForm.account_number, "—")}
                  </dd>
                </div>
                <div>
                  <dt className="text-xs font-semibold uppercase tracking-wide text-slate-500">Branch code</dt>
                  <dd className="mt-1 font-semibold text-slate-900">
                    {safeStr(paymentForm.branch_code, "—")}
                  </dd>
                </div>
                <div>
                  <dt className="text-xs font-semibold uppercase tracking-wide text-slate-500">Instructions</dt>
                  <dd className="mt-1 whitespace-pre-wrap text-slate-700">
                    {safeStr(paymentForm.payment_instructions, "—")}
                  </dd>
                </div>
              </dl>
            </div>

            <div
              className={[
                "rounded-3xl border p-5 shadow-sm",
                isPaymentComplete
                  ? "border-emerald-200 bg-emerald-50"
                  : "border-amber-200 bg-amber-50",
              ].join(" ")}
            >
              <div className="flex items-start gap-3">
                {isPaymentComplete ? (
                  <ShieldCheck className="mt-0.5 h-5 w-5 text-emerald-700" />
                ) : (
                  <AlertTriangle className="mt-0.5 h-5 w-5 text-amber-700" />
                )}
                <div>
                  <div className="font-bold text-slate-900">
                    {isPaymentComplete ? "EFT details ready" : "EFT details incomplete"}
                  </div>
                  <div className="mt-1 text-sm text-slate-700">
                    {isPaymentComplete
                      ? "Customers will see a complete EFT profile when you request payment."
                      : "For EFT orders, complete bank name, account name, and account number before marking an order ready for payment."}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      );
    }

    if (activeSection === "storefront") {
      const sale = commerceForm.storefront.sale;

      return (
        <div className="space-y-6">
          <div className="rounded-3xl border border-slate-200 bg-white p-6 shadow-sm">
            <div className="mb-4 flex items-center gap-2">
              <Store className="h-5 w-5 text-emerald-700" />
              <div className="text-lg font-extrabold text-slate-900">Storefront & sales</div>
            </div>

            <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
              <Toggle
                checked={commerceForm.storefront.accept_new_orders}
                onChange={(v) => updateCommerceSection("storefront", "accept_new_orders", v)}
                label="Accept new orders"
                hint="Lets customers place new orders from your store."
              />
              <Toggle
                checked={commerceForm.storefront.store_paused}
                onChange={(v) => updateCommerceSection("storefront", "store_paused", v)}
                label="Pause store temporarily"
                hint="Use during stock checks, farm travel, or seasonal pauses."
              />
              <Toggle
                checked={commerceForm.storefront.show_low_stock_badge}
                onChange={(v) =>
                  updateCommerceSection("storefront", "show_low_stock_badge", v)
                }
                label="Show low-stock badge"
                hint="Makes limited stock clearer to buyers."
              />
              <Toggle
                checked={commerceForm.storefront.hide_out_of_stock_products}
                onChange={(v) =>
                  updateCommerceSection("storefront", "hide_out_of_stock_products", v)
                }
                label="Hide out-of-stock products"
                hint="Prevents unavailable items from cluttering your storefront."
              />
            </div>
          </div>

          <div className="rounded-3xl border border-slate-200 bg-white p-6 shadow-sm">
            <div className="mb-4 flex items-center justify-between gap-3">
              <div>
                <div className="text-lg font-extrabold text-slate-900">Sale campaign</div>
                <div className="text-sm text-slate-600">
                  Configure a merchant sale that can later be applied to storefront pricing rules.
                </div>
              </div>
              <label className="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-slate-50 px-3 py-2 text-sm font-semibold text-slate-800">
                <input
                  type="checkbox"
                  checked={sale.enabled}
                  onChange={(e) => updateSale("enabled", e.target.checked)}
                />
                Sale active
              </label>
            </div>

            <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
              <label className="block">
                <div className="mb-1 text-xs font-semibold text-slate-600">Sale name</div>
                <input
                  value={sale.sale_name}
                  onChange={(e) => updateSale("sale_name", e.target.value)}
                  className="h-11 w-full rounded-xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-900 outline-none focus:ring-2 focus:ring-emerald-200"
                  placeholder="e.g. Fresh Harvest Weekend"
                />
              </label>

              <label className="block">
                <div className="mb-1 text-xs font-semibold text-slate-600">Discount type</div>
                <select
                  value={sale.discount_type}
                  onChange={(e) => updateSale("discount_type", e.target.value)}
                  className="h-11 w-full rounded-xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-900 outline-none focus:ring-2 focus:ring-emerald-200"
                >
                  <option value="percent">Percentage</option>
                  <option value="fixed">Fixed amount (NAD)</option>
                </select>
              </label>

              <label className="block">
                <div className="mb-1 text-xs font-semibold text-slate-600">Discount value</div>
                <input
                  type="number"
                  min="0"
                  step="0.01"
                  value={sale.discount_value}
                  onChange={(e) => updateSale("discount_value", e.target.value)}
                  className="h-11 w-full rounded-xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-900 outline-none focus:ring-2 focus:ring-emerald-200"
                />
              </label>

              <label className="block">
                <div className="mb-1 text-xs font-semibold text-slate-600">Apply scope</div>
                <select
                  value={sale.apply_scope}
                  onChange={(e) => updateSale("apply_scope", e.target.value)}
                  className="h-11 w-full rounded-xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-900 outline-none focus:ring-2 focus:ring-emerald-200"
                >
                  <option value="all">All products</option>
                  <option value="selected_products">Selected products</option>
                  <option value="selected_category">Selected category</option>
                </select>
              </label>

              <label className="block">
                <div className="mb-1 text-xs font-semibold text-slate-600">Start date</div>
                <input
                  type="datetime-local"
                  value={sale.start_at}
                  onChange={(e) => updateSale("start_at", e.target.value)}
                  className="h-11 w-full rounded-xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-900 outline-none focus:ring-2 focus:ring-emerald-200"
                />
              </label>

              <label className="block">
                <div className="mb-1 text-xs font-semibold text-slate-600">End date</div>
                <input
                  type="datetime-local"
                  value={sale.end_at}
                  onChange={(e) => updateSale("end_at", e.target.value)}
                  className="h-11 w-full rounded-xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-900 outline-none focus:ring-2 focus:ring-emerald-200"
                />
              </label>

              <label className="block lg:col-span-2">
                <div className="mb-1 text-xs font-semibold text-slate-600">Banner text</div>
                <input
                  value={sale.banner_text}
                  onChange={(e) => updateSale("banner_text", e.target.value)}
                  className="h-11 w-full rounded-xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-900 outline-none focus:ring-2 focus:ring-emerald-200"
                  placeholder="e.g. Limited harvest promotion"
                />
              </label>

              <label className="block">
                <div className="mb-1 text-xs font-semibold text-slate-600">Selected category</div>
                <input
                  value={sale.selected_category}
                  onChange={(e) => updateSale("selected_category", e.target.value)}
                  className="h-11 w-full rounded-xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-900 outline-none focus:ring-2 focus:ring-emerald-200"
                  placeholder="Use when scope = selected category"
                />
              </label>

              <label className="block">
                <div className="mb-1 text-xs font-semibold text-slate-600">Minimum stock threshold</div>
                <input
                  type="number"
                  min="0"
                  step="1"
                  value={sale.minimum_stock_threshold}
                  onChange={(e) => updateSale("minimum_stock_threshold", e.target.value)}
                  className="h-11 w-full rounded-xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-900 outline-none focus:ring-2 focus:ring-emerald-200"
                />
              </label>
            </div>

            <div className="mt-4 grid grid-cols-1 gap-3 md:grid-cols-2">
              <Toggle
                checked={sale.stack_with_other_promotions}
                onChange={(v) => updateSale("stack_with_other_promotions", v)}
                label="Allow promotion stacking"
                hint="Use only when you want this campaign to combine with other promotional rules later."
              />
            </div>
          </div>
        </div>
      );
    }

    if (activeSection === "fulfillment") {
      const f = commerceForm.fulfillment;

      return (
        <div className="rounded-3xl border border-slate-200 bg-white p-6 shadow-sm">
          <div className="mb-4 flex items-center gap-2">
            <Truck className="h-5 w-5 text-emerald-700" />
            <div className="text-lg font-extrabold text-slate-900">Orders & fulfillment</div>
          </div>

          <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
            <Toggle
              checked={f.pickup_enabled}
              onChange={(v) => updateCommerceSection("fulfillment", "pickup_enabled", v)}
              label="Pickup enabled"
              hint="Allow customers to collect orders from your pickup point."
            />
            <Toggle
              checked={f.delivery_enabled}
              onChange={(v) => updateCommerceSection("fulfillment", "delivery_enabled", v)}
              label="Delivery enabled"
              hint="Allow farmer-managed delivery within your active service area."
            />
            <Toggle
              checked={f.allow_substitutions}
              onChange={(v) =>
                updateCommerceSection("fulfillment", "allow_substitutions", v)
              }
              label="Allow substitutions"
              hint="Lets you replace unavailable produce with agreed alternatives when needed."
            />
          </div>

          <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-2">
            <label className="block">
              <div className="mb-1 text-xs font-semibold text-slate-600">Minimum order (NAD)</div>
              <input
                type="number"
                min="0"
                step="0.01"
                value={f.minimum_order_nad}
                onChange={(e) =>
                  updateCommerceSection("fulfillment", "minimum_order_nad", e.target.value)
                }
                className="h-11 w-full rounded-xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-900 outline-none focus:ring-2 focus:ring-emerald-200"
              />
            </label>

            <label className="block">
              <div className="mb-1 text-xs font-semibold text-slate-600">Preparation lead time (hours)</div>
              <input
                type="number"
                min="0"
                step="1"
                value={f.preparation_lead_hours}
                onChange={(e) =>
                  updateCommerceSection(
                    "fulfillment",
                    "preparation_lead_hours",
                    e.target.value
                  )
                }
                className="h-11 w-full rounded-xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-900 outline-none focus:ring-2 focus:ring-emerald-200"
              />
            </label>

            <label className="block">
              <div className="mb-1 text-xs font-semibold text-slate-600">Same-day cutoff time</div>
              <input
                type="time"
                value={f.same_day_cutoff_time}
                onChange={(e) =>
                  updateCommerceSection("fulfillment", "same_day_cutoff_time", e.target.value)
                }
                className="h-11 w-full rounded-xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-900 outline-none focus:ring-2 focus:ring-emerald-200"
              />
            </label>

            <label className="block">
              <div className="mb-1 text-xs font-semibold text-slate-600">Max daily orders</div>
              <input
                type="number"
                min="0"
                step="1"
                value={f.max_daily_orders}
                onChange={(e) =>
                  updateCommerceSection("fulfillment", "max_daily_orders", e.target.value)
                }
                className="h-11 w-full rounded-xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-900 outline-none focus:ring-2 focus:ring-emerald-200"
              />
            </label>

            <label className="block">
              <div className="mb-1 text-xs font-semibold text-slate-600">Service radius (km)</div>
              <input
                type="number"
                min="0"
                step="1"
                value={f.service_radius_km}
                onChange={(e) =>
                  updateCommerceSection("fulfillment", "service_radius_km", e.target.value)
                }
                className="h-11 w-full rounded-xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-900 outline-none focus:ring-2 focus:ring-emerald-200"
              />
            </label>

            <label className="block lg:col-span-2">
              <div className="mb-1 text-xs font-semibold text-slate-600">Pickup instructions</div>
              <textarea
                rows={4}
                value={f.pickup_instructions}
                onChange={(e) =>
                  updateCommerceSection("fulfillment", "pickup_instructions", e.target.value)
                }
                className="w-full rounded-xl border border-slate-200 bg-white px-3 py-3 text-sm font-medium text-slate-900 outline-none focus:ring-2 focus:ring-emerald-200"
                placeholder="Explain pickup windows, landmarks, or collection requirements."
              />
            </label>
          </div>
        </div>
      );
    }

    if (activeSection === "notifications") {
      const n = commerceForm.notifications;

      return (
        <div className="rounded-3xl border border-slate-200 bg-white p-6 shadow-sm">
          <div className="mb-4 flex items-center gap-2">
            <BellRing className="h-5 w-5 text-emerald-700" />
            <div className="text-lg font-extrabold text-slate-900">
              Farmer notification preferences
            </div>
          </div>

          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            <Toggle
              checked={n.orders_in_app}
              onChange={(v) => updateCommerceSection("notifications", "orders_in_app", v)}
              label="Orders in-app"
              hint="New orders, payment proofs, and order payment readiness alerts."
            />
            <Toggle
              checked={n.orders_email}
              onChange={(v) => updateCommerceSection("notifications", "orders_email", v)}
              label="Orders email"
              hint="Receive order-related notifications by email."
            />
            <Toggle
              checked={n.orders_sms}
              onChange={(v) => updateCommerceSection("notifications", "orders_sms", v)}
              label="Orders SMS"
              hint="Best reserved for urgent order events."
            />
            <Toggle
              checked={n.messages_in_app}
              onChange={(v) => updateCommerceSection("notifications", "messages_in_app", v)}
              label="Messages in-app"
              hint="Customer and admin communication in your seller inbox."
            />
            <Toggle
              checked={n.messages_email}
              onChange={(v) => updateCommerceSection("notifications", "messages_email", v)}
              label="Messages email"
              hint="Email a copy of seller communication notifications."
            />
            <Toggle
              checked={n.moderation_in_app}
              onChange={(v) =>
                updateCommerceSection("notifications", "moderation_in_app", v)
              }
              label="Moderation in-app"
              hint="Product approvals, rejections, and edit requests in-app."
            />
            <Toggle
              checked={n.moderation_email}
              onChange={(v) =>
                updateCommerceSection("notifications", "moderation_email", v)
              }
              label="Moderation email"
              hint="Email product review outcomes to the farmer."
            />
            <Toggle
              checked={n.daily_digest_enabled}
              onChange={(v) =>
                updateCommerceSection("notifications", "daily_digest_enabled", v)
              }
              label="Daily digest"
              hint="Receive a batched summary instead of relying only on instant awareness."
            />
            <Toggle
              checked={n.instant_payment_proof_alerts}
              onChange={(v) =>
                updateCommerceSection("notifications", "instant_payment_proof_alerts", v)
              }
              label="Instant payment-proof alerts"
              hint="Keep proof-of-payment events immediate for faster order progression."
            />
            <Toggle
              checked={n.quiet_hours_enabled}
              onChange={(v) =>
                updateCommerceSection("notifications", "quiet_hours_enabled", v)
              }
              label="Quiet hours"
              hint="Reduce interruption during non-working hours."
            />
            <Toggle
              checked={n.urgent_override}
              onChange={(v) => updateCommerceSection("notifications", "urgent_override", v)}
              label="Urgent override"
              hint="Allows critical alerts to bypass quiet hours."
            />
          </div>

          <div className="mt-4 grid grid-cols-1 gap-4 sm:grid-cols-2">
            <label className="block">
              <div className="mb-1 text-xs font-semibold text-slate-600">Quiet hours start</div>
              <input
                type="time"
                value={n.quiet_hours_start}
                onChange={(e) =>
                  updateCommerceSection("notifications", "quiet_hours_start", e.target.value)
                }
                className="h-11 w-full rounded-xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-900 outline-none focus:ring-2 focus:ring-emerald-200"
              />
            </label>

            <label className="block">
              <div className="mb-1 text-xs font-semibold text-slate-600">Quiet hours end</div>
              <input
                type="time"
                value={n.quiet_hours_end}
                onChange={(e) =>
                  updateCommerceSection("notifications", "quiet_hours_end", e.target.value)
                }
                className="h-11 w-full rounded-xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-900 outline-none focus:ring-2 focus:ring-emerald-200"
              />
            </label>
          </div>
        </div>
      );
    }

    if (activeSection === "communication") {
      const c = commerceForm.communication;

      return (
        <div className="rounded-3xl border border-slate-200 bg-white p-6 shadow-sm">
          <div className="mb-4 flex items-center gap-2">
            <Megaphone className="h-5 w-5 text-emerald-700" />
            <div className="text-lg font-extrabold text-slate-900">Customer communication</div>
          </div>

          <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
            <Toggle
              checked={c.auto_reply_enabled}
              onChange={(v) => updateCommerceSection("communication", "auto_reply_enabled", v)}
              label="Auto-reply when unavailable"
              hint="Useful during travel, harvest collection, or seasonal pauses."
            />
            <Toggle
              checked={c.display_response_time}
              onChange={(v) =>
                updateCommerceSection("communication", "display_response_time", v)
              }
              label="Display response-time indicator"
              hint="Supports buyer trust and seller professionalism."
            />
          </div>

          <div className="mt-4 space-y-4">
            <label className="block">
              <div className="mb-1 text-xs font-semibold text-slate-600">Auto-reply message</div>
              <textarea
                rows={4}
                value={c.auto_reply_message}
                onChange={(e) =>
                  updateCommerceSection("communication", "auto_reply_message", e.target.value)
                }
                className="w-full rounded-xl border border-slate-200 bg-white px-3 py-3 text-sm font-medium text-slate-900 outline-none focus:ring-2 focus:ring-emerald-200"
                placeholder="Thank you. We have received your message and will respond as soon as possible."
              />
            </label>

            <label className="block">
              <div className="mb-1 text-xs font-semibold text-slate-600">Seller welcome message</div>
              <textarea
                rows={4}
                value={c.seller_welcome_message}
                onChange={(e) =>
                  updateCommerceSection(
                    "communication",
                    "seller_welcome_message",
                    e.target.value
                  )
                }
                className="w-full rounded-xl border border-slate-200 bg-white px-3 py-3 text-sm font-medium text-slate-900 outline-none focus:ring-2 focus:ring-emerald-200"
                placeholder="Welcome to our storefront. Orders are prepared fresh and confirmed as soon as possible."
              />
            </label>

            <label className="block">
              <div className="mb-1 text-xs font-semibold text-slate-600">FAQ snippets (comma-separated)</div>
              <input
                value={(c.faq_snippets || []).join(", ")}
                onChange={(e) =>
                  updateCommerceSection(
                    "communication",
                    "faq_snippets",
                    e.target.value
                      .split(",")
                      .map((x) => x.trim())
                      .filter(Boolean)
                  )
                }
                className="h-11 w-full rounded-xl border border-slate-200 bg-white px-3 text-sm font-medium text-slate-900 outline-none focus:ring-2 focus:ring-emerald-200"
                placeholder="Pickup times, delivery areas, preparation lead time"
              />
            </label>
          </div>
        </div>
      );
    }

    if (activeSection === "analytics") {
      const a = commerceForm.analytics;

      return (
        <div className="rounded-3xl border border-slate-200 bg-white p-6 shadow-sm">
          <div className="mb-4 flex items-center gap-2">
            <BarChart3 className="h-5 w-5 text-emerald-700" />
            <div className="text-lg font-extrabold text-slate-900">
              Seller analytics preferences
            </div>
          </div>

          <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
            <Toggle
              checked={a.show_market_trends}
              onChange={(v) =>
                updateCommerceSection("analytics", "show_market_trends", v)
              }
              label="Show market trends widget"
              hint="Controls AI trend visibility on the farmer product dashboard."
            />
            <Toggle
              checked={a.show_stock_alerts}
              onChange={(v) => updateCommerceSection("analytics", "show_stock_alerts", v)}
              label="Show stock alerts widget"
              hint="Keeps restock alerts visible in the seller UI."
            />
            <Toggle
              checked={a.show_ranking_widget}
              onChange={(v) =>
                updateCommerceSection("analytics", "show_ranking_widget", v)
              }
              label="Show ranking widget"
              hint="Controls marketplace rank visibility in seller analytics."
            />
            <Toggle
              checked={a.weekly_summary_email}
              onChange={(v) =>
                updateCommerceSection("analytics", "weekly_summary_email", v)
              }
              label="Weekly summary email"
              hint="Supports periodic review outside the dashboard."
            />
          </div>

          <div className="mt-4 grid grid-cols-1 gap-4 sm:grid-cols-3">
            <label className="block">
              <div className="mb-1 text-xs font-semibold text-slate-600">Custom low-stock threshold</div>
              <input
                type="number"
                min="0"
                step="1"
                value={a.custom_low_stock_threshold}
                onChange={(e) =>
                  updateCommerceSection(
                    "analytics",
                    "custom_low_stock_threshold",
                    e.target.value
                  )
                }
                className="h-11 w-full rounded-xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-900 outline-none focus:ring-2 focus:ring-emerald-200"
              />
            </label>

            <label className="block">
              <div className="mb-1 text-xs font-semibold text-slate-600">Alert sensitivity</div>
              <select
                value={a.alert_sensitivity}
                onChange={(e) =>
                  updateCommerceSection("analytics", "alert_sensitivity", e.target.value)
                }
                className="h-11 w-full rounded-xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-900 outline-none focus:ring-2 focus:ring-emerald-200"
              >
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
              </select>
            </label>

            <label className="block">
              <div className="mb-1 text-xs font-semibold text-slate-600">Ranking window (days)</div>
              <input
                type="number"
                min="7"
                step="1"
                value={a.ranking_window_days}
                onChange={(e) =>
                  updateCommerceSection("analytics", "ranking_window_days", e.target.value)
                }
                className="h-11 w-full rounded-xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-900 outline-none focus:ring-2 focus:ring-emerald-200"
              />
            </label>
          </div>
        </div>
      );
    }

    const b = commerceForm.business_profile;

    return (
      <div className="rounded-3xl border border-slate-200 bg-white p-6 shadow-sm">
        <div className="mb-4 flex items-center gap-2">
          <Briefcase className="h-5 w-5 text-emerald-700" />
          <div className="text-lg font-extrabold text-slate-900">Business profile</div>
        </div>

        <div className="mb-4 rounded-2xl border border-slate-200 bg-slate-50 p-4 text-sm text-slate-700">
          Use this section for your storefront presentation. Use
          <span className="font-semibold"> Farmer Details</span> for your account name,
          contact number, email, and address / town.
        </div>

        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          <label className="block">
            <div className="mb-1 text-xs font-semibold text-slate-600">Store tagline</div>
            <input
              value={b.store_tagline}
              onChange={(e) =>
                updateCommerceSection("business_profile", "store_tagline", e.target.value)
              }
              className="h-11 w-full rounded-xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-900 outline-none focus:ring-2 focus:ring-emerald-200"
              placeholder="e.g. Fresh produce directly from the farm"
            />
          </label>

          <label className="block">
            <div className="mb-1 text-xs font-semibold text-slate-600">Business phone</div>
            <input
              value={b.business_phone}
              onChange={(e) =>
                updateCommerceSection("business_profile", "business_phone", e.target.value)
              }
              className="h-11 w-full rounded-xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-900 outline-none focus:ring-2 focus:ring-emerald-200"
              placeholder="Farmer business contact number"
            />
          </label>

          <label className="block lg:col-span-2">
            <div className="mb-1 text-xs font-semibold text-slate-600">Farm story / about</div>
            <textarea
              rows={5}
              value={b.farm_story}
              onChange={(e) =>
                updateCommerceSection("business_profile", "farm_story", e.target.value)
              }
              className="w-full rounded-xl border border-slate-200 bg-white px-3 py-3 text-sm font-medium text-slate-900 outline-none focus:ring-2 focus:ring-emerald-200"
              placeholder="Tell customers about your farm, production method, or seasonal availability."
            />
          </label>

          <label className="block">
            <div className="mb-1 text-xs font-semibold text-slate-600">Service regions (comma-separated)</div>
            <input
              value={(b.service_regions || []).join(", ")}
              onChange={(e) =>
                updateCommerceSection(
                  "business_profile",
                  "service_regions",
                  e.target.value
                    .split(",")
                    .map((x) => x.trim())
                    .filter(Boolean)
                )
              }
              className="h-11 w-full rounded-xl border border-slate-200 bg-white px-3 text-sm font-medium text-slate-900 outline-none focus:ring-2 focus:ring-emerald-200"
              placeholder="Windhoek, Ongwediva, Oshakati"
            />
          </label>

          <label className="block">
            <div className="mb-1 text-xs font-semibold text-slate-600">Public contact link</div>
            <input
              value={b.public_contact_link}
              onChange={(e) =>
                updateCommerceSection(
                  "business_profile",
                  "public_contact_link",
                  e.target.value
                )
              }
              className="h-11 w-full rounded-xl border border-slate-200 bg-white px-3 text-sm font-medium text-slate-900 outline-none focus:ring-2 focus:ring-emerald-200"
              placeholder="Website / WhatsApp / public link"
            />
          </label>

          <label className="block lg:col-span-2">
            <div className="mb-1 text-xs font-semibold text-slate-600">Pickup address</div>
            <textarea
              rows={4}
              value={b.pickup_address}
              onChange={(e) =>
                updateCommerceSection("business_profile", "pickup_address", e.target.value)
              }
              className="w-full rounded-xl border border-slate-200 bg-white px-3 py-3 text-sm font-medium text-slate-900 outline-none focus:ring-2 focus:ring-emerald-200"
              placeholder="Physical pickup location shown to customers when pickup is active."
            />
          </label>

          <label className="block">
            <div className="mb-1 text-xs font-semibold text-slate-600">Operating days (comma-separated)</div>
            <input
              value={(b.operating_days || []).join(", ")}
              onChange={(e) =>
                updateCommerceSection(
                  "business_profile",
                  "operating_days",
                  e.target.value
                    .split(",")
                    .map((x) => x.trim())
                    .filter(Boolean)
                )
              }
              className="h-11 w-full rounded-xl border border-slate-200 bg-white px-3 text-sm font-medium text-slate-900 outline-none focus:ring-2 focus:ring-emerald-200"
              placeholder="Mon, Tue, Wed, Thu, Fri"
            />
          </label>

          <div className="grid grid-cols-2 gap-4">
            <label className="block">
              <div className="mb-1 text-xs font-semibold text-slate-600">Opening time</div>
              <input
                type="time"
                value={b.opening_time}
                onChange={(e) =>
                  updateCommerceSection("business_profile", "opening_time", e.target.value)
                }
                className="h-11 w-full rounded-xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-900 outline-none focus:ring-2 focus:ring-emerald-200"
              />
            </label>

            <label className="block">
              <div className="mb-1 text-xs font-semibold text-slate-600">Closing time</div>
              <input
                type="time"
                value={b.closing_time}
                onChange={(e) =>
                  updateCommerceSection("business_profile", "closing_time", e.target.value)
                }
                className="h-11 w-full rounded-xl border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-900 outline-none focus:ring-2 focus:ring-emerald-200"
              />
            </label>
          </div>
        </div>
      </div>
    );
  };

  return (
    <FarmerLayout>
      <div className="space-y-6">
        <section className="overflow-hidden rounded-3xl border border-slate-200 bg-white shadow-sm">
          <div className="bg-gradient-to-r from-emerald-50 via-white to-teal-50 p-6">
            <div className="text-xs font-semibold uppercase tracking-wide text-emerald-700">
              Farmer commerce
            </div>
            <h1 className="mt-1 text-2xl font-black tracking-tight text-slate-900">
              Settings
            </h1>
            <p className="mt-1 text-sm text-slate-600">
              Manage seller identity, storefront posture, EFT details, notifications,
              operations, and business presentation from one control centre.
            </p>
          </div>
        </section>

        <section className="grid grid-cols-1 gap-4 md:grid-cols-3 xl:grid-cols-4">
          <div className="rounded-3xl border border-slate-200 bg-white p-5 shadow-sm">
            <div className="text-xs font-semibold uppercase tracking-wide text-slate-500">
              Farmer profile
            </div>
            <div className="mt-2 text-lg font-black text-slate-900">
              {isProfileComplete ? "Complete" : "Needs attention"}
            </div>
            <div className="mt-1 text-sm text-slate-600">{farmerIdentitySummary}</div>
          </div>

          <div className="rounded-3xl border border-slate-200 bg-white p-5 shadow-sm">
            <div className="text-xs font-semibold uppercase tracking-wide text-slate-500">
              Sale campaign
            </div>
            <div className="mt-2 text-lg font-black text-slate-900">
              {commerceForm.storefront.sale.enabled ? "Active" : "Inactive"}
            </div>
            <div className="mt-1 text-sm text-slate-600">{saleSummary}</div>
          </div>

          <div className="rounded-3xl border border-slate-200 bg-white p-5 shadow-sm">
            <div className="text-xs font-semibold uppercase tracking-wide text-slate-500">
              Order intake
            </div>
            <div className="mt-2 text-lg font-black text-slate-900">
              {commerceForm.storefront.store_paused
                ? "Paused"
                : commerceForm.storefront.accept_new_orders
                  ? "Open"
                  : "Closed"}
            </div>
            <div className="mt-1 text-sm text-slate-600">
              Pickup {commerceForm.fulfillment.pickup_enabled ? "on" : "off"} • Delivery{" "}
              {commerceForm.fulfillment.delivery_enabled ? "on" : "off"}
            </div>
          </div>

          <div className="rounded-3xl border border-slate-200 bg-white p-5 shadow-sm">
            <div className="text-xs font-semibold uppercase tracking-wide text-slate-500">
              Notifications
            </div>
            <div className="mt-2 text-lg font-black text-slate-900">{inboxSummary}</div>
            <div className="mt-1 text-sm text-slate-600">
              Orders, messages, and moderation can each be controlled separately.
            </div>
          </div>
        </section>

        {error ? (
          <div className="rounded-2xl border border-rose-200 bg-rose-50 p-4 text-sm text-rose-700">
            {error}
          </div>
        ) : null}

        {success ? (
          <div className="rounded-2xl border border-emerald-200 bg-emerald-50 p-4 text-sm text-emerald-800">
            {success}
          </div>
        ) : null}

        {loading ? (
          <div className="rounded-3xl border border-slate-200 bg-white p-8 text-sm text-slate-600 shadow-sm">
            Loading farmer settings…
          </div>
        ) : (
          <section className="grid grid-cols-1 gap-6 xl:grid-cols-[280px_minmax(0,1fr)]">
            <aside className="space-y-3 rounded-3xl border border-slate-200 bg-white p-4 shadow-sm xl:sticky xl:top-24 xl:self-start">
              <div className="mb-2 flex items-center gap-2 text-sm font-bold text-slate-900">
                <Settings2 className="h-4 w-4 text-emerald-700" />
                Settings areas
              </div>

              {SECTION_ITEMS.map((item) => {
                const Icon = item.icon;
                const active = activeSection === item.key;

                return (
                  <button
                    key={item.key}
                    type="button"
                    onClick={() => setActiveSection(item.key)}
                    className={[
                      "flex w-full items-center gap-3 rounded-2xl border px-3 py-3 text-left transition",
                      active
                        ? "border-green-200 bg-green-50 text-green-700"
                        : "border-slate-200 bg-white text-slate-800 hover:bg-slate-50",
                    ].join(" ")}
                  >
                    <div className="grid h-9 w-9 place-items-center rounded-xl border border-slate-200 bg-white">
                      <Icon className="h-4 w-4" />
                    </div>
                    <div>
                      <div className="text-sm font-semibold">{item.label}</div>
                    </div>
                  </button>
                );
              })}

              <button
                type="button"
                onClick={() => refreshAll(true)}
                disabled={refreshing}
                className="inline-flex w-full items-center justify-center gap-2 rounded-2xl border border-slate-200 bg-white px-4 py-3 text-sm font-semibold text-slate-800 hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-60"
              >
                <RefreshCcw className={refreshing ? "h-4 w-4 animate-spin" : "h-4 w-4"} />
                Refresh settings
              </button>
            </aside>

            <div className="space-y-6">
              {renderSection()}

              {activeSection !== "payments" && activeSection !== "farmer_details" ? (
                <div className="sticky bottom-4 z-10 rounded-3xl border border-slate-200 bg-white/95 p-4 shadow-lg backdrop-blur">
                  <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                    <div>
                      <div className="text-sm font-bold text-slate-900">
                        Save farmer commerce settings
                      </div>
                      <div className="text-xs text-slate-500">
                        Persists seller-facing settings for your store, operations, and commerce workflow.
                      </div>
                    </div>

                    <button
                      type="button"
                      onClick={saveCommerce}
                      disabled={savingCommerce}
                      className="inline-flex items-center justify-center gap-2 rounded-2xl bg-emerald-600 px-4 py-3 text-sm font-bold text-white hover:bg-emerald-700 disabled:cursor-not-allowed disabled:opacity-60"
                    >
                      <Save className="h-4 w-4" />
                      {savingCommerce ? "Saving settings…" : "Save settings"}
                    </button>
                  </div>
                </div>
              ) : null}
            </div>
          </section>
        )}
      </div>
    </FarmerLayout>
  );
}
