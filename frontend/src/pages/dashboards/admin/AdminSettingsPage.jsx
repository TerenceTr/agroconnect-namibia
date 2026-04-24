// ============================================================================
// src/pages/dashboards/admin/AdminSettingsPage.jsx — Admin System Settings
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Master-level admin control plane for marketplace-wide platform policy.
//
// DESIGN GOALS IN THIS VERSION:
//   • Explain each policy section in plain administrative language
//   • Replace button-like on/off chips with clear switch-style toggle elements
//   • Keep all current backend endpoints working:
//       GET  /admin/settings
//       POST /admin/settings
//       POST /admin/cache/flush
//   • Preserve the existing settings schema and compatibility keys
//   • Add section-level operational summaries
//   • Prompt the admin for confirmation before enabling maintenance mode
//
// WHY THIS VERSION IS BETTER:
//   • The UI becomes easier to read as a policy dashboard
//   • Boolean controls are visually obvious at a glance
//   • The page explains governance intent, not just raw fields
//   • The structure better reflects an auditable ecommerce control surface
// ============================================================================

import React, { useEffect, useMemo, useState } from "react";
import { toast } from "react-hot-toast";
import {
  Activity,
  Bell,
  Brain,
  CreditCard,
  Database,
  RefreshCcw,
  Save,
  Search,
  Settings2,
  ShieldCheck,
  Store,
  Truck,
  Wrench,
} from "lucide-react";

import AdminLayout from "../../../components/AdminLayout";
import api from "../../../api";

// ----------------------------------------------------------------------------
// Recommended baseline
// ----------------------------------------------------------------------------
const RECOMMENDED_BASELINE = {
  cache_ttl: 300,
  maintenance: false,
  version: "-",
  platform: {
    maintenance_message: "Scheduled maintenance in progress. Please try again shortly.",
    read_only_mode: false,
    default_report_days: 90,
    report_preview_rows: 25,
  },
  marketplace: {
    currency_code: "NAD",
    vat_percent: 15,
    low_stock_threshold: 5,
    featured_products_limit: 8,
    allow_ratings: true,
    allow_product_likes: true,
  },
  checkout: {
    allow_delivery: true,
    allow_pickup: true,
    auto_cancel_unpaid_hours: 24,
    default_delivery_fee: 30,
    free_delivery_threshold: 500,
    max_cart_items: 50,
    max_order_lines_per_checkout: 20,
  },
  payments: {
    eft_enabled: true,
    cash_on_delivery_enabled: false,
    manual_review_enabled: true,
    proof_of_payment_required_for_eft: true,
    max_payment_proof_mb: 5,
    manual_review_threshold_nad: 1500,
  },
  communications: {
    in_app_notifications_enabled: true,
    email_notifications_enabled: true,
    sms_notifications_enabled: true,
    broadcast_email_enabled: true,
    broadcast_sms_enabled: true,
  },
  moderation: {
    product_review_sla_hours: 48,
    auto_publish_approved_products: true,
    require_rejection_reason: true,
    flag_duplicate_products: true,
  },
  analytics: {
    ai_insights_enabled: true,
    low_stock_alerts_enabled: true,
    search_analytics_enabled: true,
    market_trends_enabled: true,
    ranking_widgets_enabled: true,
  },
  search: {
    autocomplete_enabled: true,
    trending_searches_enabled: true,
    search_history_retention_days: 90,
    search_suggestions_limit: 8,
  },
};

// ----------------------------------------------------------------------------
// Generic helpers
// ----------------------------------------------------------------------------
function deepClone(value) {
  return JSON.parse(JSON.stringify(value));
}

function deepMerge(base, incoming) {
  const output = deepClone(base);
  if (!incoming || typeof incoming !== "object") return output;

  Object.entries(incoming).forEach(([key, value]) => {
    if (
      value &&
      typeof value === "object" &&
      !Array.isArray(value) &&
      output[key] &&
      typeof output[key] === "object" &&
      !Array.isArray(output[key])
    ) {
      output[key] = deepMerge(output[key], value);
    } else {
      output[key] = value;
    }
  });

  return output;
}

function getAtPath(obj, path, fallback = "") {
  return path
    .split(".")
    .reduce((acc, key) => (acc && acc[key] !== undefined ? acc[key] : undefined), obj) ?? fallback;
}

function setAtPath(obj, path, value) {
  const clone = deepClone(obj);
  const keys = path.split(".");
  let cursor = clone;

  for (let i = 0; i < keys.length - 1; i += 1) {
    const key = keys[i];
    if (!cursor[key] || typeof cursor[key] !== "object") cursor[key] = {};
    cursor = cursor[key];
  }

  cursor[keys[keys.length - 1]] = value;
  return clone;
}

function normalizeSettings(payload) {
  return deepMerge(RECOMMENDED_BASELINE, payload || {});
}

function cn(...parts) {
  return parts.filter(Boolean).join(" ");
}

function toNumber(value, fallback = 0) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function formatCurrency(code, amount) {
  return `${code} ${toNumber(amount, 0).toFixed(2)}`;
}

function countEnabled(objectValue = {}) {
  return Object.values(objectValue || {}).filter(Boolean).length;
}

// ----------------------------------------------------------------------------
// UI atoms
// ----------------------------------------------------------------------------
function FieldHint({ children }) {
  return <p className="mt-1 text-xs leading-5 text-slate-500">{children}</p>;
}

function StatusPill({ active, onLabel = "On", offLabel = "Off" }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full px-2.5 py-1 text-[11px] font-bold uppercase tracking-wide",
        active ? "bg-emerald-100 text-emerald-700" : "bg-slate-100 text-slate-600"
      )}
    >
      {active ? onLabel : offLabel}
    </span>
  );
}

function SummaryCard({ icon: Icon, label, value, hint }) {
  return (
    <div className="rounded-2xl border border-[#D8F3DC] bg-white p-4 shadow-sm">
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="text-xs font-semibold uppercase tracking-wide text-slate-500">{label}</div>
          <div className="mt-2 text-xl font-bold text-slate-900">{value}</div>
          <div className="mt-1 text-xs text-slate-500">{hint}</div>
        </div>
        <div className="grid h-10 w-10 place-items-center rounded-2xl border border-[#B7E4C7] bg-[#F4FBF7] text-[#1B4332]">
          <Icon className="h-5 w-5" />
        </div>
      </div>
    </div>
  );
}

function SectionExplainerCard({ icon: Icon, title, summary, enabledText }) {
  return (
    <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
      <div className="flex items-start gap-3">
        <div className="grid h-10 w-10 place-items-center rounded-2xl border border-[#B7E4C7] bg-white text-[#1B4332]">
          <Icon className="h-5 w-5" />
        </div>
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <h4 className="text-sm font-semibold text-slate-900">{title}</h4>
            {enabledText ? <StatusPill active onLabel={enabledText} offLabel={enabledText} /> : null}
          </div>
          <p className="mt-1 text-xs leading-5 text-slate-600">{summary}</p>
        </div>
      </div>
    </div>
  );
}

function SectionCard({ icon: Icon, title, description, policyNote, enabledCountText, children }) {
  return (
    <section className="rounded-[24px] border border-[#D8F3DC] bg-white p-5 shadow-sm">
      <div className="mb-5 flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
        <div className="flex items-start gap-3">
          <div className="grid h-11 w-11 place-items-center rounded-2xl border border-[#B7E4C7] bg-[#F4FBF7] text-[#1B4332]">
            <Icon className="h-5 w-5" />
          </div>
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <h3 className="text-lg font-semibold text-slate-900">{title}</h3>
              {enabledCountText ? <StatusPill active onLabel={enabledCountText} offLabel={enabledCountText} /> : null}
            </div>
            <p className="mt-1 max-w-3xl text-sm leading-6 text-slate-600">{description}</p>
          </div>
        </div>

        {policyNote ? (
          <div className="max-w-md rounded-2xl border border-emerald-100 bg-emerald-50 px-3 py-2 text-xs leading-5 text-emerald-800">
            <span className="font-semibold">What this controls:</span> {policyNote}
          </div>
        ) : null}
      </div>

      {children}
    </section>
  );
}

function NumberField({ label, value, onChange, hint, min = 0, step = 1, suffix = "" }) {
  return (
    <div>
      <label className="block text-sm font-medium text-slate-700">{label}</label>
      <div className="relative mt-2">
        <input
          type="number"
          min={min}
          step={step}
          value={value}
          onChange={(e) => onChange(e.target.value === "" ? "" : Number(e.target.value))}
          className="w-full rounded-2xl border border-slate-200 bg-white px-4 py-3 pr-16 text-slate-800 outline-none transition focus:border-[#74C69D] focus:ring-2 focus:ring-[#D8F3DC]"
        />
        {suffix ? (
          <span className="pointer-events-none absolute inset-y-0 right-4 flex items-center text-xs font-semibold text-slate-500">
            {suffix}
          </span>
        ) : null}
      </div>
      {hint ? <FieldHint>{hint}</FieldHint> : null}
    </div>
  );
}

function TextAreaField({ label, value, onChange, hint, rows = 3 }) {
  return (
    <div>
      <label className="block text-sm font-medium text-slate-700">{label}</label>
      <textarea
        rows={rows}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="mt-2 w-full rounded-2xl border border-slate-200 bg-white px-4 py-3 text-slate-800 outline-none transition focus:border-[#74C69D] focus:ring-2 focus:ring-[#D8F3DC]"
      />
      {hint ? <FieldHint>{hint}</FieldHint> : null}
    </div>
  );
}

function SelectField({ label, value, onChange, options, hint }) {
  return (
    <div>
      <label className="block text-sm font-medium text-slate-700">{label}</label>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="mt-2 w-full rounded-2xl border border-slate-200 bg-white px-4 py-3 text-slate-800 outline-none transition focus:border-[#74C69D] focus:ring-2 focus:ring-[#D8F3DC]"
      >
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
      {hint ? <FieldHint>{hint}</FieldHint> : null}
    </div>
  );
}

function ToggleField({
  label,
  checked,
  onChange,
  hint,
  impact,
  onLabel = "On",
  offLabel = "Off",
}) {
  return (
    <div className="rounded-2xl border border-slate-200 bg-white p-4">
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <div className="text-sm font-semibold text-slate-800">{label}</div>
            <StatusPill active={checked} onLabel={onLabel} offLabel={offLabel} />
          </div>

          {hint ? <FieldHint>{hint}</FieldHint> : null}

          {impact ? (
            <div className="mt-2 rounded-xl bg-slate-50 px-3 py-2 text-xs leading-5 text-slate-600">
              <span className="font-semibold text-slate-700">Impact:</span> {impact}
            </div>
          ) : null}
        </div>

        <button
          type="button"
          role="switch"
          aria-checked={checked}
          onClick={() => onChange(!checked)}
          className={cn(
            "relative inline-flex h-8 w-16 shrink-0 items-center rounded-full transition",
            checked ? "bg-[#16A34A]" : "bg-slate-300"
          )}
        >
          <span
            className={cn(
              "inline-block h-6 w-6 transform rounded-full bg-white shadow transition",
              checked ? "translate-x-9" : "translate-x-1"
            )}
          />
        </button>
      </div>
    </div>
  );
}

// ----------------------------------------------------------------------------
// Main page
// ----------------------------------------------------------------------------
export default function AdminSettingsPage() {
  const [settings, setSettings] = useState(normalizeSettings(RECOMMENDED_BASELINE));
  const [baseline, setBaseline] = useState(normalizeSettings(RECOMMENDED_BASELINE));
  const [saving, setSaving] = useState(false);
  const [flushing, setFlushing] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const load = async () => {
      try {
        setLoading(true);
        const res = await api.get("/admin/settings");
        const normalized = normalizeSettings(res?.data);
        setSettings(normalized);
        setBaseline(normalized);
      } catch (err) {
        console.warn("Could not load settings", err);
        toast.error("Could not load system settings");
      } finally {
        setLoading(false);
      }
    };

    load();
  }, []);

  const dirty = useMemo(
    () => JSON.stringify(settings) !== JSON.stringify(baseline),
    [settings, baseline]
  );

  const appVersion = getAtPath(settings, "version", "-");
  const currencyCode = getAtPath(settings, "marketplace.currency_code", "NAD");

  const enabledPaymentChannels = [
    getAtPath(settings, "payments.eft_enabled", true),
    getAtPath(settings, "payments.cash_on_delivery_enabled", false),
  ].filter(Boolean).length;

  const enabledComms = countEnabled(getAtPath(settings, "communications", {}));
  const enabledModeration = countEnabled({
    auto_publish_approved_products: getAtPath(settings, "moderation.auto_publish_approved_products", true),
    require_rejection_reason: getAtPath(settings, "moderation.require_rejection_reason", true),
    flag_duplicate_products: getAtPath(settings, "moderation.flag_duplicate_products", true),
  });
  const enabledAnalytics = countEnabled(getAtPath(settings, "analytics", {}));
  const enabledSearch = countEnabled({
    autocomplete_enabled: getAtPath(settings, "search.autocomplete_enabled", true),
    trending_searches_enabled: getAtPath(settings, "search.trending_searches_enabled", true),
  });

  const updateField = (path, value) => {
    setSettings((prev) => setAtPath(prev, path, value));
  };

  const saveSettings = async () => {
    const maintenanceBefore = getAtPath(baseline, "maintenance", false);
    const maintenanceAfter = getAtPath(settings, "maintenance", false);

    // ------------------------------------------------------------------------
    // Safety confirmation for switching maintenance on.
    // This was explicitly requested so the admin does not enable it casually.
    // ------------------------------------------------------------------------
    if (!maintenanceBefore && maintenanceAfter) {
      const ok = window.confirm(
        "Are you sure you want to turn maintenance mode ON?\n\nThis marks the platform as being under planned technical work and may change how users interpret platform availability."
      );
      if (!ok) return;
    }

    try {
      setSaving(true);
      const res = await api.post("/admin/settings", settings);
      const normalized = normalizeSettings(res?.data?.settings || settings);
      setSettings(normalized);
      setBaseline(normalized);
      toast.success("System settings saved");
    } catch (err) {
      console.error("Save settings failed", err);
      toast.error(err?.response?.data?.message || "Failed to save settings");
    } finally {
      setSaving(false);
    }
  };

  const flushCache = async () => {
    const ok = window.confirm("Flush cache now?");
    if (!ok) return;

    try {
      setFlushing(true);
      await api.post("/admin/cache/flush");
      toast.success("Cache flushed");
    } catch (err) {
      console.error("Flush failed", err);
      toast.error("Failed to flush cache");
    } finally {
      setFlushing(false);
    }
  };

  const resetRecommended = () => {
    const next = normalizeSettings({ ...RECOMMENDED_BASELINE, version: appVersion });
    setSettings(next);
    toast.success("Recommended baseline applied locally. Save to persist changes.");
  };

  const explainerCards = [
    {
      icon: Wrench,
      title: "Platform Operations",
      summary: "Runtime posture, maintenance communication, report defaults, and cache behavior.",
      enabledText: getAtPath(settings, "maintenance", false) ? "Maintenance active" : "Live posture",
    },
    {
      icon: Store,
      title: "Marketplace Policy",
      summary: "Commercial defaults, VAT, low-stock governance, and buyer trust features.",
      enabledText: `${countEnabled({
        allow_ratings: getAtPath(settings, "marketplace.allow_ratings", true),
        allow_product_likes: getAtPath(settings, "marketplace.allow_product_likes", true),
      })} features on`,
    },
    {
      icon: Truck,
      title: "Checkout & Fulfilment",
      summary: "Delivery, pickup, basket limits, and fulfilment policy thresholds.",
      enabledText: `${countEnabled({
        allow_delivery: getAtPath(settings, "checkout.allow_delivery", true),
        allow_pickup: getAtPath(settings, "checkout.allow_pickup", true),
      })} fulfilment modes`,
    },
    {
      icon: CreditCard,
      title: "Payments & Risk",
      summary: "Payment channels, proof governance, and manual-review policy.",
      enabledText: `${enabledPaymentChannels} payment channels`,
    },
    {
      icon: Bell,
      title: "Communications",
      summary: "Operational notifications and admin broadcast channel availability.",
      enabledText: `${enabledComms} toggles on`,
    },
    {
      icon: ShieldCheck,
      title: "Moderation & Trust",
      summary: "Catalogue quality controls, SLA posture, and publication safeguards.",
      enabledText: `${enabledModeration} safeguards on`,
    },
    {
      icon: Brain,
      title: "Analytics & Intelligence",
      summary: "AI insight surfaces, trend analysis, alerts, and ranking visibility.",
      enabledText: `${enabledAnalytics} analytics on`,
    },
    {
      icon: Search,
      title: "Search & Discovery",
      summary: "Autocomplete, trending search behavior, and search-data retention.",
      enabledText: `${enabledSearch} discovery tools on`,
    },
  ];

  return (
    <AdminLayout>
      <div className="space-y-6">
        {/* ------------------------------------------------------------------ */}
        {/* Page hero                                                          */}
        {/* ------------------------------------------------------------------ */}
        <div className="rounded-[28px] border border-[#D8F3DC] bg-white p-6 shadow-sm">
          <div className="flex flex-col gap-5 xl:flex-row xl:items-start xl:justify-between">
            <div>
              <div className="text-xs font-semibold uppercase tracking-[0.14em] text-[#40916C]">
                AgroConnect Namibia
              </div>
              <h2 className="mt-2 text-3xl font-bold tracking-tight text-slate-900">
                System Settings
              </h2>
              <p className="mt-2 max-w-4xl text-sm leading-6 text-slate-600">
                Manage the platform as an auditable ecommerce control plane. Each section below
                explains what it governs, which controls are enabled, and how operational policy
                affects marketplace behavior.
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-3">
              <div className="rounded-2xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-600">
                App Version: <span className="font-semibold text-slate-800">{appVersion}</span>
              </div>

              <button
                type="button"
                onClick={resetRecommended}
                className="inline-flex items-center gap-2 rounded-2xl border border-slate-200 bg-white px-4 py-3 text-sm font-semibold text-slate-700 hover:bg-slate-50"
              >
                <RefreshCcw className="h-4 w-4" />
                Recommended Baseline
              </button>

              <button
                type="button"
                onClick={flushCache}
                disabled={flushing}
                className="inline-flex items-center gap-2 rounded-2xl border border-slate-200 bg-white px-4 py-3 text-sm font-semibold text-slate-700 hover:bg-slate-50 disabled:opacity-60"
              >
                <Database className="h-4 w-4" />
                {flushing ? "Flushing…" : "Flush Cache"}
              </button>

              <button
                type="button"
                onClick={saveSettings}
                disabled={saving || loading}
                className="inline-flex items-center gap-2 rounded-2xl bg-[#16A34A] px-5 py-3 text-sm font-semibold text-white hover:bg-[#15803D] disabled:opacity-60"
              >
                <Save className="h-4 w-4" />
                {saving ? "Saving…" : "Save Settings"}
              </button>
            </div>
          </div>

          <div className="mt-6 grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <SummaryCard
              icon={Activity}
              label="Operational posture"
              value={getAtPath(settings, "maintenance", false) ? "Maintenance" : "Live"}
              hint={
                getAtPath(settings, "platform.read_only_mode", false)
                  ? "Read-only safeguards active"
                  : "Read-write operations enabled"
              }
            />
            <SummaryCard
              icon={CreditCard}
              label="Payment channels"
              value={`${enabledPaymentChannels} active`}
              hint={`Manual review at ${formatCurrency(
                currencyCode,
                getAtPath(settings, "payments.manual_review_threshold_nad", 1500)
              )}`}
            />
            <SummaryCard
              icon={Bell}
              label="Communication controls"
              value={`${enabledComms} toggles on`}
              hint={`Cache TTL ${getAtPath(settings, "cache_ttl", 300)} seconds`}
            />
            <SummaryCard
              icon={ShieldCheck}
              label="Moderation SLA"
              value={`${getAtPath(settings, "moderation.product_review_sla_hours", 48)} hrs`}
              hint={
                getAtPath(settings, "moderation.auto_publish_approved_products", true)
                  ? "Approved products auto-publish"
                  : "Publishing requires an extra step"
              }
            />
          </div>

          {dirty ? (
            <div className="mt-5 rounded-2xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-800">
              You have unsaved changes. Save settings to activate the revised platform policy.
            </div>
          ) : null}
        </div>

        {/* ------------------------------------------------------------------ */}
        {/* Section explainer map                                               */}
        {/* ------------------------------------------------------------------ */}
        {!loading ? (
          <div className="rounded-[24px] border border-[#D8F3DC] bg-white p-5 shadow-sm">
            <div className="mb-4 flex items-start gap-3">
              <div className="grid h-11 w-11 place-items-center rounded-2xl border border-[#B7E4C7] bg-[#F4FBF7] text-[#1B4332]">
                <Settings2 className="h-5 w-5" />
              </div>
              <div>
                <h3 className="text-lg font-semibold text-slate-900">What each section controls</h3>
                <p className="mt-1 text-sm leading-6 text-slate-600">
                  This guide makes the policy model easier to interpret before you change values.
                  Use it as a quick governance map for the whole marketplace.
                </p>
              </div>
            </div>

            <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
              {explainerCards.map((card) => (
                <SectionExplainerCard
                  key={card.title}
                  icon={card.icon}
                  title={card.title}
                  summary={card.summary}
                  enabledText={card.enabledText}
                />
              ))}
            </div>
          </div>
        ) : null}

        {loading ? (
          <div className="rounded-[24px] border border-[#D8F3DC] bg-white p-8 text-sm text-slate-500 shadow-sm">
            Loading system settings…
          </div>
        ) : null}

        {!loading ? (
          <div className="grid grid-cols-1 gap-6">
            {/* ---------------------------------------------------------------- */}
            {/* Platform Operations                                              */}
            {/* ---------------------------------------------------------------- */}
            <SectionCard
              icon={Wrench}
              title="Platform Operations"
              description="Control runtime behavior, maintenance posture, reporting defaults, and the core cache policy used by dashboards and listing views."
              policyNote="This section governs how the platform behaves operationally rather than how products or payments behave commercially."
              enabledCountText={`${countEnabled({
                maintenance: getAtPath(settings, "maintenance", false),
                read_only_mode: getAtPath(settings, "platform.read_only_mode", false),
              })} posture controls on`}
            >
              <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
                <NumberField
                  label="Cache TTL"
                  value={getAtPath(settings, "cache_ttl", 300)}
                  onChange={(value) => updateField("cache_ttl", value)}
                  hint="How long dashboard and listing responses may remain cached before a refresh."
                  min={30}
                  step={30}
                  suffix="sec"
                />
                <NumberField
                  label="Default report window"
                  value={getAtPath(settings, "platform.default_report_days", 90)}
                  onChange={(value) => updateField("platform.default_report_days", value)}
                  hint="Used when analytics and report views open without a chosen period."
                  min={7}
                  step={1}
                  suffix="days"
                />
                <NumberField
                  label="Report preview rows"
                  value={getAtPath(settings, "platform.report_preview_rows", 25)}
                  onChange={(value) => updateField("platform.report_preview_rows", value)}
                  hint="Determines how many rows preview modals should show before export."
                  min={5}
                  step={1}
                  suffix="rows"
                />
                <TextAreaField
                  label="Maintenance message"
                  value={getAtPath(settings, "platform.maintenance_message", "")}
                  onChange={(value) => updateField("platform.maintenance_message", value)}
                  hint="Administrative message displayed when maintenance status is active."
                  rows={3}
                />
              </div>

              <div className="mt-5 grid grid-cols-1 gap-4 md:grid-cols-2">
                <ToggleField
                  label="Maintenance mode"
                  checked={getAtPath(settings, "maintenance", false)}
                  onChange={(value) => updateField("maintenance", value)}
                  hint="Marks the platform as being under planned technical work."
                  impact="Use this for operational signaling and controlled maintenance communication."
                  onLabel="On"
                  offLabel="Off"
                />

                <ToggleField
                  label="Read-only mode"
                  checked={getAtPath(settings, "platform.read_only_mode", false)}
                  onChange={(value) => updateField("platform.read_only_mode", value)}
                  hint="Keeps the platform visible while preventing sensitive write-heavy actions where route-level rules enforce it."
                  impact="Best used during controlled change windows or reconciliation periods."
                  onLabel="Read-only"
                  offLabel="Writable"
                />
              </div>
            </SectionCard>

            {/* ---------------------------------------------------------------- */}
            {/* Marketplace Policy                                               */}
            {/* ---------------------------------------------------------------- */}
            <SectionCard
              icon={Store}
              title="Marketplace Policy"
              description="Set the commercial baseline for product presentation, pricing policy, inventory sensitivity, and buyer-trust features."
              policyNote="These controls shape the marketplace’s commercial language and discovery quality."
              enabledCountText={`${countEnabled({
                allow_ratings: getAtPath(settings, "marketplace.allow_ratings", true),
                allow_product_likes: getAtPath(settings, "marketplace.allow_product_likes", true),
              })} trust features on`}
            >
              <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
                <SelectField
                  label="Marketplace currency"
                  value={getAtPath(settings, "marketplace.currency_code", "NAD")}
                  onChange={(value) => updateField("marketplace.currency_code", value)}
                  options={[
                    { value: "NAD", label: "NAD — Namibian Dollar" },
                    { value: "USD", label: "USD — US Dollar" },
                    { value: "ZAR", label: "ZAR — South African Rand" },
                  ]}
                  hint="Primary commercial currency label used across pricing and reports."
                />
                <NumberField
                  label="VAT rate"
                  value={getAtPath(settings, "marketplace.vat_percent", 15)}
                  onChange={(value) => updateField("marketplace.vat_percent", value)}
                  hint="Default VAT percentage used by pricing and checkout estimates."
                  min={0}
                  step={0.5}
                  suffix="%"
                />
                <NumberField
                  label="Low-stock threshold"
                  value={getAtPath(settings, "marketplace.low_stock_threshold", 5)}
                  onChange={(value) => updateField("marketplace.low_stock_threshold", value)}
                  hint="Inventory at or below this value is treated as low stock in policy-aware surfaces."
                  min={0}
                  step={1}
                  suffix="units"
                />
                <NumberField
                  label="Featured products limit"
                  value={getAtPath(settings, "marketplace.featured_products_limit", 8)}
                  onChange={(value) => updateField("marketplace.featured_products_limit", value)}
                  hint="Maximum number of spotlighted products used in promotional surfaces."
                  min={1}
                  step={1}
                  suffix="items"
                />
              </div>

              <div className="mt-5 grid grid-cols-1 gap-4 md:grid-cols-2">
                <ToggleField
                  label="Customer ratings"
                  checked={getAtPath(settings, "marketplace.allow_ratings", true)}
                  onChange={(value) => updateField("marketplace.allow_ratings", value)}
                  hint="Enables buyer ratings and review-led trust signals."
                  impact="Turning this off removes a major trust cue from the buying journey."
                />

                <ToggleField
                  label="Product likes / interest signals"
                  checked={getAtPath(settings, "marketplace.allow_product_likes", true)}
                  onChange={(value) => updateField("marketplace.allow_product_likes", value)}
                  hint="Supports low-friction product interest tracking for discovery."
                  impact="Useful for merchandising, popularity indicators, and recommendation support."
                />
              </div>
            </SectionCard>

            {/* ---------------------------------------------------------------- */}
            {/* Checkout & Fulfilment                                            */}
            {/* ---------------------------------------------------------------- */}
            <SectionCard
              icon={Truck}
              title="Checkout & Fulfilment"
              description="Shape the operational checkout model for delivery, pickup, free-delivery incentives, and transaction constraints."
              policyNote="This section governs how orders move from basket to fulfilment."
              enabledCountText={`${countEnabled({
                allow_delivery: getAtPath(settings, "checkout.allow_delivery", true),
                allow_pickup: getAtPath(settings, "checkout.allow_pickup", true),
              })} fulfilment modes on`}
            >
              <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
                <NumberField
                  label="Auto-cancel unpaid orders"
                  value={getAtPath(settings, "checkout.auto_cancel_unpaid_hours", 24)}
                  onChange={(value) => updateField("checkout.auto_cancel_unpaid_hours", value)}
                  hint="Hours before unpaid orders may be treated as stale."
                  min={1}
                  step={1}
                  suffix="hrs"
                />
                <NumberField
                  label="Default delivery fee"
                  value={getAtPath(settings, "checkout.default_delivery_fee", 30)}
                  onChange={(value) => updateField("checkout.default_delivery_fee", value)}
                  hint="Fallback fee when no order-specific delivery fee has been set."
                  min={0}
                  step={0.5}
                  suffix={currencyCode}
                />
                <NumberField
                  label="Free-delivery threshold"
                  value={getAtPath(settings, "checkout.free_delivery_threshold", 500)}
                  onChange={(value) => updateField("checkout.free_delivery_threshold", value)}
                  hint="Order value at or above this threshold may qualify for free delivery by default."
                  min={0}
                  step={1}
                  suffix={currencyCode}
                />
                <NumberField
                  label="Maximum cart size"
                  value={getAtPath(settings, "checkout.max_cart_items", 50)}
                  onChange={(value) => updateField("checkout.max_cart_items", value)}
                  hint="Upper bound for cart quantity to control operational and UI extremes."
                  min={1}
                  step={1}
                  suffix="items"
                />
                <NumberField
                  label="Maximum order lines"
                  value={getAtPath(settings, "checkout.max_order_lines_per_checkout", 20)}
                  onChange={(value) => updateField("checkout.max_order_lines_per_checkout", value)}
                  hint="Maximum distinct line items permitted in a single checkout."
                  min={1}
                  step={1}
                  suffix="lines"
                />
              </div>

              <div className="mt-5 grid grid-cols-1 gap-4 md:grid-cols-2">
                <ToggleField
                  label="Delivery fulfilment"
                  checked={getAtPath(settings, "checkout.allow_delivery", true)}
                  onChange={(value) => updateField("checkout.allow_delivery", value)}
                  hint="Allows route-based or home-delivery order flows."
                  impact="Turning this off makes delivery-based checkout unavailable."
                />

                <ToggleField
                  label="Pickup fulfilment"
                  checked={getAtPath(settings, "checkout.allow_pickup", true)}
                  onChange={(value) => updateField("checkout.allow_pickup", value)}
                  hint="Allows customer pickup as an alternative fulfilment pathway."
                  impact="Useful where collection is operationally easier than delivery."
                />
              </div>
            </SectionCard>

            {/* ---------------------------------------------------------------- */}
            {/* Payments & Risk Controls                                         */}
            {/* ---------------------------------------------------------------- */}
            <SectionCard
              icon={CreditCard}
              title="Payments & Risk Controls"
              description="Configure accepted payment modes, proof-of-payment governance, and thresholds that may require manual review."
              policyNote="These settings manage transaction acceptance, evidence requirements, and financial risk posture."
              enabledCountText={`${countEnabled(getAtPath(settings, "payments", {}))} policy flags on`}
            >
              <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
                <NumberField
                  label="Maximum proof upload size"
                  value={getAtPath(settings, "payments.max_payment_proof_mb", 5)}
                  onChange={(value) => updateField("payments.max_payment_proof_mb", value)}
                  hint="Maximum allowed file size for payment evidence uploads."
                  min={1}
                  step={1}
                  suffix="MB"
                />
                <NumberField
                  label="Manual review threshold"
                  value={getAtPath(settings, "payments.manual_review_threshold_nad", 1500)}
                  onChange={(value) => updateField("payments.manual_review_threshold_nad", value)}
                  hint="Transactions above this value may require administrative review."
                  min={0}
                  step={10}
                  suffix={currencyCode}
                />
              </div>

              <div className="mt-5 grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
                <ToggleField
                  label="EFT / bank transfer"
                  checked={getAtPath(settings, "payments.eft_enabled", true)}
                  onChange={(value) => updateField("payments.eft_enabled", value)}
                  hint="Controls whether bank-transfer checkout is available."
                  impact="Important when EFT settlement and proof review workflows are active."
                />

                <ToggleField
                  label="Cash on delivery"
                  checked={getAtPath(settings, "payments.cash_on_delivery_enabled", false)}
                  onChange={(value) => updateField("payments.cash_on_delivery_enabled", value)}
                  hint="Allows payment at fulfilment rather than before dispatch."
                  impact="Enable only where delivery and reconciliation controls are strong."
                />

                <ToggleField
                  label="Manual payment review"
                  checked={getAtPath(settings, "payments.manual_review_enabled", true)}
                  onChange={(value) => updateField("payments.manual_review_enabled", value)}
                  hint="Allows exceptions to be examined before final acceptance."
                  impact="Useful for high-value, suspicious, or policy-sensitive payments."
                />

                <ToggleField
                  label="Proof of payment required for EFT"
                  checked={getAtPath(settings, "payments.proof_of_payment_required_for_eft", true)}
                  onChange={(value) => updateField("payments.proof_of_payment_required_for_eft", value)}
                  hint="Requires payment evidence for transfer-based payments."
                  impact="Improves financial traceability for bank-transfer workflows."
                />
              </div>
            </SectionCard>

            {/* ---------------------------------------------------------------- */}
            {/* Communications & Notifications                                   */}
            {/* ---------------------------------------------------------------- */}
            <SectionCard
              icon={Bell}
              title="Communications & Notifications"
              description="Coordinate buyer and seller messaging across in-app, email, SMS, and administrative broadcast channels."
              policyNote="This section governs who can be reached and through which operational channels."
              enabledCountText={`${enabledComms} communication toggles on`}
            >
              <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
                <ToggleField
                  label="In-app notifications"
                  checked={getAtPath(settings, "communications.in_app_notifications_enabled", true)}
                  onChange={(value) => updateField("communications.in_app_notifications_enabled", value)}
                  hint="Supports dashboard-native alerts and workflow reminders."
                  impact="Keeps users informed without requiring email or SMS."
                />

                <ToggleField
                  label="Email notifications"
                  checked={getAtPath(settings, "communications.email_notifications_enabled", true)}
                  onChange={(value) => updateField("communications.email_notifications_enabled", value)}
                  hint="Controls operational and transactional email delivery."
                  impact="Important for longer-form communication and archived message trails."
                />

                <ToggleField
                  label="SMS notifications"
                  checked={getAtPath(settings, "communications.sms_notifications_enabled", true)}
                  onChange={(value) => updateField("communications.sms_notifications_enabled", value)}
                  hint="Supports compact high-urgency updates where SMS is available."
                  impact="Best for short, time-sensitive operational alerts."
                />

                <ToggleField
                  label="Broadcast email"
                  checked={getAtPath(settings, "communications.broadcast_email_enabled", true)}
                  onChange={(value) => updateField("communications.broadcast_email_enabled", value)}
                  hint="Allows the admin broadcast workspace to use email as a channel."
                  impact="Useful for policy notices, service updates, and structured announcements."
                />

                <ToggleField
                  label="Broadcast SMS"
                  checked={getAtPath(settings, "communications.broadcast_sms_enabled", true)}
                  onChange={(value) => updateField("communications.broadcast_sms_enabled", value)}
                  hint="Allows the admin broadcast workspace to use SMS as a channel."
                  impact="Use for short operational notices where immediacy matters."
                />
              </div>
            </SectionCard>

            {/* ---------------------------------------------------------------- */}
            {/* Moderation & Trust Governance                                    */}
            {/* ---------------------------------------------------------------- */}
            <SectionCard
              icon={ShieldCheck}
              title="Moderation & Trust Governance"
              description="Formalise catalogue trust controls, service expectations, and publication safeguards to keep marketplace quality high."
              policyNote="These rules determine how strict or lightweight product governance should be."
              enabledCountText={`${enabledModeration} moderation safeguards on`}
            >
              <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
                <NumberField
                  label="Product review SLA"
                  value={getAtPath(settings, "moderation.product_review_sla_hours", 48)}
                  onChange={(value) => updateField("moderation.product_review_sla_hours", value)}
                  hint="Target turnaround time for product moderation decisions."
                  min={1}
                  step={1}
                  suffix="hrs"
                />
              </div>

              <div className="mt-5 grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
                <ToggleField
                  label="Auto-publish approved products"
                  checked={getAtPath(settings, "moderation.auto_publish_approved_products", true)}
                  onChange={(value) => updateField("moderation.auto_publish_approved_products", value)}
                  hint="Publishes approved products without a second manual publish step."
                  impact="Improves speed, but reduces a final manual checkpoint."
                />

                <ToggleField
                  label="Require rejection reason"
                  checked={getAtPath(settings, "moderation.require_rejection_reason", true)}
                  onChange={(value) => updateField("moderation.require_rejection_reason", value)}
                  hint="Requires a reason when a product is rejected."
                  impact="Improves transparency, fairness, and farmer feedback quality."
                />

                <ToggleField
                  label="Flag duplicate product submissions"
                  checked={getAtPath(settings, "moderation.flag_duplicate_products", true)}
                  onChange={(value) => updateField("moderation.flag_duplicate_products", value)}
                  hint="Helps identify duplicate or repeated catalogue submissions."
                  impact="Supports moderation efficiency and catalogue integrity."
                />
              </div>
            </SectionCard>

            {/* ---------------------------------------------------------------- */}
            {/* Analytics & Intelligence                                         */}
            {/* ---------------------------------------------------------------- */}
            <SectionCard
              icon={Brain}
              title="Analytics & Intelligence"
              description="Decide whether AI-assisted insights, search analytics, market trends, and ranking widgets should remain active."
              policyNote="This section governs decision-support visibility rather than core commerce processing."
              enabledCountText={`${enabledAnalytics} intelligence controls on`}
            >
              <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
                <ToggleField
                  label="AI insights"
                  checked={getAtPath(settings, "analytics.ai_insights_enabled", true)}
                  onChange={(value) => updateField("analytics.ai_insights_enabled", value)}
                  hint="Enables insight surfaces derived from predictive and analytical models."
                  impact="Useful where farmers and admins rely on decision-support cues."
                />

                <ToggleField
                  label="Low-stock alerts"
                  checked={getAtPath(settings, "analytics.low_stock_alerts_enabled", true)}
                  onChange={(value) => updateField("analytics.low_stock_alerts_enabled", value)}
                  hint="Highlights products that may require replenishment attention."
                  impact="Supports proactive inventory management."
                />

                <ToggleField
                  label="Search analytics"
                  checked={getAtPath(settings, "analytics.search_analytics_enabled", true)}
                  onChange={(value) => updateField("analytics.search_analytics_enabled", value)}
                  hint="Supports product-search reporting and discovery intelligence."
                  impact="Useful for merchandising and demand interpretation."
                />

                <ToggleField
                  label="Market trends"
                  checked={getAtPath(settings, "analytics.market_trends_enabled", true)}
                  onChange={(value) => updateField("analytics.market_trends_enabled", value)}
                  hint="Controls demand and price-trend visualisations."
                  impact="Helps admins and farmers interpret directional market movement."
                />

                <ToggleField
                  label="Ranking widgets"
                  checked={getAtPath(settings, "analytics.ranking_widgets_enabled", true)}
                  onChange={(value) => updateField("analytics.ranking_widgets_enabled", value)}
                  hint="Keeps leaderboard-style or ranking summary widgets visible."
                  impact="Useful for comparative reporting and highlight surfaces."
                />
              </div>
            </SectionCard>

            {/* ---------------------------------------------------------------- */}
            {/* Search & Discovery                                               */}
            {/* ---------------------------------------------------------------- */}
            <SectionCard
              icon={Search}
              title="Search & Discovery"
              description="Tune the discovery layer that supports search, autocomplete, trending queries, and data retention for behavioural insight."
              policyNote="These settings shape how easily users find products and how much discovery data the platform retains."
              enabledCountText={`${enabledSearch} discovery tools on`}
            >
              <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
                <NumberField
                  label="Search history retention"
                  value={getAtPath(settings, "search.search_history_retention_days", 90)}
                  onChange={(value) => updateField("search.search_history_retention_days", value)}
                  hint="Retention period for search-behaviour analysis."
                  min={7}
                  step={1}
                  suffix="days"
                />
                <NumberField
                  label="Search suggestions limit"
                  value={getAtPath(settings, "search.search_suggestions_limit", 8)}
                  onChange={(value) => updateField("search.search_suggestions_limit", value)}
                  hint="Maximum suggestions shown during assisted search."
                  min={1}
                  step={1}
                  suffix="items"
                />
              </div>

              <div className="mt-5 grid grid-cols-1 gap-4 md:grid-cols-2">
                <ToggleField
                  label="Autocomplete"
                  checked={getAtPath(settings, "search.autocomplete_enabled", true)}
                  onChange={(value) => updateField("search.autocomplete_enabled", value)}
                  hint="Provides assisted query completion while users type."
                  impact="Improves usability and reduces search friction."
                />

                <ToggleField
                  label="Trending searches"
                  checked={getAtPath(settings, "search.trending_searches_enabled", true)}
                  onChange={(value) => updateField("search.trending_searches_enabled", value)}
                  hint="Allows the platform to surface trending queries or popular search intent."
                  impact="Useful for discovery, campaign curation, and demand signaling."
                />
              </div>
            </SectionCard>

            {/* ---------------------------------------------------------------- */}
            {/* Governance notes                                                 */}
            {/* ---------------------------------------------------------------- */}
            <div className="rounded-[24px] border border-[#D8F3DC] bg-white p-5 shadow-sm">
              <div className="flex items-start gap-3">
                <div className="grid h-11 w-11 place-items-center rounded-2xl border border-[#B7E4C7] bg-[#F4FBF7] text-[#1B4332]">
                  <Settings2 className="h-5 w-5" />
                </div>
                <div>
                  <h3 className="text-lg font-semibold text-slate-900">Configuration Notes</h3>
                  <p className="mt-1 text-sm leading-6 text-slate-600">
                    These controls are meaningful because the platform already works against real
                    operational domains including orders, payments, notifications, moderation,
                    search behavior, reporting, and audit activity. Treat this page as policy
                    governance, not as a cosmetic settings form.
                  </p>
                </div>
              </div>
            </div>
          </div>
        ) : null}
      </div>
    </AdminLayout>
  );
}