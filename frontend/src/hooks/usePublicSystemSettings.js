// ============================================================================
// src/hooks/usePublicSystemSettings.js
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Shared public system settings hook used by customer/farmer/admin frontend
//   surfaces that must respect marketplace-wide operational policy.
//
// WHY THIS EXISTS:
//   • Prevents repeated ad-hoc fetch logic for /admin/settings/public
//   • Gives customer/farmer surfaces one consistent interpretation of:
//       - maintenance posture
//       - read-only mode
//       - checkout policy
//       - communications policy
//       - analytics visibility
//       - search/autocomplete policy
//   • Keeps a safe frontend fallback when the public settings endpoint is not
//     reachable.
// ============================================================================

import { useCallback, useEffect, useMemo, useState } from "react";
import api from "../api";

export const DEFAULT_PUBLIC_SYSTEM_SETTINGS = {
  version: "-",
  maintenance: false,
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
    default_delivery_fee: 30,
    free_delivery_threshold: 500,
    max_cart_items: 50,
    max_order_lines_per_checkout: 20,
  },
  payments: {
    eft_enabled: true,
    cash_on_delivery_enabled: false,
    proof_of_payment_required_for_eft: true,
    max_payment_proof_mb: 5,
    manual_review_enabled: true,
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

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export function mergePublicSystemSettings(raw = {}) {
  return {
    ...DEFAULT_PUBLIC_SYSTEM_SETTINGS,
    ...(raw || {}),
    platform: {
      ...DEFAULT_PUBLIC_SYSTEM_SETTINGS.platform,
      ...(raw?.platform || {}),
    },
    marketplace: {
      ...DEFAULT_PUBLIC_SYSTEM_SETTINGS.marketplace,
      ...(raw?.marketplace || {}),
    },
    checkout: {
      ...DEFAULT_PUBLIC_SYSTEM_SETTINGS.checkout,
      ...(raw?.checkout || {}),
    },
    payments: {
      ...DEFAULT_PUBLIC_SYSTEM_SETTINGS.payments,
      ...(raw?.payments || {}),
    },
    communications: {
      ...DEFAULT_PUBLIC_SYSTEM_SETTINGS.communications,
      ...(raw?.communications || {}),
    },
    moderation: {
      ...DEFAULT_PUBLIC_SYSTEM_SETTINGS.moderation,
      ...(raw?.moderation || {}),
    },
    analytics: {
      ...DEFAULT_PUBLIC_SYSTEM_SETTINGS.analytics,
      ...(raw?.analytics || {}),
    },
    search: {
      ...DEFAULT_PUBLIC_SYSTEM_SETTINGS.search,
      ...(raw?.search || {}),
    },
  };
}

export default function usePublicSystemSettings(options = {}) {
  const {
    autoLoad = true,
    initialSettings = DEFAULT_PUBLIC_SYSTEM_SETTINGS,
  } = isPlainObject(options) ? options : {};

  const [settings, setSettings] = useState(() => mergePublicSystemSettings(initialSettings));
  const [loading, setLoading] = useState(Boolean(autoLoad));
  const [error, setError] = useState("");

  const refresh = useCallback(async () => {
    setLoading(true);
    setError("");

    try {
      const res = await api.get("/admin/settings/public", { skipAuth: true });
      const payload = res?.data?.data ?? res?.data ?? {};
      const merged = mergePublicSystemSettings(payload);
      setSettings(merged);
      return merged;
    } catch (err) {
      const fallback = mergePublicSystemSettings(initialSettings);
      setSettings(fallback);
      setError(
        err?.response?.data?.message ||
          err?.message ||
          "Could not load public system settings."
      );
      return fallback;
    } finally {
      setLoading(false);
    }
  }, [initialSettings]);

  useEffect(() => {
    if (!autoLoad) {
      setLoading(false);
      return;
    }
    refresh();
  }, [autoLoad, refresh]);

  const helpers = useMemo(() => {
    const communications = settings?.communications || {};
    const analytics = settings?.analytics || {};
    const search = settings?.search || {};
    const checkout = settings?.checkout || {};
    const platform = settings?.platform || {};

    return {
      notificationsEnabled: Boolean(communications?.in_app_notifications_enabled),
      emailNotificationsEnabled: Boolean(communications?.email_notifications_enabled),
      smsNotificationsEnabled: Boolean(communications?.sms_notifications_enabled),
      broadcastEmailEnabled: Boolean(communications?.broadcast_email_enabled),
      broadcastSmsEnabled: Boolean(communications?.broadcast_sms_enabled),
      autocompleteEnabled: Boolean(search?.autocomplete_enabled),
      trendingSearchesEnabled: Boolean(search?.trending_searches_enabled),
      aiInsightsEnabled: Boolean(analytics?.ai_insights_enabled),
      lowStockAlertsEnabled: Boolean(analytics?.low_stock_alerts_enabled),
      searchAnalyticsEnabled: Boolean(analytics?.search_analytics_enabled),
      marketTrendsEnabled: Boolean(analytics?.market_trends_enabled),
      rankingWidgetsEnabled: Boolean(analytics?.ranking_widgets_enabled),
      deliveryEnabled: Boolean(checkout?.allow_delivery),
      pickupEnabled: Boolean(checkout?.allow_pickup),
      maintenanceEnabled: Boolean(settings?.maintenance),
      readOnlyMode: Boolean(platform?.read_only_mode),
      maintenanceMessage:
        String(platform?.maintenance_message || "").trim() ||
        DEFAULT_PUBLIC_SYSTEM_SETTINGS.platform.maintenance_message,
      suggestionLimit: Number(search?.search_suggestions_limit) > 0
        ? Number(search.search_suggestions_limit)
        : DEFAULT_PUBLIC_SYSTEM_SETTINGS.search.search_suggestions_limit,
    };
  }, [settings]);

  return {
    settings,
    setSettings,
    loading,
    error,
    refresh,
    helpers,
  };
}