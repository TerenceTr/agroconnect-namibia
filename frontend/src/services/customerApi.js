// ============================================================================
// frontend/src/services/customerApi.js
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Customer-facing API service layer for marketplace, profile, orders,
//   checkout, likes, ratings, leaderboards, reviewable items,
//   and public homepage content.
//
// THIS VERSION IMPROVES:
//   ✅ Keeps existing service coverage used by the app
//   ✅ Adds missing fetchReviewableOrderItems export for CustomerDashboard
//   ✅ Adds stronger normalization for public homepage payloads
//   ✅ Tries /products/homepage first
//   ✅ Falls back to /products and derives homepage sections client-side
//   ✅ Preserves backward-compatible exports already used elsewhere
//   ✅ Keeps defensive normalization for order, payment, and rating data
//   ✅ Makes checkout payment-method aware for EFT vs cash on delivery
//   ✅ Prevents initial checkout from sending proof/reference too early
//   ✅ Rejects cash proof uploads on the client before the request is sent
//   ✅ Adds safer endpoint fallbacks for profile, likes, ratings, orders,
//      and leaderboard calls
//
// IMPORTANT:
//   - Frontend-only update
//   - No backend / USSD logic is touched here
//   - Designed to work even before /api/products/homepage is fully live
// ============================================================================

import api from '../api';

const NEW_PRODUCTS_WINDOW_DAYS = 7;
const DEFAULT_NEW_PRODUCTS_LIMIT = 24;
const DEFAULT_HOMEPAGE_PRODUCT_LIMIT = 120;
const DEFAULT_HOMEPAGE_TOP_PRODUCTS_LIMIT = 10;
const DEFAULT_HOMEPAGE_TOP_FARMERS_LIMIT = 8;
const DEFAULT_HOMEPAGE_FEATURED_LIMIT = 6;

// ----------------------------------------------------------------------------
// Generic numeric helpers
// ----------------------------------------------------------------------------
function toNumber(value, fallback = 0) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function toPositiveInt(value, fallback = 1) {
  const n = Math.floor(toNumber(value, fallback));
  return n > 0 ? n : fallback;
}

function toPositiveNumber(value, fallback = 0) {
  const n = Number(value);
  return Number.isFinite(n) && n >= 0 ? n : fallback;
}

function uniqueStrings(values = []) {
  return Array.from(
    new Set(
      values
        .map((value) => String(value ?? '').trim())
        .filter(Boolean)
    )
  );
}

// ----------------------------------------------------------------------------
// Generic payload / envelope helpers
// ----------------------------------------------------------------------------
function unwrapApiDataEnvelope(raw) {
  if (raw == null) return raw;
  if (Array.isArray(raw)) return raw;
  if (typeof raw !== 'object') return raw;

  if (Object.prototype.hasOwnProperty.call(raw, 'data') && raw.data != null) {
    return raw.data;
  }

  return raw;
}

function extractData(response) {
  const first = response?.data ?? response;
  return unwrapApiDataEnvelope(first);
}

function asArray(data) {
  const payload = unwrapApiDataEnvelope(data);

  if (Array.isArray(payload)) return payload;
  if (Array.isArray(payload?.items)) return payload.items;
  if (Array.isArray(payload?.data)) return payload.data;
  if (Array.isArray(payload?.results)) return payload.results;
  if (Array.isArray(payload?.rows)) return payload.rows;
  if (Array.isArray(payload?.products)) return payload.products;
  if (Array.isArray(payload?.orders)) return payload.orders;
  if (Array.isArray(payload?.likes)) return payload.likes;
  if (Array.isArray(payload?.ratings)) return payload.ratings;
  if (Array.isArray(payload?.leaderboard)) return payload.leaderboard;
  if (Array.isArray(payload?.farmers)) return payload.farmers;
  if (Array.isArray(payload?.farmer_ranking)) return payload.farmer_ranking;
  if (Array.isArray(payload?.featured_products)) return payload.featured_products;
  if (Array.isArray(payload?.top_products)) return payload.top_products;
  if (Array.isArray(payload?.top_farmers)) return payload.top_farmers;
  if (Array.isArray(payload?.categories)) return payload.categories;

  return [];
}

function normalizeError(error, fallback = 'Request failed.') {
  const message =
    error?.response?.data?.message ||
    error?.response?.data?.error ||
    error?.message ||
    fallback;

  const e = new Error(message);
  e.cause = error;
  e.status = error?.response?.status ?? null;
  e.payload = error?.response?.data ?? null;
  return e;
}

// ----------------------------------------------------------------------------
// Product date / freshness helpers
// ----------------------------------------------------------------------------
function getCreatedAtMs(raw = {}) {
  const value =
    raw?.created_at ??
    raw?.createdAt ??
    raw?.posted_at ??
    raw?.published_at ??
    raw?.date_created ??
    null;

  if (!value) return null;

  const ms = new Date(value).getTime();
  return Number.isFinite(ms) ? ms : null;
}

function sortProductsNewestFirst(rows = []) {
  return [...rows].sort((a, b) => {
    const aMs = getCreatedAtMs(a) ?? 0;
    const bMs = getCreatedAtMs(b) ?? 0;
    return bMs - aMs;
  });
}

function isProductWithinDays(raw = {}, days = NEW_PRODUCTS_WINDOW_DAYS) {
  const createdAtMs = getCreatedAtMs(raw);
  if (!createdAtMs) return false;

  const safeDays = Math.max(1, toPositiveInt(days, NEW_PRODUCTS_WINDOW_DAYS));
  const ageMs = Date.now() - createdAtMs;
  const windowMs = safeDays * 24 * 60 * 60 * 1000;

  return ageMs >= 0 && ageMs <= windowMs;
}

function filterProductsCreatedWithinDays(rows = [], days = NEW_PRODUCTS_WINDOW_DAYS) {
  return sortProductsNewestFirst(rows).filter((row) => isProductWithinDays(row, days));
}

// ----------------------------------------------------------------------------
// Product normalization helpers
// ----------------------------------------------------------------------------
function isCustomerVisibleStatus(status) {
  const s = String(status ?? '').trim().toLowerCase();
  return ['available', 'approved', 'active', 'published'].includes(s);
}

function normalizeProduct(raw = {}) {
  const productId = raw.product_id ?? raw.id ?? raw.uuid ?? raw.productId ?? null;
  const price = toNumber(raw.price ?? raw.unit_price ?? 0, 0);
  const stock = toNumber(raw.stock_quantity ?? raw.stock ?? raw.quantity ?? 0, 0);

  const images = [
    raw.image_url,
    raw.imageUrl,
    raw.image,
    raw.photo_url,
    raw.thumbnail,
    ...(Array.isArray(raw.images) ? raw.images : []),
  ].filter(Boolean);

  return {
    ...raw,
    product_id: productId,
    id: productId ?? raw.id ?? null,
    name: raw.name ?? raw.product_name ?? 'Unnamed Product',
    product_name: raw.product_name ?? raw.name ?? 'Unnamed Product',
    category: raw.category ?? raw.product_category ?? 'Other',
    price,
    unit_price: price,
    stock_quantity: stock,
    stock,
    quantity: stock,
    farmer_id: raw.farmer_id ?? raw.seller_id ?? raw.farmer?.id ?? raw.user_id ?? null,
    farmer_name: raw.farmer_name ?? raw.seller_name ?? raw.farmer?.name ?? 'Farmer',
    location:
      raw.location ??
      raw.region ??
      raw.city ??
      raw.town ??
      raw.farmer_location ??
      raw.farmer?.location ??
      '',
    image_url: images[0] ?? null,
    image_candidates: images,
    status: raw.status ?? raw.product_status ?? 'available',
    avg_rating: toNumber(raw.avg_rating ?? raw.rating_avg ?? raw.average_rating ?? 0, 0),
    rating_count: Math.max(
      0,
      Math.round(toNumber(raw.rating_count ?? raw.ratings_count ?? raw.total_ratings ?? 0, 0))
    ),
    orders_count: Math.max(
      0,
      Math.round(toNumber(raw.orders_count ?? raw.order_count ?? raw.sales_count ?? 0, 0))
    ),
    order_count: Math.max(
      0,
      Math.round(toNumber(raw.order_count ?? raw.orders_count ?? raw.sales_count ?? 0, 0))
    ),
  };
}

function filterCustomerVisibleProducts(rows = []) {
  return rows
    .map(normalizeProduct)
    .filter((normalized) => {
      const stock = toNumber(
        normalized.stock_quantity ?? normalized.stock ?? normalized.quantity ?? 0,
        0
      );
      return isCustomerVisibleStatus(normalized.status) && stock > 0;
    });
}

// ----------------------------------------------------------------------------
// Homepage normalization helpers
// ----------------------------------------------------------------------------
function normalizeHomepageCategory(raw = {}) {
  return {
    ...raw,
    category: String(raw?.category ?? raw?.name ?? 'Other').trim() || 'Other',
    count: Math.max(0, Math.round(toNumber(raw?.count ?? raw?.product_count ?? 0, 0))),
    product_count: Math.max(0, Math.round(toNumber(raw?.product_count ?? raw?.count ?? 0, 0))),
    image_url: raw?.image_url ?? raw?.imageUrl ?? null,
    preview_names: uniqueStrings(raw?.preview_names ?? raw?.top_product_names ?? []),
    tagline:
      raw?.tagline ??
      `Explore ${String(raw?.category ?? raw?.name ?? 'other').toLowerCase()} available in the AgroConnect marketplace.`,
  };
}

function normalizeHomepageFarmer(raw = {}) {
  const featuredCategories = uniqueStrings(
    raw?.featured_categories ?? raw?.top_categories ?? raw?.category_names ?? []
  );
  const topProductNames = uniqueStrings(raw?.top_product_names ?? raw?.preview_names ?? []);

  const totalOrders = Math.max(
    0,
    Math.round(
      toNumber(
        raw?.orders_count ?? raw?.order_count ?? raw?.sales_count ?? raw?.completed_orders ?? 0,
        0
      )
    )
  );

  const rating = toPositiveNumber(
    raw?.avg_rating ?? raw?.rating_avg ?? raw?.average_rating ?? raw?.rating ?? 0,
    0
  );

  return {
    ...raw,
    farmer_id: raw?.farmer_id ?? raw?.user_id ?? raw?.id ?? null,
    id: raw?.id ?? raw?.farmer_id ?? raw?.user_id ?? null,
    farmer_name: raw?.farmer_name ?? raw?.name ?? raw?.full_name ?? 'Farmer',
    full_name: raw?.full_name ?? raw?.farmer_name ?? raw?.name ?? 'Farmer',
    location: raw?.location ?? raw?.region ?? raw?.city ?? raw?.town ?? '',
    image_url: raw?.image_url ?? raw?.avatar_url ?? raw?.profile_image_url ?? null,
    avatar_url: raw?.avatar_url ?? raw?.image_url ?? raw?.profile_image_url ?? null,
    avg_rating: rating,
    rating,
    rating_count: Math.max(
      0,
      Math.round(toNumber(raw?.rating_count ?? raw?.ratings_count ?? raw?.total_ratings ?? 0, 0))
    ),
    orders_count: totalOrders,
    order_count: totalOrders,
    sales_count: totalOrders,
    product_count: Math.max(
      0,
      Math.round(toNumber(raw?.product_count ?? raw?.products_count ?? raw?.listing_count ?? 0, 0))
    ),
    revenue_total: toPositiveNumber(raw?.revenue_total ?? raw?.total_revenue ?? 0, 0),
    featured_categories: featuredCategories,
    top_categories: featuredCategories,
    top_product_names: topProductNames,
    preview_names: topProductNames,
    bio:
      raw?.bio ??
      raw?.about ??
      (featuredCategories.length
        ? `Known for ${featuredCategories.slice(0, 3).join(', ')}.`
        : 'Supplying fresh produce through AgroConnect.'),
  };
}

function buildHomepageCategoriesFromProducts(products = [], limit = 8) {
  const bucket = new Map();

  products.forEach((product) => {
    const normalized = normalizeProduct(product);
    const category = String(normalized.category ?? 'Other').trim() || 'Other';

    if (!bucket.has(category)) {
      bucket.set(category, {
        category,
        count: 0,
        image_url: normalized.image_url ?? null,
        preview_names: [],
      });
    }

    const entry = bucket.get(category);
    entry.count += 1;

    if (!entry.image_url && normalized.image_url) {
      entry.image_url = normalized.image_url;
    }

    if (entry.preview_names.length < 3 && normalized.name) {
      entry.preview_names.push(normalized.name);
    }
  });

  return Array.from(bucket.values())
    .map((entry) => normalizeHomepageCategory(entry))
    .sort((a, b) => (b.count ?? 0) - (a.count ?? 0) || a.category.localeCompare(b.category))
    .slice(0, toPositiveInt(limit, 8));
}

function buildFeaturedProducts(products = [], limit = DEFAULT_HOMEPAGE_FEATURED_LIMIT) {
  return [...products]
    .map(normalizeProduct)
    .sort((a, b) => {
      const bScore =
        toNumber(b.orders_count ?? b.order_count ?? 0, 0) * 3 +
        toNumber(b.avg_rating ?? 0, 0) * 2 +
        (getCreatedAtMs(b) ?? 0) / 1_000_000_000_000;

      const aScore =
        toNumber(a.orders_count ?? a.order_count ?? 0, 0) * 3 +
        toNumber(a.avg_rating ?? 0, 0) * 2 +
        (getCreatedAtMs(a) ?? 0) / 1_000_000_000_000;

      return bScore - aScore;
    })
    .slice(0, toPositiveInt(limit, DEFAULT_HOMEPAGE_FEATURED_LIMIT));
}

function buildTopProducts(products = [], limit = DEFAULT_HOMEPAGE_TOP_PRODUCTS_LIMIT) {
  return [...products]
    .map(normalizeProduct)
    .sort((a, b) => {
      const byOrders =
        toNumber(b.orders_count ?? b.order_count ?? 0, 0) -
        toNumber(a.orders_count ?? a.order_count ?? 0, 0);
      if (byOrders !== 0) return byOrders;

      const byRating = toNumber(b.avg_rating ?? 0, 0) - toNumber(a.avg_rating ?? 0, 0);
      if (byRating !== 0) return byRating;

      return (getCreatedAtMs(b) ?? 0) - (getCreatedAtMs(a) ?? 0);
    })
    .slice(0, toPositiveInt(limit, DEFAULT_HOMEPAGE_TOP_PRODUCTS_LIMIT));
}

function buildTopFarmers(products = [], limit = DEFAULT_HOMEPAGE_TOP_FARMERS_LIMIT) {
  const bucket = new Map();

  products.forEach((product) => {
    const normalized = normalizeProduct(product);
    const farmerId = normalized.farmer_id ?? normalized.user_id ?? normalized.id;
    if (!farmerId) return;

    if (!bucket.has(farmerId)) {
      bucket.set(farmerId, {
        farmer_id: farmerId,
        farmer_name: normalized.farmer_name ?? 'Farmer',
        full_name: normalized.farmer_name ?? 'Farmer',
        location: normalized.location ?? '',
        image_url: normalized.avatar_url ?? null,
        avg_rating: 0,
        rating_count: 0,
        orders_count: 0,
        product_count: 0,
        categories: new Set(),
        productNames: [],
      });
    }

    const entry = bucket.get(farmerId);
    entry.product_count += 1;
    entry.orders_count += Math.max(
      0,
      Math.round(toNumber(normalized.orders_count ?? normalized.order_count ?? 0, 0))
    );
    entry.avg_rating += toNumber(normalized.avg_rating ?? 0, 0);
    entry.rating_count += Math.max(0, Math.round(toNumber(normalized.rating_count ?? 0, 0)));

    if (normalized.category) entry.categories.add(normalized.category);
    if (normalized.name && entry.productNames.length < 4) {
      entry.productNames.push(normalized.name);
    }
    if (!entry.image_url && normalized.image_url) {
      entry.image_url = normalized.image_url;
    }
  });

  return Array.from(bucket.values())
    .map((entry) =>
      normalizeHomepageFarmer({
        ...entry,
        avg_rating: entry.product_count > 0 ? entry.avg_rating / entry.product_count : 0,
        featured_categories: Array.from(entry.categories),
        top_product_names: entry.productNames,
      })
    )
    .sort((a, b) => {
      const byOrders = toNumber(b.orders_count ?? 0, 0) - toNumber(a.orders_count ?? 0, 0);
      if (byOrders !== 0) return byOrders;
      return toNumber(b.avg_rating ?? 0, 0) - toNumber(a.avg_rating ?? 0, 0);
    })
    .slice(0, toPositiveInt(limit, DEFAULT_HOMEPAGE_TOP_FARMERS_LIMIT));
}

function normalizeHomepagePayload(raw = {}, fallbackProducts = []) {
  const payload = unwrapApiDataEnvelope(raw) ?? {};
  const visibleFallbackProducts = filterCustomerVisibleProducts(fallbackProducts);

  const categoriesSource = asArray(payload.categories);
  const featuredSource = asArray(payload.featured_products);
  const topProductsSource = asArray(payload.top_products);
  const topFarmersSource = asArray(payload.top_farmers);
  const latestSource = asArray(payload.latest_products);
  const productsSource = asArray(payload.products);

  const featured_products = (featuredSource.length
    ? featuredSource
    : buildFeaturedProducts(visibleFallbackProducts, DEFAULT_HOMEPAGE_FEATURED_LIMIT)
  ).map(normalizeProduct);

  const top_products = (topProductsSource.length
    ? topProductsSource
    : buildTopProducts(visibleFallbackProducts, DEFAULT_HOMEPAGE_TOP_PRODUCTS_LIMIT)
  ).map(normalizeProduct);

  const latest_products = (latestSource.length
    ? latestSource
    : filterProductsCreatedWithinDays(visibleFallbackProducts, NEW_PRODUCTS_WINDOW_DAYS).slice(
        0,
        DEFAULT_NEW_PRODUCTS_LIMIT
      )
  ).map(normalizeProduct);

  const top_farmers = (topFarmersSource.length
    ? topFarmersSource
    : buildTopFarmers(visibleFallbackProducts, DEFAULT_HOMEPAGE_TOP_FARMERS_LIMIT)
  ).map(normalizeHomepageFarmer);

  const categories = (categoriesSource.length
    ? categoriesSource
    : buildHomepageCategoriesFromProducts(visibleFallbackProducts, 8)
  ).map(normalizeHomepageCategory);

  const normalizedProducts = (productsSource.length ? productsSource : visibleFallbackProducts).map(
    normalizeProduct
  );

  return {
    ...payload,
    categories,
    featured_products,
    top_products,
    latest_products,
    top_farmers,
    products: normalizedProducts,
    meta: {
      ...(payload.meta ?? {}),
      source:
        payload?.meta?.source ?? (categoriesSource.length || featuredSource.length ? 'homepage' : 'fallback'),
      counts: {
        categories: categories.length,
        featured_products: featured_products.length,
        top_products: top_products.length,
        latest_products: latest_products.length,
        top_farmers: top_farmers.length,
      },
    },
  };
}

// ----------------------------------------------------------------------------
// Rating normalization helpers
// ----------------------------------------------------------------------------
function normalizeRating(raw = {}) {
  return {
    ...raw,
    rating_id: raw.rating_id ?? raw.id ?? null,
    id: raw.id ?? raw.rating_id ?? null,
    score: Math.max(
      0,
      Math.min(5, toNumber(raw.score ?? raw.rating ?? raw.rating_score ?? 0, 0))
    ),
    rating_score: Math.max(
      0,
      Math.min(5, toNumber(raw.rating_score ?? raw.score ?? raw.rating ?? 0, 0))
    ),
    comment: raw.comment ?? raw.comments ?? raw.review ?? '',
    comments: raw.comments ?? raw.comment ?? raw.review ?? '',
    product_id: raw.product_id ?? raw.id_product ?? null,
    user_id: raw.user_id ?? raw.customer_id ?? null,
    customer_name: raw.customer_name ?? raw.user_name ?? raw.full_name ?? 'Customer',
    verified_purchase: Boolean(raw.verified_purchase ?? raw.verifiedPurchase ?? raw.order_item_id),
    order_id: raw.order_id ?? raw.orderId ?? null,
    order_item_id: raw.order_item_id ?? raw.orderItemId ?? null,
    issue_tag: raw.issue_tag ?? null,
    resolution_status: raw.resolution_status ?? 'open',
    public_responses: Array.isArray(raw.public_responses) ? raw.public_responses : [],
    public_response_count: toPositiveInt(raw.public_response_count ?? 0, 0),
    latest_public_response: raw.latest_public_response ?? null,
    created_at: raw.created_at ?? raw.date_created ?? raw.timestamp ?? null,
  };
}

// ----------------------------------------------------------------------------
// Order / payment normalization helpers
// ----------------------------------------------------------------------------
function normalizePaymentMethod(value) {
  const raw = String(value ?? '').trim().toLowerCase();
  if (!raw) return null;

  if (['cash', 'cod', 'cash_on_delivery', 'cash-on-delivery', 'cash on delivery'].includes(raw)) {
    return 'cash_on_delivery';
  }

  if (
    ['eft', 'bank_transfer', 'bank-transfer', 'bank transfer', 'electronic transfer'].includes(raw)
  ) {
    return 'eft';
  }

  return raw;
}

function paymentMethodIsCash(value) {
  return normalizePaymentMethod(value) === 'cash_on_delivery';
}

function paymentMethodIsEft(value) {
  return normalizePaymentMethod(value) === 'eft';
}

function normalizeCheckoutPayload(payload = {}) {
  const next = { ...payload };

  if (Object.prototype.hasOwnProperty.call(next, 'payment_method')) {
    next.payment_method = normalizePaymentMethod(next.payment_method) ?? next.payment_method;
  }

  if (Object.prototype.hasOwnProperty.call(next, 'paymentMethod')) {
    next.paymentMethod = normalizePaymentMethod(next.paymentMethod) ?? next.paymentMethod;
  }

  return next;
}

function normalizePaymentSummary(raw = {}) {
  const proofUrl =
    raw?.proof_url ?? raw?.payment_proof_url ?? raw?.proofUrl ?? raw?.receipt_url ?? null;

  return {
    ...raw,
    payment_id: raw?.payment_id ?? raw?.id ?? null,
    id: raw?.id ?? raw?.payment_id ?? null,
    amount: toPositiveNumber(raw?.amount ?? raw?.payment_amount ?? 0, 0),
    status: String(raw?.status ?? raw?.payment_status ?? 'unpaid').toLowerCase(),
    method: normalizePaymentMethod(raw?.method ?? raw?.payment_method ?? raw?.paymentMethod),
    payment_method: normalizePaymentMethod(raw?.payment_method ?? raw?.method ?? raw?.paymentMethod),
    reference: raw?.reference ?? raw?.payment_reference ?? raw?.proof_reference ?? '',
    proof_url: proofUrl,
    proof_uploaded: Boolean(raw?.proof_uploaded ?? proofUrl),
    submitted_at: raw?.submitted_at ?? raw?.created_at ?? raw?.timestamp ?? null,
    updated_at: raw?.updated_at ?? raw?.modified_at ?? raw?.timestamp ?? null,
  };
}

function normalizeScopePayment(raw = {}) {
  const summary = normalizePaymentSummary(raw);
  const stage =
    raw?.checkout_stage ??
    raw?.stage ??
    summary?.checkout_stage ??
    (paymentMethodIsCash(summary.method)
      ? summary.status === 'paid'
        ? 'cash_received'
        : 'awaiting_cash_delivery'
      : summary.status === 'paid'
        ? 'payment_verified'
        : summary.proof_uploaded || summary.reference
          ? 'payment_submitted'
          : 'awaiting_customer_payment');

  return {
    ...summary,
    checkout_stage: stage,
    payment_confirmed: Boolean(
      raw?.payment_confirmed ?? (summary.status === 'paid')
    ),
    delivery_blocked: Boolean(
      raw?.delivery_blocked ??
        (paymentMethodIsEft(summary.method) && summary.status !== 'paid')
    ),
    bank_name: raw?.bank_name ?? raw?.bank ?? '',
    account_name: raw?.account_name ?? '',
    account_number: raw?.account_number ?? '',
    branch_code: raw?.branch_code ?? '',
    amount_due: toPositiveNumber(raw?.amount_due ?? raw?.final_amount ?? raw?.amount ?? 0, 0),
    currency: raw?.currency ?? 'NAD',
    confirmation_meta: raw?.confirmation_meta ?? null,
  };
}

function normalizeOrderItem(raw = {}) {
  return {
    ...raw,
    item_id: raw?.item_id ?? raw?.id ?? null,
    id: raw?.id ?? raw?.item_id ?? null,
    product_id: raw?.product_id ?? raw?.id_product ?? null,
    product_name: raw?.product_name ?? raw?.name ?? 'Product',
    quantity: toPositiveNumber(raw?.quantity ?? raw?.qty ?? 0, 0),
    unit_price: toPositiveNumber(raw?.unit_price ?? raw?.price ?? 0, 0),
    line_total: toPositiveNumber(raw?.line_total ?? raw?.subtotal ?? raw?.total ?? 0, 0),
    farmer_id: raw?.farmer_id ?? raw?.seller_id ?? raw?.user_id ?? null,
    farmer_name: raw?.farmer_name ?? raw?.seller_name ?? 'Farmer',
    image_url: raw?.image_url ?? raw?.image ?? null,
    unit: raw?.unit ?? '',
    pack_size: raw?.pack_size ?? null,
    pack_unit: raw?.pack_unit ?? '',
  };
}

function normalizeOrder(raw = {}) {
  const paymentSummary = normalizePaymentSummary(raw?.payment ?? raw?.payment_summary ?? raw ?? {});
  const scopePayments = Array.isArray(raw?.payment_scopes)
    ? raw.payment_scopes.map(normalizeScopePayment)
    : Array.isArray(raw?.scopes)
      ? raw.scopes.map(normalizeScopePayment)
      : [];

  return {
    ...raw,
    order_id: raw?.order_id ?? raw?.id ?? null,
    id: raw?.id ?? raw?.order_id ?? null,
    status: String(raw?.status ?? raw?.order_status ?? 'pending').toLowerCase(),
    payment_status: String(raw?.payment_status ?? paymentSummary.status ?? 'unpaid').toLowerCase(),
    payment_method: normalizePaymentMethod(raw?.payment_method ?? paymentSummary.method ?? raw?.method),
    order_total: toPositiveNumber(raw?.order_total ?? raw?.total ?? raw?.grand_total ?? 0, 0),
    subtotal: toPositiveNumber(raw?.subtotal ?? raw?.order_subtotal ?? 0, 0),
    delivery_fee: toPositiveNumber(raw?.delivery_fee ?? raw?.shipping_fee ?? 0, 0),
    delivery_method: raw?.delivery_method ?? raw?.shipping_method ?? 'delivery',
    delivery_status: String(raw?.delivery_status ?? raw?.shipping_status ?? 'pending').toLowerCase(),
    order_date: raw?.order_date ?? raw?.created_at ?? raw?.timestamp ?? null,
    expected_delivery_date: raw?.expected_delivery_date ?? raw?.delivery_date ?? null,
    delivered_at: raw?.delivered_at ?? null,
    delivery_address: raw?.delivery_address ?? raw?.address ?? '',
    buyer_name: raw?.buyer_name ?? raw?.customer_name ?? raw?.full_name ?? 'Customer',
    customer_name: raw?.customer_name ?? raw?.buyer_name ?? raw?.full_name ?? 'Customer',
    items: asArray(raw?.items).map(normalizeOrderItem),
    payment: paymentSummary,
    payment_summary: paymentSummary,
    payment_scopes: scopePayments,
    checkout_stage:
      raw?.checkout_stage ??
      paymentSummary.checkout_stage ??
      scopePayments[0]?.checkout_stage ??
      null,
  };
}

function normalizeCheckoutResponse(raw = {}) {
  const payload = unwrapApiDataEnvelope(raw) ?? {};
  const order = normalizeOrder(payload?.order ?? payload);
  const paymentScopes = Array.isArray(payload?.payment_scopes)
    ? payload.payment_scopes.map(normalizeScopePayment)
    : order.payment_scopes;

  return {
    ...payload,
    order,
    payment_scopes: paymentScopes,
    order_id: payload?.order_id ?? order.order_id,
    message: payload?.message ?? 'Order request submitted successfully.',
  };
}

function shouldUseFormData(payload = {}) {
  const next = normalizeCheckoutPayload(payload);

  return Boolean(
    next?.image ||
      next?.file ||
      next?.attachment ||
      next?.product_image ||
      next?.avatar ||
      next?.photo
  );
}

function buildCheckoutFormData(payload = {}) {
  const next = normalizeCheckoutPayload(payload);
  const formData = new FormData();

  Object.entries(next).forEach(([key, value]) => {
    if (value == null) return;

    // NOTE:
    // Initial checkout should not carry payment-proof information.
    if (
      [
        'payment_proof',
        'proof_file',
        'proof',
        'receipt',
        'payment_proof_reference',
        'payment_reference',
        'proof_reference',
      ].includes(key)
    ) {
      return;
    }

    if (Array.isArray(value)) {
      value.forEach((entry) =>
        formData.append(key, typeof entry === 'object' ? JSON.stringify(entry) : String(entry))
      );
      return;
    }

    if (typeof value === 'object' && !(value instanceof Blob) && !(value instanceof File)) {
      formData.append(key, JSON.stringify(value));
      return;
    }

    formData.append(key, value);
  });

  return formData;
}

// ----------------------------------------------------------------------------
// Public homepage / marketplace APIs
// ----------------------------------------------------------------------------
export async function fetchPublicHomepage(options = {}) {
  const limit = toPositiveInt(options.limit, DEFAULT_HOMEPAGE_PRODUCT_LIMIT);

  try {
    const response = await api.get('/products/homepage', { params: { limit } });
    const payload = extractData(response);
    return normalizeHomepagePayload(payload);
  } catch (error) {
    const fallbackResponse = await api.get('/products', {
      params: {
        limit,
        include_inactive: false,
      },
    });

    const fallbackPayload = extractData(fallbackResponse);
    const visibleProducts = filterCustomerVisibleProducts(asArray(fallbackPayload));
    return normalizeHomepagePayload({}, visibleProducts);
  }
}

export async function fetchPublicProducts(options = {}) {
  try {
    const response = await api.get('/products', {
      params: {
        ...(options ?? {}),
      },
    });

    return filterCustomerVisibleProducts(asArray(extractData(response)));
  } catch (error) {
    throw normalizeError(error, 'Failed to load products.');
  }
}

export async function fetchPublicCategories(options = {}) {
  const homepage = await fetchPublicHomepage(options);
  return homepage.categories ?? [];
}

export async function fetchFeaturedProducts(options = {}) {
  const homepage = await fetchPublicHomepage(options);
  return homepage.featured_products ?? [];
}

export async function fetchTopProducts(options = {}) {
  const homepage = await fetchPublicHomepage(options);
  return homepage.top_products ?? [];
}

export async function fetchTopFarmers(options = {}) {
  const homepage = await fetchPublicHomepage(options);
  return homepage.top_farmers ?? [];
}

export async function fetchNewProducts(options = {}) {
  const homepage = await fetchPublicHomepage(options);
  return homepage.latest_products ?? [];
}

export async function fetchProductById(productId) {
  try {
    const response = await api.get(`/products/${productId}`);
    return normalizeProduct(extractData(response));
  } catch (error) {
    throw normalizeError(error, 'Failed to load product.');
  }
}

// ----------------------------------------------------------------------------
// Customer profile / likes / ratings APIs
// ----------------------------------------------------------------------------
export async function fetchCustomerProfile() {
  try {
    const response = await api.get('/auth/me');
    return extractData(response);
  } catch (primaryError) {
    try {
      const fallbackResponse = await api.get('/customers/profile');
      return extractData(fallbackResponse);
    } catch (fallbackError) {
      throw normalizeError(fallbackError, 'Failed to load profile.');
    }
  }
}

export async function updateCustomerProfile(payload = {}) {
  try {
    const response = await api.put('/auth/me', payload);
    return extractData(response);
  } catch (primaryError) {
    try {
      const fallbackResponse = await api.put('/customers/profile', payload);
      return extractData(fallbackResponse);
    } catch (fallbackError) {
      throw normalizeError(fallbackError, 'Failed to update profile.');
    }
  }
}

export async function fetchCustomerLikes(options = {}) {
  try {
    const response = await api.get('/likes', {
      params: {
        limit: toPositiveInt(options?.limit, 500),
        offset: Math.max(0, Math.floor(toNumber(options?.offset, 0))),
      },
    });

    const payload = extractData(response);
    return asArray(payload?.likes ?? payload).map(normalizeProduct);
  } catch (primaryError) {
    try {
      const fallbackResponse = await api.get('/customers/likes', {
        params: {
          limit: toPositiveInt(options?.limit, 500),
          offset: Math.max(0, Math.floor(toNumber(options?.offset, 0))),
        },
      });

      const payload = extractData(fallbackResponse);
      return asArray(payload?.likes ?? payload).map(normalizeProduct);
    } catch (fallbackError) {
      throw normalizeError(fallbackError, 'Failed to load liked products.');
    }
  }
}

export async function likeProduct(productId) {
  try {
    const response = await api.post(`/likes/${productId}`);
    return extractData(response);
  } catch (primaryError) {
    try {
      const fallbackResponse = await api.post(`/products/${productId}/like`);
      return extractData(fallbackResponse);
    } catch (fallbackError) {
      throw normalizeError(fallbackError, 'Failed to like product.');
    }
  }
}

export async function unlikeProduct(productId) {
  try {
    const response = await api.delete(`/likes/${productId}`);
    return extractData(response);
  } catch (primaryError) {
    try {
      const fallbackResponse = await api.delete(`/products/${productId}/like`);
      return extractData(fallbackResponse);
    } catch (fallbackError) {
      throw normalizeError(fallbackError, 'Failed to unlike product.');
    }
  }
}

export async function fetchProductRatings(productId, options = {}) {
  try {
    const response = await api.get('/ratings', {
      params: {
        product_id: productId,
        limit: toPositiveInt(options?.limit, 50),
      },
    });

    const payload = extractData(response);
    return asArray(payload?.ratings ?? payload).map(normalizeRating);
  } catch (primaryError) {
    try {
      const fallbackResponse = await api.get(`/products/${productId}/ratings`, {
        params: {
          limit: toPositiveInt(options?.limit, 50),
        },
      });

      return asArray(extractData(fallbackResponse)).map(normalizeRating);
    } catch (fallbackError) {
      throw normalizeError(fallbackError, 'Failed to load ratings.');
    }
  }
}

export async function submitProductRating(productIdOrPayload, payload = {}) {
  const inferredProductId =
    typeof productIdOrPayload === 'string' || typeof productIdOrPayload === 'number'
      ? productIdOrPayload
      : productIdOrPayload?.product_id ?? productIdOrPayload?.productId ?? null;

  const body =
    typeof productIdOrPayload === 'object' &&
    productIdOrPayload != null &&
    !Array.isArray(productIdOrPayload)
      ? productIdOrPayload
      : payload;

  if (!inferredProductId) {
    throw new Error('Missing product id for rating submission.');
  }

  const ratingPayload = {
    product_id: inferredProductId,
    order_id: body?.order_id ?? body?.orderId ?? null,
    order_item_id: body?.order_item_id ?? body?.orderItemId ?? null,
    rating_score: body?.rating_score ?? body?.score ?? body?.rating ?? 0,
    score: body?.score ?? body?.rating_score ?? body?.rating ?? 0,
    comments: body?.comments ?? body?.comment ?? '',
    comment: body?.comment ?? body?.comments ?? '',
  };

  try {
    const response = await api.post('/ratings', ratingPayload);
    return normalizeRating(extractData(response));
  } catch (primaryError) {
    try {
      const fallbackResponse = await api.post(`/products/${inferredProductId}/ratings`, ratingPayload);
      return normalizeRating(extractData(fallbackResponse));
    } catch (fallbackError) {
      throw normalizeError(fallbackError, 'Failed to submit rating.');
    }
  }
}

// ----------------------------------------------------------------------------
// Verified review / reviewable purchase helpers
// ----------------------------------------------------------------------------
export async function fetchReviewableOrderItems(options = {}) {
  const params = {};

  if (options?.product_id || options?.productId) {
    params.product_id = options.product_id ?? options.productId;
  }

  if (typeof options?.include_reviewed !== 'undefined') {
    params.include_reviewed = options.include_reviewed ? 1 : 0;
  } else if (typeof options?.includeReviewed !== 'undefined') {
    params.include_reviewed = options.includeReviewed ? 1 : 0;
  }

  try {
    const response = await api.get('/ratings/reviewable-items', { params });
    const payload = extractData(response);
    return asArray(payload?.items ?? payload);
  } catch (error) {
    throw normalizeError(error, 'Failed to load reviewable order items.');
  }
}

export async function getReviewableOrderItems(options = {}) {
  return fetchReviewableOrderItems(options);
}

export async function getReviewableItems(options = {}) {
  return fetchReviewableOrderItems(options);
}

// ----------------------------------------------------------------------------
// Customer checkout / orders APIs
// ----------------------------------------------------------------------------
export async function submitCheckout(payload = {}) {
  const next = normalizeCheckoutPayload(payload);

  try {
    let response;

    if (shouldUseFormData(next)) {
      response = await api.post('/orders/checkout', buildCheckoutFormData(next), {
        headers: { 'Content-Type': 'multipart/form-data' },
      });
    } else {
      response = await api.post('/orders/checkout', next);
    }

    return normalizeCheckoutResponse(extractData(response));
  } catch (error) {
    throw normalizeError(error, 'Failed to submit checkout.');
  }
}

export async function fetchCustomerOrders(options = {}) {
  try {
    const response = await api.get('/orders/me', {
      params: {
        ...(options ?? {}),
      },
    });

    return asArray(extractData(response)).map(normalizeOrder);
  } catch (primaryError) {
    try {
      const fallbackResponse = await api.get('/orders/my', {
        params: {
          ...(options ?? {}),
        },
      });

      return asArray(extractData(fallbackResponse)).map(normalizeOrder);
    } catch (secondaryError) {
      try {
        const legacyResponse = await api.get('/orders/customer', {
          params: {
            ...(options ?? {}),
          },
        });

        return asArray(extractData(legacyResponse)).map(normalizeOrder);
      } catch (legacyError) {
        throw normalizeError(legacyError, 'Failed to load orders.');
      }
    }
  }
}

export async function fetchCustomerOrderById(orderId) {
  try {
    const response = await api.get(`/orders/${orderId}`);
    return normalizeOrder(extractData(response));
  } catch (error) {
    throw normalizeError(error, 'Failed to load order.');
  }
}

export async function cancelCustomerOrder(orderId, payload = {}) {
  try {
    const response = await api.post(`/orders/${orderId}/cancel`, payload);
    return normalizeOrder(extractData(response));
  } catch (error) {
    throw normalizeError(error, 'Failed to cancel order.');
  }
}

export async function uploadPaymentProof(orderId, file, options = {}) {
  const normalizedMethod = normalizePaymentMethod(
    options?.payment_method ?? options?.paymentMethod ?? options?.method
  );

  // NOTE:
  // Cash on delivery must never attempt proof upload.
  if (paymentMethodIsCash(normalizedMethod)) {
    throw new Error('Cash on delivery does not require proof upload.');
  }

  if (!(file instanceof File) && !(file instanceof Blob)) {
    throw new Error('Missing payment proof file.');
  }

  const formData = new FormData();
  formData.append('payment_proof', file);

  if (options?.reference) {
    formData.append('payment_reference', String(options.reference));
  }
  if (options?.scope_user_id != null) {
    formData.append('scope_user_id', String(options.scope_user_id));
  }
  if (normalizedMethod) {
    formData.append('payment_method', normalizedMethod);
  }

  try {
    const response = await api.post(`/orders/${orderId}/payment-proof`, formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    });
    return normalizeCheckoutResponse(extractData(response));
  } catch (error) {
    throw normalizeError(error, 'Failed to upload payment proof.');
  }
}

// ----------------------------------------------------------------------------
// Customer leaderboard / farmer discovery APIs
// ----------------------------------------------------------------------------
export async function fetchFarmerLeaderboard(options = {}) {
  try {
    const response = await api.get('/farmers/leaderboard', {
      params: {
        ...(options ?? {}),
      },
    });

    return asArray(extractData(response)).map(normalizeHomepageFarmer);
  } catch (primaryError) {
    try {
      const fallbackResponse = await api.get('/ai/weekly-top-farmers', {
        params: {
          ...(options ?? {}),
        },
      });

      return asArray(extractData(fallbackResponse)).map(normalizeHomepageFarmer);
    } catch (fallbackError) {
      throw normalizeError(fallbackError, 'Failed to load farmer leaderboard.');
    }
  }
}

export async function fetchFarmerProfile(farmerId) {
  try {
    const response = await api.get(`/farmers/${farmerId}`);
    return normalizeHomepageFarmer(extractData(response));
  } catch (error) {
    throw normalizeError(error, 'Failed to load farmer profile.');
  }
}

// ----------------------------------------------------------------------------
// Customer workspace / analytics compatibility APIs
// ----------------------------------------------------------------------------
export async function fetchCustomerInsights(options = {}) {
  try {
    const response = await api.get('/customer/insights', {
      params: {
        months: Math.max(3, Math.min(toPositiveInt(options?.months, 6), 18)),
      },
    });
    return extractData(response);
  } catch (error) {
    return {
      summary: {},
      trends: [],
      recommendations: [],
      recent_activity: [],
    };
  }
}

export async function fetchCustomerPayments() {
  try {
    const response = await api.get('/customer/payments');
    return extractData(response);
  } catch (error) {
    return {
      payments: [],
      stats: {},
    };
  }
}

export async function fetchCustomerSavedSearch() {
  try {
    const response = await api.get('/customer/saved-search');
    return extractData(response);
  } catch (error) {
    return {
      saved_searches: [],
      suggestions: [],
    };
  }
}

export async function fetchCustomerAccountWorkspace() {
  try {
    const response = await api.get('/customer/account');
    return extractData(response);
  } catch (error) {
    return {
      profile: null,
      preferences: {},
      security: {},
    };
  }
}

// ----------------------------------------------------------------------------
// Legacy / compatibility wrappers for older customer UI modules
// ----------------------------------------------------------------------------
export async function fetchProducts(options = {}) {
  return fetchPublicProducts(options);
}

export async function fetchOrders(arg = {}) {
  if (arg && typeof arg === 'object' && !Array.isArray(arg)) {
    return fetchCustomerOrders(arg);
  }
  return fetchCustomerOrders({});
}

export async function getProducts(options = {}) {
  return fetchPublicProducts(options);
}

export async function listProducts(options = {}) {
  return fetchPublicProducts(options);
}

export async function getMarketplaceProducts(options = {}) {
  return fetchPublicProducts(options);
}

export async function getAvailableProducts(options = {}) {
  return fetchPublicProducts(options);
}

export async function fetchMyProfile() {
  return fetchCustomerProfile();
}

export async function getMyProfile() {
  return fetchCustomerProfile();
}

export async function getCustomerMe() {
  return fetchCustomerProfile();
}

export async function getMe() {
  return fetchCustomerProfile();
}

export async function updateMyProfile(payload = {}) {
  return updateCustomerProfile(payload);
}

export async function getWeeklyTopFarmers(options = {}) {
  return fetchFarmerLeaderboard(options);
}

export async function fetchMyProductLikes(options = {}) {
  return fetchCustomerLikes(options);
}

export async function syncProductLikes(productIds = [], options = {}) {
  try {
    const response = await api.post('/likes/bulk-sync', {
      product_ids: Array.isArray(productIds) ? productIds : [],
      replace: Boolean(options?.replace),
    });

    const payload = extractData(response);
    return asArray(payload?.likes ?? payload).map(normalizeProduct);
  } catch (error) {
    return fetchCustomerLikes();
  }
}

export async function setProductLike(productId, liked = true) {
  return liked ? likeProduct(productId) : unlikeProduct(productId);
}

export async function fetchRatings(productIdOrOptions, maybeOptions = {}) {
  if (
    productIdOrOptions &&
    typeof productIdOrOptions === 'object' &&
    !Array.isArray(productIdOrOptions)
  ) {
    return [];
  }

  return fetchProductRatings(productIdOrOptions, maybeOptions);
}

export async function fetchMyRatings(_options = {}) {
  return [];
}

export async function submitRating(payload = {}) {
  if (payload && typeof payload === 'object' && !Array.isArray(payload)) {
    return submitProductRating(payload);
  }
  return submitProductRating(payload);
}

export async function fetchFollowed(options = {}) {
  return fetchCustomerLikes(options);
}

export async function followProduct(productId) {
  return likeProduct(productId);
}

export async function unfollowProduct(productId) {
  return unlikeProduct(productId);
}

// ----------------------------------------------------------------------------
// Legacy / compatibility aliases used in older UI files
// ----------------------------------------------------------------------------
export const getPublicHomepage = fetchPublicHomepage;
export const getPublicProducts = fetchPublicProducts;
export const getFeaturedProducts = fetchFeaturedProducts;
export const getTopProducts = fetchTopProducts;
export const getTopFarmers = fetchTopFarmers;
export const getNewProducts = fetchNewProducts;
export const getProductById = fetchProductById;

export const getCustomerProfile = fetchCustomerProfile;
export const saveCustomerProfile = updateCustomerProfile;
export const getCustomerOrders = fetchCustomerOrders;
export const getCustomerOrderById = fetchCustomerOrderById;
export const submitOrderCheckout = submitCheckout;
export const submitOrderPaymentProof = uploadPaymentProof;
export const getCustomerLikes = fetchCustomerLikes;
export const addProductLike = likeProduct;
export const removeProductLike = unlikeProduct;
export const getProductRatings = fetchProductRatings;
export const createProductRating = submitProductRating;
export const getFarmerLeaderboard = fetchFarmerLeaderboard;
export const getFarmerProfile = fetchFarmerProfile;

// ----------------------------------------------------------------------------
// Default export for existing import styles across the project
// ----------------------------------------------------------------------------
const customerApi = {
  // Public homepage / marketplace
  fetchPublicHomepage,
  fetchPublicProducts,
  fetchPublicCategories,
  fetchFeaturedProducts,
  fetchTopProducts,
  fetchTopFarmers,
  fetchNewProducts,
  fetchProductById,

  // Profile / likes / ratings
  fetchCustomerProfile,
  updateCustomerProfile,
  fetchCustomerLikes,
  likeProduct,
  unlikeProduct,
  fetchProductRatings,
  submitProductRating,

  // Orders / checkout / reviewable items
  submitCheckout,
  fetchCustomerOrders,
  fetchCustomerOrderById,
  cancelCustomerOrder,
  uploadPaymentProof,
  fetchReviewableOrderItems,
  getReviewableOrderItems,
  getReviewableItems,

  // Farmers / discovery
  fetchFarmerLeaderboard,
  fetchFarmerProfile,

  // Workspace / older dashboard compatibility
  fetchCustomerInsights,
  fetchCustomerPayments,
  fetchCustomerSavedSearch,
  fetchCustomerAccountWorkspace,

  // Legacy wrappers still imported directly by older pages
  fetchProducts,
  fetchOrders,
  getProducts,
  listProducts,
  getMarketplaceProducts,
  getAvailableProducts,
  fetchMyProfile,
  getMyProfile,
  getCustomerMe,
  getMe,
  updateMyProfile,
  getWeeklyTopFarmers,
  fetchMyProductLikes,
  syncProductLikes,
  setProductLike,
  fetchRatings,
  fetchMyRatings,
  submitRating,
  fetchFollowed,
  followProduct,
  unfollowProduct,

  // Compatibility aliases
  getPublicHomepage,
  getPublicProducts,
  getFeaturedProducts,
  getTopProducts,
  getTopFarmers,
  getNewProducts,
  getProductById,
  getCustomerProfile,
  saveCustomerProfile,
  getCustomerOrders,
  getCustomerOrderById,
  submitOrderCheckout,
  submitOrderPaymentProof,
  getCustomerLikes,
  addProductLike,
  removeProductLike,
  getProductRatings,
  createProductRating,
  getFarmerLeaderboard,
  getFarmerProfile,

  // Shared helpers intentionally exposed for UI normalization
  normalizeProduct,
  normalizeOrder,
  normalizeOrderItem,
  normalizePaymentSummary,
  normalizeScopePayment,
  normalizeCheckoutResponse,
  normalizePaymentMethod,
  paymentMethodIsCash,
  paymentMethodIsEft,
  normalizeHomepagePayload,
  normalizeHomepageFarmer,
  normalizeHomepageCategory,
  filterCustomerVisibleProducts,
  normalizeRating,
};

export default customerApi;