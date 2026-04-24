// ====================================================================
// frontend/src/pages/StartScreen.js
// --------------------------------------------------------------------
// FILE ROLE:
//   Public AgroConnect marketplace homepage.
//
// PERMANENT FIX IN THIS VERSION:
//   ✔ StartScreen now uses ONE lightweight public marketplace endpoint
//   ✔ Removed duplicate fetchProducts({ limit: 220 }) homepage loading
//   ✔ Prevents the old timeout loop caused by loading /api/products too
//   ✔ Products, categories, featured products, and farmers are derived
//     from /api/public/marketplace-summary
//   ✔ Keeps the existing marketplace UI, modals, image fallback system,
//     farmer drawer, category quick view, and auth dialog flow
//
// EXPECTED SERVICE:
//   fetchPublicHomepage() should call:
//     GET /api/public/marketplace-summary
// ====================================================================

import React, { useEffect, useMemo, useState } from 'react';
import {
  ArrowRight,
  ChevronLeft,
  ChevronRight,
  Eye,
  Leaf,
  LogIn,
  MapPin,
  Package,
  Search,
  ShoppingCart,
  Star,
  Store,
  TrendingUp,
  X,
} from 'lucide-react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import AuthDialog from '../components/auth/AuthDialog';
import { fetchPublicHomepage } from '../services/customerApi';
import { resolveProductImageCandidates } from '../utils/productImage';

// --------------------------------------------------------------------
// Constants
// --------------------------------------------------------------------
const AUTOPLAY_MS = 5500;

const AUTH_MODE_LOGIN = 'login';
const AUTH_MODE_REGISTER = 'register';

const AUTH_ROLE_CUSTOMER = 'customer';
const AUTH_ROLE_FARMER = 'farmer';

const START_BTN_BASE =
  'inline-flex items-center justify-center gap-2 rounded-[14px] border-2 text-sm font-extrabold transition-all duration-200 active:translate-y-[1px] shadow-[0_10px_26px_rgba(0,0,0,0.14)] hover:bg-[#C1A362] hover:border-[#C1A362] hover:text-[#1F1F1F] hover:shadow-[0_0_26px_rgba(193,163,98,0.30)]';

const START_BTN_SIZE = 'min-h-[48px] min-w-[176px] px-5 py-3';

const START_BTN_DARK = `${START_BTN_BASE} ${START_BTN_SIZE} border-[#10B981]/60 bg-white/10 text-white backdrop-blur-sm`;
const START_BTN_PRIMARY = `${START_BTN_BASE} ${START_BTN_SIZE} border-[#10B981]/60 bg-[#52B788] text-[#081C15]`;
const START_BTN_LIGHT = `${START_BTN_BASE} ${START_BTN_SIZE} border-[#10B981]/60 bg-white text-[#163322]`;
const START_BTN_SOFT = `${START_BTN_BASE} ${START_BTN_SIZE} border-[#B7E4C7] bg-[#F7FBF8] text-[#1B4332]`;

// --------------------------------------------------------------------
// Generic helpers
// --------------------------------------------------------------------
function safeArray(value) {
  return Array.isArray(value) ? value : [];
}

function safeText(value, fallback = '') {
  if (value == null) return fallback;
  const text = String(value).trim();
  return text || fallback;
}

function toNumber(value, fallback = 0) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function isEmptyValue(value) {
  return (
    value == null ||
    value === '' ||
    value === 'null' ||
    value === 'undefined' ||
    (Array.isArray(value) && value.length === 0)
  );
}

function mergePreferPrimary(primary = {}, secondary = {}) {
  const merged = { ...secondary, ...primary };

  Object.keys(secondary).forEach((key) => {
    const primaryValue = primary?.[key];
    const secondaryValue = secondary?.[key];

    if (isEmptyValue(primaryValue) && !isEmptyValue(secondaryValue)) {
      merged[key] = secondaryValue;
    }
  });

  return merged;
}

function uniqueByKey(rows = [], getter) {
  const map = new Map();

  rows.forEach((row, index) => {
    const key = safeText(getter(row), `row-${index}`);
    if (!map.has(key)) {
      map.set(key, row);
    }
  });

  return [...map.values()];
}

function uniqueStrings(values = []) {
  const seen = new Set();
  const out = [];

  safeArray(values).forEach((value) => {
    const normalized = safeText(value);
    if (!normalized || seen.has(normalized)) return;
    seen.add(normalized);
    out.push(normalized);
  });

  return out;
}

function normalizeCategoryKey(value) {
  return safeText(value).toLowerCase();
}

function scrollToSection(sectionId) {
  const node = document.getElementById(sectionId);
  if (!node) return;
  node.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function unwrapHomepagePayload(payload) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    return {};
  }

  if (payload.data && typeof payload.data === 'object' && !Array.isArray(payload.data)) {
    return payload.data;
  }

  return payload;
}

// --------------------------------------------------------------------
// Permanent endpoint helper
// --------------------------------------------------------------------
// The backend now returns all StartScreen data in one response:
//   categories
//   featured_products
//   top_products
//   top_farmers
//   latest_products
//
// This helper extracts product rows from that one response so the existing
// UI can still build product lookups, farmer drawers, search results, and
// category previews without calling /api/products separately.
function extractProductsFromHomepage(homepage = {}) {
  const sections = homepage?.sections || {};

  return uniqueByKey(
    [
      ...safeArray(homepage?.featured_products),
      ...safeArray(homepage?.top_products),
      ...safeArray(homepage?.latest_products),
      ...safeArray(sections?.featured_products),
      ...safeArray(sections?.top_products),
      ...safeArray(sections?.latest_products),
    ].filter(Boolean),
    (row) => row?.product_id || row?.id || row?.name || row?.product_name
  );
}

// --------------------------------------------------------------------
// Formatting helpers
// --------------------------------------------------------------------
function formatCount(value) {
  return new Intl.NumberFormat('en-NA', {
    maximumFractionDigits: 0,
  }).format(toNumber(value, 0));
}

function formatQty(value) {
  const n = toNumber(value, 0);

  return new Intl.NumberFormat('en-NA', {
    minimumFractionDigits: n % 1 === 0 ? 0 : 1,
    maximumFractionDigits: 1,
  }).format(n);
}

function formatCurrency(value) {
  return new Intl.NumberFormat('en-NA', {
    style: 'currency',
    currency: 'NAD',
    maximumFractionDigits: 2,
  }).format(toNumber(value, 0));
}

// --------------------------------------------------------------------
// Image helpers
// --------------------------------------------------------------------
function svgDataUri(svg) {
  return `data:image/svg+xml;charset=UTF-8,${encodeURIComponent(svg)}`;
}

function buildDefaultProductArtwork(label = 'Marketplace Product') {
  const safeLabel = safeText(label, 'Marketplace Product').slice(0, 32);

  return svgDataUri(`
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 720">
      <defs>
        <linearGradient id="g" x1="0" x2="1" y1="0" y2="1">
          <stop offset="0%" stop-color="#EDF8F0" />
          <stop offset="55%" stop-color="#B7E4C7" />
          <stop offset="100%" stop-color="#74C69D" />
        </linearGradient>
      </defs>
      <rect width="1200" height="720" fill="url(#g)" />
      <circle cx="990" cy="140" r="170" fill="rgba(22,51,34,0.08)" />
      <circle cx="190" cy="610" r="200" fill="rgba(22,51,34,0.07)" />
      <ellipse cx="600" cy="400" rx="180" ry="108" fill="rgba(22,51,34,0.16)" />
      <path d="M610 170 C648 130,720 140,742 190 C756 230,735 280,690 302 C664 315,645 338,637 366 L614 366 C620 330,608 297,579 276 C550 254,532 214,551 180 C569 146,602 132,610 170 Z" fill="rgba(22,51,34,0.30)" />
      <text x="58" y="92" fill="rgba(22,51,34,0.18)" font-family="Arial, sans-serif" font-size="42" font-weight="700">AgroConnect</text>
      <text x="600" y="640" text-anchor="middle" fill="#163322" font-family="Arial, sans-serif" font-size="52" font-weight="800">${safeLabel}</text>
    </svg>
  `);
}

function buildDefaultFarmerArtwork(name = 'Farmer') {
  const initials =
    safeText(name, 'F')
      .split(/\s+/)
      .slice(0, 2)
      .map((part) => part.charAt(0).toUpperCase())
      .join('') || 'F';

  return svgDataUri(`
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 720">
      <defs>
        <linearGradient id="g" x1="0" x2="1" y1="0" y2="1">
          <stop offset="0%" stop-color="#163322" />
          <stop offset="50%" stop-color="#24543E" />
          <stop offset="100%" stop-color="#2D6A4F" />
        </linearGradient>
      </defs>
      <rect width="1200" height="720" fill="url(#g)" />
      <circle cx="950" cy="150" r="185" fill="rgba(255,255,255,0.06)" />
      <circle cx="220" cy="590" r="220" fill="rgba(255,255,255,0.05)" />
      <circle cx="600" cy="320" r="135" fill="rgba(255,255,255,0.12)" />
      <circle cx="600" cy="264" r="54" fill="rgba(255,255,255,0.28)" />
      <path d="M505 412 C540 350,660 350,695 412 L740 505 C748 521,736 540,718 540 L482 540 C464 540,452 521,460 505 Z" fill="rgba(255,255,255,0.18)" />
      <text x="82" y="118" fill="rgba(255,255,255,0.14)" font-family="Arial, sans-serif" font-size="46" font-weight="700">AgroConnect Farmer</text>
      <text x="600" y="655" text-anchor="middle" fill="#FFFFFF" font-family="Arial, sans-serif" font-size="84" font-weight="800">${initials}</text>
    </svg>
  `);
}

function tryParseImageJson(value) {
  const raw = safeText(value);
  if (!raw) return null;

  const looksJson =
    (raw.startsWith('[') && raw.endsWith(']')) ||
    (raw.startsWith('{') && raw.endsWith('}'));

  if (!looksJson) return null;

  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function flattenImageCandidates(value) {
  if (value == null) return [];

  if (Array.isArray(value)) {
    return value.flatMap((item) => flattenImageCandidates(item));
  }

  if (typeof value === 'string') {
    const parsed = tryParseImageJson(value);
    if (parsed) return flattenImageCandidates(parsed);
    return [value];
  }

  if (typeof value === 'object') {
    const directKeys = [
      'url',
      'src',
      'path',
      'image',
      'image_url',
      'imageUrl',
      'thumbnail',
      'thumb',
      'photo',
      'photo_url',
      'photoUrl',
      'hero_image_url',
      'heroImageUrl',
      'cover_image',
      'coverImage',
      'featured_image',
      'featuredImage',
      'file_url',
      'download_url',
      'secure_url',
      'original',
      'medium',
      'large',
      'small',
      'public_url',
      'publicUrl',
    ];

    const nestedKeys = ['images', 'gallery', 'media', 'files', 'items', 'product_images'];
    const candidates = [];

    directKeys.forEach((key) => {
      if (!isEmptyValue(value?.[key])) {
        candidates.push(value[key]);
      }
    });

    nestedKeys.forEach((key) => {
      if (!isEmptyValue(value?.[key])) {
        candidates.push(...flattenImageCandidates(value[key]));
      }
    });

    return candidates;
  }

  return [];
}

function normalizeImageUrl(value, fallback = '') {
  // FILE ROLE:
  // Final light cleanup for image candidates before rendering.
  // The full candidate strategy lives in utils/productImage.js.
  const raw = safeText(value);
  if (!raw || raw === 'null' || raw === 'undefined') return fallback;

  if (/^(https?:)?\/\//i.test(raw) || raw.startsWith('blob:') || raw.startsWith('data:')) {
    return raw;
  }

  let normalized = raw.replace(/\\/g, '/').replace(/^\.\//, '').trim();

  if (!normalized.startsWith('/')) {
    normalized = `/${normalized}`;
  }

  normalized = normalized
    .replace(/^\/api\/api\//i, '/api/')
    .replace(/^\/api\/uploads\/api\/uploads\//i, '/api/uploads/')
    .replace(/^\/uploads\/api\/uploads\//i, '/api/uploads/')
    .replace(/^\/api\/uploads\/uploads\//i, '/api/uploads/')
    .replace(/^\/uploads\/uploads\//i, '/uploads/')
    .replace(/^\/assets\//i, '/Assets/')
    .replace(/^\/uploads\//i, '/api/uploads/')
    .replace(/^\/+/, '/');

  const lower = normalized.toLowerCase();
  const isDefaultish =
    lower.includes('/defaults/') ||
    lower.includes('default.jpg') ||
    lower.includes('default.jpeg') ||
    lower.includes('default.png') ||
    lower.includes('default-product');

  if (isDefaultish) {
    return '/Assets/product_images/default.jpg';
  }

  return normalized;
}

function resolveImage(value, fallback = '') {
  return normalizeImageUrl(value, fallback);
}

function firstValidImage(candidates = [], fallback = '') {
  for (const candidate of candidates.flatMap((item) => flattenImageCandidates(item))) {
    const resolved = normalizeImageUrl(candidate, '');
    if (resolved) return resolved;
  }

  return fallback;
}

function getFarmerAssetCandidates(index = 0) {
  const publicBase = process.env.PUBLIC_URL || '';
  const femaleFarmer = `${publicBase}/Assets/female_farmer.png`;
  const maleFarmer = `${publicBase}/Assets/male_farmer.png`;

  return index % 2 === 0 ? [maleFarmer, femaleFarmer] : [femaleFarmer, maleFarmer];
}

function getProductImageCandidates(product, fallbackImage) {
  return uniqueStrings([
    ...safeArray(resolveProductImageCandidates(product)),
    resolveImage(
      product?.image_url ||
        product?.imageUrl ||
        product?.thumbnail ||
        product?.photo_url ||
        product?.photoUrl ||
        product?.image,
      ''
    ),
    buildDefaultProductArtwork(product?.name || product?.product_name || 'Product'),
    fallbackImage,
  ]);
}

function getPrimaryProductImage(product, fallbackImage = '') {
  return getProductImageCandidates(product, fallbackImage)[0] || fallbackImage || '';
}

function getFarmerImageCandidates(farmer, index = 0, fallbackImage) {
  const explicitImage = resolveImage(
    farmer?.hero_image_url ||
      farmer?.heroImageUrl ||
      farmer?.image_url ||
      farmer?.imageUrl ||
      farmer?.image,
    ''
  );

  return uniqueStrings([
    explicitImage,
    ...getFarmerAssetCandidates(index),
    fallbackImage,
    buildDefaultFarmerArtwork(farmer?.farmer_name || farmer?.name || 'Farmer'),
  ]);
}

function getCategoryRotationImages(category, categoryProducts = [], fallbackImage = '') {
  const productImages = safeArray(categoryProducts).flatMap((product) =>
    getProductImageCandidates(product, '')
      .filter((candidate) => !safeText(candidate).startsWith('data:image'))
      .filter(Boolean)
  );

  return uniqueStrings([
    ...productImages,
    resolveImage(category?.image_url, ''),
    buildDefaultProductArtwork(category?.category || 'Category'),
    fallbackImage,
  ]);
}

// --------------------------------------------------------------------
// Data helpers
// --------------------------------------------------------------------
function buildProductLookup(products = []) {
  const byId = new Map();
  const byName = new Map();

  safeArray(products).forEach((product) => {
    const idKey = safeText(product?.product_id || product?.id);
    const nameKey = safeText(product?.name || product?.product_name).toLowerCase();

    if (idKey && !byId.has(idKey)) {
      byId.set(idKey, product);
    }

    if (nameKey && !byName.has(nameKey)) {
      byName.set(nameKey, product);
    }
  });

  return { byId, byName };
}

function hydrateProductRecord(product, lookup) {
  if (!product) return product;

  const idKey = safeText(product?.product_id || product?.id);
  const nameKey = safeText(product?.name || product?.product_name).toLowerCase();

  const matched =
    (idKey && lookup?.byId?.get(idKey)) || (nameKey && lookup?.byName?.get(nameKey)) || null;

  return matched ? mergePreferPrimary(product, matched) : product;
}

function deriveCategoriesFromProducts(products = [], fallbackImage) {
  const grouped = new Map();

  safeArray(products).forEach((product) => {
    const rawCategory = safeText(product?.category);
    if (!rawCategory) return;

    const key = rawCategory.toLowerCase();
    const current = grouped.get(key) || {
      category: rawCategory,
      count: 0,
      product_count: 0,
      preview_names: [],
      image_url: '',
      tagline: 'Preview products in this category before registration.',
    };

    current.count += 1;
    current.product_count += 1;

    const productName = safeText(product?.name || product?.product_name);
    if (productName && !current.preview_names.includes(productName)) {
      current.preview_names.push(productName);
    }

    if (!current.image_url) {
      current.image_url = getPrimaryProductImage(product, fallbackImage);
    }

    grouped.set(key, current);
  });

  return [...grouped.values()]
    .sort((a, b) => b.count - a.count || a.category.localeCompare(b.category))
    .map((group) => ({
      ...group,
      preview_names: group.preview_names.slice(0, 3),
    }));
}

function buildCategoryProductMap(products = []) {
  const map = new Map();

  safeArray(products).forEach((product) => {
    const key = normalizeCategoryKey(product?.category);
    if (!key) return;

    const rows = map.get(key) || [];
    rows.push(product);
    map.set(key, rows);
  });

  return map;
}

function enrichCategoryRecord(category, categoryProductMap, fallbackImage) {
  const key = normalizeCategoryKey(category?.category);
  const products = safeArray(categoryProductMap.get(key));
  const previewNames = safeArray(category?.preview_names).filter(Boolean);

  return {
    ...category,
    count: toNumber(category?.count || category?.product_count, products.length),
    product_count: toNumber(category?.product_count || category?.count, products.length),
    preview_names:
      previewNames.length > 0
        ? previewNames.slice(0, 3)
        : products
            .map((product) => safeText(product?.name || product?.product_name))
            .filter(Boolean)
            .slice(0, 3),
    image_url:
      firstValidImage(
        [category?.image_url, ...products.map((product) => getPrimaryProductImage(product, ''))],
        ''
      ) || fallbackImage,
    tagline:
      safeText(category?.tagline) || 'Preview products in this category before registration.',
  };
}

function deriveTopProductsFromProducts(products = []) {
  return uniqueByKey(products, (row) => row?.product_id || row?.id || row?.name)
    .sort((a, b) => {
      const orderDiff =
        toNumber(b?.orders_count || b?.order_count || b?.sales_count, 0) -
        toNumber(a?.orders_count || a?.order_count || a?.sales_count, 0);

      if (orderDiff !== 0) return orderDiff;

      const ratingDiff = toNumber(b?.avg_rating, 0) - toNumber(a?.avg_rating, 0);
      if (ratingDiff !== 0) return ratingDiff;

      return toNumber(b?.price, 0) - toNumber(a?.price, 0);
    })
    .slice(0, 16);
}

function deriveTopFarmersFromProducts(products = [], fallbackImage) {
  const grouped = new Map();

  uniqueByKey(products, (row) => row?.product_id || row?.id || row?.name).forEach((product) => {
    const farmerName = safeText(product?.farmer_name || product?.seller_name);
    if (!farmerName) return;

    const farmerId = safeText(product?.farmer_id || farmerName);
    const current = grouped.get(farmerId) || {
      farmer_id: farmerId,
      farmer_name: farmerName,
      location: safeText(product?.location, 'Namibia'),
      product_count: 0,
      total_orders: 0,
      rating_total: 0,
      rating_entries: 0,
      featured_categories: [],
      image_url: '',
      hero_image_url: '',
      seller_intro:
        'This public AgroConnect seller profile helps visitors inspect seller activity, specialties, and visible marketplace listings before registration.',
    };

    current.product_count += 1;
    current.total_orders += toNumber(
      product?.orders_count || product?.order_count || product?.sales_count,
      0
    );

    const rating = toNumber(product?.avg_rating, 0);
    if (rating > 0) {
      current.rating_total += rating;
      current.rating_entries += 1;
    }

    const category = safeText(product?.category);
    if (category && !current.featured_categories.includes(category)) {
      current.featured_categories.push(category);
    }

    if (!current.image_url) {
      current.image_url = getPrimaryProductImage(product, fallbackImage);
    }

    if (!current.hero_image_url) {
      current.hero_image_url = getPrimaryProductImage(product, fallbackImage);
    }

    grouped.set(farmerId, current);
  });

  return [...grouped.values()]
    .map((item) => ({
      ...item,
      avg_rating: item.rating_entries > 0 ? item.rating_total / item.rating_entries : 0,
      featured_categories: item.featured_categories.slice(0, 4),
    }))
    .sort((a, b) => {
      const productDiff = toNumber(b?.product_count, 0) - toNumber(a?.product_count, 0);
      if (productDiff !== 0) return productDiff;

      const orderDiff = toNumber(b?.total_orders, 0) - toNumber(a?.total_orders, 0);
      if (orderDiff !== 0) return orderDiff;

      return toNumber(b?.avg_rating, 0) - toNumber(a?.avg_rating, 0);
    })
    .slice(0, 8);
}

function buildFeaturedProducts(homepage, allProducts, productLookup) {
  return uniqueByKey(
    [
      ...safeArray(homepage?.featured_products).map((row) =>
        hydrateProductRecord(row, productLookup)
      ),
      ...safeArray(homepage?.top_products).map((row) => hydrateProductRecord(row, productLookup)),
      ...safeArray(homepage?.latest_products).map((row) =>
        hydrateProductRecord(row, productLookup)
      ),
      ...safeArray(allProducts),
    ],
    (row) => row?.product_id || row?.id || row?.name
  ).slice(0, 10);
}

function belongsToFarmer(product, farmer) {
  const farmerId = safeText(farmer?.farmer_id || farmer?.id);
  const productFarmerId = safeText(product?.farmer_id || product?.seller_id);

  if (farmerId && productFarmerId && farmerId === productFarmerId) {
    return true;
  }

  const farmerName = safeText(farmer?.farmer_name || farmer?.name).toLowerCase();
  const productFarmerName = safeText(product?.farmer_name || product?.seller_name).toLowerCase();

  return !!farmerName && farmerName === productFarmerName;
}

function deriveFarmerProducts(products = [], farmer) {
  return uniqueByKey(
    safeArray(products).filter((product) => belongsToFarmer(product, farmer)),
    (row) => row?.product_id || row?.id || row?.name
  )
    .sort((a, b) => {
      const orderDiff =
        toNumber(b?.orders_count || b?.order_count || b?.sales_count, 0) -
        toNumber(a?.orders_count || a?.order_count || a?.sales_count, 0);

      if (orderDiff !== 0) return orderDiff;

      const ratingDiff = toNumber(b?.avg_rating, 0) - toNumber(a?.avg_rating, 0);
      if (ratingDiff !== 0) return ratingDiff;

      return toNumber(b?.price, 0) - toNumber(a?.price, 0);
    })
    .slice(0, 5);
}

function looksLikeProduct(record) {
  if (!record || typeof record !== 'object') return false;

  return (
    record?.product_id != null ||
    record?.product_name != null ||
    record?.price != null ||
    record?.stock_quantity != null
  );
}

// --------------------------------------------------------------------
// Shared UI
// --------------------------------------------------------------------
function PageContainer({ children, className = '' }) {
  return (
    <div
      className={`mx-auto w-full max-w-[1720px] px-4 sm:px-6 lg:px-8 xl:px-10 2xl:px-12 ${className}`}
    >
      {children}
    </div>
  );
}

function AmazonShelf({ id, children, className = '' }) {
  return (
    <section
      id={id}
      className={`overflow-hidden rounded-[18px] border border-[#D8E6DD] bg-white shadow-[0_10px_28px_rgba(18,31,21,0.08)] ${className}`}
    >
      {children}
    </section>
  );
}

function ShelfHeader({
  eyebrow,
  title,
  subtitle,
  actionLabel,
  actionTo,
  actionKind = 'route',
  actionState,
  onActionClick,
}) {
  return (
    <div className="mb-6 flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
      <div className="max-w-4xl">
        {eyebrow ? (
          <div className="mb-2 text-[11px] font-extrabold uppercase tracking-[0.22em] text-[#2D6A4F]">
            {eyebrow}
          </div>
        ) : null}

        <h2 className="text-[2rem] font-black tracking-tight text-[#163322] sm:text-[2.2rem]">
          {title}
        </h2>

        {subtitle ? (
          <p className="mt-2 max-w-3xl text-sm leading-7 text-[#5D7869] sm:text-base">
            {subtitle}
          </p>
        ) : null}
      </div>

      {actionLabel ? (
        actionKind === 'section' && actionTo ? (
          <StartActionButton
            type="button"
            onClick={() => scrollToSection(actionTo)}
            variant="soft"
            className="self-start"
          >
            {actionLabel}
            <ArrowRight size={16} />
          </StartActionButton>
        ) : actionKind === 'callback' ? (
          <StartActionButton
            type="button"
            onClick={onActionClick}
            variant="soft"
            className="self-start"
          >
            {actionLabel}
            <ArrowRight size={16} />
          </StartActionButton>
        ) : actionTo ? (
          <StartLinkButton
            to={actionTo}
            state={actionState}
            variant="soft"
            className="self-start"
          >
            {actionLabel}
            <ArrowRight size={16} />
          </StartLinkButton>
        ) : null
      ) : null}
    </div>
  );
}

const START_BUTTON_VARIANTS = {
  dark: START_BTN_DARK,
  primary: START_BTN_PRIMARY,
  light: START_BTN_LIGHT,
  soft: START_BTN_SOFT,
};

function StartLinkButton({
  to,
  children,
  variant = 'soft',
  className = '',
  state,
  onClick,
}) {
  return (
    <Link
      to={to}
      state={state}
      onClick={onClick}
      className={`${START_BUTTON_VARIANTS[variant] || START_BTN_SOFT} ${className}`.trim()}
    >
      {children}
    </Link>
  );
}

function StartActionButton({
  type = 'button',
  onClick,
  children,
  variant = 'soft',
  className = '',
}) {
  return (
    <button
      type={type}
      onClick={onClick}
      className={`${START_BUTTON_VARIANTS[variant] || START_BTN_SOFT} ${className}`.trim()}
    >
      {children}
    </button>
  );
}

function HeaderNavButton({ icon: Icon, label, to, accent = false, state, onClick }) {
  if (onClick) {
    return (
      <StartActionButton type="button" onClick={onClick} variant={accent ? 'primary' : 'dark'}>
        <Icon size={16} />
        {label}
      </StartActionButton>
    );
  }

  return (
    <StartLinkButton to={to} state={state} variant={accent ? 'primary' : 'dark'}>
      <Icon size={16} />
      {label}
    </StartLinkButton>
  );
}

function DeckPanel({ eyebrow, title, subtitle, children, actionLabel, onAction }) {
  return (
    <div className="flex h-full flex-col rounded-[16px] border border-[#D8E6DD] bg-white p-5 shadow-[0_10px_26px_rgba(17,29,19,0.08)]">
      <div className="mb-2 text-[11px] font-extrabold uppercase tracking-[0.2em] text-[#2D6A4F]">
        {eyebrow}
      </div>

      <h3 className="text-[1.25rem] font-black tracking-tight text-[#163322]">{title}</h3>

      {subtitle ? <p className="mt-2 text-sm leading-6 text-[#5D7869]">{subtitle}</p> : null}

      <div className="mt-4 flex-1">{children}</div>

      {actionLabel ? (
        <StartActionButton
          type="button"
          onClick={onAction}
          variant="soft"
          className="mt-4 self-start"
        >
          {actionLabel}
          <ArrowRight size={15} />
        </StartActionButton>
      ) : null}
    </div>
  );
}

function LoadingCard({ className = '' }) {
  return (
    <div className={`animate-pulse rounded-[28px] border border-[#DCEBE2] bg-white ${className}`} />
  );
}

// --------------------------------------------------------------------
// Resilient image components
// --------------------------------------------------------------------
function ResilientImage({
  candidates = [],
  alt,
  className = '',
  loading = 'lazy',
}) {
  const safeCandidates = useMemo(() => uniqueStrings(candidates), [candidates]);
  const candidateKey = useMemo(() => safeCandidates.join('|'), [safeCandidates]);
  const [index, setIndex] = useState(0);

  useEffect(() => {
    setIndex(0);
  }, [candidateKey]);

  const src = safeCandidates[index] || safeCandidates[0] || '';

  return (
    <img
      src={src}
      alt={alt}
      loading={loading}
      className={className}
      onError={() => {
        setIndex((current) => {
          if (current >= safeCandidates.length - 1) return current;
          return current + 1;
        });
      }}
    />
  );
}

function ProductThumb({ product, fallbackImage, className = '', loading = 'lazy' }) {
  return (
    <ResilientImage
      candidates={getProductImageCandidates(product, fallbackImage)}
      alt={product?.name || product?.product_name || 'Product'}
      className={className}
      loading={loading}
    />
  );
}

function FarmerThumb({
  farmer,
  index = 0,
  fallbackImage,
  className = '',
  loading = 'lazy',
}) {
  return (
    <ResilientImage
      candidates={getFarmerImageCandidates(farmer, index, fallbackImage)}
      alt={farmer?.farmer_name || farmer?.name || 'Farmer'}
      className={className}
      loading={loading}
    />
  );
}

function CategoryThumb({
  category,
  categoryProducts = [],
  fallbackImage,
  className = '',
  loading = 'lazy',
}) {
  return (
    <ResilientImage
      candidates={getCategoryRotationImages(category, categoryProducts, fallbackImage)}
      alt={category?.category || 'Category'}
      className={className}
      loading={loading}
    />
  );
}

// --------------------------------------------------------------------
// Category UI
// --------------------------------------------------------------------
function CategoryCard({ category, categoryProducts = [], fallbackImage, onOpenQuickView }) {
  return (
    <button
      type="button"
      onClick={() => onOpenQuickView?.(category)}
      className="group overflow-hidden rounded-[16px] border border-[#D8E6DD] bg-white text-left shadow-[0_8px_20px_rgba(17,29,19,0.06)] transition hover:-translate-y-1 hover:shadow-[0_16px_30px_rgba(17,29,19,0.10)]"
    >
      <div className="relative h-44 overflow-hidden bg-[#EDF8F0]">
        <CategoryThumb
          category={category}
          categoryProducts={categoryProducts}
          fallbackImage={fallbackImage}
          className="h-full w-full object-cover transition duration-500 group-hover:scale-105"
          loading="lazy"
        />

        <div className="absolute inset-0 bg-gradient-to-t from-[#081C15]/18 via-transparent to-transparent" />
      </div>

      <div className="space-y-3 p-4">
        <div className="flex items-center justify-between gap-3">
          <span className="rounded-full bg-[#F4FBF7] px-3 py-1 text-xs font-extrabold text-[#163322]">
            {formatCount(category?.count || category?.product_count)} products
          </span>

          <span className="inline-flex items-center gap-1 rounded-full border border-[#D8F3DC] bg-white px-3 py-1 text-xs font-bold text-[#163322] shadow-sm">
            <Eye size={13} />
            Quick view
          </span>
        </div>

        <div className="flex items-start justify-between gap-3">
          <div>
            <div className="text-xl font-black tracking-tight text-[#163322]">
              {category?.category || 'Category'}
            </div>
            <p className="mt-2 text-sm leading-6 text-[#5D7869]">
              {category?.tagline || 'Preview products in this category before registration.'}
            </p>
          </div>

          <div className="rounded-xl bg-[#F4FBF7] p-2.5 text-[#2D6A4F]">
            <Leaf size={16} />
          </div>
        </div>

        {safeArray(category?.preview_names).length ? (
          <div className="flex flex-wrap gap-2">
            {safeArray(category?.preview_names).slice(0, 3).map((name) => (
              <span
                key={`${category?.category}-${name}`}
                className="rounded-full bg-[#F4FBF7] px-3 py-1 text-xs font-semibold text-[#2D6A4F]"
              >
                {name}
              </span>
            ))}
          </div>
        ) : null}
      </div>
    </button>
  );
}

// --------------------------------------------------------------------
// Category quick view modal
// --------------------------------------------------------------------
function CategoryQuickViewModal({
  category,
  products,
  fallbackImage,
  onClose,
  onOpenFarmerDetails,
  onOpenAuth,
}) {
  if (!category) return null;

  return (
    <div className="fixed inset-0 z-[90] bg-[#081C15]/72 p-4 backdrop-blur-sm sm:p-6">
      <div className="mx-auto flex max-h-[92vh] w-full max-w-7xl flex-col overflow-hidden rounded-[24px] border border-white/15 bg-white shadow-[0_30px_80px_rgba(8,28,21,0.35)]">
        <div className="flex items-start justify-between gap-4 border-b border-[#E4F1E8] px-6 py-5 sm:px-8">
          <div className="max-w-3xl">
            <div className="text-xs font-extrabold uppercase tracking-[0.22em] text-[#2D6A4F]">
              Category quick view
            </div>
            <h3 className="mt-2 text-2xl font-black tracking-tight text-[#163322] sm:text-3xl">
              {category?.category || 'Category'}
            </h3>
            <p className="mt-2 text-sm leading-7 text-[#587667] sm:text-base">
              Visitors can preview products in this category before creating an account. To buy a
              product, registration is required.
            </p>
          </div>

          <button
            type="button"
            onClick={onClose}
            className="inline-flex h-11 w-11 items-center justify-center rounded-full border border-[#D8F3DC] bg-white text-[#163322] transition hover:bg-[#F4FBF7]"
            aria-label="Close quick view"
          >
            <X size={18} />
          </button>
        </div>

        <div className="overflow-y-auto px-6 py-6 sm:px-8">
          {products.length ? (
            <div className="grid gap-5 md:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-4">
              {products.map((product, idx) => (
                <div
                  key={product?.product_id || product?.id || product?.name || `category-product-${idx}`}
                  className="overflow-hidden rounded-[18px] border border-[#D8F3DC] bg-white shadow-[0_10px_24px_rgba(17,29,19,0.07)]"
                >
                  <div className="relative h-48 overflow-hidden bg-[#EDF8F0]">
                    <ProductThumb
                      product={product}
                      fallbackImage={fallbackImage}
                      className="h-full w-full object-cover"
                      loading="lazy"
                    />

                    <div className="absolute bottom-3 left-3 rounded-full bg-white/95 px-3 py-1 text-xs font-extrabold text-[#163322] shadow-sm">
                      {formatCurrency(product?.price)}
                    </div>
                  </div>

                  <div className="space-y-3 p-4">
                    <div>
                      <h4 className="line-clamp-1 text-lg font-extrabold text-[#163322]">
                        {product?.name || product?.product_name || 'Product'}
                      </h4>
                      <p className="mt-2 line-clamp-3 text-sm leading-6 text-[#587667]">
                        {product?.description || 'Fresh and marketplace-ready agricultural product.'}
                      </p>
                    </div>

                    <div className="flex flex-wrap gap-2 text-xs font-semibold text-[#2D6A4F]">
                      <button
                        type="button"
                        onClick={() => onOpenFarmerDetails?.(product)}
                        className="rounded-full bg-[#F4FBF7] px-3 py-1 transition hover:bg-[#EAF7EF]"
                      >
                        {product?.farmer_name || 'Verified farmer'}
                      </button>

                      <span className="rounded-full bg-[#F4FBF7] px-3 py-1">
                        {product?.location || 'Namibia'}
                      </span>

                      <span className="rounded-full bg-[#F4FBF7] px-3 py-1">
                        {formatQty(product?.stock_quantity ?? product?.stock ?? product?.quantity)} available
                      </span>
                    </div>

                    <div className="flex items-center justify-between gap-3 pt-1">
                      <div className="flex items-center gap-1 text-sm font-bold text-[#305C46]">
                        <Star size={16} className="fill-[#F4B400] text-[#F4B400]" />
                        {toNumber(product?.avg_rating, 0).toFixed(1)}
                        <span className="text-xs font-medium text-[#6A8777]">
                          ({formatCount(product?.rating_count)})
                        </span>
                      </div>

                      <StartActionButton
                        type="button"
                        onClick={() => onOpenAuth?.(AUTH_MODE_REGISTER, AUTH_ROLE_CUSTOMER)}
                        variant="primary"
                        className="min-w-[176px]"
                      >
                        Register to buy
                        <ArrowRight size={16} />
                      </StartActionButton>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="rounded-[18px] border border-dashed border-[#CFE9D7] bg-[#F8FCF8] p-8 text-sm text-[#587667]">
              No products are available in this category yet.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
// --------------------------------------------------------------------
// Farmer details drawer / bottom sheet
// --------------------------------------------------------------------
function FarmerDetailsPanel({
  farmer,
  products,
  fallbackImage,
  productFallbackImage,
  onClose,
  onOpenAuth,
}) {
  if (!farmer) return null;

  const farmerName = safeText(farmer?.farmer_name || farmer?.name, 'AgroConnect Farmer');
  const farmerLocation = safeText(farmer?.location, 'Namibia');
  const farmerInitial = farmerName.charAt(0).toUpperCase() || 'F';
  const intro =
    safeText(farmer?.seller_intro || farmer?.bio) ||
    'This public AgroConnect seller profile helps visitors inspect seller activity, specialties, and visible marketplace listings before registration.';
  const categories = safeArray(farmer?.featured_categories).slice(0, 6);
  const ratingValue = toNumber(farmer?.avg_rating, 0).toFixed(1);

  return (
    <div
      className="fixed inset-0 z-[95] bg-[#081C15]/72 backdrop-blur-sm"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
      aria-label="Farmer details"
    >
      <div
        className="absolute inset-x-0 bottom-0 flex max-h-[88vh] flex-col overflow-hidden rounded-t-[28px] border border-white/10 bg-white shadow-[0_30px_80px_rgba(8,28,21,0.35)] lg:inset-y-0 lg:left-auto lg:right-0 lg:h-full lg:max-h-screen lg:w-[580px] lg:rounded-none lg:rounded-l-[28px]"
        onClick={(event) => event.stopPropagation()}
      >
        <div className="flex-shrink-0 border-b border-[#E4F1E8] px-5 py-4 sm:px-6">
          <div className="flex items-center justify-between gap-4">
            <div>
              <div className="text-[11px] font-extrabold uppercase tracking-[0.22em] text-[#2D6A4F]">
                Seller details
              </div>
              <div className="mt-1 text-xl font-black text-[#163322]">Explore farmer profile</div>
            </div>

            <button
              type="button"
              onClick={onClose}
              className="inline-flex h-11 w-11 items-center justify-center rounded-full border border-[#D8F3DC] bg-white text-[#163322] transition hover:bg-[#F4FBF7]"
              aria-label="Close farmer details"
            >
              <X size={18} />
            </button>
          </div>
        </div>

        <div
          className="min-h-0 flex-1 overflow-y-auto overscroll-contain px-5 py-5 sm:px-6"
          style={{ WebkitOverflowScrolling: 'touch', touchAction: 'pan-y' }}
        >
          <div className="overflow-hidden rounded-[22px] border border-[#D8E6DD] bg-white shadow-[0_10px_22px_rgba(17,29,19,0.06)]">
            <div className="relative h-56 overflow-hidden bg-[#163322] sm:h-64">
              <FarmerThumb
                farmer={farmer}
                fallbackImage={fallbackImage}
                className="h-full w-full object-cover"
                loading="lazy"
              />

              <div className="absolute inset-0 bg-gradient-to-t from-[#081C15]/88 via-[#081C15]/46 to-transparent" />

              <div className="absolute left-4 right-4 top-4 flex items-start justify-between gap-3">
                <div className="min-w-0 rounded-[20px] bg-[#081C15]/78 px-3 py-3 text-white backdrop-blur-md shadow-[0_10px_24px_rgba(8,28,21,0.28)]">
                  <div className="flex items-center gap-3">
                    <div className="flex h-12 w-12 items-center justify-center rounded-full border border-white/18 bg-white/12 text-lg font-extrabold">
                      {farmerInitial}
                    </div>

                    <div className="min-w-0">
                      <div className="line-clamp-1 text-xl font-black">{farmerName}</div>
                      <div className="mt-1 inline-flex items-center gap-2 text-sm text-white/92">
                        <MapPin size={14} />
                        {farmerLocation}
                      </div>
                    </div>
                  </div>
                </div>

                <div className="rounded-full bg-white/94 px-3 py-1.5 text-xs font-extrabold text-[#163322] shadow-sm">
                  {formatCount(farmer?.product_count)} products
                </div>
              </div>
            </div>

            <div className="space-y-5 p-4 sm:p-5">
              <div className="rounded-[16px] border border-[#E6F2E9] bg-[#F8FCF9] p-4">
                <div className="text-xs font-extrabold uppercase tracking-[0.18em] text-[#2D6A4F]">
                  Seller overview
                </div>
                <p className="mt-2 text-sm leading-7 text-[#587667]">{intro}</p>
              </div>

              <div className="grid grid-cols-3 gap-3">
                <div className="rounded-[16px] bg-[#F4FBF7] p-3.5">
                  <div className="text-[11px] font-bold uppercase tracking-[0.16em] text-[#2D6A4F]">
                    Products
                  </div>
                  <div className="mt-2 text-2xl font-black text-[#163322]">
                    {formatCount(farmer?.product_count)}
                  </div>
                </div>

                <div className="rounded-[16px] bg-[#F4FBF7] p-3.5">
                  <div className="text-[11px] font-bold uppercase tracking-[0.16em] text-[#2D6A4F]">
                    Orders
                  </div>
                  <div className="mt-2 text-2xl font-black text-[#163322]">
                    {formatCount(farmer?.total_orders || farmer?.orders_count)}
                  </div>
                </div>

                <div className="rounded-[16px] bg-[#F4FBF7] p-3.5">
                  <div className="text-[11px] font-bold uppercase tracking-[0.16em] text-[#2D6A4F]">
                    Rating
                  </div>
                  <div className="mt-2 flex items-center gap-1 text-2xl font-black text-[#163322]">
                    <Star size={16} className="fill-[#F4B400] text-[#F4B400]" />
                    {ratingValue}
                  </div>
                </div>
              </div>

              <div>
                <div className="text-xs font-extrabold uppercase tracking-[0.18em] text-[#2D6A4F]">
                  Specialties
                </div>

                <div className="mt-3 flex flex-wrap gap-2">
                  {categories.length ? (
                    categories.map((category) => (
                      <span
                        key={`${farmer?.farmer_id || farmer?.id || farmerName}-${category}`}
                        className="rounded-full border border-[#D8F3DC] bg-white px-3 py-1.5 text-xs font-semibold text-[#2D6A4F]"
                      >
                        {category}
                      </span>
                    ))
                  ) : (
                    <span className="rounded-full border border-[#D8F3DC] bg-white px-3 py-1.5 text-xs font-semibold text-[#2D6A4F]">
                      Public marketplace seller
                    </span>
                  )}
                </div>
              </div>
            </div>
          </div>

          <div className="mt-6">
            <div className="mb-3">
              <div className="text-xs font-extrabold uppercase tracking-[0.18em] text-[#2D6A4F]">
                Visible listings
              </div>
              <div className="mt-1 text-lg font-black text-[#163322]">
                Top products from this seller
              </div>
            </div>

            {products.length ? (
              <div className="space-y-3">
                {products.map((product, idx) => (
                  <div
                    key={
                      product?.product_id ||
                      product?.id ||
                      product?.name ||
                      `farmer-product-${idx}`
                    }
                    className="flex items-center gap-3 rounded-[18px] border border-[#D8E6DD] bg-white p-3 shadow-[0_8px_20px_rgba(17,29,19,0.05)]"
                  >
                    <div className="h-16 w-16 flex-shrink-0 overflow-hidden rounded-[14px] bg-[#EDF8F0]">
                      <ProductThumb
                        product={product}
                        fallbackImage={productFallbackImage}
                        className="h-full w-full object-cover"
                        loading="lazy"
                      />
                    </div>

                    <div className="min-w-0 flex-1">
                      <div className="line-clamp-1 text-sm font-extrabold text-[#163322]">
                        {product?.name || product?.product_name || 'Marketplace product'}
                      </div>

                      <div className="mt-1 flex flex-wrap gap-2 text-xs font-semibold text-[#2D6A4F]">
                        <span className="rounded-full bg-[#F4FBF7] px-2.5 py-1">
                          {product?.category || 'Marketplace'}
                        </span>
                        <span className="rounded-full bg-[#F4FBF7] px-2.5 py-1">
                          {product?.location || 'Namibia'}
                        </span>
                      </div>
                    </div>

                    <div className="text-right">
                      <div className="text-sm font-black text-[#163322]">
                        {formatCurrency(product?.price)}
                      </div>
                      <div className="mt-1 text-xs text-[#6A8777]">
                        {formatQty(product?.stock_quantity ?? product?.stock ?? product?.quantity)}{' '}
                        available
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="rounded-[18px] border border-dashed border-[#CFE9D7] bg-[#F8FCF8] p-4 text-sm text-[#587667]">
                No visible public products found for this seller yet.
              </div>
            )}
          </div>
        </div>

        <div className="flex-shrink-0 border-t border-[#E4F1E8] bg-white px-5 py-4 sm:px-6">
          <div className="grid gap-3 sm:grid-cols-2">
            <StartActionButton
              type="button"
              onClick={() => onOpenAuth?.(AUTH_MODE_REGISTER, AUTH_ROLE_CUSTOMER)}
              variant="primary"
              className="w-full min-w-0"
            >
              <ShoppingCart size={17} />
              Register to Buy
            </StartActionButton>

            <StartActionButton
              type="button"
              onClick={() => onOpenAuth?.(AUTH_MODE_REGISTER, AUTH_ROLE_FARMER)}
              variant="light"
              className="w-full min-w-0"
            >
              <Store size={17} />
              Register to Sell
            </StartActionButton>
          </div>
        </div>
      </div>
    </div>
  );
}

// --------------------------------------------------------------------
// Featured slider
// --------------------------------------------------------------------
function FeaturedSlider({
  products,
  activeIndex,
  onPrevious,
  onNext,
  onJump,
  fallbackImage,
  onOpenFarmerDetails,
  onOpenAuth,
}) {
  const product = products[activeIndex] || null;
  if (!product) return null;

  return (
    <div className="overflow-hidden rounded-[16px] border border-[#D8E6DD] bg-white shadow-[0_8px_22px_rgba(17,29,19,0.07)]">
      <div className="grid lg:grid-cols-[1.25fr_0.75fr]">
        <div className="relative h-[320px] overflow-hidden bg-[#0F2419] sm:h-[360px]">
          <ProductThumb
            product={product}
            fallbackImage={fallbackImage}
            className="h-full w-full object-cover"
            loading="eager"
          />

          <div className="absolute inset-0 bg-gradient-to-r from-[#081C15]/80 via-[#081C15]/40 to-transparent" />
          <div className="absolute inset-0 bg-gradient-to-t from-[#081C15]/70 via-transparent to-transparent" />

          <div className="absolute left-5 top-5 inline-flex items-center gap-2 rounded-full border border-white/15 bg-white/12 px-3 py-1.5 text-xs font-extrabold uppercase tracking-[0.18em] text-white backdrop-blur-sm">
            <TrendingUp size={14} />
            Featured product
          </div>

          <div className="absolute bottom-5 left-5 right-5 max-w-[38rem] text-white">
            <div className="mb-3 flex flex-wrap gap-2">
              <span className="rounded-full bg-white/14 px-3 py-1 text-xs font-bold backdrop-blur-sm">
                {product?.category || 'Marketplace'}
              </span>
              <span className="rounded-full bg-[#52B788] px-3 py-1 text-xs font-bold text-[#081C15]">
                {formatCurrency(product?.price)}
              </span>
            </div>

            <h3 className="text-2xl font-black tracking-tight sm:text-3xl">
              {product?.name || product?.product_name || 'Featured product'}
            </h3>

            <p className="mt-3 max-w-2xl text-sm leading-7 text-white/94 sm:text-base">
              {product?.description ||
                'Discover quality farm products from verified AgroConnect sellers across Namibia.'}
            </p>

            <div className="mt-4 flex flex-wrap gap-2 text-xs text-white/92 sm:text-sm">
              <button
                type="button"
                onClick={() => onOpenFarmerDetails?.(product)}
                className="inline-flex items-center gap-2 rounded-full bg-white/10 px-3 py-1.5 backdrop-blur-sm"
              >
                <Store size={14} />
                {product?.farmer_name || 'Verified farmer'}
              </button>

              <span className="inline-flex items-center gap-2 rounded-full bg-white/10 px-3 py-1.5 backdrop-blur-sm">
                <MapPin size={14} />
                {product?.location || 'Namibia'}
              </span>

              <span className="inline-flex items-center gap-2 rounded-full bg-white/10 px-3 py-1.5 backdrop-blur-sm">
                <Package size={14} />
                {formatQty(product?.stock_quantity ?? product?.stock ?? product?.quantity)} in stock
              </span>
            </div>
          </div>
        </div>

        <div className="flex flex-col justify-between bg-[#F8FCF9] p-5 sm:p-6">
          <div>
            <div className="inline-flex items-center gap-2 rounded-full bg-[#EAF7EF] px-3 py-1 text-[11px] font-extrabold uppercase tracking-[0.18em] text-[#2D6A4F]">
              Explore first
            </div>

            <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-1 xl:grid-cols-2">
              <div className="rounded-[14px] border border-[#D8F3DC] bg-white p-4">
                <div className="text-[11px] font-bold uppercase tracking-[0.16em] text-[#2D6A4F]">
                  Average rating
                </div>
                <div className="mt-2 flex items-center gap-2 text-2xl font-black text-[#163322]">
                  <Star size={18} className="fill-[#F4B400] text-[#F4B400]" />
                  {toNumber(product?.avg_rating, 0).toFixed(1)}
                </div>
                <p className="mt-1 text-sm text-[#5A7766]">
                  {formatCount(product?.rating_count)} reviews
                </p>
              </div>

              <div className="rounded-[14px] border border-[#D8F3DC] bg-white p-4">
                <div className="text-[11px] font-bold uppercase tracking-[0.16em] text-[#2D6A4F]">
                  Marketplace activity
                </div>
                <div className="mt-2 text-2xl font-black text-[#163322]">
                  {formatCount(product?.orders_count || product?.order_count || product?.sales_count)}
                </div>
                <p className="mt-1 text-sm text-[#5A7766]">Visible order activity</p>
              </div>
            </div>

            <div className="mt-4 rounded-[14px] border border-[#D8F3DC] bg-white p-4">
              <div className="mb-2 text-sm font-bold text-[#1B4332]">Direct actions</div>
              <div className="flex flex-wrap gap-3">
                <StartActionButton
                  type="button"
                  onClick={() => scrollToSection('top-products')}
                  variant="soft"
                  className="min-w-[176px]"
                >
                  View top products
                  <ArrowRight size={16} />
                </StartActionButton>

                <StartActionButton
                  type="button"
                  onClick={() => scrollToSection('top-farmers')}
                  variant="soft"
                  className="min-w-[176px]"
                >
                  View top farmers
                  <ArrowRight size={16} />
                </StartActionButton>
              </div>
            </div>
          </div>

          <div className="mt-5 grid gap-3 sm:grid-cols-2">
            <StartActionButton
              type="button"
              onClick={() => onOpenAuth?.(AUTH_MODE_REGISTER, AUTH_ROLE_CUSTOMER)}
              variant="primary"
              className="w-full min-w-0"
            >
              <ShoppingCart size={17} />
              Register to Buy
            </StartActionButton>

            <StartActionButton
              type="button"
              onClick={() => onOpenAuth?.(AUTH_MODE_REGISTER, AUTH_ROLE_FARMER)}
              variant="light"
              className="w-full min-w-0"
            >
              <Store size={17} />
              Register to Sell
            </StartActionButton>
          </div>
        </div>
      </div>

      <div className="flex flex-wrap items-center justify-between gap-4 border-t border-[#E4F1E8] bg-white px-5 py-4">
        <div className="flex items-center gap-2">
          {products.map((item, idx) => (
            <button
              key={item?.product_id || item?.id || `featured-dot-${idx}`}
              type="button"
              onClick={() => onJump(idx)}
              aria-label={`Go to featured product ${idx + 1}`}
              className={`h-2.5 rounded-full transition ${
                idx === activeIndex ? 'w-8 bg-[#2D6A4F]' : 'w-2.5 bg-[#CFE9D7] hover:bg-[#95D5B2]'
              }`}
            />
          ))}
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={onPrevious}
            className="inline-flex h-11 w-11 items-center justify-center rounded-full border border-[#D8F3DC] bg-white text-[#1B4332] transition hover:bg-[#F4FBF7]"
            aria-label="Previous featured product"
          >
            <ChevronLeft size={18} />
          </button>

          <button
            type="button"
            onClick={onNext}
            className="inline-flex h-11 w-11 items-center justify-center rounded-full border border-[#D8F3DC] bg-white text-[#1B4332] transition hover:bg-[#F4FBF7]"
            aria-label="Next featured product"
          >
            <ChevronRight size={18} />
          </button>
        </div>
      </div>
    </div>
  );
}
// --------------------------------------------------------------------
// Product card
// --------------------------------------------------------------------
function ProductCard({ product, fallbackImage, onOpenFarmerDetails, onOpenAuth }) {
  return (
    <div className="group flex h-full flex-col overflow-hidden rounded-[16px] border border-[#D8E6DD] bg-white shadow-[0_8px_20px_rgba(17,29,19,0.06)] transition hover:-translate-y-1 hover:border-[#95D5B2] hover:shadow-[0_16px_30px_rgba(17,29,19,0.10)]">
      <div className="relative h-52 overflow-hidden bg-[#EDF8F0]">
        <ProductThumb
          product={product}
          fallbackImage={fallbackImage}
          className="h-full w-full object-cover transition duration-500 group-hover:scale-105"
          loading="lazy"
        />

        <div className="absolute inset-0 bg-gradient-to-t from-[#081C15]/78 via-transparent to-transparent" />

        <div className="absolute left-4 top-4 rounded-full bg-white/95 px-3 py-1 text-[11px] font-extrabold uppercase tracking-[0.16em] text-[#163322] shadow-sm">
          {product?.category || 'Marketplace'}
        </div>

        <div className="absolute bottom-4 left-4 right-4 flex items-end justify-between gap-3">
          <div className="rounded-[14px] bg-[#081C15]/60 px-3 py-2 text-white backdrop-blur-sm">
            <div className="text-[11px] font-bold uppercase tracking-[0.16em] text-white/84">
              Price
            </div>
            <div className="text-2xl font-extrabold text-white">
              {formatCurrency(product?.price)}
            </div>
          </div>

          <div className="rounded-full bg-white/16 px-3 py-1.5 text-xs font-bold text-white backdrop-blur-sm">
            {formatQty(product?.stock_quantity ?? product?.stock ?? product?.quantity)} available
          </div>
        </div>
      </div>

      <div className="flex flex-1 flex-col space-y-4 p-4">
        <div>
          <div className="line-clamp-1 text-xl font-extrabold text-[#163322]">
            {product?.name || product?.product_name || 'Untitled product'}
          </div>

          <p className="mt-2 line-clamp-3 text-sm leading-6 text-[#587667]">
            {product?.description || 'Fresh, local, and marketplace-ready agricultural goods.'}
          </p>
        </div>

        <div className="flex flex-wrap gap-2 text-xs font-semibold text-[#2D6A4F]">
          <button
            type="button"
            onClick={() => onOpenFarmerDetails?.(product)}
            className="rounded-full bg-[#F4FBF7] px-3 py-1 transition hover:bg-[#EAF7EF]"
          >
            {product?.farmer_name || 'Verified farmer'}
          </button>

          <span className="rounded-full bg-[#F4FBF7] px-3 py-1">
            {product?.location || 'Namibia'}
          </span>
        </div>

        <div className="mt-auto flex items-center justify-between gap-3">
          <div className="flex items-center gap-1 text-sm font-bold text-[#305C46]">
            <Star size={15} className="fill-[#F4B400] text-[#F4B400]" />
            {toNumber(product?.avg_rating, 0).toFixed(1)}
            <span className="text-xs font-medium text-[#6A8777]">
              ({formatCount(product?.rating_count)})
            </span>
          </div>

          <StartActionButton
            type="button"
            onClick={() => onOpenAuth?.(AUTH_MODE_REGISTER, AUTH_ROLE_CUSTOMER)}
            variant="primary"
            className="min-w-[140px] px-4"
          >
            Register
            <ArrowRight size={15} />
          </StartActionButton>
        </div>
      </div>
    </div>
  );
}

// --------------------------------------------------------------------
// Farmer card
// --------------------------------------------------------------------
function FarmerCard({ farmer, fallbackImage, onOpenDetails, index = 0 }) {
  const farmerName = safeText(farmer?.farmer_name || farmer?.name, 'AgroConnect Farmer');
  const farmerLocation = safeText(farmer?.location, 'Namibia');
  const farmerInitial = farmerName.charAt(0).toUpperCase() || 'F';
  const ratingValue = toNumber(farmer?.avg_rating, 0).toFixed(1);
  const categories = safeArray(farmer?.featured_categories).slice(0, 3);
  const summary =
    safeText(farmer?.seller_intro || farmer?.bio) ||
    'Public farmer profile visible before registration. Explore seller details and visible listings.';

  return (
    <div className="group flex h-full flex-col overflow-hidden rounded-[18px] border border-[#D8E6DD] bg-white shadow-[0_8px_20px_rgba(17,29,19,0.06)] transition hover:-translate-y-1 hover:border-[#95D5B2] hover:shadow-[0_16px_30px_rgba(17,29,19,0.10)]">
      <div className="relative h-40 overflow-hidden bg-[#163322]">
        <FarmerThumb
          farmer={farmer}
          index={index}
          fallbackImage={fallbackImage}
          className="h-full w-full object-cover transition duration-500 group-hover:scale-[1.03]"
          loading="lazy"
        />

        <div className="absolute inset-0 bg-gradient-to-t from-[#081C15]/88 via-[#081C15]/42 to-transparent" />

        <div className="absolute left-4 right-4 top-4 flex items-start justify-between gap-3">
          <div className="min-w-0 rounded-[18px] bg-[#081C15]/78 px-3 py-3 text-white backdrop-blur-md shadow-[0_10px_24px_rgba(8,28,21,0.28)]">
            <div className="flex items-center gap-3">
              <div className="flex h-11 w-11 items-center justify-center rounded-full border border-white/18 bg-white/12 text-base font-extrabold">
                {farmerInitial}
              </div>

              <div className="min-w-0">
                <div className="line-clamp-1 text-lg font-black">{farmerName}</div>
                <div className="mt-1 inline-flex items-center gap-2 text-xs text-white/92">
                  <MapPin size={13} />
                  {farmerLocation}
                </div>
              </div>
            </div>
          </div>

          <div className="rounded-full bg-white/94 px-3 py-1.5 text-xs font-extrabold text-[#163322] shadow-sm">
            View details
          </div>
        </div>
      </div>

      <div className="flex flex-1 flex-col p-4">
        <div className="rounded-[14px] border border-[#E6F2E9] bg-[#F8FCF9] px-3 py-3">
          <p className="line-clamp-2 text-sm leading-6 text-[#587667]">{summary}</p>
        </div>

        <div className="mt-4 grid grid-cols-3 gap-3">
          <div className="rounded-[14px] bg-[#F4FBF7] p-3">
            <div className="text-[11px] font-bold uppercase tracking-[0.16em] text-[#2D6A4F]">
              Products
            </div>
            <div className="mt-2 text-2xl font-extrabold text-[#163322]">
              {formatCount(farmer?.product_count)}
            </div>
          </div>

          <div className="rounded-[14px] bg-[#F4FBF7] p-3">
            <div className="text-[11px] font-bold uppercase tracking-[0.16em] text-[#2D6A4F]">
              Orders
            </div>
            <div className="mt-2 text-2xl font-extrabold text-[#163322]">
              {formatCount(farmer?.total_orders || farmer?.orders_count)}
            </div>
          </div>

          <div className="rounded-[14px] bg-[#F4FBF7] p-3">
            <div className="text-[11px] font-bold uppercase tracking-[0.16em] text-[#2D6A4F]">
              Rating
            </div>
            <div className="mt-2 flex items-center gap-1 text-2xl font-extrabold text-[#163322]">
              <Star size={16} className="fill-[#F4B400] text-[#F4B400]" />
              {ratingValue}
            </div>
          </div>
        </div>

        <div className="mt-4 flex flex-wrap gap-2">
          {categories.length ? (
            categories.map((category) => (
              <span
                key={`${farmer?.farmer_id || farmer?.id || farmerName}-${category}`}
                className="rounded-full border border-[#D8F3DC] bg-white px-3 py-1 text-xs font-semibold text-[#2D6A4F]"
              >
                {category}
              </span>
            ))
          ) : (
            <span className="rounded-full border border-[#D8F3DC] bg-white px-3 py-1 text-xs font-semibold text-[#2D6A4F]">
              Public marketplace seller
            </span>
          )}
        </div>

        <StartActionButton
          type="button"
          onClick={() => onOpenDetails?.(farmer)}
          variant="primary"
          className="mt-auto w-full min-w-0"
        >
          View farmer details
          <ArrowRight size={16} />
        </StartActionButton>
      </div>
    </div>
  );
}

// --------------------------------------------------------------------
// Main page
// --------------------------------------------------------------------
export default function StartScreen() {
  const location = useLocation();
  const navigate = useNavigate();

  const logoImage = `${process.env.PUBLIC_URL}/Assets/logo.png`;
  const productFallbackImage = buildDefaultProductArtwork('Marketplace Product');
  const farmerFallbackImage = buildDefaultFarmerArtwork('AgroConnect Farmer');

  const [homepage, setHomepage] = useState(null);
  const [allProducts, setAllProducts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [errorText, setErrorText] = useState('');
  const [activeSlide, setActiveSlide] = useState(0);
  const [selectedCategory, setSelectedCategory] = useState(null);
  const [selectedFarmer, setSelectedFarmer] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');

  const [authOpen, setAuthOpen] = useState(false);
  const [authMode, setAuthMode] = useState(AUTH_MODE_LOGIN);
  const [authDefaultRole, setAuthDefaultRole] = useState(AUTH_ROLE_CUSTOMER);

  useEffect(() => {
    let mounted = true;

    async function loadHomepage() {
      setLoading(true);
      setErrorText('');

      try {
        // Permanent frontend fix:
        // Use only the new lightweight public endpoint.
        // Do NOT call fetchProducts() from StartScreen because it can duplicate
        // heavy product loading and reintroduce timeout errors.
        const payload = await fetchPublicHomepage();

        if (!mounted) return;

        const homepagePayload = unwrapHomepagePayload(payload);
        const homepageProducts = extractProductsFromHomepage(homepagePayload);

        setHomepage(homepagePayload);
        setAllProducts(homepageProducts);
      } catch (error) {
        if (!mounted) return;

        setHomepage({});
        setAllProducts([]);
        setErrorText(error?.message || 'Could not load marketplace homepage.');
      } finally {
        if (mounted) {
          setLoading(false);
        }
      }
    }

    loadHomepage();

    return () => {
      mounted = false;
    };
  }, []);

  const productLookup = useMemo(() => buildProductLookup(allProducts), [allProducts]);

  const allHydratedProducts = useMemo(
    () => safeArray(allProducts).map((product) => hydrateProductRecord(product, productLookup)),
    [allProducts, productLookup]
  );

  const categoryProductMap = useMemo(
    () => buildCategoryProductMap(allHydratedProducts),
    [allHydratedProducts]
  );

  const derivedCategories = useMemo(
    () => deriveCategoriesFromProducts(allHydratedProducts, productFallbackImage),
    [allHydratedProducts, productFallbackImage]
  );

  const categories = useMemo(() => {
    const homepageCategories = safeArray(homepage?.categories);
    const baseRows = homepageCategories.length ? homepageCategories : derivedCategories;

    return baseRows.map((category) =>
      enrichCategoryRecord(category, categoryProductMap, productFallbackImage)
    );
  }, [homepage, derivedCategories, categoryProductMap, productFallbackImage]);

  const derivedTopProducts = useMemo(
    () => deriveTopProductsFromProducts(allHydratedProducts),
    [allHydratedProducts]
  );

  const topProducts = useMemo(() => {
    const homepageRows = safeArray(homepage?.top_products).map((product) =>
      hydrateProductRecord(product, productLookup)
    );

    const rows = homepageRows.length ? homepageRows : derivedTopProducts;
    return rows.slice(0, 16);
  }, [homepage, derivedTopProducts, productLookup]);

  const derivedTopFarmers = useMemo(
    () => deriveTopFarmersFromProducts(allHydratedProducts, farmerFallbackImage),
    [allHydratedProducts, farmerFallbackImage]
  );

  const topFarmers = useMemo(() => {
    const homepageFarmers = safeArray(homepage?.top_farmers);

    const rows = homepageFarmers.length
      ? homepageFarmers.map((farmer) => {
          const match = derivedTopFarmers.find((item) => {
            const itemId = safeText(item?.farmer_id || item?.id);
            const farmerId = safeText(farmer?.farmer_id || farmer?.id);
            const itemName = safeText(item?.farmer_name || item?.name).toLowerCase();
            const farmerName = safeText(farmer?.farmer_name || farmer?.name).toLowerCase();

            return (
              (farmerId && itemId && farmerId === itemId) ||
              (farmerName && itemName && farmerName === itemName)
            );
          });

          return match ? mergePreferPrimary(farmer, match) : farmer;
        })
      : derivedTopFarmers;

    return rows.slice(0, 8);
  }, [homepage, derivedTopFarmers]);

  const featuredProducts = useMemo(
    () => buildFeaturedProducts(homepage, allHydratedProducts, productLookup),
    [homepage, allHydratedProducts, productLookup]
  );
  const allMarketplaceProducts = useMemo(
    () =>
      uniqueByKey(
        [
          ...safeArray(allHydratedProducts),
          ...safeArray(featuredProducts),
          ...safeArray(topProducts),
        ],
        (row) => row?.product_id || row?.id || row?.name
      ),
    [allHydratedProducts, featuredProducts, topProducts]
  );

  const topDeckCategories = categories.slice(0, 4);
  const topDeckProducts = topProducts.slice(0, 4);
  const topDeckFarmers = topFarmers.slice(0, 4);
  const heroFeatured = featuredProducts[0] || topProducts[0] || null;

  const selectedCategoryProducts = useMemo(() => {
    const categoryName = safeText(selectedCategory?.category).toLowerCase();
    if (!categoryName) return [];

    return allMarketplaceProducts
      .filter((product) => safeText(product?.category).toLowerCase() === categoryName)
      .slice(0, 12);
  }, [selectedCategory, allMarketplaceProducts]);

  const selectedFarmerProducts = useMemo(() => {
    if (!selectedFarmer) return [];
    return deriveFarmerProducts(allMarketplaceProducts, selectedFarmer);
  }, [allMarketplaceProducts, selectedFarmer]);

  const filteredTopProducts = useMemo(() => {
    const term = safeText(searchTerm).toLowerCase();
    if (!term) return topProducts;

    return allMarketplaceProducts
      .filter((product) => {
        const haystack = [
          product?.name,
          product?.product_name,
          product?.category,
          product?.farmer_name,
          product?.location,
          product?.description,
        ]
          .map((value) => safeText(value).toLowerCase())
          .join(' ');

        return haystack.includes(term);
      })
      .slice(0, 16);
  }, [searchTerm, topProducts, allMarketplaceProducts]);

  function resolveFarmerFromProduct(product) {
    const productFarmerId = safeText(product?.farmer_id);
    const productFarmerName = safeText(product?.farmer_name || product?.seller_name);

    const matched =
      topFarmers.find((farmer) => {
        const farmerId = safeText(farmer?.farmer_id || farmer?.id);
        const farmerName = safeText(farmer?.farmer_name || farmer?.name).toLowerCase();

        if (productFarmerId && farmerId && productFarmerId === farmerId) return true;
        if (productFarmerName && farmerName && productFarmerName.toLowerCase() === farmerName) {
          return true;
        }

        return false;
      }) ||
      derivedTopFarmers.find((farmer) => {
        const farmerId = safeText(farmer?.farmer_id || farmer?.id);
        const farmerName = safeText(farmer?.farmer_name || farmer?.name).toLowerCase();

        if (productFarmerId && farmerId && productFarmerId === farmerId) return true;
        if (productFarmerName && farmerName && productFarmerName.toLowerCase() === farmerName) {
          return true;
        }

        return false;
      });

    if (matched) return matched;

    return {
      farmer_id: productFarmerId || productFarmerName || 'public-farmer',
      farmer_name: productFarmerName || 'AgroConnect Farmer',
      location: product?.location || 'Namibia',
      product_count: 1,
      total_orders: toNumber(
        product?.orders_count || product?.order_count || product?.sales_count,
        0
      ),
      avg_rating: toNumber(product?.avg_rating, 0),
      featured_categories: product?.category ? [safeText(product.category)] : [],
      image_url: getPrimaryProductImage(product, farmerFallbackImage),
      hero_image_url: getPrimaryProductImage(product, farmerFallbackImage),
      seller_intro:
        'This public AgroConnect seller profile helps visitors inspect seller activity, specialties, and visible marketplace listings before registration.',
    };
  }

  function openCategoryQuickView(category) {
    const categoryName = typeof category === 'string' ? category : category?.category;
    if (!categoryName) return;

    const fullCategory =
      categories.find(
        (item) => normalizeCategoryKey(item?.category) === normalizeCategoryKey(categoryName)
      ) || {
        category: categoryName,
      };

    setSelectedFarmer(null);
    setSelectedCategory(fullCategory);
  }

  function openFarmerDetails(record) {
    if (!record) return;

    const farmer = looksLikeProduct(record) ? resolveFarmerFromProduct(record) : record;

    setSelectedCategory(null);
    setSelectedFarmer(farmer);
  }

  function handleMarketplaceSearchSubmit(event) {
    event.preventDefault();
    scrollToSection('top-products');
  }

  function openAuthDialog(mode, role = AUTH_ROLE_CUSTOMER) {
    setAuthMode(mode);
    setAuthDefaultRole(role);
    setAuthOpen(true);
  }

  function closeAuthDialog() {
    setAuthOpen(false);
  }

  function handleAuthModeChange(mode) {
    setAuthMode(mode);
  }

  useEffect(() => {
    const requestedMode = location.state?.authMode || location.state?.openAuthMode;
    const requestedRole = String(
      location.state?.defaultRole || location.state?.registrationRole || AUTH_ROLE_CUSTOMER
    )
      .trim()
      .toLowerCase();

    if (!requestedMode) return;

    const normalizedRole =
      requestedRole === AUTH_ROLE_FARMER || requestedRole === 'farmer' || requestedRole === 'seller'
        ? AUTH_ROLE_FARMER
        : AUTH_ROLE_CUSTOMER;

    openAuthDialog(requestedMode, normalizedRole);

    navigate(`${location.pathname}${location.search}${location.hash}`, {
      replace: true,
      state: null,
    });
  }, [location, navigate]);

  useEffect(() => {
    if (!selectedCategory && !selectedFarmer) return undefined;

    const previousBodyOverflow = document.body.style.overflow;
    const previousHtmlOverflow = document.documentElement.style.overflow;

    document.body.style.overflow = 'hidden';
    document.documentElement.style.overflow = 'hidden';

    const handleKeydown = (event) => {
      if (event.key === 'Escape') {
        setSelectedCategory(null);
        setSelectedFarmer(null);
      }
    };

    window.addEventListener('keydown', handleKeydown);

    return () => {
      document.body.style.overflow = previousBodyOverflow;
      document.documentElement.style.overflow = previousHtmlOverflow;
      window.removeEventListener('keydown', handleKeydown);
    };
  }, [selectedCategory, selectedFarmer]);

  useEffect(() => {
    if (!featuredProducts.length) return undefined;

    const timer = window.setInterval(() => {
      setActiveSlide((current) => (current + 1) % featuredProducts.length);
    }, AUTOPLAY_MS);

    return () => window.clearInterval(timer);
  }, [featuredProducts.length]);

  useEffect(() => {
    if (!featuredProducts.length) {
      setActiveSlide(0);
      return;
    }

    if (activeSlide >= featuredProducts.length) {
      setActiveSlide(0);
    }
  }, [activeSlide, featuredProducts.length]);

  const handlePrevSlide = () => {
    if (!featuredProducts.length) return;
    setActiveSlide((current) => (current - 1 + featuredProducts.length) % featuredProducts.length);
  };

  const handleNextSlide = () => {
    if (!featuredProducts.length) return;
    setActiveSlide((current) => (current + 1) % featuredProducts.length);
  };

  return (
    <div className="min-h-[100svh] overflow-x-hidden bg-[#E9EFEB] text-[#163322]">
      {selectedCategory ? (
        <CategoryQuickViewModal
          category={selectedCategory}
          products={selectedCategoryProducts}
          fallbackImage={productFallbackImage}
          onClose={() => setSelectedCategory(null)}
          onOpenFarmerDetails={openFarmerDetails}
          onOpenAuth={openAuthDialog}
        />
      ) : null}

      {selectedFarmer ? (
        <FarmerDetailsPanel
          farmer={selectedFarmer}
          products={selectedFarmerProducts}
          fallbackImage={farmerFallbackImage}
          productFallbackImage={productFallbackImage}
          onClose={() => setSelectedFarmer(null)}
          onOpenAuth={openAuthDialog}
        />
      ) : null}

      <AuthDialog
        open={authOpen}
        mode={authMode}
        defaultRole={authDefaultRole}
        onClose={closeAuthDialog}
        onModeChange={handleAuthModeChange}
      />

      <header className="relative z-20">
        <div className="bg-[#163322] text-white shadow-[0_10px_24px_rgba(8,28,21,0.14)]">
          <PageContainer className="py-3">
            <div className="grid gap-3 lg:grid-cols-[auto_1fr_auto] lg:items-center">
              <button
                type="button"
                onClick={() => window.scrollTo({ top: 0, behavior: 'smooth' })}
                className="flex items-center gap-3 text-left"
              >
                <img
                  src={logoImage}
                  alt="AgroConnect Logo"
                  className="h-14 w-auto rounded-xl bg-white/95 p-2"
                />
                <div>
                  <div className="text-[11px] font-extrabold uppercase tracking-[0.22em] text-[#D8F3DC]">
                    Public marketplace
                  </div>
                  <div className="text-2xl font-black tracking-tight text-white">
                    AgroConnect Namibia
                  </div>
                </div>
              </button>

              <form onSubmit={handleMarketplaceSearchSubmit} className="w-full">
                <div className="flex w-full overflow-hidden rounded-[12px] border border-[#95D5B2] bg-white shadow-[0_8px_18px_rgba(8,28,21,0.16)]">
                  <div className="flex items-center px-4 text-[#587667]">
                    <Search size={18} />
                  </div>
                  <input
                    type="text"
                    value={searchTerm}
                    onChange={(event) => setSearchTerm(event.target.value)}
                    placeholder="Search public products, categories, or farmers"
                    className="w-full border-0 bg-white px-2 py-3 text-sm text-[#163322] outline-none placeholder:text-[#839A8D]"
                  />
                  <button
                    type="submit"
                    className="bg-[#52B788] px-5 text-sm font-extrabold text-[#081C15] transition hover:bg-[#74C69D]"
                  >
                    Search
                  </button>
                </div>
              </form>

              <div className="flex flex-wrap items-center gap-2 justify-start lg:justify-end">
                <HeaderNavButton
                  icon={LogIn}
                  label="Login"
                  onClick={() => openAuthDialog(AUTH_MODE_LOGIN, AUTH_ROLE_CUSTOMER)}
                />
                <HeaderNavButton
                  icon={ShoppingCart}
                  label="Register to Buy"
                  onClick={() => openAuthDialog(AUTH_MODE_REGISTER, AUTH_ROLE_CUSTOMER)}
                  accent
                />
                <StartActionButton
                  type="button"
                  onClick={() => openAuthDialog(AUTH_MODE_REGISTER, AUTH_ROLE_FARMER)}
                  variant="light"
                >
                  <Store size={16} />
                  Register to Sell
                </StartActionButton>
              </div>
            </div>
          </PageContainer>
        </div>
      </header>

      <main className="relative pb-20 pt-8 sm:pt-10 lg:pt-12">
        <PageContainer className="space-y-10">
          <div className="grid gap-6 xl:grid-cols-4">
            <DeckPanel
              eyebrow="Browse"
              title="Marketplace categories"
              subtitle="Open a category and preview real public listings before registration."
              actionLabel="Open categories"
              onAction={() => scrollToSection('categories')}
            >
              <div className="grid grid-cols-2 gap-3">
                {topDeckCategories.length ? (
                  topDeckCategories.map((item, idx) => (
                    <button
                      key={item?.category || `deck-category-${idx}`}
                      type="button"
                      onClick={() => openCategoryQuickView(item)}
                      className="overflow-hidden rounded-[14px] border border-[#D8E6DD] bg-[#F7FBF8] text-left transition hover:-translate-y-0.5 hover:bg-white"
                    >
                      <div className="h-24 overflow-hidden bg-[#EDF8F0]">
                        <CategoryThumb
                          category={item}
                          categoryProducts={safeArray(
                            categoryProductMap.get(normalizeCategoryKey(item?.category))
                          )}
                          fallbackImage={productFallbackImage}
                          className="h-full w-full object-cover"
                          loading="lazy"
                        />
                      </div>
                      <div className="p-3">
                        <div className="line-clamp-1 text-sm font-extrabold text-[#163322]">
                          {item?.category}
                        </div>
                        <div className="mt-1 text-xs text-[#587667]">
                          {formatCount(item?.count || item?.product_count)} products
                        </div>
                      </div>
                    </button>
                  ))
                ) : (
                  <div className="col-span-2 rounded-[14px] border border-dashed border-[#D8E6DD] bg-[#F7FBF8] p-4 text-sm text-[#587667]">
                    Categories will appear here when public products are available.
                  </div>
                )}
              </div>
            </DeckPanel>

            <DeckPanel
              eyebrow="Featured now"
              title={heroFeatured?.name || heroFeatured?.product_name || 'Marketplace highlight'}
              subtitle={
                heroFeatured?.description ||
                'A highlighted public product from the current marketplace feed.'
              }
              actionLabel="See featured section"
              onAction={() => scrollToSection('featured-products')}
            >
              {heroFeatured ? (
                <button
                  type="button"
                  onClick={() => scrollToSection('featured-products')}
                  className="block overflow-hidden rounded-[14px] border border-[#D8E6DD] bg-[#F7FBF8] text-left transition hover:-translate-y-0.5 hover:bg-white"
                >
                  <div className="relative h-48 overflow-hidden bg-[#EDF8F0]">
                    <ProductThumb
                      product={heroFeatured}
                      fallbackImage={productFallbackImage}
                      className="h-full w-full object-cover"
                      loading="lazy"
                    />
                    <div className="absolute bottom-3 left-3 rounded-full bg-white/95 px-3 py-1 text-xs font-extrabold text-[#163322] shadow-sm">
                      {formatCurrency(heroFeatured?.price)}
                    </div>
                  </div>

                  <div className="space-y-2 p-4">
                    <div className="line-clamp-1 text-lg font-extrabold text-[#163322]">
                      {heroFeatured?.name || heroFeatured?.product_name}
                    </div>
                    <div className="flex flex-wrap gap-2 text-xs font-semibold text-[#2D6A4F]">
                      <span className="rounded-full bg-[#F4FBF7] px-3 py-1">
                        {heroFeatured?.category || 'Marketplace'}
                      </span>
                      <button
                        type="button"
                        onClick={(event) => {
                          event.stopPropagation();
                          openFarmerDetails(heroFeatured);
                        }}
                        className="rounded-full bg-[#F4FBF7] px-3 py-1 transition hover:bg-[#EAF7EF]"
                      >
                        {heroFeatured?.farmer_name || 'Verified farmer'}
                      </button>
                    </div>
                  </div>
                </button>
              ) : (
                <div className="rounded-[14px] border border-dashed border-[#D8E6DD] bg-[#F7FBF8] p-4 text-sm text-[#587667]">
                  Featured products will appear here automatically.
                </div>
              )}
            </DeckPanel>

            <DeckPanel
              eyebrow="High-performing"
              title="Top products"
              subtitle="Quickly review what is performing well before you decide to register as a buyer."
              actionLabel="Open top products"
              onAction={() => scrollToSection('top-products')}
            >
              <div className="space-y-3">
                {topDeckProducts.length ? (
                  topDeckProducts.map((product, idx) => (
                    <button
                      key={product?.product_id || product?.id || product?.name || `deck-product-${idx}`}
                      type="button"
                      onClick={() => scrollToSection('top-products')}
                      className="flex w-full items-center gap-3 rounded-[14px] border border-[#D8E6DD] bg-[#F7FBF8] p-3 text-left transition hover:-translate-y-0.5 hover:bg-white"
                    >
                      <div className="h-14 w-14 flex-shrink-0 overflow-hidden rounded-xl bg-[#EDF8F0]">
                        <ProductThumb
                          product={product}
                          fallbackImage={productFallbackImage}
                          className="h-full w-full object-cover"
                          loading="lazy"
                        />
                      </div>

                      <div className="min-w-0 flex-1">
                        <div className="line-clamp-1 text-sm font-extrabold text-[#163322]">
                          {product?.name || product?.product_name}
                        </div>
                        <div className="mt-1 text-xs text-[#587667]">
                          {product?.category || 'Marketplace'}
                        </div>
                        <div className="mt-1 text-sm font-bold text-[#2D6A4F]">
                          {formatCurrency(product?.price)}
                        </div>
                      </div>
                    </button>
                  ))
                ) : (
                  <div className="rounded-[14px] border border-dashed border-[#D8E6DD] bg-[#F7FBF8] p-4 text-sm text-[#587667]">
                    Top products will appear here automatically.
                  </div>
                )}
              </div>
            </DeckPanel>

            <DeckPanel
              eyebrow="Trusted sellers"
              title="Top farmers"
              subtitle="Open a seller profile to inspect more marketplace details before registration."
              actionLabel="Open top farmers"
              onAction={() => scrollToSection('top-farmers')}
            >
              <div className="space-y-3">
                {topDeckFarmers.length ? (
                  topDeckFarmers.map((farmer, idx) => (
                    <button
                      key={
                        farmer?.farmer_id ||
                        farmer?.id ||
                        farmer?.farmer_name ||
                        `deck-farmer-${idx}`
                      }
                      type="button"
                      onClick={() => openFarmerDetails(farmer)}
                      className="flex w-full items-center gap-3 rounded-[14px] border border-[#D8E6DD] bg-[#F7FBF8] p-3 text-left transition hover:-translate-y-0.5 hover:bg-white"
                    >
                      <div className="h-14 w-14 flex-shrink-0 overflow-hidden rounded-xl bg-[#EDF8F0]">
                        <FarmerThumb
                          farmer={farmer}
                          index={idx}
                          fallbackImage={farmerFallbackImage}
                          className="h-full w-full object-cover"
                          loading="lazy"
                        />
                      </div>

                      <div className="min-w-0 flex-1">
                        <div className="line-clamp-1 text-sm font-extrabold text-[#163322]">
                          {farmer?.farmer_name || farmer?.name}
                        </div>
                        <div className="mt-1 text-xs text-[#587667]">
                          {farmer?.location || 'Namibia'}
                        </div>
                        <div className="mt-1 text-xs font-semibold text-[#2D6A4F]">
                          {formatCount(farmer?.product_count)} products •{' '}
                          {formatCount(farmer?.total_orders || farmer?.orders_count)} orders
                        </div>
                      </div>
                    </button>
                  ))
                ) : (
                  <div className="rounded-[14px] border border-dashed border-[#D8E6DD] bg-[#F7FBF8] p-4 text-sm text-[#587667]">
                    Top farmers will appear here automatically.
                  </div>
                )}
              </div>
            </DeckPanel>
          </div>

          <AmazonShelf id="categories" className="p-6 sm:p-8 xl:p-10">
            <ShelfHeader
              eyebrow="Marketplace categories"
              title="Browse the marketplace by category"
              subtitle="Open any category to preview real marketplace products, compare listings, and understand what is publicly available before registration."
              actionLabel="Go to top products"
              actionTo="top-products"
              actionKind="section"
            />

            {loading ? (
              <div className="grid gap-6 md:grid-cols-2 xl:grid-cols-4">
                {Array.from({ length: 8 }).map((_, idx) => (
                  <LoadingCard key={`category-loading-${idx}`} className="h-[320px]" />
                ))}
              </div>
            ) : categories.length ? (
              <div className="grid gap-6 md:grid-cols-2 xl:grid-cols-4">
                {categories.map((category, idx) => (
                  <CategoryCard
                    key={category?.category || `category-${idx}`}
                    category={category}
                    categoryProducts={safeArray(
                      categoryProductMap.get(normalizeCategoryKey(category?.category))
                    )}
                    fallbackImage={productFallbackImage}
                    onOpenQuickView={openCategoryQuickView}
                  />
                ))}
              </div>
            ) : (
              <div className="rounded-[14px] border border-dashed border-[#CFE9D7] bg-[#F8FCF8] p-6 text-sm text-[#587667]">
                No categories are available yet. This section will populate automatically when public
                products exist in the database.
              </div>
            )}
          </AmazonShelf>

          <AmazonShelf id="featured-products" className="p-6 sm:p-8 xl:p-10">
            <ShelfHeader
              eyebrow="Featured products"
              title="Spotlight products from the live marketplace"
              subtitle="The highlighted product area gives visitors a clearer, more premium, and discovery-led overview of the marketplace."
              actionLabel="See top farmers"
              actionTo="top-farmers"
              actionKind="section"
            />

            {loading ? (
              <LoadingCard className="h-[440px]" />
            ) : featuredProducts.length ? (
              <FeaturedSlider
                products={featuredProducts}
                activeIndex={activeSlide}
                onPrevious={handlePrevSlide}
                onNext={handleNextSlide}
                onJump={setActiveSlide}
                fallbackImage={productFallbackImage}
                onOpenFarmerDetails={openFarmerDetails}
                onOpenAuth={openAuthDialog}
              />
            ) : (
              <div className="rounded-[14px] border border-dashed border-[#CFE9D7] bg-[#F8FCF8] p-8 text-sm text-[#587667]">
                Featured products are not available yet. Once approved public products exist, this
                section will update automatically.
              </div>
            )}
          </AmazonShelf>

          <AmazonShelf id="top-products" className="p-6 sm:p-8 xl:p-10">
            <ShelfHeader
              eyebrow="Top products"
              title={searchTerm ? `Search results for "${searchTerm}"` : 'Top marketplace products'}
              subtitle={
                searchTerm
                  ? 'Filtered public marketplace products based on your search.'
                  : 'Public visitors can review high-performing marketplace products first and register only when they are ready to purchase.'
              }
              actionLabel="Register to buy"
              actionKind="callback"
              onActionClick={() => openAuthDialog(AUTH_MODE_REGISTER, AUTH_ROLE_CUSTOMER)}
            />

            {loading ? (
              <div className="grid gap-6 md:grid-cols-2 xl:grid-cols-4 2xl:grid-cols-5">
                {Array.from({ length: 10 }).map((_, idx) => (
                  <LoadingCard key={`product-loading-${idx}`} className="h-[420px]" />
                ))}
              </div>
            ) : filteredTopProducts.length ? (
              <div className="grid gap-6 md:grid-cols-2 xl:grid-cols-4 2xl:grid-cols-5">
                {filteredTopProducts.map((product, idx) => (
                  <ProductCard
                    key={product?.product_id || product?.id || `product-${idx}`}
                    product={product}
                    fallbackImage={productFallbackImage}
                    onOpenFarmerDetails={openFarmerDetails}
                    onOpenAuth={openAuthDialog}
                  />
                ))}
              </div>
            ) : (
              <div className="rounded-[14px] border border-dashed border-[#CFE9D7] bg-[#F8FCF8] p-6 text-sm text-[#587667]">
                No public products match your search.
              </div>
            )}
          </AmazonShelf>

          <AmazonShelf id="top-farmers" className="p-6 sm:p-8 xl:p-10">
            <ShelfHeader
              eyebrow="Top farmers"
              title="Meet leading farmers on AgroConnect"
              subtitle="Open a seller card to inspect more seller details before registration."
              actionLabel="Register to sell"
              actionKind="callback"
              onActionClick={() => openAuthDialog(AUTH_MODE_REGISTER, AUTH_ROLE_FARMER)}
            />

            {loading ? (
              <div className="grid gap-6 md:grid-cols-2 xl:grid-cols-4">
                {Array.from({ length: 8 }).map((_, idx) => (
                  <LoadingCard key={`farmer-loading-${idx}`} className="h-[410px]" />
                ))}
              </div>
            ) : topFarmers.length ? (
              <div className="grid gap-6 md:grid-cols-2 xl:grid-cols-4">
                {topFarmers.map((farmer, idx) => (
                  <FarmerCard
                    key={farmer?.farmer_id || farmer?.id || `farmer-${idx}`}
                    farmer={farmer}
                    index={idx}
                    fallbackImage={farmerFallbackImage}
                    onOpenDetails={openFarmerDetails}
                  />
                ))}
              </div>
            ) : (
              <div className="rounded-[14px] border border-dashed border-[#CFE9D7] bg-[#F8FCF8] p-6 text-sm text-[#587667]">
                Top farmers will appear here once the platform has enough public marketplace activity.
              </div>
            )}
          </AmazonShelf>

          {errorText ? (
            <div className="rounded-[14px] border border-[#FFD7D7] bg-[#FFF5F5] px-5 py-4 text-sm font-medium text-[#9B2C2C] shadow-sm">
              {errorText}
            </div>
          ) : null}
        </PageContainer>
      </main>
    </div>
  );
}