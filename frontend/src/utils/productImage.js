// ============================================================================
// frontend/src/utils/productImage.js — Product Image Resolver (shared)
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Central place to resolve product image URLs with robust fallbacks.
//
// FIXES IN THIS VERSION:
//   ✅ Fixes broken regex/string syntax that caused parser errors
//   ✅ No globalThis usage (fixes ESLint no-undef)
//   ✅ Handles Windows absolute file paths stored in DB (extracts /public/...)
//   ✅ Prevents stored generic default images from winning too early
//   ✅ Tries product-name guesses before falling back to default artwork
//   ✅ Adds exact-case overrides for common bundled marketplace products
//   ✅ Stronger fallback candidates for frontend public assets + backend uploads
//   ✅ Deterministic cache-busting for mutable image paths
// ============================================================================


export const PLACEHOLDER_IMG =
  "data:image/svg+xml;charset=UTF-8," +
  encodeURIComponent(`
  <svg xmlns="http://www.w3.org/2000/svg" width="640" height="480">
    <rect width="100%" height="100%" fill="#f1f5f9"/>
    <rect x="40" y="40" width="560" height="400" rx="28" fill="#ffffff" stroke="#e2e8f0" stroke-width="4"/>
    <path d="M140 340l90-110 80 90 110-140 140 160" fill="none" stroke="#94a3b8" stroke-width="10" stroke-linecap="round" stroke-linejoin="round"/>
    <circle cx="245" cy="190" r="32" fill="#cbd5e1"/>
    <text x="320" y="420" font-size="26" text-anchor="middle" fill="#64748b" font-family="Arial, sans-serif">No image</text>
  </svg>
`);

export const DEFAULT_PRODUCT_IMG = "/Assets/product_images/default.jpg";

// ----------------------------------------------------------------------------
// Low-level helpers
// ----------------------------------------------------------------------------
function cleanStr(x) {
  return String(x ?? "").trim();
}

function uniq(list) {
  const out = [];
  const seen = new Set();

  for (const v of list || []) {
    const s = cleanStr(v);
    if (!s) continue;
    if (seen.has(s)) continue;
    seen.add(s);
    out.push(s);
  }

  return out;
}

function stripTrailingSlash(s) {
  return cleanStr(s).replace(/\/+$/, "");
}

function isAbsUrl(s) {
  const v = cleanStr(s);
  return /^(https?:)?\/\//i.test(v) || /^data:/i.test(v) || /^blob:/i.test(v);
}

function isRootPath(s) {
  return cleanStr(s).startsWith("/");
}

function hasFileExt(name) {
  return /\.[a-z0-9]+$/i.test(cleanStr(name));
}

function isPublicAssetPath(path) {
  const p = cleanStr(path);
  return /^(?:\/)?(?:Assets|assets)\//.test(p) || /^(?:\/)?(?:product_images|images\/product_images)\//.test(p);
}

function isApiUploadPath(path) {
  return /^\/api\/uploads\//i.test(cleanStr(path));
}

function isUploadsPath(path) {
  return /^\/uploads\//i.test(cleanStr(path));
}

function looksLikeUploadFilename(name) {
  const base = cleanStr(name).split("/").pop() || "";
  const stem = base.replace(/\.[^.]+$/, "");
  return /^[a-f0-9]{24,}$/i.test(stem) || /^[a-f0-9-]{30,}$/i.test(stem);
}

function toCanonicalRootPath(path) {
  // FILE ROLE:
  // Normalize stored image paths into browser-safe root paths.
  //
  // Important:
  //   - Do not create /api/uploads/api/uploads/...
  //   - Keep frontend public assets under /Assets/...
  //   - Keep backend runtime uploads under /api/uploads/...
  const raw = cleanStr(path).replace(/\\/g, "/").trim();
  if (!raw) return "";

  let p = raw;

  // Preserve absolute/external URLs.
  if (isAbsUrl(p) || /^blob:/i.test(p) || /^data:/i.test(p)) return p;

  // Ensure a single leading slash for app-relative paths.
  p = p.replace(/^\/+/, "/");
  if (!p.startsWith("/")) p = `/${p}`;

  // Collapse known bad duplicated prefixes.
  p = p
    .replace(/^\/api\/api\//i, "/api/")
    .replace(/^\/api\/uploads\/api\/uploads\//i, "/api/uploads/")
    .replace(/^\/uploads\/api\/uploads\//i, "/api/uploads/")
    .replace(/^\/api\/uploads\/uploads\//i, "/api/uploads/")
    .replace(/^\/uploads\/uploads\//i, "/uploads/")
    .replace(/^\/assets\//i, "/Assets/");

  // Normalize plain /uploads/... into the Flask-served API upload path.
  if (/^\/uploads\//i.test(p)) {
    p = p.replace(/^\/uploads\//i, "/api/uploads/");
  }

  if (isGenericDefaultImage(p)) return DEFAULT_PRODUCT_IMG;

  return p.replace(/\/{2,}/g, "/");
}

function toExtVariants(base) {
  const b = cleanStr(base);
  if (!b) return [];
  return ["jpg", "jpeg", "png", "webp"].map((ext) => `${b}.${ext}`);
}

// ----------------------------------------------------------------------------
// Environment helpers (NO globalThis)
// ----------------------------------------------------------------------------
function getWindowOrigin() {
  if (typeof window !== "undefined" && window?.location?.origin) {
    return window.location.origin;
  }
  return "";
}

function publicBase() {
  // CRA runtime env
  try {
    // eslint-disable-next-line no-undef
    const u =
      typeof process !== "undefined" && process?.env ? process.env.PUBLIC_URL : "";
    return stripTrailingSlash(u || "");
  } catch {
    return "";
  }
}

function withPublicBase(path) {
  const p = cleanStr(path);
  if (!p || isAbsUrl(p)) return p;

  const base = publicBase();
  if (!base) return p;

  return `${base}${p.startsWith("/") ? "" : "/"}${p}`;
}

function withVersion(url, version) {
  const u = cleanStr(url);
  const v = cleanStr(version);
  if (!u || !v) return u;
  if (u.startsWith("data:") || u.startsWith("blob:")) return u;
  if (/[?&]v=/.test(u)) return u;
  return `${u}${u.includes("?") ? "&" : "?"}v=${encodeURIComponent(v)}`;
}

function isExternalHttpUrl(url) {
  return /^https?:\/\//i.test(cleanStr(url));
}

function isSameOriginAbsoluteUrl(url) {
  const u = cleanStr(url);
  const origin = stripTrailingSlash(getWindowOrigin());
  if (!u || !origin) return false;
  return stripTrailingSlash(u).startsWith(origin);
}

function shouldCacheBustUrl(url) {
  const u = cleanStr(url);
  if (!u) return false;
  if (u.startsWith("data:") || u.startsWith("blob:")) return false;
  if (isRootPath(u)) return true;
  if (isSameOriginAbsoluteUrl(u)) return true;
  if (isExternalHttpUrl(u)) return false;
  return true;
}

function maybeWithVersion(url, version) {
  const u = cleanStr(url);
  if (!u) return u;
  return shouldCacheBustUrl(u) ? withVersion(u, version) : u;
}

// ----------------------------------------------------------------------------
// Product naming normalization + explicit overrides
// ----------------------------------------------------------------------------
const NAME_IMAGE_OVERRIDES = [
  // ------------------------------------------------------------------
  // High-impact fixes first
  // ------------------------------------------------------------------
  { re: /\bpotatoes?\b/i, file: "potatoes.jpg" },
  { re: /\bcowpeas?\b|\bbeans?\b/i, file: "beans.jpg" },
  { re: /\bred\s*onions?\b|\bonions?\b/i, file: "Onions.jpg" },

  // ------------------------------------------------------------------
  // Farm Supplies / commonly failing product-image matches
  // ------------------------------------------------------------------
  { re: /\banimal\s*feed\b|\bbran\s*mix\b/i, file: "animal_feed.jpg" },
  { re: /\bsalt\s*lick\s*block\b/i, file: "salt_lick_block.jpg" },
  { re: /\bthatching\s*grass\b/i, file: "thatching_grass.jpg" },
  { re: /\bsugar\s*cane\b/i, file: "Sugarcane.jpg" },
  { re: /\bwheat\b/i, file: "Wheat.jpg" },
  { re: /\bsorghum\b/i, file: "Sorghum.jpg" },
  { re: /\blucerne\b|\balfalfa\b/i, file: "lucerne.jpg" },
  { re: /\bcarrots?\b/i, file: "carrots.jpg" },
  {
    re: /\bfresh\s*maize\s*cobs?\b|\bgreen\s*mealies\b|\bmaize\s*cobs?\b/i,
    file: "Maize.jpg",
  },

  // ------------------------------------------------------------------
  // Existing project examples
  // ------------------------------------------------------------------
  { re: /\bsweet\s*melon\b|\bcantaloupe\b/i, file: "sweet_melon.jpg" },
  { re: /\bcucumbers?\b/i, file: "cucumber.jpg" },
  { re: /\bmahangu\b|\bpearl\s*millet\b/i, file: "mahangu.jpg" },
];

function stripDiacritics(s) {
  const v = cleanStr(s);
  if (!v) return "";

  try {
    return v.normalize("NFKD").replace(/[\u0300-\u036f]/g, "");
  } catch {
    return v;
  }
}

function normalizeNameVariants(name) {
  const n = stripDiacritics(name).toLowerCase();
  if (!n) return [];

  const noParen = n.replace(/\([^)]*\)/g, " ").replace(/\s+/g, " ").trim();
  const beforeParen = n.split("(")[0].trim();
  const beforeComma = n.split(",")[0].trim();
  const beforeDash = n.split("-")[0].trim();

  return uniq([n, noParen, beforeParen, beforeComma, beforeDash]).filter(Boolean);
}

function slugifyVariants(name) {
  const variants = normalizeNameVariants(name);
  const slugs = [];

  for (const v of variants) {
    const basic = cleanStr(v)
      .replace(/["']/g, "")
      .replace(/[^a-z0-9\s_-]/g, " ")
      .replace(/\s+/g, " ")
      .trim();

    if (!basic) continue;

    slugs.push(basic.replace(/\s+/g, "_")); // snake_case
    slugs.push(basic.replace(/\s+/g, "-")); // kebab-case
    slugs.push(basic.replace(/\s+/g, "")); // compact
  }

  return uniq(slugs);
}

function canonicalImageFilenameForProduct(name) {
  const n = cleanStr(name);
  if (!n) return "";

  for (const item of NAME_IMAGE_OVERRIDES) {
    if (item.re.test(n)) return item.file;
  }

  return "";
}

export function getBundledProductImageNames() {
  const base = ["default.jpg"];
  const mapped = NAME_IMAGE_OVERRIDES.map((x) => x.file);
  return uniq([...base, ...mapped]).sort((a, b) => a.localeCompare(b));
}

// ----------------------------------------------------------------------------
// Image field parsing
// ----------------------------------------------------------------------------
function pickImageField(product) {
  const p = product || {};

  return (
    p.image_url ||
    p.imageUrl ||
    p.image_src ||
    p.imageSrc ||
    p.photo_url ||
    p.photo ||
    p.image ||
    p.image_path ||
    p.imagePath ||
    p.thumbnail ||
    p.thumbnail_url ||
    p.filename ||
    p.image_filename ||
    p.imageFileName ||
    p.image_name ||
    p.imageName ||
    ""
  );
}

function isGenericDefaultImage(raw) {
  // FIX:
  // Properly normalize backslashes before checking image-path markers.
  const s = cleanStr(raw).replace(/\\/g, "/").toLowerCase();
  if (!s) return true;

  return (
    s.includes("default.jpg") ||
    s.includes("default.jpeg") ||
    s.includes("default.png") ||
    s.includes("default-product") ||
    s.includes("/defaults/") ||
    s.includes("/uploads/defaults/") ||
    s.includes("/api/uploads/defaults/") ||
    s.includes("/uploads/product_images/default") ||
    s.includes("/api/uploads/product_images/default") ||
    s.includes("placeholder") ||
    s.includes("no-image") ||
    s.includes("no_image") ||
    s.includes("noimage")
  );
}

function extractPublicPathFromFilesystemPath(raw) {
  // Converts:
  // C:\...\frontend\public\Assets\product_images\potatoes.jpg
  // -> /Assets/product_images/potatoes.jpg
  const s = cleanStr(raw).replace(/\\/g, "/");
  if (!s) return "";

  const marker = "/public/";
  const idx = s.toLowerCase().lastIndexOf(marker);
  if (idx >= 0) {
    const tail = s.slice(idx + marker.length).replace(/^\/+/, "");
    return tail ? `/${tail}` : "";
  }

  return "";
}

function normalizeRawImage(raw) {
  const s = cleanStr(raw);
  if (!s) return "";

  if (isGenericDefaultImage(s)) return DEFAULT_PRODUCT_IMG;

  // If someone accidentally stored a local filesystem path, try to map it.
  const fromPublic = extractPublicPathFromFilesystemPath(s);
  if (fromPublic) return toCanonicalRootPath(fromPublic);

  if (isRootPath(s)) return toCanonicalRootPath(s);

  return s;
}

function getVersionToken(product) {
  const p = product || {};
  const raw =
    p.image_cache_bust ||
    p.imageCacheBust ||
    p.image_updated_at ||
    p.imageUpdatedAt ||
    p.updated_at ||
    p.updatedAt ||
    p.modified_at ||
    p.modifiedAt ||
    p.last_updated ||
    p.lastUpdated ||
    p.version ||
    p.image_version ||
    p.imageVersion ||
    "";

  const s = cleanStr(raw);
  if (!s) return "";

  const t = Date.parse(s);
  if (Number.isFinite(t)) return String(t);
  return s;
}

// ----------------------------------------------------------------------------
// Candidate builders
// ----------------------------------------------------------------------------
function pushCandidate(candidates, url, versionToken) {
  const u = cleanStr(url);
  if (!u) return;

  const publicVariant = withPublicBase(u);
  const variants = uniq([
    maybeWithVersion(u, versionToken),
    publicVariant !== u ? maybeWithVersion(publicVariant, versionToken) : "",
  ]);

  for (const v of variants) {
    if (cleanStr(v)) candidates.push(v);
  }
}

function pushPathEverywhere(candidates, path, versionToken) {
  // FILE ROLE:
  // Add exactly one sensible URL for a known path.
  //
  // This intentionally avoids "trying everywhere" because that caused repeated
  // 404s and paths such as /api/uploads/api/uploads/products/...
  const raw = cleanStr(path);
  if (!raw) return;

  const p = toCanonicalRootPath(raw);
  if (!p) return;

  if (isPublicAssetPath(p)) {
    pushCandidate(candidates, p, versionToken);
    return;
  }

  if (isApiUploadPath(p)) {
    pushCandidate(candidates, p, versionToken);
    return;
  }

  if (isUploadsPath(p)) {
    pushCandidate(candidates, p.replace(/^\/uploads\//i, "/api/uploads/"), versionToken);
    return;
  }

  // Stored "products/file.jpg" means backend runtime upload only when it looks
  // like a real uploaded filename. Semantic product images should come from
  // /Assets/product_images instead.
  if (/^\/products\//i.test(p)) {
    const fn = cleanStr(p.split("/").filter(Boolean).pop());
    if (looksLikeUploadFilename(fn)) {
      pushCandidate(candidates, `/api/uploads/products/${fn}`, versionToken);
    } else if (fn) {
      pushCandidate(candidates, `/Assets/product_images/${fn}`, versionToken);
    }
    return;
  }

  pushCandidate(candidates, p, versionToken);
}

function pushFileNamePaths(candidates, filename, versionToken) {
  // FILE ROLE:
  // Convert a bare filename into the correct candidate path.
  //
  // Rule:
  //   - Hash-like uploaded files -> backend runtime uploads.
  //   - Human/product filenames -> bundled public assets.
  //
  // This prevents Lucerne/Sorghum/etc. from causing backend upload 404 spam.
  const fn = cleanStr(filename).replace(/\\/g, "/").split("/").filter(Boolean).pop();
  if (!fn) return;

  if (looksLikeUploadFilename(fn)) {
    pushCandidate(candidates, `/api/uploads/products/${fn}`, versionToken);
    return;
  }

  pushCandidate(candidates, `/Assets/product_images/${fn}`, versionToken);
}

// ----------------------------------------------------------------------------
// Public resolver API
// ----------------------------------------------------------------------------
export function resolveProductImageCandidates(product) {
  const p = product || {};

  const rawOriginal = cleanStr(pickImageField(p));
  const raw = normalizeRawImage(rawOriginal);

  const name = cleanStr(p.name || p.product_name || p.title || "");
  const versionToken = getVersionToken(p);

  const candidates = [];
  const canonicalFile = canonicalImageFilenameForProduct(name);
  const rawIsGeneric = isGenericDefaultImage(raw);

  const rawPath = cleanStr(raw).replace(/[?#].*$/, "");
  const rawFilename = rawPath.split("/").filter(Boolean).pop() || "";
  const canonicalLower = cleanStr(canonicalFile).toLowerCase();
  const rawLower = cleanStr(raw).toLowerCase();

  const normalizedRawPath = toCanonicalRootPath(raw);
  const rawIsRuntimeUpload =
    Boolean(raw) &&
    isApiUploadPath(normalizedRawPath) &&
    looksLikeUploadFilename(rawFilename);

  function pushRawImageValue() {
    if (!raw || rawIsGeneric) return;

    if (isAbsUrl(raw)) {
      pushCandidate(candidates, raw, versionToken);
      return;
    }

    if (isRootPath(raw)) {
      pushPathEverywhere(candidates, raw, versionToken);
      return;
    }

    // Bare filename with or without extension.
    if (!raw.includes("/") && !isAbsUrl(raw)) {
      const filenames = hasFileExt(raw) ? [raw] : uniq([raw, ...toExtVariants(raw)]);
      for (const fn of filenames) {
        pushFileNamePaths(candidates, fn, versionToken);
      }
      return;
    }

    // Relative path string.
    if (!isAbsUrl(raw) && raw.includes("/")) {
      const clean = raw.replace(/\\/g, "/").replace(/^\/+/, "");
      const filename = clean.split("/").filter(Boolean).pop() || "";

      if (/^api\/uploads\//i.test(clean) || /^uploads\//i.test(clean)) {
        pushPathEverywhere(candidates, `/${clean}`, versionToken);
        return;
      }

      if (/^assets\//i.test(clean) || /^Assets\//.test(clean)) {
        pushPathEverywhere(candidates, `/${clean}`, versionToken);
        return;
      }

      if (/^images\/product_images\//i.test(clean) || /^product_images\//i.test(clean)) {
        if (filename) pushFileNamePaths(candidates, filename, versionToken);
        return;
      }

      if (/^products\//i.test(clean)) {
        if (looksLikeUploadFilename(filename)) {
          pushPathEverywhere(candidates, `/api/uploads/products/${filename}`, versionToken);
        } else if (canonicalFile) {
          pushFileNamePaths(candidates, canonicalFile, versionToken);
        } else if (filename) {
          pushFileNamePaths(candidates, filename, versionToken);
        }
        return;
      }

      if (filename) {
        if (looksLikeUploadFilename(filename)) {
          pushPathEverywhere(candidates, `/api/uploads/products/${filename}`, versionToken);
        } else {
          pushFileNamePaths(candidates, filename, versionToken);
        }
      }
    }
  }

  function pushNameBasedCandidates() {
    // Canonical semantic match, for example:
    //   Lucerne (Alfalfa) -> lucerne.jpg
    //   Sorghum -> Sorghum.jpg
    //   Mahangu -> mahangu.jpg
    if (canonicalFile) {
      pushFileNamePaths(candidates, canonicalFile, versionToken);
    }

    // If the stored public asset differs from the stronger canonical match,
    // try the canonical asset before any stale stored asset.
    if (
      canonicalFile &&
      raw &&
      isPublicAssetPath(raw) &&
      canonicalLower &&
      !rawLower.endsWith(`/${canonicalLower}`)
    ) {
      pushFileNamePaths(candidates, canonicalFile, versionToken);
    }

    // Name-based guesses should only look inside bundled public assets.
    // They should not generate backend upload requests.
    const slugs = slugifyVariants(name);
    const exts = ["jpg", "jpeg", "png", "webp"];

    for (const slug of slugs) {
      for (const ext of exts) {
        const guessFiles = uniq([
          `${slug}.${ext}`,
          `${slug.replace(/-/g, "_")}.${ext}`,
          `${slug.replace(/_/g, "-")}.${ext}`,
        ]);

        for (const gf of guessFiles) {
          pushFileNamePaths(candidates, gf, versionToken);
        }
      }
    }
  }

  // Order:
  //   - Real hash-like uploads first.
  //   - Known bundled product assets first for semantic product names.
  // This avoids stale upload paths like lucerne_alfalfa.jpg causing backend 404s.
  if (rawIsRuntimeUpload) {
    pushRawImageValue();
    pushNameBasedCandidates();
  } else {
    pushNameBasedCandidates();
    pushRawImageValue();
  }

  pushCandidate(candidates, DEFAULT_PRODUCT_IMG, versionToken);
  candidates.push(DEFAULT_PRODUCT_IMG);
  candidates.push(PLACEHOLDER_IMG);

  return uniq(candidates);
}

export function resolvePrimaryProductImage(product) {
  const candidates = resolveProductImageCandidates(product);
  return candidates[0] || DEFAULT_PRODUCT_IMG;
}

export function resolveProductImage(product) {
  return resolvePrimaryProductImage(product);
}