-- ============================================================================
-- migrations\versions\migrate_product_categories.sql — AgroConnect Namibia
-- ----------------------------------------------------------------------------
-- GOAL:
--   1) Normalize products.category into Namibia top-level categories (9 enums)
--   2) Fix missing/wrong image_url by mapping known product names to local assets
--   3) Add a DB constraint to prevent invalid categories going forward
--
-- SAFE DESIGN:
--   - Creates a backup table of old values (category + image_url) before changes
--   - Includes a rollback section at the bottom
--
-- ASSUMPTIONS:
--   - Table: public.products
--   - PK: product_id (uuid)
--   - Columns: category (text), image_url (text), product_name (text), description (text)
--   - Your frontend assets live at: /Assets/product_images/<file>
-- ============================================================================

BEGIN;

-- ---------------------------------------------------------------------------
-- 0) Backup (for rollback safety)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS public.products_category_image_backup (
  product_id uuid PRIMARY KEY,
  old_category text,
  old_image_url text,
  backed_up_at timestamptz NOT NULL DEFAULT now()
);

-- Insert missing backups only (idempotent)
INSERT INTO public.products_category_image_backup (product_id, old_category, old_image_url)
SELECT p.product_id, p.category, p.image_url
FROM public.products p
LEFT JOIN public.products_category_image_backup b ON b.product_id = p.product_id
WHERE b.product_id IS NULL;

-- ---------------------------------------------------------------------------
-- 1) Normalize category to Namibia top-level categories
-- ---------------------------------------------------------------------------
-- Namibia Top Categories (canonical):
--   1 Fresh Produce
--   2 Animal Products
--   3 Fish & Seafood
--   4 Staples
--   5 Nuts, Seeds & Oils
--   6 Honey & Sweeteners
--   7 Value-Added & Processed (Farm-made)
--   8 Farm Supplies
--   9 Wild Harvest
--
-- Strategy:
--   - If category is already one of these, keep it
--   - Else infer from category + product_name + description text
--   - Default fallback: Fresh Produce

UPDATE public.products p
SET category = CASE
  WHEN coalesce(trim(p.category), '') ILIKE 'Fresh Produce' THEN 'Fresh Produce'
  WHEN coalesce(trim(p.category), '') ILIKE 'Animal Products' THEN 'Animal Products'
  WHEN coalesce(trim(p.category), '') ILIKE 'Fish & Seafood' THEN 'Fish & Seafood'
  WHEN coalesce(trim(p.category), '') ILIKE 'Staples' THEN 'Staples'
  WHEN coalesce(trim(p.category), '') ILIKE 'Nuts, Seeds & Oils' THEN 'Nuts, Seeds & Oils'
  WHEN coalesce(trim(p.category), '') ILIKE 'Honey & Sweeteners' THEN 'Honey & Sweeteners'
  WHEN coalesce(trim(p.category), '') ILIKE 'Value-Added & Processed (Farm-made)' THEN 'Value-Added & Processed (Farm-made)'
  WHEN coalesce(trim(p.category), '') ILIKE 'Farm Supplies' THEN 'Farm Supplies'
  WHEN coalesce(trim(p.category), '') ILIKE 'Wild Harvest' THEN 'Wild Harvest'

  ELSE
    CASE
      -- Wild Harvest
      WHEN (coalesce(p.category,'') || ' ' || coalesce(p.product_name,'') || ' ' || coalesce(p.description,'')) ~* '(wild|!nara|mopane|mushroom|veld)'
        THEN 'Wild Harvest'

      -- Farm Supplies
      WHEN (coalesce(p.category,'') || ' ' || coalesce(p.product_name,'') || ' ' || coalesce(p.description,'')) ~* '(feed|forage|lucerne|hay|bran|seedling|nursery|fib(re|er)|hide|skin|wool|mohair|suppl(y|ies))'
        THEN 'Farm Supplies'

      -- Honey & Sweeteners
      WHEN (coalesce(p.category,'') || ' ' || coalesce(p.product_name,'') || ' ' || coalesce(p.description,'')) ~* '(honey|sweetener|syrup|beeswax)'
        THEN 'Honey & Sweeteners'

      -- Fish & Seafood
      WHEN (coalesce(p.category,'') || ' ' || coalesce(p.product_name,'') || ' ' || coalesce(p.description,'')) ~* '(fish|seafood|hake|tilapia|oyster|prawn|shrimp|crab|smoked fish|dried fish)'
        THEN 'Fish & Seafood'

      -- Nuts, Seeds & Oils
      WHEN (coalesce(p.category,'') || ' ' || coalesce(p.product_name,'') || ' ' || coalesce(p.description,'')) ~* '(nut|seed|groundnut|peanut|sunflower|sesame|pumpkin seed|oil|olive)'
        THEN 'Nuts, Seeds & Oils'

      -- Staples
      WHEN (coalesce(p.category,'') || ' ' || coalesce(p.product_name,'') || ' ' || coalesce(p.description,'')) ~* '(staple|grain|cereal|mahangu|maize|corn|sorghum|rice|wheat|legume|pulse|bean|cowpea|lentil)'
        THEN 'Staples'

      -- Animal Products
      WHEN (coalesce(p.category,'') || ' ' || coalesce(p.product_name,'') || ' ' || coalesce(p.description,'')) ~* '(animal|dairy|milk|omaere|yoghurt|yogurt|cheese|butter|egg|meat|poultry|beef|goat|chicken|lamb|pork|game)'
        THEN 'Animal Products'

      -- Value-Added & Processed
      WHEN (coalesce(p.category,'') || ' ' || coalesce(p.product_name,'') || ' ' || coalesce(p.description,'')) ~* '(value|processed|farm-made|meal|flour|peanut butter|jam|dried fruit|pickle|atchar|sauce|chutney|biltong|dro(e|ë)wors)'
        THEN 'Value-Added & Processed (Farm-made)'

      -- Default
      ELSE 'Fresh Produce'
    END
END;

-- ---------------------------------------------------------------------------
-- 2) Fix image_url mapping for your missing/broken images (local asset paths)
-- ---------------------------------------------------------------------------
-- Your confirmed asset filenames (from your frontend zip):
--   /Assets/product_images/Watermelon.jpg
--   /Assets/product_images/Sweet_Melon.jpg
--   /Assets/product_images/Cucumber.jpg
--   /Assets/product_images/ell_peppers.jpg   <-- NOTE: folder contains 'ell_peppers.jpg'
--   /Assets/product_images/beans.jpg
--   /Assets/product_images/lucerne.jpg
--   /Assets/product_images/Mahangu.jpg
--   /Assets/product_images/placeholder.png
--
-- Update rule:
--   - If image_url is NULL/empty/placeholder-ish, set it based on product_name match.

UPDATE public.products p
SET image_url = CASE
  WHEN lower(coalesce(p.product_name,'')) LIKE '%watermelon%' THEN '/Assets/product_images/Watermelon.jpg'
  WHEN lower(coalesce(p.product_name,'')) LIKE '%sweet%melon%' THEN '/Assets/product_images/Sweet_Melon.jpg'
  WHEN lower(coalesce(p.product_name,'')) LIKE '%cantaloupe%' THEN '/Assets/product_images/Sweet_Melon.jpg'
  WHEN lower(coalesce(p.product_name,'')) LIKE '%cucumber%' THEN '/Assets/product_images/Cucumber.jpg'

  -- Bell peppers: your asset is "ell_peppers.jpg" (as per zip)
  WHEN lower(coalesce(p.product_name,'')) LIKE '%bell%pepper%' THEN '/Assets/product_images/ell_peppers.jpg'
  WHEN lower(coalesce(p.product_name,'')) LIKE '%peppers%' THEN '/Assets/product_images/ell_peppers.jpg'

  -- Cowpeas/beans
  WHEN lower(coalesce(p.product_name,'')) LIKE '%cowpea%' THEN '/Assets/product_images/beans.jpg'
  WHEN lower(coalesce(p.product_name,'')) LIKE '%beans%' THEN '/Assets/product_images/beans.jpg'

  -- Lucerne / Alfalfa
  WHEN lower(coalesce(p.product_name,'')) LIKE '%lucerne%' THEN '/Assets/product_images/lucerne.jpg'
  WHEN lower(coalesce(p.product_name,'')) LIKE '%alfalfa%' THEN '/Assets/product_images/lucerne.jpg'

  -- Mahangu / Pearl Millet
  WHEN lower(coalesce(p.product_name,'')) LIKE '%mahangu%' THEN '/Assets/product_images/Mahangu.jpg'
  WHEN lower(coalesce(p.product_name,'')) LIKE '%pearl%millet%' THEN '/Assets/product_images/Mahangu.jpg'

  ELSE p.image_url
END
WHERE
  p.image_url IS NULL
  OR btrim(p.image_url) = ''
  OR p.image_url ILIKE '%placeholder%'
  OR p.image_url ILIKE '%no-image%'
  OR p.image_url ILIKE '%default%';

-- ---------------------------------------------------------------------------
-- 3) Add category constraint (prevents bad values going forward)
-- ---------------------------------------------------------------------------
-- Use NOT VALID first, then VALIDATE (safer on large tables).
ALTER TABLE public.products
  DROP CONSTRAINT IF EXISTS products_category_top_level_chk;

ALTER TABLE public.products
  ADD CONSTRAINT products_category_top_level_chk
  CHECK (category IN (
    'Fresh Produce',
    'Animal Products',
    'Fish & Seafood',
    'Staples',
    'Nuts, Seeds & Oils',
    'Honey & Sweeteners',
    'Value-Added & Processed (Farm-made)',
    'Farm Supplies',
    'Wild Harvest'
  )) NOT VALID;

ALTER TABLE public.products
  VALIDATE CONSTRAINT products_category_top_level_chk;

COMMIT;

-- ============================================================================
-- DATA-QUALITY AUDIT QUERIES (RUN ANYTIME)
-- ============================================================================
-- 1) Any products still missing/empty category?
-- SELECT product_id, product_name, category FROM public.products
-- WHERE category IS NULL OR btrim(category) = '';

-- 2) Any products violating allowed category set? (should be 0 after constraint)
-- SELECT product_id, product_name, category
-- FROM public.products
-- WHERE category NOT IN (
--   'Fresh Produce','Animal Products','Fish & Seafood','Staples','Nuts, Seeds & Oils',
--   'Honey & Sweeteners','Value-Added & Processed (Farm-made)','Farm Supplies','Wild Harvest'
-- );

-- 3) Missing image_url after migration
-- SELECT product_id, product_name, image_url
-- FROM public.products
-- WHERE image_url IS NULL OR btrim(image_url) = '';

-- 4) Placeholder / suspicious image_url patterns
-- SELECT product_id, product_name, image_url
-- FROM public.products
-- WHERE image_url ILIKE '%placeholder%' OR image_url ILIKE '%no-image%' OR image_url ILIKE '%default%';

-- 5) Which product names are still not mapped to local assets (helpful for expanding rules)
-- SELECT product_name, count(*) AS n
-- FROM public.products
-- WHERE image_url IS NULL OR image_url ILIKE '%placeholder%'
-- GROUP BY product_name
-- ORDER BY n DESC, product_name ASC;

-- ============================================================================
-- ROLLBACK (SAFETY) — restore old category/image_url + remove constraint
-- ----------------------------------------------------------------------------
-- USE WHEN:
--   - You want to revert to original category/image_url values
--
-- NOTE:
--   This assumes the backup table has rows for the products you want to restore.
-- ============================================================================
-- BEGIN;
-- ALTER TABLE public.products DROP CONSTRAINT IF EXISTS products_category_top_level_chk;
--
-- UPDATE public.products p
-- SET
--   category  = b.old_category,
--   image_url = b.old_image_url
-- FROM public.products_category_image_backup b
-- WHERE b.product_id = p.product_id;
--
-- COMMIT;
--
-- Optional cleanup (only if you are sure you no longer need backups):
-- DROP TABLE public.products_category_image_backup;
