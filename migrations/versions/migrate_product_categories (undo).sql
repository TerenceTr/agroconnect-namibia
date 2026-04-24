BEGIN;

-- Roll back image_url changes
UPDATE products
SET image_url = NULL
WHERE image_url LIKE '/Assets/product_images/%';

-- Roll back categories (best-effort)
UPDATE products
SET category = 'Uncategorized'
WHERE category IN (
  'Fresh Produce',
  'Staples',
  'Farm Supplies',
  'Animal Products',
  'Fish & Seafood',
  'Nuts, Seeds & Oils',
  'Honey & Sweeteners',
  'Value-Added & Processed (Farm-made)',
  'Wild Harvest'
);

COMMIT;
