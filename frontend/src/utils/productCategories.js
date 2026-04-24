// ============================================================================
export const NAMIBIA_CATEGORIES = [
  "Fresh Produce",
  "Animal Products",
  "Fish & Seafood",
  "Staples",
  "Nuts, Seeds & Oils",
  "Honey & Sweeteners",
  "Value-Added & Processed (Farm-made)",
  "Farm Supplies",
  "Wild Harvest",
];

export function normalizeCategory(cat = "") {
  const c = cat.toLowerCase();
  if (["fruit", "vegetable", "root"].includes(c)) return "Fresh Produce";
  if (["grain", "legume"].includes(c)) return "Staples";
  if (["lucerne", "hay"].includes(c)) return "Farm Supplies";
  return cat;
}
