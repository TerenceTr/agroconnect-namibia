/**
 * Product Contract (Documentation-Level DTO)
 * This file is NOT compiled — it enforces consistency by convention.
 */

export const ProductShape = {
  id: "number",
  name: "string",
  category: "string?",
  price: "number",
  location: "string?",
  farmer_id: "number",
  average_rating: "number?",
  total_sales: "number?",
};
