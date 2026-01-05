// ============================================================================
// src/services/customerApi.js — AgroConnect Namibia (Customer)
// ----------------------------------------------------------------------------
// ROLE:
// • One place for all customer dashboard API calls
// • Keeps UI components clean and testable
//
// IMPORTANT:
// • Your axios instance (src/api.js) already uses baseURL: http://.../api
// • Therefore DO NOT prefix routes with "/api" here.
//   Use "/products", "/orders", "/cart", etc.
// ============================================================================

import api from '../api';

// -----------------------------
// Products
// -----------------------------
export async function fetchProducts(params = {}) {
  const res = await api.get('/products', { params });
  return res.data;
}

export async function fetchProductById(productId) {
  const res = await api.get(`/products/${productId}`);
  return res.data;
}

export async function fetchNewProducts(limit = 6) {
  const res = await api.get('/products/new', { params: { limit } });
  return res.data;
}

export async function fetchTopSellingProducts(limit = 6) {
  const res = await api.get('/products/top-selling', { params: { limit } });
  return res.data;
}

// -----------------------------
// Followed products
// -----------------------------
export async function fetchFollowed() {
  const res = await api.get('/customer/followed');
  return res.data;
}

export async function followProduct(productId) {
  const res = await api.post('/customer/follow', { product_id: productId });
  return res.data;
}

export async function unfollowProduct(productId) {
  const res = await api.delete(`/customer/unfollow/${productId}`);
  return res.data;
}

// -----------------------------
// Cart
// -----------------------------
export async function fetchCart() {
  const res = await api.get('/cart');
  return res.data;
}

export async function addToCart(productId, qty = 1) {
  const res = await api.post('/cart/items', { product_id: productId, qty });
  return res.data;
}

export async function updateCartItem(itemId, qty) {
  const res = await api.patch(`/cart/items/${itemId}`, { qty });
  return res.data;
}

export async function removeCartItem(itemId) {
  const res = await api.delete(`/cart/items/${itemId}`);
  return res.data;
}

export async function clearCart() {
  const res = await api.delete('/cart');
  return res.data;
}

// -----------------------------
// Orders + checkout
// -----------------------------
export async function fetchOrders(params = {}) {
  const res = await api.get('/orders', { params });
  return res.data;
}

export async function fetchOrderById(orderId) {
  const res = await api.get(`/orders/${orderId}`);
  return res.data;
}

export async function placeOrder(payload) {
  const res = await api.post('/orders', payload);
  return res.data;
}

// -----------------------------
// Recommendations (optional AI)
// NOTE: only keep if your backend actually exposes it.
// -----------------------------
export async function fetchRecommendations(params = {}) {
  const res = await api.get('/recommendations', { params });
  return res.data;
}

// -----------------------------
// Ratings / comments
// -----------------------------
export async function fetchRatings(productId) {
  const res = await api.get(`/ratings`, { params: { product_id: productId } });
  return res.data;
}

export async function submitRating({ product_id, farmer_id, rating, comment }) {
  const res = await api.post('/ratings', { product_id, farmer_id, rating, comment });
  return res.data;
}
