// ====================================================================
// frontend/src/api/http.js — API Client (Access token + Refresh flow)
// ====================================================================
// FILE ROLE:
//   • Central Axios instance
//   • Adds Authorization: Bearer <access>
//   • Auto-refreshes access token on 401 (once)
//   • Uses HttpOnly refresh cookie via withCredentials=true
// ====================================================================

import axios from "axios";

const API_BASE = import.meta.env.VITE_API_BASE || "http://localhost:5000";

let accessToken = null;

export function setAccessToken(token) {
  accessToken = token;
}

export function getAccessToken() {
  return accessToken;
}

const http = axios.create({
  baseURL: API_BASE,
  withCredentials: true, // IMPORTANT: sends refresh cookie
});

// Attach access token
http.interceptors.request.use((config) => {
  if (accessToken) {
    config.headers = config.headers || {};
    config.headers.Authorization = `Bearer ${accessToken}`;
  }
  return config;
});

let isRefreshing = false;
let pending = [];

function queueRequest(cb) {
  pending.push(cb);
}

function flushQueue(newToken) {
  pending.forEach((cb) => cb(newToken));
  pending = [];
}

// Refresh access token on 401
http.interceptors.response.use(
  (res) => res,
  async (err) => {
    const original = err.config;

    if (!original || original._retry) {
      return Promise.reject(err);
    }

    if (err.response && err.response.status === 401) {
      original._retry = true;

      if (!isRefreshing) {
        isRefreshing = true;
        try {
          const r = await axios.post(`${API_BASE}/api/auth/refresh`, null, {
            withCredentials: true,
          });
          const newToken = r.data?.access_token;
          if (!newToken) throw new Error("No access_token from refresh");
          setAccessToken(newToken);
          flushQueue(newToken);
        } finally {
          isRefreshing = false;
        }
      }

      return new Promise((resolve) => {
        queueRequest((newToken) => {
          original.headers.Authorization = `Bearer ${newToken}`;
          resolve(http(original));
        });
      });
    }

    return Promise.reject(err);
  }
);

export default http;
