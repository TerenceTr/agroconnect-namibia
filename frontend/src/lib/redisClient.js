// frontend/lib/redisClient.js
// Browser-safe Redis wrapper using your backend API

import apiClient from "../api";

export const RedisClient = {
  async get(key) {
    const res = await apiClient.api.get(`/cache/get/${key}`);
    return res.data.value;
  },

  async set(key, value) {
    return apiClient.api.post(`/cache/set`, { key, value });
  },

  async del(key) {
    return apiClient.api.delete(`/cache/del/${key}`);
  }
};

export default RedisClient;
