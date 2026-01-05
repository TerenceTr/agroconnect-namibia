// src/hooks/ai/aiClient.js
import apiClient from "../../api"; // central axios wrapper (exports .api)

const API = {
  post: (path, data, config = {}) => apiClient.api.post(`/ai${path}`, data, config),
  get: (path, config = {}) => apiClient.api.get(`/ai${path}`, config),
};

export default API;
