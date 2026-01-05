// ====================================================================
// 🌟 frontend/utils/notify.js — Global Toast Utility
// --------------------------------------------------------------------
// Centralized toast notification wrapper with consistent styling used
// across the entire application (admin, farmer, customer dashboards).
// ====================================================================

import { toast } from "react-toastify";

// Shared styling
const baseStyle = {
  background: "rgba(16,185,129,0.95)", // Namibia green glow
  color: "#fff",
  borderRadius: "12px",
  backdropFilter: "blur(10px)",
  boxShadow: "0 4px 20px rgba(0,0,0,0.15)",
};

export const notifySuccess = (msg) =>
  toast.success(msg, {
    style: baseStyle,
    progressStyle: { background: "#FACC15" },
  });

export const notifyError = (msg) =>
  toast.error(msg, {
    style: { ...baseStyle, background: "rgba(220,38,38,0.95)" },
    progressStyle: { background: "#000" },
  });

export const notifyWarning = (msg) =>
  toast.warn(msg, {
    style: { ...baseStyle, background: "rgba(251,191,36,0.95)" },
    progressStyle: { background: "#000" },
  });

export const notifyInfo = (msg) =>
  toast.info(msg, {
    style: { ...baseStyle, background: "rgba(59,130,246,0.95)" },
    progressStyle: { background: "#fff" },
  });
