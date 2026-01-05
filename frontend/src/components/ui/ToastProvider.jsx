// ====================================================================
// frontend\src\components\ui\ToastProvider.jsx
// --------------------------------------------------------------------
// Centralized ToastContainer styling
// ====================================================================

import React from "react";
import { ToastContainer } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";

export default function ToastProvider() {
  return (
    <ToastContainer
      position="top-right"
      autoClose={4000}
      newestOnTop
      draggable
      pauseOnHover
      theme="colored"
      toastStyle={{
        background: "rgba(16,185,129,0.92)",
        backdropFilter: "blur(10px)",
        borderRadius: "12px",
        color: "#fff",
        boxShadow: "0 4px 20px rgba(0,0,0,0.2)"
      }}
      progressStyle={{ background: "#FACC15" }}
    />
  );
}
