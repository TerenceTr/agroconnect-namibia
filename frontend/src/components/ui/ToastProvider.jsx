// ====================================================================
// frontend/src/components/ui/ToastProvider.jsx
// --------------------------------------------------------------------
// FILE ROLE:
//   Mount both toast systems currently used across the app.
//
// WHY THIS UPDATE MATTERS:
//   The reports workspace and many dashboards call react-hot-toast, while some
//   legacy screens still call react-toastify. Rendering both providers makes
//   report preview/export feedback visible again.
// ====================================================================

import React from "react";
import { Toaster } from "react-hot-toast";
import { ToastContainer } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";

const sharedCardStyle = {
  background: "rgba(15,23,42,0.94)",
  backdropFilter: "blur(10px)",
  borderRadius: "14px",
  color: "#F8FAFC",
  border: "1px solid rgba(148,163,184,0.18)",
  boxShadow: "0 10px 30px rgba(15,23,42,0.25)",
};

export default function ToastProvider() {
  return (
    <>
      <Toaster
        position="top-right"
        gutter={12}
        toastOptions={{
          duration: 4000,
          style: sharedCardStyle,
          success: { iconTheme: { primary: "#10B981", secondary: "#F8FAFC" } },
          error: { iconTheme: { primary: "#EF4444", secondary: "#F8FAFC" } },
          loading: { iconTheme: { primary: "#0EA5E9", secondary: "#F8FAFC" } },
        }}
      />

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
          boxShadow: "0 4px 20px rgba(0,0,0,0.2)",
        }}
        progressStyle={{ background: "#FACC15" }}
      />
    </>
  );
}
