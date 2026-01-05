// ====================================================================
// ResetPassword.js — AgroConnect Namibia
// Fullscreen hero + glass UI + logo + motion
// ====================================================================

import React from "react";
import { motion } from "framer-motion";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { resetPasswordSchema } from "../components/auth/validationSchemas";
import { useAuth } from "../components/auth/AuthProvider";
import { useSearchParams, Link } from "react-router-dom";

const fadeUp = {
  hidden: { opacity: 0, y: 45 },
  visible: { opacity: 1, y: 0, transition: { duration: 0.9, ease: "easeOut" } },
};

export default function ResetPassword() {
  const { resetPassword, loading } = useAuth();
  const [params] = useSearchParams();
  const token = params.get("token");

  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm({ resolver: zodResolver(resetPasswordSchema) });

  const bgImage = `${process.env.PUBLIC_URL}/assets/namibia-bg.jpg`;
  const logoImage = `${process.env.PUBLIC_URL}/assets/logo.png`;

  return (
    <motion.div
      initial="hidden"
      animate="visible"
      variants={fadeUp}
      className="min-h-screen flex items-center justify-center relative"
      style={{ backgroundImage: `url(${bgImage})`, backgroundSize: "cover" }}
    >
      <div className="absolute inset-0 bg-black/40 backdrop-blur-sm"/>

      <div className="relative z-10 max-w-md w-full px-4">
        <div className="glass-card p-10 rounded-xl shadow-glass text-white">

          <img src={logoImage} className="mx-auto h-24 mb-6" alt="logo" />

          <h1 className="text-3xl font-bold text-center mb-4">Create New Password</h1>

          {!token && (
            <p className="text-red-300 text-center mb-3">Invalid or missing reset token.</p>
          )}

          <p className="text-center mb-6 opacity-90">Enter a new password below.</p>

          <form
            onSubmit={handleSubmit((d) =>
              resetPassword({ token, password: d.password, confirmPassword: d.confirmPassword })
            )}
            className="space-y-6"
          >
            <div>
              <label>New Password</label>
              <input
                {...register("password")}
                type="password"
                className="w-full mt-2 p-3 rounded-xl bg-white/70 focus:bg-white outline-none"
                placeholder="••••••••"
              />
              {errors.password && <p className="text-red-300 text-sm">{errors.password.message}</p>}
            </div>

            <div>
              <label>Confirm Password</label>
              <input
                {...register("confirmPassword")}
                type="password"
                className="w-full mt-2 p-3 rounded-xl bg-white/70 focus:bg-white outline-none"
                placeholder="••••••••"
              />
              {errors.confirmPassword && (
                <p className="text-red-300 text-sm">{errors.confirmPassword.message}</p>
              )}
            </div>

            <button disabled={loading || !token} className="ac-btn-primary w-full mt-2">
              {loading ? "Updating..." : "Update Password"}
            </button>
          </form>

          <div className="text-center mt-6">
            <Link to="/login" className="underline hover:text-gray-200">Back to Login</Link>
          </div>

        </div>
      </div>
    </motion.div>
  );
}
