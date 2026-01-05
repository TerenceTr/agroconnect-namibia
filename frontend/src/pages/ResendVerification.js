// ====================================================================
// ResendVerification.js — AgroConnect Namibia
// Updated to StartScreen layout + logo + glass card
// ====================================================================

import React, { useState } from "react";
import { motion } from "framer-motion";
import { Mail, Eye, EyeOff, Lock, CheckCircle } from "lucide-react";
import { Link } from "react-router-dom";
import axios from "axios";

import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { toast } from "react-toastify";
import { resendVerificationSchema } from "../components/auth/validationSchemas";

const fadeUp = {
  hidden: { opacity: 0, y: 45 },
  visible: { opacity: 1, y: 0, transition: { duration: 0.9, ease: "easeOut" } },
};

export default function ResendVerification() {
  const [sent, setSent] = useState(false);
  const [loading, setLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);

  const {
    register,
    handleSubmit,
    formState: { errors },
    reset,
  } = useForm({ resolver: zodResolver(resendVerificationSchema) });

  const bgImage = `${process.env.PUBLIC_URL}/assets/namibia-bg.jpg`;
  const logoImage = `${process.env.PUBLIC_URL}/assets/logo.png`;

  const onSubmit = async (data) => {
    setLoading(true);
    try {
      await axios.post(`${process.env.REACT_APP_API_URL}/auth/resend-verification`, data);
      toast.success("Verification link sent!");
      setSent(true);
      reset();
    } catch (err) {
      toast.error(err?.response?.data?.error || "Failed to send link");
    } finally {
      setLoading(false);
    }
  };

  if (sent) {
    return (
      <motion.div
        initial="hidden"
        animate="visible"
        variants={fadeUp}
        className="min-h-screen flex items-center justify-center text-white relative"
        style={{ backgroundImage: `url(${bgImage})`, backgroundSize: "cover" }}
      >
        <div className="absolute inset-0 bg-black/50 backdrop-blur-sm" />

        <div className="relative bg-white/10 backdrop-blur-lg p-8 rounded-2xl border border-white/20 shadow-xl max-w-md w-full text-center">

          <img src={logoImage} className="mx-auto h-20 mb-4" alt="logo" />

          <CheckCircle className="text-namibia-green w-16 h-16 mx-auto mb-4" />
          <h2 className="text-2xl font-bold mb-3">Link Sent!</h2>
          <p className="opacity-90 mb-6">Check your inbox for the verification link.</p>

          <Link to="/login" className="ac-btn-primary px-6 py-3 inline-block">Back to Login</Link>
        </div>
      </motion.div>
    );
  }

  return (
    <motion.div
      initial="hidden"
      animate="visible"
      variants={fadeUp}
      className="min-h-screen flex items-center justify-center relative"
      style={{ backgroundImage: `url(${bgImage})`, backgroundSize: "cover" }}
    >
      <div className="absolute inset-0 bg-black/40 backdrop-blur-sm" />

      <form
        onSubmit={handleSubmit(onSubmit)}
        className="relative z-10 bg-white/10 backdrop-blur-lg p-8 rounded-2xl w-full max-w-md border border-white/20 shadow-2xl text-white"
      >
        <img src={logoImage} className="mx-auto h-20 mb-6" alt="logo" />

        <h2 className="text-3xl font-bold mb-6 text-center">Resend Verification</h2>

        <p className="text-center opacity-90 mb-6">
          Enter your email and password to receive a new verification link.
        </p>

        {/* EMAIL */}
        <div className="mb-4">
          <label className="block mb-1">Email</label>
          <div className="relative">
            <Mail className="absolute left-3 top-1/2 -translate-y-1/2 text-white/70" size={18} />
            <input
              {...register("email")}
              placeholder="you@example.com"
              className="w-full pl-10 p-3 rounded-lg bg-white/20 text-white placeholder-white/60 border border-white/30 focus:border-namibia-green"
            />
          </div>
          {errors.email && <p className="text-red-300 text-sm">{errors.email.message}</p>}
        </div>

        {/* PASSWORD */}
        <div className="mb-6">
          <label className="block mb-1">Password</label>
          <div className="relative">
            <Lock className="absolute left-3 top-1/2 -translate-y-1/2 text-white/70" size={18} />

            <input
              {...register("password")}
              type={showPassword ? "text" : "password"}
              placeholder="your password"
              className="w-full pl-10 pr-10 p-3 rounded-lg bg-white/20 text-white placeholder-white/60 border border-white/30 focus:border-namibia-green"
            />

            <button
              type="button"
              onClick={() => setShowPassword(!showPassword)}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-white/70"
            >
              {showPassword ? <EyeOff /> : <Eye />}
            </button>
          </div>
          {errors.password && <p className="text-red-300 text-sm">{errors.password.message}</p>}
        </div>

        <button
          type="submit"
          disabled={loading}
          className="w-full bg-namibia-green py-3 rounded-lg font-semibold hover:bg-green-600 disabled:opacity-50"
        >
          {loading ? "Sending..." : "Resend Verification"}
        </button>

        <p className="text-center mt-6 text-white/90">
          Remember your password?{" "}
          <Link to="/login" className="underline">Sign in</Link>
        </p>
      </form>
    </motion.div>
  );
}
