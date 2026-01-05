// ====================================================================
// ForgotPassword.js — AgroConnect Namibia
// ------------------------------------------------
// ✔ Uses auth-input
// ✔ Clear text contrast
// ✔ Matches Login & Register
// ✔ Scroll-safe
// ====================================================================

import React from 'react';
import { motion } from 'framer-motion';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { forgotPasswordSchema } from '../components/auth/validationSchemas';
import { useAuth } from '../components/auth/AuthProvider';
import { Link } from 'react-router-dom';
import AuthPageShell from '../components/layout/AuthPageShell';

export default function ForgotPassword() {
  const { requestPasswordReset, loading } = useAuth();

  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm({ resolver: zodResolver(forgotPasswordSchema) });

  return (
    <AuthPageShell bgImage={`${process.env.PUBLIC_URL}/assets/namibia-bg.jpg`}>
      <motion.div
        initial={{ opacity: 0, y: 18 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="glass-card w-full max-w-md p-6 sm:p-8 text-white"
      >
        <img
          src={`${process.env.PUBLIC_URL}/assets/logo.png`}
          alt="AgroConnect Logo"
          className="mx-auto h-20 mb-4"
        />

        <h1 className="text-3xl font-bold text-center mb-3">Reset Password</h1>

        <p className="text-center text-white/80 mb-6">
          Enter your email to receive a reset link.
        </p>

        <form
          onSubmit={handleSubmit((d) => requestPasswordReset(d.email))}
          className="space-y-5"
        >
          <input
            {...register('email')}
            placeholder="example@example.com"
            className="auth-input"
          />
          {errors.email && <p className="auth-error">{errors.email.message}</p>}

          <button className="ac-btn-primary w-full" disabled={loading}>
            {loading ? 'Sending...' : 'Send Reset Link'}
          </button>
        </form>

        <div className="text-center mt-6 text-white/90">
          <Link to="/login" className="underline">
            Back to Login
          </Link>
        </div>
      </motion.div>
    </AuthPageShell>
  );
}
