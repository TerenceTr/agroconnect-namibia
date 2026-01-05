// ============================================================================
// Login.js — AgroConnect Namibia (LOCKED AUTH FLOW)
// ----------------------------------------------------------------------------
// ROLE:
// • Secure authentication entry point (UI layer)
// • Delegates authentication to AuthProvider
// • Performs ALL navigation AFTER successful login
//
// GUARANTEES:
// • No router usage inside AuthProvider
// • Deterministic redirects
// • Safe error handling (network + auth)
// ============================================================================

import React, { useEffect } from 'react';
import { motion } from 'framer-motion';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { LogIn } from 'lucide-react';

import { loginSchema } from '../components/auth/validationSchemas';
import { useAuth } from '../components/auth/AuthProvider';

import AuthPageShell from '../components/auth/AuthPageShell';
import GlassInput from '../components/common/GlassInput';
import { notifyError } from '../utils/notify';

// ---------------------------------------------------------------------------
// Card-only animation (prevents layout shift)
// ---------------------------------------------------------------------------
const fadeUp = {
  hidden: { opacity: 0, y: 16 },
  visible: { opacity: 1, y: 0, transition: { duration: 0.45, ease: 'easeOut' } },
};

// ---------------------------------------------------------------------------
// Role → dashboard mapping (single source of truth)
// ---------------------------------------------------------------------------
function roleHome(roleName) {
  const role = String(roleName || '').toLowerCase();
  if (role === 'admin') return '/dashboard/admin';
  if (role === 'farmer') return '/dashboard/farmer';
  if (role === 'customer') return '/dashboard/customer';
  return '/';
}

export default function Login() {
  const navigate = useNavigate();
  const location = useLocation();

  const { login, loading, user, isAuthenticated } = useAuth();

  // -------------------------------------------------------------------------
  // Prevent authenticated users from seeing /login
  // -------------------------------------------------------------------------
  useEffect(() => {
    if (!isAuthenticated || !user) return;

    const from = location.state?.from?.pathname;
    navigate(from || roleHome(user.role_name), { replace: true });
  }, [isAuthenticated, user, location.state, navigate]);

  // -------------------------------------------------------------------------
  // Form handling
  // -------------------------------------------------------------------------
  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm({ resolver: zodResolver(loginSchema) });

  // -------------------------------------------------------------------------
  // Submit
  // -------------------------------------------------------------------------
  const onSubmit = async (form) => {
    try {
      const loggedInUser = await login(form);

      const from = location.state?.from?.pathname;
      navigate(from || roleHome(loggedInUser?.role_name), { replace: true });
    } catch (err) {
      notifyError(
        err?.response?.data?.message ||
          err?.response?.data?.error ||
          err?.message ||
          'Login failed'
      );
    }
  };

  return (
    <AuthPageShell bgImage={`${process.env.PUBLIC_URL}/assets/namibia-bg.jpg`}>
      <motion.div
        initial="hidden"
        animate="visible"
        variants={fadeUp}
        className="glass-card w-full max-w-md p-6 sm:p-8 md:p-10 text-white"
      >
        <img
          src={`${process.env.PUBLIC_URL}/assets/logo.png`}
          className="mx-auto h-20 mb-6"
          alt="AgroConnect Logo"
        />

        <h1 className="text-3xl font-bold text-center mb-6">Login</h1>

        <form onSubmit={handleSubmit(onSubmit)} className="space-y-5" noValidate>
          <GlassInput
            name="email"
            label="Email Address"
            register={register}
            error={errors.email}
            autoComplete="email"
          />

          <GlassInput
            name="password"
            type="password"
            label="Password"
            register={register}
            error={errors.password}
            autoComplete="current-password"
            enablePasswordToggle
          />

          <button type="submit" className="ac-btn-primary w-full" disabled={loading}>
            {loading ? 'Signing in…' : <><LogIn size={18} /> Sign In</>}
          </button>
        </form>

        <div className="text-center mt-6 space-y-2 text-white/90">
          <Link to="/forgot-password" className="underline">Forgot password?</Link>
          <p>
            Don’t have an account?{' '}
            <Link to="/register" className="underline">Register</Link>
          </p>
        </div>
      </motion.div>
    </AuthPageShell>
  );
}
