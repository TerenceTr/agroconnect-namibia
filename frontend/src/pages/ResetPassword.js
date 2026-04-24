// ====================================================================
// frontend/src/pages/ResetPassword.js — AgroConnect Namibia
// --------------------------------------------------------------------
// FILE ROLE:
// • Public reset-password page for the web interface
// • Consumes the password reset token from the query string
// • Submits the new password to the backend
//
// THIS VERSION FIXES:
// • Uses the shared AuthPageShell layout
// • Uses AuthProvider resetPassword()
// • Handles missing / invalid tokens cleanly
// • Returns users to the Start screen with login opened after success
// ====================================================================

import React from 'react';
import { motion } from 'framer-motion';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { KeyRound } from 'lucide-react';

import { resetPasswordSchema } from '../components/auth/validationSchemas';
import { useAuth } from '../components/auth/AuthProvider';
import AuthPageShell from '../components/auth/AuthPageShell';
import GlassInput from '../components/common/GlassInput';
import { notifyError, notifySuccess } from '../utils/notify';

const fadeUp = {
  hidden: { opacity: 0, y: 16 },
  visible: { opacity: 1, y: 0, transition: { duration: 0.45, ease: 'easeOut' } },
};

const START_LOGIN_STATE = { authMode: 'login' };

export default function ResetPassword() {
  const navigate = useNavigate();
  const { resetPassword, loading } = useAuth();
  const [params] = useSearchParams();
  const token = String(params.get('token') || '').trim();

  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm({
    resolver: zodResolver(resetPasswordSchema),
    defaultValues: {
      password: '',
      confirmPassword: '',
    },
  });

  const onSubmit = async ({ password, confirmPassword }) => {
    if (!token) {
      notifyError('Invalid or missing reset token.');
      return;
    }

    try {
      const data = await resetPassword({ token, password, confirmPassword });

      notifySuccess(data?.message || 'Password updated successfully. You can now sign in.');
      navigate('/', { replace: true, state: START_LOGIN_STATE });
    } catch (err) {
      notifyError(
        err?.response?.data?.message ||
          err?.response?.data?.error ||
          err?.message ||
          'Could not reset password.'
      );
    }
  };

  return (
    <AuthPageShell bgImage={`${process.env.PUBLIC_URL}/assets/namibia-bg.jpg`}>
      <motion.div
        initial="hidden"
        animate="visible"
        variants={fadeUp}
        className="glass-card w-full max-w-md p-6 text-white sm:p-8 md:p-10"
      >
        <img
          src={`${process.env.PUBLIC_URL}/assets/logo.png`}
          alt="AgroConnect Logo"
          className="mx-auto mb-6 h-20"
        />

        <h1 className="mb-3 text-center text-3xl font-bold">Create New Password</h1>

        <p className="mb-6 text-center leading-7 text-white/80">
          Enter your new password below to complete the secure reset process.
        </p>

        {!token ? (
          <div className="mb-6 rounded-2xl border border-red-300/35 bg-red-500/15 p-4 text-sm text-white backdrop-blur-sm">
            Invalid or missing reset token. Request a new password reset link and try again.
          </div>
        ) : null}

        <form onSubmit={handleSubmit(onSubmit)} className="space-y-5" noValidate>
          <GlassInput
            name="password"
            label="New Password"
            type="password"
            placeholder="Minimum 6 characters"
            register={register}
            error={errors.password}
            autoComplete="new-password"
            enablePasswordToggle
          />

          <GlassInput
            name="confirmPassword"
            label="Confirm Password"
            type="password"
            placeholder="Re-enter your new password"
            register={register}
            error={errors.confirmPassword}
            autoComplete="new-password"
            enablePasswordToggle
          />

          <button type="submit" className="ac-btn-primary w-full" disabled={loading || !token}>
            {loading ? (
              'Updating password…'
            ) : (
              <>
                <KeyRound size={18} />
                Update Password
              </>
            )}
          </button>
        </form>

        <div className="mt-6 space-y-2 text-center text-white/90">
          <Link to="/forgot-password" className="underline">
            Request another reset link
          </Link>
          <p>
            <Link to="/" state={START_LOGIN_STATE} className="underline">
              Back to Start
            </Link>
          </p>
        </div>
      </motion.div>
    </AuthPageShell>
  );
}
