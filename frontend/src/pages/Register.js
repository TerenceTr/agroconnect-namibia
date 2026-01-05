// ====================================================================
// frontend/src/pages/Register.js — AgroConnect Namibia
// --------------------------------------------------------------------
// FILE ROLE:
// • User registration page (Farmer / Customer)
// • Handles form validation (React Hook Form + Zod)
// • Submits data to backend via shared API client
// • Provides password strength feedback (UI-only)
// ====================================================================

import React, { useEffect, useMemo, useState } from 'react';
import { motion } from 'framer-motion';
import { UserPlus, Tractor, ShoppingCart } from 'lucide-react';
import { Link, useNavigate } from 'react-router-dom';

import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { registerSchema } from '../components/auth/validationSchemas';

import api from '../api'; // ✅ central Axios client
import { notifySuccess, notifyError } from '../utils/notify';

import AuthPageShell from '../components/auth/AuthPageShell';
import GlassInput from '../components/common/GlassInput';

// --------------------------------------------------------------------
// Subtle entrance animation (content only)
// --------------------------------------------------------------------
const fadeUp = {
  hidden: { opacity: 0, y: 16 },
  visible: { opacity: 1, y: 0, transition: { duration: 0.45 } },
};

export default function Register() {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);

  // ------------------------------------------------------------------
  // React Hook Form + Zod validation
  // ------------------------------------------------------------------
  const {
    register,
    handleSubmit,
    formState: { errors },
    reset,
    watch,
    setFocus,
  } = useForm({
    resolver: zodResolver(registerSchema),
    defaultValues: {
      full_name: '',
      email: '',
      phone: '',
      location: '',
      password: '',
      confirmPassword: '',
      role: '2', // Farmer by default (matches backend ROLE_FARMER)
    },
  });

  // ------------------------------------------------------------------
  // Auto-focus first invalid field on submit
  // ------------------------------------------------------------------
  useEffect(() => {
    const firstError = Object.keys(errors)[0];
    if (firstError) setFocus(firstError);
  }, [errors, setFocus]);

  // ------------------------------------------------------------------
  // Password strength indicator (advisory only)
  // ------------------------------------------------------------------
  const password = watch('password', '');

  const strength = useMemo(() => {
    let score = 0;
    if (password.length >= 6) score++;
    if (/[A-Z]/.test(password)) score++;
    if (/[0-9]/.test(password)) score++;
    if (/[^A-Za-z0-9]/.test(password)) score++;
    return score;
  }, [password]);

  const strengthLabel =
    ['Very weak', 'Weak', 'Fair', 'Good', 'Strong'][strength] || 'Very weak';

  // ------------------------------------------------------------------
  // Submit handler
  // ------------------------------------------------------------------
  const onSubmit = async (formData) => {
    setLoading(true);

    try {
      // Backend expects role as number, not string
      const payload = {
        ...formData,
        role: Number(formData.role),
      };

      await api.post('/auth/register', payload);

      notifySuccess('Account created successfully. You can now log in.');
      reset();
      navigate('/login');
    } catch (err) {
      notifyError(
        err?.response?.data?.message ||
        err?.response?.data?.error ||
        'Registration failed'
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <AuthPageShell bgImage={`${process.env.PUBLIC_URL}/assets/namibia-bg.jpg`}>
      <motion.form
        variants={fadeUp}
        initial="hidden"
        animate="visible"
        onSubmit={handleSubmit(onSubmit)}
        className="glass-card w-full max-w-4xl p-8 md:p-10 text-white"
        noValidate
      >
        {/* ================= HEADER ================= */}
        <header className="text-center mb-10">
          <img
            src={`${process.env.PUBLIC_URL}/assets/logo.png`}
            alt="AgroConnect"
            className="mx-auto h-16 mb-4"
          />
          <h1 className="text-3xl font-bold">Create Your Account</h1>
          <p className="text-white/70 mt-2">
            Join Namibia’s digital agricultural marketplace
          </p>
        </header>

        {/* ================= PERSONAL INFO ================= */}
        <section className="mb-10">
          <h2 className="text-lg font-semibold mb-4">Personal Information</h2>

          <div className="grid md:grid-cols-2 gap-4">
            <GlassInput
              name="full_name"
              label="Full Name"
              placeholder="Firstname & Surname"
              register={register}
              error={errors.full_name}
            />

            <GlassInput
              name="email"
              type="email"
              label="Email Address"
              placeholder="example@example.com"
              register={register}
              error={errors.email}
            />

            <GlassInput
              name="phone"
              label="Phone Number"
              placeholder="0812345678"
              register={register}
              error={errors.phone}
            />

            <GlassInput
              name="location"
              label="Location"
              placeholder="Town or Region (e.g. Windhoek)"
              register={register}
              error={errors.location}
            />
          </div>

          <p className="text-xs text-white/60 mt-3">
            Phone number and location help connect you with nearby buyers and sellers.
          </p>
        </section>

        {/* ================= SECURITY ================= */}
        <section className="mb-12">
          <h2 className="text-lg font-semibold mb-4">Account Security</h2>

          <div className="grid md:grid-cols-2 gap-4">
            <GlassInput
              name="password"
              type="password"
              label="Password"
              placeholder="Minimum 6 characters"
              register={register}
              error={errors.password}
              enablePasswordToggle
            />

            <GlassInput
              name="confirmPassword"
              type="password"
              label="Confirm Password"
              placeholder="Re-enter your password"
              register={register}
              error={errors.confirmPassword}
              enablePasswordToggle
            />
          </div>

          {/* Strength meter (visual only) */}
          {password && (
            <div className="mt-4">
              <div className="flex gap-1">
                {[...Array(4)].map((_, i) => (
                  <span
                    key={i}
                    className={`h-1 flex-1 rounded ${
                      i < strength ? 'bg-emerald-400' : 'bg-white/30'
                    }`}
                  />
                ))}
              </div>
              <p className="text-xs mt-1 text-white/70">
                Strength: <span className="font-semibold">{strengthLabel}</span>
              </p>
            </div>
          )}
        </section>

        {/* ================= ROLE ================= */}
        <section className="mb-12">
          <h2 className="text-lg font-semibold mb-4 text-center">
            Select Your Role
          </h2>

          <div className="flex justify-center">
            <div className="glass-radio-group">
              <input
                type="radio"
                id="role-farmer"
                value="2"
                {...register('role')}
                defaultChecked
              />
              <label htmlFor="role-farmer">
                <Tractor size={16} className="mr-2" />
                Farmer
              </label>

              <input
                type="radio"
                id="role-customer"
                value="3"
                {...register('role')}
              />
              <label htmlFor="role-customer">
                <ShoppingCart size={16} className="mr-2" />
                Customer
              </label>

              <div className="glass-glider" />
            </div>
          </div>
        </section>

        {/* ================= SUBMIT ================= */}
        <button
          type="submit"
          disabled={loading}
          className="ac-btn-primary w-full"
        >
          {loading ? (
            'Creating account…'
          ) : (
            <>
              <UserPlus size={18} /> Create Account
            </>
          )}
        </button>

        <p className="text-center mt-6 text-white/80">
          Already registered?{' '}
          <Link to="/login" className="underline">
            Login here
          </Link>
        </p>
      </motion.form>
    </AuthPageShell>
  );
}
