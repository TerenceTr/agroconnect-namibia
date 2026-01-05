// ====================================================================
// validationSchemas.js — AgroConnect Namibia (Master-Level Validation)
// Centralized Zod validators for all auth, profile, and verification forms
// --------------------------------------------------------------------
// DESIGN PRINCIPLES:
// ✓ Single source of truth
// ✓ HTML-compatible (string inputs)
// ✓ Zod handles coercion + validation
// ✓ Backend-safe DTO alignment
// ====================================================================

import { z } from 'zod';

/* ==============================================================
   SHARED FIELD DEFINITIONS
   ============================================================== */

// Email
const emailField = z
  .string()
  .trim()
  .min(1, 'Email is required')
  .email('Enter a valid email address');

// Password
const passwordField = z.string().trim().min(6, 'Password must be at least 6 characters');

// Full name
const nameField = z
  .string()
  .trim()
  .min(2, 'Name is too short')
  .max(50, 'Name is too long');

// Phone number
const phoneField = z
  .string()
  .trim()
  .min(7, 'Phone number is too short')
  .max(15, 'Phone number is too long');

// Location (required for marketplace relevance)
const locationField = z
  .string()
  .trim()
  .min(1, 'Location is required')
  .max(60, 'Location is too long');

// Role
// Radios emit strings → Zod coerces to number
// Valid roles:
// 2 = Farmer
// 3 = Customer
const roleField = z.coerce
  .number()
  .refine((val) => val === 2 || val === 3, { message: 'Please select a valid role' });

/* ==============================================================
   AUTH SCHEMAS
   ============================================================== */

// --------------------
// LOGIN
// --------------------
export const loginSchema = z.object({
  email: emailField,
  password: passwordField,
});

// --------------------
// REGISTER
// --------------------
export const registerSchema = z
  .object({
    full_name: nameField,
    email: emailField,
    phone: phoneField,
    location: locationField,
    password: passwordField,
    confirmPassword: passwordField,
    role: roleField,
  })
  .refine((data) => data.password === data.confirmPassword, {
    message: 'Passwords do not match',
    path: ['confirmPassword'],
  });

// --------------------
// FORGOT PASSWORD
// --------------------
export const forgotPasswordSchema = z.object({
  email: emailField,
});

// --------------------
// RESET PASSWORD
// --------------------
export const resetPasswordSchema = z
  .object({
    password: passwordField,
    confirmPassword: passwordField,
  })
  .refine((data) => data.password === data.confirmPassword, {
    message: 'Passwords do not match',
    path: ['confirmPassword'],
  });

// --------------------
// RESEND VERIFICATION
// --------------------
export const resendVerificationSchema = z.object({
  email: emailField,
  password: passwordField,
});

// --------------------
// UPDATE PROFILE (OPTIONAL FIELDS)
// --------------------
export const updateProfileSchema = z.object({
  full_name: nameField.optional(),
  phone: phoneField.optional(),
  location: locationField.optional(),
  password: passwordField.optional(),
});
