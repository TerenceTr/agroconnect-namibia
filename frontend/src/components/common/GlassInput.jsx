// ====================================================================
// frontend/src/components/common/GlassInput.jsx
// --------------------------------------------------------------------
// FILE ROLE:
//   Reusable auth-friendly input field used by login, register,
//   forgot-password, reset-password, and the shared auth dialog.
//
// THIS VERSION IMPROVES:
//   • stronger readability on dark auth surfaces by default
//   • cleaner labels, helper text, and validation messages
//   • better hover, focus, and error states
//   • clearer password toggle button
//   • safe fallback when react-hook-form register is not provided
//   • extra native input prop support through ...rest
//
// NOTE:
//   This component now defaults to theme="dark" because it is mainly
//   used inside the shared auth dialog and auth screens. If you use it
//   on a light page/card, pass theme="light" explicitly.
// ====================================================================

import React, { useMemo, useState } from 'react';
import clsx from 'clsx';
import { Eye, EyeOff } from 'lucide-react';
import { AnimatePresence, motion } from 'framer-motion';

export default function GlassInput({
  label,
  name,
  type = 'text',
  register,
  error,
  placeholder = '',
  autoComplete,
  disabled = false,
  enablePasswordToggle = false,
  helperText = '',
  theme = 'dark',
  containerClassName = '',
  labelClassName = '',
  inputClassName = '',
  ...rest
}) {
  // ------------------------------------------------------------------
  // Detect whether this input is a password field and whether the eye
  // toggle should be shown.
  // ------------------------------------------------------------------
  const isPassword = type === 'password';
  const canTogglePassword = isPassword && enablePasswordToggle;

  // ------------------------------------------------------------------
  // Local state only affects password visibility when toggling is active.
  // ------------------------------------------------------------------
  const [showPassword, setShowPassword] = useState(false);

  // ------------------------------------------------------------------
  // Resolve the actual input type rendered to the DOM.
  // ------------------------------------------------------------------
  const resolvedType = canTogglePassword
    ? showPassword
      ? 'text'
      : 'password'
    : type;

  // ------------------------------------------------------------------
  // Theme palettes.
  // Dark palette is optimized for the shared auth dialog and glass cards.
  // Light palette is available for use on white / light surfaces.
  // ------------------------------------------------------------------
  const palette = useMemo(() => {
    if (theme === 'light') {
      return {
        label: 'text-[#1B3A2C]',
        labelStyle: undefined,

        input:
          'bg-white text-[#173324] border border-[#D8E8DC] ' +
          'placeholder:text-slate-400 hover:border-[#BFD8C8] ' +
          'focus:border-emerald-500/65 focus:ring-4 focus:ring-emerald-200/50 ' +
          'shadow-[0_10px_22px_rgba(16,40,24,0.06)]',

        helper: 'text-slate-500',
        error: 'text-rose-500',

        toggle:
          'bg-[#F6FBF7] text-slate-600 border border-[#DDECE2] ' +
          'hover:bg-[#ECF7F0] hover:text-[#173324] ' +
          'focus:ring-2 focus:ring-emerald-300/50',
      };
    }

    return {
      label: 'text-white/95',
      labelStyle: { textShadow: '0 1px 12px rgba(0,0,0,0.35)' },

      input:
        'bg-[rgba(255,255,255,0.96)] text-[#153021] border border-white/16 ' +
        'placeholder:text-[#6E8579] hover:border-emerald-200/65 hover:bg-white ' +
        'focus:bg-white focus:border-emerald-300/80 focus:ring-4 focus:ring-emerald-300/18 ' +
        'shadow-[0_14px_30px_rgba(0,0,0,0.16)]',

      helper: 'text-white/74',
      error: 'text-rose-300',

      toggle:
        'bg-[#EEF7F1] text-[#355947] border border-white/12 ' +
        'hover:bg-white hover:text-[#173324] ' +
        'focus:ring-2 focus:ring-emerald-300/55 shadow-sm',
    };
  }, [theme]);

  // ------------------------------------------------------------------
  // Error flag simplifies conditional styling.
  // ------------------------------------------------------------------
  const hasError = Boolean(error);

  // ------------------------------------------------------------------
  // Support react-hook-form when register is supplied, but do not fail
  // if this component is used outside RHF.
  // ------------------------------------------------------------------
  const registrationProps =
    typeof register === 'function' && name ? register(name) : {};

  // ------------------------------------------------------------------
  // Helper / error message ids improve accessibility.
  // ------------------------------------------------------------------
  const helperId = helperText ? `${name}-helper-text` : undefined;
  const errorId = hasError ? `${name}-error-text` : undefined;
  const describedBy = hasError ? errorId : helperId;

  return (
    <div className={clsx('space-y-1.5', containerClassName)}>
      {/* --------------------------------------------------------------
         Label
      -------------------------------------------------------------- */}
      {label ? (
        <label
          htmlFor={name}
          className={clsx(
            'block text-sm font-bold tracking-[0.01em]',
            palette.label,
            labelClassName
          )}
          style={palette.labelStyle}
        >
          {label}
        </label>
      ) : null}

      {/* --------------------------------------------------------------
         Input wrapper
      -------------------------------------------------------------- */}
      <div className="relative">
        <input
          id={name}
          name={name}
          type={resolvedType}
          placeholder={placeholder}
          autoComplete={autoComplete}
          disabled={disabled}
          aria-invalid={hasError ? 'true' : 'false'}
          aria-describedby={describedBy}
          {...registrationProps}
          {...rest}
          className={clsx(
            'w-full rounded-2xl px-4 py-3.5 text-sm font-medium outline-none transition duration-200',
            canTogglePassword && 'pr-14',
            palette.input,
            hasError &&
              'border-rose-400 focus:border-rose-400 focus:ring-4 focus:ring-rose-200/40',
            disabled && 'cursor-not-allowed opacity-60',
            inputClassName
          )}
        />

        {/* ------------------------------------------------------------
           Password toggle button
        ------------------------------------------------------------ */}
        {canTogglePassword ? (
          <button
            type="button"
            onClick={() => setShowPassword((current) => !current)}
            aria-label={showPassword ? 'Hide password' : 'Show password'}
            className={clsx(
              'absolute right-2 top-1/2 inline-flex h-9 w-9 -translate-y-1/2 items-center justify-center rounded-full transition focus:outline-none',
              palette.toggle
            )}
          >
            <AnimatePresence mode="wait" initial={false}>
              <motion.span
                key={showPassword ? 'hide' : 'show'}
                initial={{ opacity: 0, rotate: -12, scale: 0.92 }}
                animate={{ opacity: 1, rotate: 0, scale: 1 }}
                exit={{ opacity: 0, rotate: 12, scale: 0.92 }}
                transition={{ duration: 0.18 }}
              >
                {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
              </motion.span>
            </AnimatePresence>
          </button>
        ) : null}
      </div>

      {/* --------------------------------------------------------------
         Error text
      -------------------------------------------------------------- */}
      {hasError ? (
        <p
          id={errorId}
          className={clsx('text-xs font-semibold', palette.error)}
        >
          {error.message}
        </p>
      ) : null}

      {/* --------------------------------------------------------------
         Helper text
      -------------------------------------------------------------- */}
      {!hasError && helperText ? (
        <p
          id={helperId}
          className={clsx('text-xs leading-5', palette.helper)}
          style={
            theme === 'dark'
              ? { textShadow: '0 1px 10px rgba(0,0,0,0.25)' }
              : undefined
          }
        >
          {helperText}
        </p>
      ) : null}
    </div>
  );
}