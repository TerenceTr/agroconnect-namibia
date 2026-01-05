// ====================================================================
// frontend/src/components/common/GlassInput.jsx
// Layout-neutral, reusable input (FINAL)
// --------------------------------------------------------------------
// FIXES:
// ✓ High-contrast password toggle (clearly visible)
// ✓ Accessible focus + hover states
// ✓ No layout shift
// ✓ Works for Password & Confirm Password
// ====================================================================

import React, { useState } from 'react';
import clsx from 'clsx';
import { Eye, EyeOff } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

export default function GlassInput({
  label,
  name,
  type = 'text',
  register,
  error,
  placeholder,
  autoComplete,
  disabled = false,
  enablePasswordToggle = false,
}) {
  const isPassword = type === 'password';
  const canToggle = isPassword && enablePasswordToggle;
  const [showPw, setShowPw] = useState(false);

  return (
    <div className="space-y-1">
      {/* Label */}
      {label && (
        <label htmlFor={name} className="block text-sm font-medium text-white/90">
          {label}
        </label>
      )}

      {/* Input wrapper */}
      <div className="relative">
        <input
          id={name}
          type={canToggle ? (showPw ? 'text' : 'password') : type}
          placeholder={placeholder}
          autoComplete={autoComplete}
          disabled={disabled}
          {...register(name)}
          className={clsx(
            `
              w-full px-4 py-3 rounded-xl
              bg-white/85 text-gray-900
              border border-white/35
              placeholder-gray-500
              outline-none transition
              focus:bg-white
            `,
            canToggle && 'pr-14', // reserve space for toggle
            error
              ? 'border-red-400 focus:ring-2 focus:ring-red-300'
              : 'focus:ring-2 focus:ring-emerald-300/60',
            disabled && 'opacity-60 cursor-not-allowed'
          )}
        />

        {/* 👁️ Password visibility toggle */}
        {canToggle && (
          <button
            type="button"
            onClick={() => setShowPw((v) => !v)}
            aria-label={showPw ? 'Hide password' : 'Show password'}
            className="
              absolute right-2 top-1/2 -translate-y-1/2
              flex items-center justify-center
              h-9 w-9
              rounded-full
              bg-white/70
              text-gray-700
              hover:bg-white
              hover:text-gray-900
              focus:outline-none
              focus:ring-2 focus:ring-emerald-400
              transition
            "
          >
            <AnimatePresence mode="wait">
              <motion.span
                key={showPw ? 'hide' : 'show'}
                initial={{ opacity: 0, rotate: -15 }}
                animate={{ opacity: 1, rotate: 0 }}
                exit={{ opacity: 0, rotate: 15 }}
                transition={{ duration: 0.2 }}
              >
                {showPw ? <EyeOff size={18} /> : <Eye size={18} />}
              </motion.span>
            </AnimatePresence>
          </button>
        )}
      </div>

      {/* Error */}
      {error && <p className="text-red-300 text-xs mt-1">{error.message}</p>}
    </div>
  );
}
