// frontend/pages/VerificationFailed.jsx
// VerificationFailed: Error page for invalid/expired link; options to resend or login.
// Key Block: Motion stagger for error animation; Link to resend/login (user flow).
// Trade-off: Inline error (simple) vs. backend check (redundant API call); toast for feedback.

import React from 'react';
import { motion } from 'framer-motion';
import { XCircle, RefreshCcw, ArrowLeft } from 'lucide-react';
import { Link } from 'react-router-dom';

// Variants: Staggered for error reveal (dramatic but not overwhelming).
const variants = {
  container: {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: {
        staggerChildren: 0.1,
        delayChildren: 0.2
      }
    }
  },
  item: {
    hidden: { opacity: 0, y: 30 },
    visible: { opacity: 1, y: 0, transition: { duration: 0.6, ease: 'easeOut' } }
  }
};

const VerificationFailed = () => (
  <motion.div
    variants={variants.container}
    initial="hidden"
    animate="visible"
    className="min-h-screen flex items-center justify-center text-white relative overflow-hidden"
    style={{
      backgroundImage: `url(${process.env.PUBLIC_URL}/assets/namibia-bg.jpg)`,
      backgroundSize: 'cover',
      backgroundPosition: 'center'
    }}
  >
    <div className="absolute inset-0 bg-black/40 backdrop-blur-sm" aria-hidden="true" />
    <motion.div variants={variants.item} className="relative z-10 bg-white/10 backdrop-blur-md p-8 rounded-2xl w-full max-w-md border border-white/20 shadow-2xl text-center">
      <motion.img
        src={`${process.env.PUBLIC_URL}/assets/logo.png`}
        alt="AgroConnect Namibia Logo"
        className="mx-auto h-24 mb-6 drop-shadow-lg"
        variants={variants.item}
      />
      <motion.div variants={variants.item} className="flex justify-center mb-6">
        <XCircle className="text-red-400 w-16 h-16 drop-shadow-lg" />
      </motion.div>
      <motion.h2 variants={variants.item} className="text-2xl font-bold mb-3 text-white">
        Verification Failed
      </motion.h2>
      <motion.p variants={variants.item} className="text-white/80 mb-8 text-sm leading-relaxed">
        The verification link is invalid, expired, or has already been used. Request a new one.
      </motion.p>
      <motion.div variants={variants.item} className="flex flex-col sm:flex-row justify-center gap-4">
        <Link
          to="/resend-verification"
          className="inline-flex items-center justify-center gap-2 bg-namibia-green text-white px-5 py-3 rounded-lg font-semibold hover:bg-green-600 transition-colors"
        >
          <RefreshCcw size={18} /> Resend Link
        </Link>
        <Link
          to="/login"
          className="inline-flex items-center justify-center gap-2 bg-white/20 border border-white/30 px-5 py-3 rounded-lg font-semibold text-white hover:bg-white/30 transition-colors"
        >
          <ArrowLeft size={18} /> Back to Login
        </Link>
      </motion.div>
    </motion.div>
  </motion.div>
);

export default VerificationFailed;