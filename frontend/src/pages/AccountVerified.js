// frontend/src/pages/AccountVerified.js
// AccountVerified: Success page after email verification; redirects to login.
// Key Block: Timeout auto-redirect (smooth UX); motion variants for celebration animation.
// Trade-off: Auto-redirect (convenient) vs. manual button (user control); Firebase listener for verification state.

import React, { useEffect } from 'react';
import { motion } from 'framer-motion';
import { CheckCircle, ArrowRight, UserCheck } from 'lucide-react';
import { Link, useNavigate } from 'react-router-dom';

// Animation variants: Staggered entrance for celebration effect.
const variants = {
  hidden: { opacity: 0, y: 30 },
  visible: { opacity: 1, y: 0, transition: { duration: 0.7, ease: 'easeOut' } }
};

const AccountVerified = () => {
  const navigate = useNavigate();

  useEffect(() => {
    const timer = setTimeout(() => navigate('/login'), 3000);  // Auto-redirect after 3s.
    return () => clearTimeout(timer);
  }, [navigate]);

  return (
    <motion.div
      initial="hidden"
      animate="visible"
      variants={variants}
      className="min-h-screen flex items-center justify-center text-white relative overflow-hidden"
      style={{
        backgroundImage: `url(${process.env.PUBLIC_URL}/assets/namibia-bg.jpg)`,
        backgroundSize: 'cover',
        backgroundPosition: 'center'
      }}
    >
      <div className="absolute inset-0 bg-black/40 backdrop-blur-sm" aria-hidden="true" />
      <div className="relative z-10 bg-white/10 backdrop-blur-md p-8 rounded-2xl w-full max-w-md border border-white/20 shadow-2xl text-center">
        <motion.img
          src={`${process.env.PUBLIC_URL}/assets/logo.png`}
          alt="AgroConnect Namibia Logo"
          className="mx-auto h-24 mb-6 drop-shadow-lg"
          variants={variants}
        />
        <motion.div variants={variants} className="flex justify-center mb-6">
          <CheckCircle className="text-namibia-green w-16 h-16 drop-shadow-lg" />
        </motion.div>
        <motion.h2 variants={variants} className="text-2xl font-bold mb-3 text-white">
          Account Verified!
        </motion.h2>
        <motion.p variants={variants} className="text-white/80 mb-6 text-sm leading-relaxed">
          Your email has been successfully verified. Redirecting to login...
        </motion.p>
        <motion.div variants={variants} className="flex justify-center mb-8">
          <UserCheck className="w-10 h-10 text-white/80" />
        </motion.div>
        <motion.div variants={variants}>
          <Link to="/login" className="inline-flex items-center justify-center gap-2 bg-namibia-green text-white px-6 py-3 rounded-lg font-semibold hover:bg-green-600 transition-colors">
            Continue to Login <ArrowRight size={18} />
          </Link>
        </motion.div>
      </div>
    </motion.div>
  );
};

export default AccountVerified;