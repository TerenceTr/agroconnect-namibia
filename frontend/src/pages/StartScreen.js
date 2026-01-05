// ====================================================================
// StartScreen.js — AgroConnect Namibia
// Clean hero landing page
// ✔ No double animation
// ✔ No layout shift
// ✔ Mobile-safe (svh)
// ✔ Single motion layer
// ====================================================================

import React from 'react';
import { motion } from 'framer-motion';
import { LogIn } from 'lucide-react';
import { Link } from 'react-router-dom';

// ------------------------------------------------------------
// Single entrance animation (content only)
// ------------------------------------------------------------
const fadeUp = {
  hidden: { opacity: 0, y: 28 },
  visible: {
    opacity: 1,
    y: 0,
    transition: { duration: 0.7, ease: 'easeOut' },
  },
};

export default function StartScreen() {
  const bgImage = `${process.env.PUBLIC_URL}/assets/namibia-bg.jpg`;
  const logoImage = `${process.env.PUBLIC_URL}/assets/logo.png`;

  return (
    <div
      className="relative min-h-[100svh] w-full overflow-hidden"
      style={{
        backgroundImage: `url(${bgImage})`,
        backgroundSize: 'cover',
        backgroundPosition: 'center',
      }}
    >
      {/* Dark overlay for contrast */}
      <div className="absolute inset-0 bg-black/45 backdrop-blur-sm" />

      {/* Centered content */}
      <div className="relative z-10 flex min-h-[100svh] items-center justify-center px-4">
        <motion.div
          initial="hidden"
          animate="visible"
          variants={fadeUp}
          className="text-center max-w-3xl"
        >
          {/* Logo */}
          <img
            src={logoImage}
            alt="AgroConnect Logo"
            className="mx-auto h-24 sm:h-28 mb-8 drop-shadow-2xl"
          />

          {/* Heading */}
          <h1 className="text-[clamp(2rem,5vw,3.5rem)] font-extrabold text-white mb-5">
            AgroConnect Namibia
          </h1>

          {/* Subtitle */}
          <p className="text-[clamp(1rem,2.5vw,1.4rem)] text-white/90 mb-10 leading-relaxed">
            Empowering Namibian farmers with AI-driven insights, direct market access, and
            real-time agricultural intelligence.
          </p>

          {/* CTA */}
          <Link to="/login" className="ac-btn-primary inline-flex items-center">
            <LogIn className="mr-2" size={20} />
            Get Started
          </Link>
        </motion.div>
      </div>
    </div>
  );
}
