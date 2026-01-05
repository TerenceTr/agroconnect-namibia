// frontend/src/pages/EmailSent.jsx
// EmailSent: Confirmation after reset/verification email sent; checks inbox/spam note.
// Key Block: Toast notification for success; motion stagger for elements (celebration UX).
// Trade-off: Inline timer for redirect (simple) vs. button (user control); backend log for audit.

import React from 'react';
import { motion } from 'framer-motion';
import { CheckCircle, Mail, ArrowRight } from 'lucide-react';
import { Link, useNavigate } from 'react-router-dom';
import { toast } from 'react-toastify';

// Variants: Staggered animation for sequential reveal.
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

const EmailSent = () => {
  const navigate = useNavigate();

  const handleLogin = () => navigate('/login');

  useEffect(() => {
    toast.success('Email sent! Check your inbox.');
  }, []);

  return (
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
          <CheckCircle className="text-namibia-green w-16 h-16 drop-shadow-lg" />
        </motion.div>
        <motion.h2 variants={variants.item} className="text-2xl font-bold mb-3 text-white">
          Email Sent!
        </motion.h2>
        <motion.p variants={variants.item} className="text-white/80 mb-6 text-sm leading-relaxed">
          We've sent a link to your inbox (check spam if not there). Click it to continue.
        </motion.p>
        <motion.div variants={variants.item} className="flex justify-center mb-8">
          <Mail className="w-10 h-10 text-white/80" />
        </motion.div>
        <motion.div variants={variants.item}>
          <button onClick={handleLogin} className="inline-flex items-center justify-center gap-2 bg-namibia-green text-white px-6 py-3 rounded-lg font-semibold hover:bg-green-600 transition-colors">
            Return to Login <ArrowRight size={18} />
          </button>
        </motion.div>
      </motion.div>
    </motion.div>
  );
};

export default EmailSent;