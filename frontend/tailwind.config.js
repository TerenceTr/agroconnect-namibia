/** @type {import('tailwindcss').Config} */ 
// ============================================================================
// frontend\tailwind.config.js
// AgroConnect Namibia Tailwind Configuration (Master’s-Level Edition)
// ----------------------------------------------------------------------------
// 🎯 PURPOSE:
//   - Professional, consistent design system across Login, Register, Dashboards
//   - Namibia-inspired color identity
//   - Advanced UI components (glass, shadows, animated buttons)
//   - Tailwind extensions for motion, layout, responsiveness
// ============================================================================

module.exports = {
  content: ['./src/**/*.{js,jsx,ts,tsx}'],

  theme: {
    container: {
      center: true,
      padding: "1rem",
      screens: {
        sm: "600px",
        md: "720px",
        lg: "960px",
        xl: "1140px",
      },
    },

    extend: {
      // ------------------------------------------------------------
      // 🎨 NAMIBIA COLOR PALETTE (Brand Identity)
      // ------------------------------------------------------------
      colors: {
        'namibia-green': '#10B981',
        'namibia-dark': '#065F46',
        'namibia-deep': '#054435',
        'namibia-light': '#A7F3D0',
        'namibia-sand': '#F9FAF5',
        'namibia-gold': '#FACC15',
        'namibia-red': '#EF4444',   // Alerts / errors
        'glass-white': 'rgba(255,255,255,0.15)',
        'glass-dark': 'rgba(0,0,0,0.25)',
      },

      // ------------------------------------------------------------
      // 🌅 BACKGROUNDS & GRADIENTS
      // ------------------------------------------------------------
      backgroundImage: {
        'namibia-gradient':
          'linear-gradient(135deg, #10B981 0%, #0D7A57 30%, #065F46 60%, #054435 100%)',
        'admin-cards':
          'linear-gradient(145deg, rgba(255,255,255,0.08), rgba(255,255,255,0.02))',
      },

      // ------------------------------------------------------------
      // 🧊 GLASSMORPHISM UTILITIES
      // ------------------------------------------------------------
      backdropBlur: {
        xs: '2px',
        sm: '4px',
        md: '8px',
        lg: '14px',
        xl: '18px',
      },

      // ------------------------------------------------------------
      // 🌓 SHADOW SYSTEM (Depth Levels)
      // ------------------------------------------------------------
      boxShadow: {
        glass: '0 4px 30px rgba(0, 0, 0, 0.1)',
        'glass-strong': '0 6px 35px rgba(0, 0, 0, 0.15)',
        soft: '0 2px 8px rgba(0,0,0,0.10)',
        'soft-lg': '0 10px 25px rgba(0,0,0,0.15)',
        'button-hover': '0 6px 14px rgba(0,0,0,0.18)',
      },

      // ------------------------------------------------------------
      // 🧱 TYPOGRAPHY
      // ------------------------------------------------------------
      fontFamily: {
        sans: ['Inter', 'Poppins', 'system-ui', 'sans-serif'],
      },

      // ------------------------------------------------------------
      // ⚡ ANIMATIONS (UI Motion System)
      // ------------------------------------------------------------
      keyframes: {
        fadeIn: {
          '0%': { opacity: 0 },
          '100%': { opacity: 1 },
        },
        slideUp: {
          '0%': { opacity: 0, transform: 'translateY(25px)' },
          '100%': { opacity: 1, transform: 'translateY(0)' },
        },
        popIn: {
          '0%': { transform: 'scale(0.8)', opacity: 0 },
          '60%': { transform: 'scale(1.05)', opacity: 1 },
          '100%': { transform: 'scale(1)' },
        },
        pulseSoft: {
          '0%, 100%': { opacity: 1 },
          '50%': { opacity: 0.5 },
        },
      },

      animation: {
        fadeIn: 'fadeIn 0.7s ease-out',
        slideUp: 'slideUp 0.7s ease-out',
        popIn: 'popIn 0.4s ease-out',
        pulseSoft: 'pulseSoft 2s ease-in-out infinite',
      },

      // ------------------------------------------------------------
      // 🌟 BUTTON COMPONENT LAYER (Reusable — PRO LEVEL)
      // ------------------------------------------------------------
      borderRadius: {
        xl2: '1.2rem',
      },
    },
  },

  // ------------------------------------------------------------
  // 🧩 PLUGINS
  // ------------------------------------------------------------
  plugins: [
    require('@tailwindcss/forms'),
    require('@tailwindcss/typography'),

    // ✨ Custom Button Component Layer
    function ({ addComponents, theme }) {
      const buttons = {
        // PRIMARY BUTTON — green
        '.btn-primary': {
          backgroundColor: theme('colors.namibia-green'),
          color: '#fff',
          padding: '0.65rem 1.4rem',
          borderRadius: '0.75rem',
          fontWeight: '600',
          transition: '0.25s',
          boxShadow: theme('boxShadow.soft'),
        },
        '.btn-primary:hover': {
          backgroundColor: theme('colors.namibia-dark'),
          boxShadow: theme('boxShadow.button-hover'),
        },

        // SECONDARY BUTTON — subtle white glass
        '.btn-secondary': {
          backgroundColor: 'rgba(255,255,255,0.2)',
          color: '#fff',
          padding: '0.65rem 1.4rem',
          borderRadius: '0.75rem',
          backdropFilter: 'blur(6px)',
          fontWeight: '500',
          transition: '0.25s',
          border: '1px solid rgba(255,255,255,0.25)',
        },
        '.btn-secondary:hover': {
          backgroundColor: 'rgba(255,255,255,0.3)',
          borderColor: 'rgba(255,255,255,0.45)',
        },

        // OUTLINE BUTTON — clean for cancel/neutral actions
        '.btn-outline': {
          border: `2px solid ${theme('colors.namibia-green')}`,
          color: theme('colors.namibia-green'),
          background: 'transparent',
          padding: '0.6rem 1.3rem',
          borderRadius: '0.75rem',
          fontWeight: '600',
          transition: '0.25s',
        },
        '.btn-outline:hover': {
          background: theme('colors.namibia-green'),
          color: '#fff',
        },

        // DANGER BUTTON — red actions
        '.btn-danger': {
          backgroundColor: theme('colors.namibia-red'),
          color: '#fff',
          padding: '0.65rem 1.4rem',
          borderRadius: '0.75rem',
          fontWeight: '600',
          transition: '0.25s',
          boxShadow: theme('boxShadow.soft'),
        },
        '.btn-danger:hover': {
          backgroundColor: '#b91c1c',
          boxShadow: theme('boxShadow.button-hover'),
        },

        // SUBTLE BUTTON — minimal UI (filters, small actions)
        '.btn-subtle': {
          backgroundColor: 'rgba(255,255,255,0.05)',
          color: '#fff',
          padding: '0.45rem 1.1rem',
          borderRadius: '0.6rem',
          fontWeight: '500',
          transition: '0.2s',
        },
        '.btn-subtle:hover': {
          backgroundColor: 'rgba(255,255,255,0.12)',
        },
      };
      addComponents(buttons);
    },
  ],
};
