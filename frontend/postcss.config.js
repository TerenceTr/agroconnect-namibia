// ============================================================================
// AgroConnect Namibia - PostCSS Configuration
// frontend\postcss.config.js
// ----------------------------------------------------------------------------
// 🎯 Purpose:
//   This configuration ensures that TailwindCSS and Autoprefixer are
//   properly integrated into the build process for maximum compatibility.
//
// ⚙️ What it does:
//   1. Loads TailwindCSS utilities (compiled from tailwind.config.js)
//   2. Adds vendor prefixes automatically via Autoprefixer
//   3. Ensures clean, cross-browser-ready CSS for production deployment
//
// 🚀 Compatible with:
//   - Vite
//   - CRA (Create React App)
//   - Render / Netlify / Vercel builds
// ============================================================================

module.exports = {
  plugins: {
    // ✅ TailwindCSS (core utility generator)
    tailwindcss: {},

    // ✅ Autoprefixer (adds browser-specific prefixes automatically)
    autoprefixer: {},
  },
};