// ====================================================================
// AuthPageShell.jsx — AgroConnect Namibia
// --------------------------------------------------------------------
// Master’s-Level Auth Layout Shell
//
// ✔ Centralized background & overlay system
// ✔ Mobile-safe viewport (svh)
// ✔ No layout shift on load / keyboard open
// ✔ Adjustable overlay strength
// ✔ Accessibility-first structure
// ✔ Consistent centering across auth pages
// ====================================================================

import React from 'react';

/**
 * AuthPageShell
 *
 * @param {string} bgImage   - Background image URL
 * @param {ReactNode} children
 * @param {"light" | "dark"} overlay - Overlay intensity preset
 */
export default function AuthPageShell({ bgImage, children, overlay = 'dark' }) {
  return (
    <main
      className="
        relative w-full
        min-h-[100svh]
        overflow-y-auto
      "
      aria-label="Authentication page"
      style={{
        backgroundImage: `url(${bgImage})`,
        backgroundSize: 'cover',
        backgroundPosition: 'center',
        backgroundRepeat: 'no-repeat',
      }}
    >
      {/* ===============================================================
         BACKGROUND OVERLAY LAYER
         - Gradient + blur gives depth (not flat darkness)
         - Tunable via prop (future-ready)
         =============================================================== */}
      <div
        aria-hidden="true"
        className={[
          'absolute inset-0',
          overlay === 'dark'
            ? 'bg-gradient-to-br from-black/55 via-black/45 to-black/60 backdrop-blur-sm'
            : 'bg-gradient-to-br from-black/35 via-black/25 to-black/40 backdrop-blur-[2px]',
        ].join(' ')}
      />

      {/* ===============================================================
         CONTENT CONTAINER
         - Uses padding instead of absolute centering → mobile-safe
         - svh avoids iOS address bar jump
         =============================================================== */}
      <div
        className="
          relative z-10
          flex min-h-[100svh]
          items-center justify-center
          px-4 py-10
        "
      >
        {/* =============================================================
           INNER WRAPPER
           - Controls max readable width
           - Prevents edge stretching on ultrawide screens
           ============================================================= */}
        <div className="w-full max-w-[1100px] flex justify-center">{children}</div>
      </div>
    </main>
  );
}
