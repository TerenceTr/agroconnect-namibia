// ====================================================================
// frontend/src/components/auth/AuthPageShell.jsx
// --------------------------------------------------------------------
// FILE ROLE:
//   Shared full-screen shell for standalone auth pages.
//
// THIS VERSION IMPROVES:
//   • better contrast over the farm background
//   • more premium layered atmosphere
//   • mobile-safe vertical centering and scrolling
//   • cleaner separation between backdrop and auth content
// ====================================================================

import React from 'react';

export default function AuthPageShell({ bgImage, children, overlay = 'dark' }) {
  const overlayClass =
    overlay === 'light'
      ? 'bg-[linear-gradient(135deg,rgba(4,18,13,0.38),rgba(4,18,13,0.30),rgba(4,18,13,0.42))]'
      : 'bg-[linear-gradient(135deg,rgba(4,18,13,0.62),rgba(4,18,13,0.44),rgba(4,18,13,0.68))]';

  return (
    <main
      className="relative min-h-[100svh] overflow-y-auto"
      aria-label="Authentication page"
      style={{
        backgroundImage: `url(${bgImage})`,
        backgroundSize: 'cover',
        backgroundPosition: 'center',
        backgroundRepeat: 'no-repeat',
      }}
    >
      <div className={`absolute inset-0 ${overlayClass}`} aria-hidden="true" />
      <div className="absolute inset-0 backdrop-blur-[3px]" aria-hidden="true" />

      <div className="pointer-events-none absolute inset-0 overflow-hidden" aria-hidden="true">
        <div className="absolute -left-20 top-16 h-72 w-72 rounded-full bg-emerald-400/12 blur-3xl" />
        <div className="absolute right-0 top-0 h-80 w-80 rounded-full bg-[#C1A362]/10 blur-3xl" />
        <div className="absolute bottom-0 left-1/3 h-72 w-72 rounded-full bg-emerald-200/8 blur-3xl" />
      </div>

      <div className="relative z-10 flex min-h-[100svh] items-center justify-center px-4 py-10 sm:px-6 lg:px-8">
        <div className="w-full max-w-[1180px]">{children}</div>
      </div>
    </main>
  );
}
