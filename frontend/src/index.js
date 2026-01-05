// ============================================================================
// src/index.js — AgroConnect Namibia
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Single React entry point (mounts the SPA into #root).
//
// RESPONSIBILITIES:
//   • Mount <App /> exactly once (stable dev behavior).
//   • Perform safe splash teardown (non-blocking).
//   • Never rely on animation events to reveal the app.
//
// WHY THIS FIXES YOUR “BLANK GREEN SCREEN”:
//   If #root was hidden (or splash never fades), you can get a page that shows
//   only the background. This guarantees #root is visible and splash is removed.
// ============================================================================

import React from 'react';
import ReactDOM from 'react-dom/client';

import './index.css';
import App from './App';
import reportWebVitals from './reportWebVitals';

// ---------------------------------------------------------------------------
// Ensure root is visible immediately (never allow display:none to block UI).
// ---------------------------------------------------------------------------
function ensureRootVisible() {
  const rootEl = document.getElementById('root');
  if (!rootEl) return;

  // Keep root visible so React can render even if splash fails.
  rootEl.style.display = 'block';

  // Optional: render behind splash without a flash.
  if (!rootEl.style.opacity) {
    rootEl.style.opacity = '0';
  }
}

// ---------------------------------------------------------------------------
// Splash teardown (safe + has timeout fallback).
// ---------------------------------------------------------------------------
function hideSplash() {
  const rootEl = document.getElementById('root');
  const splashEl = document.getElementById('loading-screen');

  // No splash? Just show the app.
  if (!splashEl) {
    if (rootEl) rootEl.style.opacity = '1';
    return;
  }

  const finalize = () => {
    splashEl.style.display = 'none';
    if (rootEl) rootEl.style.opacity = '1';
  };

  // If animation doesn't fire for any reason, still reveal app.
  const FALLBACK_MS = 900;
  const timer = window.setTimeout(finalize, FALLBACK_MS);

  // Trigger fade-out (CSS exists in index.css AND inline in index.html).
  splashEl.classList.add('fade-out');

  splashEl.addEventListener(
    'animationend',
    () => {
      window.clearTimeout(timer);
      finalize();
    },
    { once: true }
  );
}

// ---------------------------------------------------------------------------
// Mount React app (NO StrictMode — stable dev behavior).
// ---------------------------------------------------------------------------
const container = document.getElementById('root');
const root = ReactDOM.createRoot(container);

ensureRootVisible();
root.render(<App />);

// Defer splash hide until after paint (avoids edge cases during initial load).
requestAnimationFrame(() => requestAnimationFrame(hideSplash));

reportWebVitals();
