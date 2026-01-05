// ============================================================================
// src/utils/lazyWithRetry.js
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Safer React.lazy wrapper that retries once when a chunk fails to load.
//
// WHY THIS FIX:
//   ChunkLoadError commonly happens when:
//     • the dev server rebuilds chunks
//     • the browser has an older chunk filename cached
//     • a service worker serves stale assets
//
// BEHAVIOR:
//   • If a chunk fails, reload once (session-guarded)
//   • If it still fails, bubble the error (so your ErrorBoundary can show UI)
// ============================================================================

import React from "react";

function isChunkLoadError(err) {
  const msg = String(err?.message || err || "");
  return /ChunkLoadError|Loading chunk .* failed|CSS_CHUNK_LOAD_FAILED/i.test(msg);
}

export function lazyWithRetry(factory) {
  return React.lazy(() =>
    factory().catch((err) => {
      if (!isChunkLoadError(err)) throw err;

      const key = "ac_chunk_retry_once";
      const already = sessionStorage.getItem(key);

      // Reload only once per session to avoid infinite loops
      if (!already) {
        sessionStorage.setItem(key, "1");
        window.location.reload();
      }

      throw err;
    })
  );
}
