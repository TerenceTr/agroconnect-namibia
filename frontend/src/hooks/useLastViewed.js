// ============================================================================
// hooks/useLastViewed.js
// ----------------------------------------------------------------------------
// ROLE:
// • Tracks "last checked" product per customer (frontend-only)
// • This is useful for MSc dashboards even before backend support exists.
// ============================================================================

import { useCallback, useMemo, useState } from 'react';

const KEY = 'agroconnect:lastViewedProduct';

export default function useLastViewed() {
  const [lastViewed, setLastViewed] = useState(() => {
    try {
      return JSON.parse(localStorage.getItem(KEY) || 'null');
    } catch {
      return null;
    }
  });

  const set = useCallback((product) => {
    const payload = product
      ? { id: product.id, name: product.name, at: new Date().toISOString() }
      : null;
    localStorage.setItem(KEY, JSON.stringify(payload));
    setLastViewed(payload);
  }, []);

  return useMemo(() => ({ lastViewed, setLastViewed: set }), [lastViewed, set]);
}
