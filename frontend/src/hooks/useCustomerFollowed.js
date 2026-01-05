// ============================================================================
// hooks/useCustomerFollowed.js
// ----------------------------------------------------------------------------
// ROLE:
// • Loads + manages the customer's followed products
// • Encapsulates follow/unfollow logic for reuse
// ============================================================================

import { useCallback, useEffect, useMemo, useState } from 'react';
import { fetchFollowed, followProduct, unfollowProduct } from '../services/customerApi';
import toast from 'react-hot-toast';

export default function useCustomerFollowed() {
  const [followed, setFollowed] = useState([]);
  const [loading, setLoading] = useState(true);

  const reload = useCallback(async () => {
    try {
      setLoading(true);
      const data = await fetchFollowed();
      setFollowed(Array.isArray(data) ? data : data?.items || []);
    } catch (e) {
      console.error(e);
      toast.error('Failed to load followed products');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    reload();
  }, [reload]);

  const isFollowed = useCallback(
    (productId) => followed.some((f) => String(f.product_id) === String(productId)),
    [followed]
  );

  const follow = useCallback(
    async (productId) => {
      try {
        await followProduct(productId);
        toast.success('Followed');
        await reload();
      } catch (e) {
        console.error(e);
        toast.error('Failed to follow');
      }
    },
    [reload]
  );

  const unfollow = useCallback(
    async (productId) => {
      try {
        await unfollowProduct(productId);
        toast.success('Unfollowed');
        await reload();
      } catch (e) {
        console.error(e);
        toast.error('Failed to unfollow');
      }
    },
    [reload]
  );

  return useMemo(
    () => ({ followed, loading, reload, isFollowed, follow, unfollow }),
    [followed, loading, reload, isFollowed, follow, unfollow]
  );
}
