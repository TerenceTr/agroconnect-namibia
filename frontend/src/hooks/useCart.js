// ============================================================================
// hooks/useCart.js
// ----------------------------------------------------------------------------
// ROLE:
// • Manages cart state + totals
// • Wraps API calls so UI stays simple
// ============================================================================

import { useCallback, useEffect, useMemo, useState } from 'react';
import toast from 'react-hot-toast';
import {
  fetchCart,
  addToCart,
  updateCartItem,
  removeCartItem,
  clearCart,
} from '../services/customerApi';

export default function useCart() {
  const [cart, setCart] = useState({ items: [] });
  const [loading, setLoading] = useState(true);

  const reload = useCallback(async () => {
    try {
      setLoading(true);
      const data = await fetchCart();
      setCart(data?.cart || data || { items: [] });
    } catch (e) {
      console.error(e);
      toast.error('Failed to load cart');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    reload();
  }, [reload]);

  const add = useCallback(
    async (productId, qty = 1) => {
      try {
        await addToCart(productId, qty);
        toast.success('Added to cart');
        await reload();
      } catch (e) {
        console.error(e);
        toast.error('Failed to add item');
      }
    },
    [reload]
  );

  const updateQty = useCallback(
    async (itemId, qty) => {
      try {
        await updateCartItem(itemId, qty);
        await reload();
      } catch (e) {
        console.error(e);
        toast.error('Failed to update quantity');
      }
    },
    [reload]
  );

  const remove = useCallback(
    async (itemId) => {
      try {
        await removeCartItem(itemId);
        toast.success('Removed');
        await reload();
      } catch (e) {
        console.error(e);
        toast.error('Failed to remove item');
      }
    },
    [reload]
  );

  const clear = useCallback(async () => {
    try {
      await clearCart();
      toast.success('Cart cleared');
      await reload();
    } catch (e) {
      console.error(e);
      toast.error('Failed to clear cart');
    }
  }, [reload]);

  const totals = useMemo(() => {
    const items = cart?.items || [];
    const subtotal = items.reduce(
      (sum, it) => sum + (Number(it.unit_price) || 0) * (Number(it.qty) || 0),
      0
    );
    const itemCount = items.reduce((sum, it) => sum + (Number(it.qty) || 0), 0);
    return { subtotal, itemCount };
  }, [cart]);

  return useMemo(
    () => ({ cart, loading, reload, add, updateQty, remove, clear, totals }),
    [cart, loading, reload, add, updateQty, remove, clear, totals]
  );
}
