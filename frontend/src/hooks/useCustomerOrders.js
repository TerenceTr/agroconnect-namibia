// ============================================================================
// hooks/useCustomerOrders.js
// ----------------------------------------------------------------------------
// ROLE:
// • Loads customer order history + status
// • Supports filters (e.g., pending/completed)
// ============================================================================

import { useCallback, useEffect, useMemo, useState } from 'react';
import toast from 'react-hot-toast';
import { fetchOrders, fetchOrderById } from '../services/customerApi';

export default function useCustomerOrders() {
  const [orders, setOrders] = useState([]);
  const [loading, setLoading] = useState(true);

  const reload = useCallback(async (params = {}) => {
    try {
      setLoading(true);
      const data = await fetchOrders(params);
      setOrders(Array.isArray(data) ? data : data?.orders || []);
    } catch (e) {
      console.error(e);
      toast.error('Failed to load orders');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    reload();
  }, [reload]);

  const getOne = useCallback(async (orderId) => {
    const data = await fetchOrderById(orderId);
    return data?.order || data;
  }, []);

  return useMemo(
    () => ({ orders, loading, reload, getOne }),
    [orders, loading, reload, getOne]
  );
}
