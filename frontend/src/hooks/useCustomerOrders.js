// ============================================================================
// frontend/src/hooks/useCustomerOrders.js
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Loads customer order history + status for the customer dashboard.
//
// THIS UPDATE:
//   ✅ Requests full order details with items included
//   ✅ Uses all_time=1 so the customer sees complete order history
//   ✅ Keeps response normalization defensive across backend payload shapes
// ============================================================================

import { useCallback, useEffect, useState } from "react";
import * as customerApi from "../services/customerApi";

export default function useCustomerOrders() {
  const [orders, setOrders] = useState([]);
  const [loading, setLoading] = useState(true);

  function pickOrders(payload) {
    if (Array.isArray(payload)) return payload;
    if (!payload || typeof payload !== "object") return [];

    if (Array.isArray(payload.orders)) return payload.orders;
    if (Array.isArray(payload.data)) return payload.data;
    if (Array.isArray(payload.items)) return payload.items;
    if (Array.isArray(payload.results)) return payload.results;

    if (payload.data && typeof payload.data === "object") {
      if (Array.isArray(payload.data.orders)) return payload.data.orders;
      if (Array.isArray(payload.data.items)) return payload.data.items;
      if (Array.isArray(payload.data.results)) return payload.data.results;
    }

    return [];
  }

  const reload = useCallback(async () => {
    try {
      setLoading(true);

      // Explicitly request:
      // - include_items=1 so the page can show the products in each order
      // - all_time=1 so the customer sees full history, not only recent window
      const data = await customerApi.fetchOrders({
        include_items: 1,
        all_time: 1,
      });

      setOrders(pickOrders(data));
    } catch {
      setOrders([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    reload();
  }, [reload]);

  return { orders, loading, reload };
}