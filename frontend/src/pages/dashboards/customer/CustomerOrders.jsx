// pages/dashboards/customer/CustomerOrders.jsx
// ============================================================================
// ROLE:
// • Displays order lifecycle
// • Confirms notifications + updates
// ============================================================================

import React from 'react';
import OrderHistory from '../../../components/customer/OrderHistory';
import useCustomerOrders from '../../../hooks/useCustomerOrders';

export default function CustomerOrders() {
  const orders = useCustomerOrders();

  return (
    <OrderHistory
      orders={orders.orders}
      loading={orders.loading}
      onRefresh={orders.reload}
    />
  );
}
