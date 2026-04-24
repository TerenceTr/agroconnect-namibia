// ============================================================================
// frontend/src/pages/dashboards/customer/CustomerMessagesPage.jsx — Customer Messages
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Customer-facing conversation workspace for buyer ↔ farmer communication.
// ============================================================================

import React from "react";

import MessagingWorkspace from "../../../components/messaging/MessagingWorkspace";

export default function CustomerMessagesPage() {
  return (
    <MessagingWorkspace
      role="customer"
      eyebrow="Buyer communication"
      title="Messages"
      description="Ask farmers about stock, freshness, delivery, and order details in one organised workspace."
    />
  );
}
