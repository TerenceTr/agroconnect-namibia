// ============================================================================
// frontend/src/pages/dashboards/farmer/FarmerMessagesPage.jsx — Farmer Messages
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Farmer-facing conversation workspace for customer communication.
// ============================================================================

import React from "react";

import FarmerLayout from "../../../components/FarmerLayout";
import MessagingWorkspace from "../../../components/messaging/MessagingWorkspace";

export default function FarmerMessagesPage() {
  return (
    <FarmerLayout>
      <MessagingWorkspace
        role="farmer"
        eyebrow="Seller communication"
        title="Messages"
        description="Manage customer conversations, reply to buyer questions, and keep one clean message history per listing."
      />
    </FarmerLayout>
  );
}
