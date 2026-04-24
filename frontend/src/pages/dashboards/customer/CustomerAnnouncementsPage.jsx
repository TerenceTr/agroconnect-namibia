// ============================================================================
// frontend/src/pages/dashboards/customer/CustomerAnnouncementsPage.jsx
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Customer-facing administrative announcement history.
// ============================================================================

import React from "react";

import AnnouncementWorkspace from "../../../components/announcements/AnnouncementWorkspace";

export default function CustomerAnnouncementsPage() {
  return (
    <AnnouncementWorkspace
      role="customer"
      eyebrow="Platform announcements"
      title="Announcements"
      description="Review customer-facing service updates, governance notices, and administrative announcements without mixing them into farmer conversations."
    />
  );
}
