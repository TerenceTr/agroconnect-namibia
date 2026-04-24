// ============================================================================
// frontend/src/pages/dashboards/farmer/FarmerAnnouncementsPage.jsx
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Farmer-facing administrative announcement history.
// ============================================================================

import React from "react";

import FarmerLayout from "../../../components/FarmerLayout";
import AnnouncementWorkspace from "../../../components/announcements/AnnouncementWorkspace";

export default function FarmerAnnouncementsPage() {
  return (
    <FarmerLayout>
      <AnnouncementWorkspace
        role="farmer"
        eyebrow="Admin announcements"
        title="Announcements"
        description="Review seller-facing platform notices, operational updates, and governance announcements without mixing them into customer conversations."
      />
    </FarmerLayout>
  );
}
