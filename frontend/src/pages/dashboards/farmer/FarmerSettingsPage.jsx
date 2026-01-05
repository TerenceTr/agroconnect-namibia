import React from "react";
import { Settings } from "lucide-react";

import Card, { CardContent, CardHeader, CardTitle } from "../../../components/ui/Card";
import EmptyState from "../../../components/ui/EmptyState";

/**
 * Placeholder page so FarmerLayout sidebar links don't 404.
 * Replace with preferences/profile settings later.
 */
export default function FarmerSettingsPage() {
  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle>Settings</CardTitle>
        </CardHeader>
        <CardContent>
          <EmptyState
            icon={Settings}
            title="Settings coming soon"
            description="Profile and notification preferences will live here."
          />
        </CardContent>
      </Card>
    </div>
  );
}
