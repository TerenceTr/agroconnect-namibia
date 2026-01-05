import React from "react";
import { ChartColumn } from "lucide-react";

import Card, { CardContent, CardHeader, CardTitle } from "../../../components/ui/Card";
import EmptyState from "../../../components/ui/EmptyState";

/**
 * Placeholder page so FarmerLayout sidebar links don't 404.
 * You can later move the analytics widgets from FarmerDashboard into this page.
 */
export default function FarmerAnalyticsPage() {
  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle>Analytics</CardTitle>
        </CardHeader>
        <CardContent>
          <EmptyState
            icon={ChartColumn}
            title="Analytics view coming soon"
            description="We can move the dashboard charts here later, and keep the main dashboard as a quick overview."
          />
        </CardContent>
      </Card>
    </div>
  );
}
