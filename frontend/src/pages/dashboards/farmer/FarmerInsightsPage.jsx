import React from "react";
import { Sparkles } from "lucide-react";

import Card, { CardContent, CardHeader, CardTitle } from "../../../components/ui/Card";
import EmptyState from "../../../components/ui/EmptyState";

/**
 * Placeholder page so FarmerLayout sidebar links don't 404.
 * Replace with AI insights, recommendations, and market trends later.
 */
export default function FarmerInsightsPage() {
  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle>Insights</CardTitle>
        </CardHeader>
        <CardContent>
          <EmptyState
            icon={Sparkles}
            title="Insights page coming soon"
            description="This is a placeholder route. Later we can show AI recommendations, demand forecasts, and pricing insights."
          />
        </CardContent>
      </Card>
    </div>
  );
}
