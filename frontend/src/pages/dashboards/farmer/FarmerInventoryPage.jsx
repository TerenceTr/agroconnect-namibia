import React from "react";
import { Boxes } from "lucide-react";

import Card, { CardContent, CardHeader, CardTitle } from "../../../components/ui/Card";
import EmptyState from "../../../components/ui/EmptyState";

/**
 * Placeholder page so FarmerLayout sidebar links don't 404.
 * Replace with inventory management later.
 */
export default function FarmerInventoryPage() {
  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle>Inventory</CardTitle>
        </CardHeader>
        <CardContent>
          <EmptyState
            icon={Boxes}
            title="Inventory page coming soon"
            description="This is a placeholder route. Later we can show stock levels, low-stock alerts, and quick updates."
          />
        </CardContent>
      </Card>
    </div>
  );
}
