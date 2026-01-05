import React from "react";
import { MessageSquareText } from "lucide-react";

import Card, { CardContent, CardHeader, CardTitle } from "../../../components/ui/Card";
import EmptyState from "../../../components/ui/EmptyState";

/**
 * Placeholder page so FarmerLayout sidebar links don't 404.
 * Replace with a real messages/inbox view later.
 */
export default function FarmerMessagesPage() {
  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle>Messages</CardTitle>
        </CardHeader>
        <CardContent>
          <EmptyState
            icon={MessageSquareText}
            title="No messages view yet"
            message="This page is wired up so navigation works. Add your inbox/chat UI here later."
          />
        </CardContent>
      </Card>
    </div>
  );
}
