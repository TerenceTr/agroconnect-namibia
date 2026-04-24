// ============================================================================
// FILE ROLE:
//   Modal to capture admin rejection reason
// ============================================================================

import React, { useState } from "react";
import Card from "../ui/Card";

export default function RejectReasonModal({
  open,
  onClose,
  onSubmit,
  productName,
}) {
  const [reason, setReason] = useState("");

  if (!open) return null;

  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50">
      <Card className="w-full max-w-md p-6 space-y-4">
        <h3 className="font-extrabold text-lg">
          Reject “{productName}”
        </h3>

        <textarea
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          placeholder="Reason for rejection (required)…"
          className="w-full border rounded-xl p-3 text-sm"
          rows={4}
        />

        <div className="flex justify-end gap-2">
          <button onClick={onClose} className="btn-secondary">
            Cancel
          </button>
          <button
            onClick={() => onSubmit(reason)}
            disabled={!reason.trim()}
            className="btn-danger"
          >
            Reject Product
          </button>
        </div>
      </Card>
    </div>
  );
}
