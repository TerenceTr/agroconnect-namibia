// ============================================================================
// AdminPresenceWidget.jsx — Sticky Admin Presence
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Lightweight sidebar widget showing:
//     • Admins currently online
//     • Recently seen admins
//
// DATA SOURCE:
//   Injected from AdminLayout via overview payload
// ============================================================================

import React from "react";
import Card from "../ui/Card";
import EmptyState from "../ui/EmptyState";

function safeArray(v) {
  return Array.isArray(v) ? v : [];
}

export default function AdminPresenceWidget({ presence }) {
  const online = safeArray(presence?.online);
  const recent = safeArray(presence?.recent);
  const windowMin = presence?.window_minutes ?? 10;

  return (
    <Card className="p-3 border border-slate-200 bg-white sticky top-6">
      <div className="text-xs font-extrabold text-slate-700 mb-1">
        Admin Presence
      </div>
      <div className="text-[11px] text-slate-500 font-semibold mb-2">
        Online window: {windowMin} min
      </div>

      {online.length === 0 && recent.length === 0 ? (
        <EmptyState message="No admin activity." />
      ) : (
        <div className="space-y-3">
          <div>
            <div className="text-xs font-bold text-slate-700 mb-1">
              Online
            </div>
            {online.length === 0 ? (
              <div className="text-xs text-slate-500">None</div>
            ) : (
              <ul className="space-y-1 text-xs">
                {online.map((a) => (
                  <li key={a.user_id} className="flex justify-between">
                    <span className="truncate">
                      {a.full_name || a.email || "Admin"}
                    </span>
                    <span className="h-2 w-2 rounded-full bg-emerald-500" />
                  </li>
                ))}
              </ul>
            )}
          </div>

          <div>
            <div className="text-xs font-bold text-slate-700 mb-1">
              Recently seen
            </div>
            <ul className="space-y-1 text-xs">
              {recent.slice(0, 6).map((a) => (
                <li key={a.user_id} className="flex justify-between">
                  <span className="truncate">
                    {a.full_name || a.email || "Admin"}
                  </span>
                  <span
                    className={`h-2 w-2 rounded-full ${
                      a.is_online ? "bg-emerald-500" : "bg-slate-300"
                    }`}
                  />
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}
    </Card>
  );
}
