// ====================================================================
// AdminSettingsPage.jsx — Admin System Settings
// --------------------------------------------------------------------
// FILE ROLE:
//   Admin controls for server settings.
//   • cache TTL
//   • maintenance mode toggle
//   • cache flush (if backend supports)
// --------------------------------------------------------------------
// API (RELATIVE):
//   GET  /admin/settings
//   POST /admin/settings
//   POST /admin/cache/flush
// ====================================================================

import React, { useEffect, useState } from "react";
import { toast } from "react-hot-toast";

import AdminLayout from "../../../components/AdminLayout";
import api from "../../../api";

export default function AdminSettingsPage() {
  const [cacheTTL, setCacheTTL] = useState(300);
  const [maintenance, setMaintenance] = useState(false);
  const [appVersion, setAppVersion] = useState("-");
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    const load = async () => {
      try {
        const res = await api.get("/admin/settings");
        const d = res?.data;

        if (d) {
          if (typeof d.cache_ttl === "number") setCacheTTL(d.cache_ttl);
          if (typeof d.maintenance === "boolean") setMaintenance(d.maintenance);
          if (d.version) setAppVersion(d.version);
        }
      } catch (err) {
        console.warn("Could not load settings", err);
      }
    };

    load();
  }, []);

  const saveSettings = async () => {
    try {
      setSaving(true);
      await api.post("/admin/settings", {
        cache_ttl: Number(cacheTTL),
        maintenance,
      });
      toast.success("Settings saved");
    } catch (err) {
      console.error("Save settings failed", err);
      toast.error("Failed to save settings");
    } finally {
      setSaving(false);
    }
  };

  const flushCache = async () => {
    const ok = window.confirm("Flush cache now?");
    if (!ok) return;

    try {
      await api.post("/admin/cache/flush");
      toast.success("Cache flushed");
    } catch (err) {
      console.error("Flush failed", err);
      toast.error("Failed to flush cache");
    }
  };

  return (
    <AdminLayout>
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <h2 className="text-2xl font-semibold text-gray-800">System Settings</h2>
          <div className="text-gray-600">
            App Version: <span className="font-medium">{appVersion}</span>
          </div>
        </div>

        <div className="bg-white p-6 rounded-2xl border border-gray-200 shadow-sm">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm text-gray-700 mb-2">Cache TTL (seconds)</label>
              <input
                type="number"
                value={cacheTTL}
                onChange={(e) => setCacheTTL(Number(e.target.value))}
                className="w-full px-3 py-2 rounded border border-gray-300 text-gray-800 outline-none"
              />
              <p className="text-xs text-gray-500 mt-2">
                Controls how long product lists and reports stay cached.
              </p>
            </div>

            <div>
              <label className="block text-sm text-gray-700 mb-2">Maintenance Mode</label>
              <div className="flex items-center gap-3">
                <button
                  type="button"
                  onClick={() => setMaintenance(false)}
                  className={`px-3 py-2 rounded ${
                    !maintenance ? "bg-green-600 text-white" : "bg-gray-100 text-gray-800"
                  }`}
                >
                  Off
                </button>
                <button
                  type="button"
                  onClick={() => setMaintenance(true)}
                  className={`px-3 py-2 rounded ${
                    maintenance ? "bg-red-600 text-white" : "bg-gray-100 text-gray-800"
                  }`}
                >
                  On
                </button>
              </div>
              <p className="text-xs text-gray-500 mt-2">
                When enabled, the site should show a maintenance page (backend must implement it).
              </p>
            </div>
          </div>

          <div className="flex gap-3 mt-6">
            <button
              onClick={saveSettings}
              disabled={saving}
              className="px-4 py-2 rounded bg-green-600 text-white hover:bg-green-700 disabled:opacity-60"
            >
              {saving ? "Saving…" : "Save Settings"}
            </button>
            <button
              onClick={flushCache}
              className="px-4 py-2 rounded bg-gray-100 text-gray-800 hover:bg-gray-200"
            >
              Flush Cache
            </button>
          </div>
        </div>
      </div>
    </AdminLayout>
  );
}
