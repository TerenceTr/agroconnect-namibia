// ====================================================================
// AdminMessagingPage.jsx — Admin Messaging & Broadcasts
// --------------------------------------------------------------------
// FILE ROLE:
//   Admin UI for broadcasting notifications via multiple channels.
//   • SMS / Email
//   • Audience targeting
//   • Clean thesis-level UI aligned with AdminLayout
//
// IMPORTANT ROUTER FIX:
//   Ensure App.js has route: /dashboard/admin/messaging
//
// BACKEND (RELATIVE; baseURL already includes "/api"):
//   POST /admin/notifications/broadcast
// ====================================================================

import React, { useMemo, useState } from "react";
import toast from "react-hot-toast";
import { MessageSquare, Send, Mail, Smartphone } from "lucide-react";

import AdminLayout from "../../../components/AdminLayout";
import ProtectedRoute from "../../../components/auth/ProtectedRoute";
import Card from "../../../components/ui/Card";
import api from "../../../api";

export default function AdminMessagingPage() {
  const [channels, setChannels] = useState({ sms: true, email: true });
  const [subject, setSubject] = useState("");
  const [message, setMessage] = useState("");
  const [audienceRole, setAudienceRole] = useState("all");
  const [sending, setSending] = useState(false);

  const selectedChannels = useMemo(
    () => Object.keys(channels).filter((k) => channels[k]),
    [channels]
  );

  const charCount = message.length;

  const submitBroadcast = async (e) => {
    e?.preventDefault();

    if (!message.trim()) return toast.error("Message required");
    if (selectedChannels.length === 0) return toast.error("Select at least one channel");

    try {
      setSending(true);

      const payload = {
        channels: selectedChannels,
        subject: subject.trim(),
        message: message.trim(),
        audience: { role: audienceRole }, // backend supports: all / farmers / customers
      };

      await api.post("/admin/notifications/broadcast", payload);

      toast.success("Broadcast queued");
      setMessage("");
      setSubject("");
    } catch (err) {
      console.error("Broadcast failed", err);
      toast.error("Failed to send broadcast");
    } finally {
      setSending(false);
    }
  };

  return (
    <ProtectedRoute roles={["admin"]}>
      <AdminLayout>
        <div className="space-y-6">
          <Card className="p-6">
            <div className="flex items-center gap-2">
              <MessageSquare className="h-5 w-5 text-emerald-700" />
              <h2 className="text-xl font-extrabold text-slate-900">
                Messaging & Broadcasts
              </h2>
            </div>
            <p className="text-sm text-slate-600 mt-1">
              Send targeted announcements to users via SMS and/or Email.
            </p>
          </Card>

          <Card className="p-6">
            <form onSubmit={submitBroadcast} className="space-y-5">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* Audience */}
                <div>
                  <label className="text-sm font-semibold text-slate-700 block mb-2">
                    Audience
                  </label>
                  <select
                    value={audienceRole}
                    onChange={(e) => setAudienceRole(e.target.value)}
                    className="w-full px-3 py-2 rounded-xl bg-white border border-slate-200 text-slate-900 outline-none focus:ring-2 focus:ring-emerald-200"
                  >
                    <option value="all">All Users</option>
                    <option value="farmers">Farmers</option>
                    <option value="customers">Customers</option>
                  </select>
                  <p className="text-xs text-slate-500 mt-2">
                    Tip: use Farmers for production announcements, Customers for promotions.
                  </p>
                </div>

                {/* Channels */}
                <div>
                  <label className="text-sm font-semibold text-slate-700 block mb-2">
                    Channels
                  </label>

                  <div className="flex flex-wrap gap-3">
                    <label className="flex items-center gap-2 px-3 py-2 rounded-xl border border-slate-200 bg-slate-50">
                      <input
                        type="checkbox"
                        checked={channels.sms}
                        onChange={(e) =>
                          setChannels((s) => ({ ...s, sms: e.target.checked }))
                        }
                      />
                      <Smartphone className="h-4 w-4 text-slate-700" />
                      <span className="text-sm text-slate-900 font-semibold">SMS</span>
                    </label>

                    <label className="flex items-center gap-2 px-3 py-2 rounded-xl border border-slate-200 bg-slate-50">
                      <input
                        type="checkbox"
                        checked={channels.email}
                        onChange={(e) =>
                          setChannels((s) => ({ ...s, email: e.target.checked }))
                        }
                      />
                      <Mail className="h-4 w-4 text-slate-700" />
                      <span className="text-sm text-slate-900 font-semibold">Email</span>
                    </label>
                  </div>

                  <div className="text-xs text-slate-500 mt-2">
                    Selected:{" "}
                    <span className="font-semibold">
                      {selectedChannels.join(", ") || "none"}
                    </span>
                  </div>
                </div>
              </div>

              {/* Subject */}
              <div>
                <label className="text-sm font-semibold text-slate-700 block mb-2">
                  Subject (optional)
                </label>
                <input
                  value={subject}
                  onChange={(e) => setSubject(e.target.value)}
                  className="w-full px-3 py-2 rounded-xl bg-white border border-slate-200 text-slate-900 outline-none focus:ring-2 focus:ring-emerald-200"
                  placeholder="e.g., System update, Weekly market prices…"
                />
              </div>

              {/* Message */}
              <div>
                <div className="flex items-center justify-between">
                  <label className="text-sm font-semibold text-slate-700 block mb-2">
                    Message
                  </label>
                  <div className="text-xs text-slate-500">{charCount} chars</div>
                </div>
                <textarea
                  value={message}
                  onChange={(e) => setMessage(e.target.value)}
                  rows={7}
                  className="w-full px-3 py-2 rounded-xl bg-white border border-slate-200 text-slate-900 outline-none focus:ring-2 focus:ring-emerald-200"
                  placeholder="Write your broadcast message…"
                />
                <p className="text-xs text-slate-500 mt-2">
                  Keep SMS messages concise; Email can be longer and include context.
                </p>
              </div>

              {/* Actions */}
              <div className="flex flex-wrap gap-3 justify-end">
                <button
                  type="button"
                  className="inline-flex items-center justify-center rounded-xl px-4 py-2 text-sm font-semibold border border-slate-200 bg-white hover:bg-slate-50"
                  onClick={() => {
                    setMessage("");
                    setSubject("");
                  }}
                >
                  Clear
                </button>

                <button
                  type="submit"
                  className="inline-flex items-center gap-2 rounded-xl px-4 py-2 text-sm font-semibold bg-emerald-600 text-white hover:bg-emerald-700 shadow-sm disabled:opacity-60"
                  disabled={sending}
                >
                  <Send className="h-4 w-4" />
                  {sending ? "Sending…" : "Send Broadcast"}
                </button>
              </div>
            </form>
          </Card>
        </div>
      </AdminLayout>
    </ProtectedRoute>
  );
}
