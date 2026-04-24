// ============================================================================
// frontend/src/components/ai/SmsSender.jsx
// ----------------------------------------------------------------------------
// FILE ROLE:
//   Optional “Market Alerts” tool.
//   • Lets user send an SMS (or auto-generate message if backend supports it)
//   • Uses AI SMS hook
//
// IMPORTANT:
//   Some backends implement auto-generate through the same endpoint.
//   We call sendSms with to=null only for suggestion IF user enabled autoGen.
// ============================================================================

import React, { useEffect, useState } from "react";
import { Loader2, Send } from "lucide-react";
import { useAiSms } from "../../hooks/ai/useAiSms";

export default function SmsSender({ productName = null }) {
  const [to, setTo] = useState("");
  const [msg, setMsg] = useState("");
  const [autoGen, setAutoGen] = useState(Boolean(productName));

  const { sendSms, result, loading, error } = useAiSms();

  // Auto-generate suggested message (if supported by backend)
  useEffect(() => {
    let cancelled = false;

    async function generate() {
      if (!autoGen || !productName) return;

      try {
        const r = await sendSms({
          to: null,
          message: null,
          auto_generate: true,
          context: { product: productName },
        });

        const suggested = r?.suggested_message || r?.message || "";
        if (!cancelled && suggested && !msg) {
          setMsg(String(suggested));
        }
      } catch {
        // ignore — user can type manually
      }
    }

    generate();
    return () => {
      cancelled = true;
    };
    // We intentionally do NOT depend on msg to avoid re-trigger loops.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [autoGen, productName, sendSms]);

  async function handleSend() {
    if (!to.trim()) {
      alert("Provide recipient phone number (e.g. +264...)");
      return;
    }
    if (!msg.trim() && !autoGen) {
      alert("Provide a message, or enable auto-generation.");
      return;
    }

    await sendSms({
      to: to.trim(),
      message: msg.trim() || null,
      auto_generate: autoGen,
      context: { product: productName },
    });
  }

  return (
    <div className="space-y-3">
      <div className="text-sm font-extrabold text-slate-900 inline-flex items-center gap-2">
        <Send className="h-4 w-4 text-emerald-700" />
        Send SMS
      </div>

      <div className="rounded-2xl border border-slate-200 bg-white p-3 space-y-3">
        <input
          type="text"
          placeholder="Recipient phone number (e.g. +264...)"
          value={to}
          onChange={(e) => setTo(e.target.value)}
          className="w-full rounded-2xl border border-slate-200 px-3 py-2 text-sm outline-none"
        />

        <div className="flex items-center justify-between gap-3">
          <label className="flex items-center gap-2 text-sm text-slate-700">
            <input
              type="checkbox"
              checked={autoGen}
              onChange={(e) => setAutoGen(e.target.checked)}
            />
            Auto-generate message
          </label>

          {productName && (
            <div className="text-xs text-slate-500 font-semibold">
              Context: {productName}
            </div>
          )}
        </div>

        <textarea
          placeholder="Write message…"
          value={msg}
          onChange={(e) => setMsg(e.target.value)}
          rows={3}
          className="w-full rounded-2xl border border-slate-200 px-3 py-2 text-sm outline-none"
        />

        <button
          type="button"
          onClick={handleSend}
          disabled={loading}
          className="h-10 w-full rounded-2xl bg-emerald-600 hover:bg-emerald-700 text-white text-sm font-semibold inline-flex items-center justify-center gap-2 disabled:opacity-60"
        >
          {loading ? (
            <>
              <Loader2 className="h-5 w-5 animate-spin" /> Sending…
            </>
          ) : (
            <>
              <Send className="h-5 w-5" /> Send SMS
            </>
          )}
        </button>

        {error && <p className="text-rose-700 text-sm">{String(error)}</p>}
        {result && (
          <p className="text-emerald-700 text-sm">
            Message accepted → {result?.to || "accepted"}
          </p>
        )}
      </div>
    </div>
  );
}
