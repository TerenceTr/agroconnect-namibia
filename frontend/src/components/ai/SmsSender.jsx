// src/components/ai/SmsSender.jsx
import React, { useEffect, useState } from "react";
import { Card, CardHeader, CardContent, CardTitle } from "../../components/ui/Card";
import { Button } from "../../components/ui/Button";
import { Loader2, Send } from "lucide-react";
import { useAiSms } from "../../hooks/ai/useAiSms";

/**
 * Props:
 * - productName (optional) -> used to auto-generate a market/SMS message context
 */
export default function SmsSender({ productName = null }) {
  const [to, setTo] = useState("");
  const [msg, setMsg] = useState("");
  const [autoGen, setAutoGen] = useState(!!productName);
  const { sendSms, result, loading, error } = useAiSms();

  // If a productName is provided and autoGen true, call backend to generate suggested message
  useEffect(() => {
    let didCancel = false;

    const gen = async () => {
      if (!autoGen || !productName) return;
      try {
        // Call AI endpoint to generate short SMS preview
        const r = await sendSms({ to: null, message: null, auto_generate: true, context: { product: productName } });
        if (!didCancel && r && r.suggested_message) {
          setMsg(r.suggested_message);
        }
      } catch (err) {
        // ignore — user can type a message
      }
    };

    gen();

    return () => {
      didCancel = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [autoGen, productName]);

  const handleSend = async () => {
    if (!to || (!msg && !autoGen)) return alert("Provide recipient and message (or enable auto-generation).");

    // sendSms will handle auto_generate flag too, but we pass the final message if exists
    await sendSms({ to, message: msg || null, auto_generate: autoGen, context: { product: productName } });
  };

  return (
    <Card className="rounded-2xl shadow-md">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Send className="h-5 w-5 text-primary" />
          Send SMS
        </CardTitle>
      </CardHeader>

      <CardContent className="space-y-4">
        <input
          type="text"
          placeholder="Recipient phone number (e.g. +2648...)"
          value={to}
          onChange={(e) => setTo(e.target.value)}
          className="w-full rounded-xl border px-3 py-2"
        />

        <div className="flex items-center gap-3">
          <label className="flex items-center gap-2">
            <input type="checkbox" checked={autoGen} onChange={(e) => setAutoGen(e.target.checked)} />
            Auto-generate message
          </label>
          {productName && <div className="text-sm text-gray-500">Context: {productName}</div>}
        </div>

        <textarea
          placeholder="Write message…"
          value={msg}
          onChange={(e) => setMsg(e.target.value)}
          rows={3}
          className="w-full rounded-xl border px-3 py-2"
        ></textarea>

        <Button
          onClick={handleSend}
          disabled={loading}
          className="w-full flex items-center gap-2"
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
        </Button>

        {error && <p className="text-red-600 text-sm">{error}</p>}
        {result && (
          <p className="text-green-600 text-sm">
            Message accepted → {result.to || "accepted"}
          </p>
        )}
      </CardContent>
    </Card>
  );
}
