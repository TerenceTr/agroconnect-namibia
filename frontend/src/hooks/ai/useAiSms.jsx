// src/hooks/ai/useAiSms.js
import { useState, useCallback } from "react";
import API from "./aiClient";

export function useAiSms() {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const sendSms = useCallback(async ({ to, message, auto_generate = false, context = {} }) => {
    setLoading(true);
    setError(null);

    try {
      const { data } = await API.post("/sms/send", {
        to,
        message,
        auto_generate,
        context,
      });
      setResult(data);
      return data;
    } catch (err) {
      const msg = err?.response?.data?.error || err.message || "SMS send failed";
      setError(msg);
      return null;
    } finally {
      setLoading(false);
    }
  }, []);

  return { sendSms, result, loading, error };
}
