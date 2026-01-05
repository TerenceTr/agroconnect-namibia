// ============================================================================
// AIModelAccuracy.jsx — Admin Analytics Card (Chart.js + Confidence Bands)
// ----------------------------------------------------------------------------
// ROLE:
// • Admin dashboard analytics widget
// • Shows AI model accuracy over time (or by model version)
// • Uses line segment styling to reflect confidence per time-step
//
// IMPORTANT:
// • src/api.js baseURL already ends with "/api"
// • So use "/ai/..." here, NOT "/api/ai/..."
// ============================================================================

import React, { useEffect, useMemo, useState } from 'react';
import { Line } from 'react-chartjs-2';

import api from '../../../api';
import { applyConfidenceToDataset, clamp01 } from '../../../utils/chartConfidence';

import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Tooltip,
  Legend,
  Filler,
} from 'chart.js';

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Tooltip, Legend, Filler);

function toPercentIfNeeded(arr) {
  if (!Array.isArray(arr)) return [];
  const max = Math.max(...arr.map((n) => Number(n) || 0), 0);
  if (max <= 1.5) return arr.map((n) => (Number(n) || 0) * 100);
  return arr.map((n) => Number(n) || 0);
}

export default function AIModelAccuracy() {
  const [labels, setLabels] = useState([]);
  const [accuracy, setAccuracy] = useState([]);
  const [confidence, setConfidence] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let alive = true;

    async function load() {
      setLoading(true);
      try {
        const { data } = await api.get('/ai/analytics/model-accuracy');
        if (!alive) return;

        setLabels(Array.isArray(data?.labels) ? data.labels : []);
        setAccuracy(Array.isArray(data?.accuracy) ? data.accuracy : []);
        setConfidence(Array.isArray(data?.confidence) ? data.confidence : []);
      } catch {
        if (!alive) return;
        setLabels([]);
        setAccuracy([]);
        setConfidence([]);
      } finally {
        if (alive) setLoading(false);
      }
    }

    load();
    return () => {
      alive = false;
    };
  }, []);

  const percentAccuracy = useMemo(() => toPercentIfNeeded(accuracy), [accuracy]);

  const chartData = useMemo(() => {
    const baseDataset = {
      label: 'Model Accuracy',
      data: percentAccuracy,
    };

    const dataset = applyConfidenceToDataset({
      dataset: baseDataset,
      confidence,
      kind: 'line',
      rgb: '16,185,129',
    });

    return { labels, datasets: [dataset] };
  }, [labels, percentAccuracy, confidence]);

  const options = useMemo(
    () => ({
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            label: (ctx) => {
              const i = ctx.dataIndex;
              const y = Number(ctx.raw || 0);
              const c = clamp01(confidence?.[i]);
              return ` ${y.toFixed(1)}% (confidence ${Math.round(c * 100)}%)`;
            },
          },
        },
      },
      scales: {
        x: { ticks: { color: 'rgba(255,255,255,0.85)' } },
        y: {
          min: 0,
          max: 100,
          ticks: { color: 'rgba(255,255,255,0.85)', callback: (v) => `${v}%` },
        },
      },
    }),
    [confidence]
  );

  return (
    <div className="glass-card p-6 text-white">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h3 className="text-lg font-semibold">AI Model Accuracy</h3>
          <p className="text-sm text-white/70">
            Accuracy trend (line segments are shaded by confidence).
          </p>
        </div>

        {loading ? <span className="text-xs text-white/70">Loading…</span> : null}
      </div>

      <div className="mt-5 h-[320px]">
        {labels.length === 0 ? (
          <div className="h-full flex items-center justify-center text-white/70 text-sm">
            No model accuracy data available.
          </div>
        ) : (
          <Line data={chartData} options={options} />
        )}
      </div>

      <p className="mt-3 text-xs text-white/70">
        Tip: Higher confidence increases segment opacity and border strength.
      </p>
    </div>
  );
}
