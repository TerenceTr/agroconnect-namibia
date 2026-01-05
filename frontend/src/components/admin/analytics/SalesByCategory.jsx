// ============================================================================
// SalesByCategory.jsx — Admin Analytics Card (Chart.js + Confidence Bands)
// ----------------------------------------------------------------------------
// ROLE:
// • Admin dashboard analytics widget
// • Shows sales revenue grouped by product category
//
// IMPORTANT:
// • src/api.js baseURL already ends with "/api"
// • So use "/ai/..." here, NOT "/api/ai/..."
// ============================================================================

import React, { useEffect, useMemo, useState } from 'react';
import { Bar } from 'react-chartjs-2';

import api from '../../../api';
import { applyConfidenceToDataset, confidenceBand, clamp01 } from '../../../utils/chartConfidence';

import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  Tooltip,
  Legend,
} from 'chart.js';

ChartJS.register(CategoryScale, LinearScale, BarElement, Tooltip, Legend);

function ConfidenceLegend({ sample = [0.85, 0.65, 0.45] }) {
  return (
    <div className="flex flex-wrap items-center gap-2 text-xs text-white/80 mt-3">
      {sample.map((c) => {
        const v = clamp01(c);
        const meta = confidenceBand(v);
        return (
          <span
            key={c}
            className="inline-flex items-center gap-2 rounded-full border border-white/15 px-3 py-1"
          >
            <span className="inline-block h-2 w-2 rounded-full bg-white/70" />
            <span>{meta.label} confidence</span>
            <span className="opacity-70">{Math.round(v * 100)}%</span>
          </span>
        );
      })}
      <span className="opacity-70">(Bar strength reflects model confidence)</span>
    </div>
  );
}

export default function SalesByCategory() {
  const [labels, setLabels] = useState([]);
  const [values, setValues] = useState([]);
  const [confidence, setConfidence] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let alive = true;

    async function load() {
      setLoading(true);
      try {
        const { data } = await api.get('/ai/analytics/sales-by-category');
        if (!alive) return;

        setLabels(Array.isArray(data?.labels) ? data.labels : []);
        setValues(Array.isArray(data?.values) ? data.values : []);
        setConfidence(Array.isArray(data?.confidence) ? data.confidence : []);
      } catch {
        if (!alive) return;
        setLabels([]);
        setValues([]);
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

  const chartData = useMemo(() => {
    const baseDataset = {
      label: 'Sales by Category',
      data: values,
    };

    const dataset = applyConfidenceToDataset({
      dataset: baseDataset,
      confidence,
      kind: 'bar',
      rgb: '16,185,129',
    });

    return { labels, datasets: [dataset] };
  }, [labels, values, confidence]);

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
              const v = ctx.raw;
              const c = clamp01(confidence?.[i]);
              return ` ${v} (confidence ${Math.round(c * 100)}%)`;
            },
          },
        },
      },
      scales: {
        x: { ticks: { color: 'rgba(255,255,255,0.85)' } },
        y: { ticks: { color: 'rgba(255,255,255,0.85)' } },
      },
    }),
    [confidence]
  );

  return (
    <div className="glass-card p-6 text-white">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h3 className="text-lg font-semibold">Sales by Category</h3>
          <p className="text-sm text-white/70">
            Category-level revenue (bars include model confidence).
          </p>
        </div>

        {loading ? <span className="text-xs text-white/70">Loading…</span> : null}
      </div>

      <div className="mt-5 h-[320px]">
        {labels.length === 0 ? (
          <div className="h-full flex items-center justify-center text-white/70 text-sm">
            No sales data available.
          </div>
        ) : (
          <Bar data={chartData} options={options} />
        )}
      </div>

      <ConfidenceLegend />
    </div>
  );
}
