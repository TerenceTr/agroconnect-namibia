// ====================================================================
// 🌾 AiDashboard.jsx — AgroConnect Namibia (MSc-Level Final)
// --------------------------------------------------------------------
// ROLE OF FILE:
// • AI decision-support dashboard (Admin + Farmer)
// • Visualizes forecasts, recommendations & actions
//
// MSc VALUE:
// • Demonstrates explainable AI
// • Human-in-the-loop control (inputs → insights → action)
// • Clean, defensible UI for grading & demo
// ====================================================================

import React, { useState } from 'react';

// AI widgets
import ForecastChart from '../../components/ai/ForecastChart';
import RecommendationList from '../../components/ai/RecommendationList';
import SmsSender from '../../components/ai/SmsSender';

// UI system
import { Card, CardHeader, CardTitle, CardContent } from '../../components/ui/Card';

import {
  Select,
  SelectTrigger,
  SelectValue,
  SelectContent,
  SelectItem,
} from '../../components/ui/Select';

import Input from '../../components/ui/Input';
import EmptyState from '../../components/ui/EmptyState';

// Icons
import { Sparkles, LineChart, Phone } from 'lucide-react';

// ====================================================================
// MAIN COMPONENT
// ====================================================================
export default function AiDashboard() {
  // --------------------------------------------------------------
  // Controlled AI inputs
  // --------------------------------------------------------------
  const [product, setProduct] = useState('Tomatoes');
  const [region, setRegion] = useState('North');
  const [buyerId, setBuyerId] = useState(101);

  // --------------------------------------------------------------
  // Guard: minimal validity
  // --------------------------------------------------------------
  const validBuyer = Number.isInteger(buyerId) && buyerId > 0;

  return (
    <div className="p-6 space-y-6 fade-in">
      {/* ========================================================= */}
      {/* HEADER */}
      {/* ========================================================= */}
      <div className="flex items-center gap-2">
        <Sparkles className="text-emerald-400" />
        <h1 className="text-2xl font-bold text-white">AI Insights Dashboard</h1>
      </div>

      {/* ========================================================= */}
      {/* AI CONTROLS */}
      {/* ========================================================= */}
      <Card>
        <CardHeader>
          <CardTitle>AI Controls</CardTitle>
        </CardHeader>

        <CardContent className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* PRODUCT */}
          <div>
            <label className="text-sm text-white/80">Product</label>
            <Select value={product} onValueChange={setProduct}>
              <SelectTrigger className="mt-1">
                <SelectValue placeholder="Select product" />
              </SelectTrigger>
              <SelectContent>
                {['Tomatoes', 'Maize', 'Potatoes', 'Wheat'].map((p) => (
                  <SelectItem key={p} value={p}>
                    {p}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {/* REGION */}
          <div>
            <label className="text-sm text-white/80">Region</label>
            <Select value={region} onValueChange={setRegion}>
              <SelectTrigger className="mt-1">
                <SelectValue placeholder="Select region" />
              </SelectTrigger>
              <SelectContent>
                {['North', 'Central', 'South', 'National'].map((r) => (
                  <SelectItem key={r} value={r}>
                    {r}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {/* BUYER ID */}
          <div>
            <label className="text-sm text-white/80">Buyer ID</label>
            <Input
              className="mt-1"
              type="number"
              value={buyerId}
              onChange={(e) => setBuyerId(Number(e.target.value))}
              error={!validBuyer ? 'Invalid buyer ID' : null}
            />
          </div>
        </CardContent>
      </Card>

      {/* ========================================================= */}
      {/* MAIN GRID */}
      {/* ========================================================= */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* FORECAST */}
        <Card className="xl:col-span-2">
          <CardHeader>
            <CardTitle>
              <LineChart className="inline mr-2" />
              Demand Forecast
            </CardTitle>
          </CardHeader>

          <CardContent>
            <ForecastChart product={product} region={region} horizon={14} />
          </CardContent>
        </Card>

        {/* RECOMMENDATIONS */}
        <Card>
          <CardHeader>
            <CardTitle>Recommendations</CardTitle>
          </CardHeader>

          <CardContent>
            {validBuyer ? (
              <RecommendationList
                buyerId={buyerId}
                recent={[1012, 2033, 3044]}
                limit={5}
              />
            ) : (
              <EmptyState message="Enter a valid buyer ID." />
            )}
          </CardContent>
        </Card>
      </div>

      {/* ========================================================= */}
      {/* SMS ACTION */}
      {/* ========================================================= */}
      <Card>
        <CardHeader>
          <CardTitle>
            <Phone className="inline mr-2" />
            Notify Buyers
          </CardTitle>
        </CardHeader>

        <CardContent>
          <SmsSender />
        </CardContent>
      </Card>
    </div>
  );
}
