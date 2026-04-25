import React from "react";
import { X } from "lucide-react";
import {
  ComposedChart, Line, Area, XAxis, YAxis, Tooltip,
  ReferenceLine, ResponsiveContainer, Legend,
} from "recharts";

const C  = { text: "#e6edf3", muted: "#7d8590", dark: "#080c10", border: "#21262d" };
const SC = { increasing: "#ff4444", stable: "#00d4ff", decreasing: "#00ff88", unknown: "#7d8590" };

export default function ForecastDetailModal({ forecast, onClose }) {
  if (!forecast) return null;
  const trendColor = SC[forecast.trend] ?? "#7d8590";

  const chartData = (forecast.predicted_scores || []).map(p => ({
    date:     p.date,
    point:    p.point,
    lower_95: p.lower_95,
    upper_95: p.upper_95,
  }));

  return (
    <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.75)",
      display: "flex", alignItems: "center", justifyContent: "center", zIndex: 1000 }}>
      <div style={{ background: C.dark, border: `1px solid ${C.border}`, borderRadius: 12,
        padding: 24, width: "100%", maxWidth: 640, maxHeight: "85vh", overflowY: "auto",
        position: "relative" }}>
        <button onClick={onClose} style={{ position: "absolute", top: 12, right: 12,
          background: "none", border: "none", color: C.muted, cursor: "pointer" }}>
          <X size={18} />
        </button>

        <div style={{ marginBottom: 16 }}>
          <div style={{ color: C.text, fontWeight: 700, fontSize: 15 }}>{forecast.entity}</div>
          <div style={{ display: "flex", gap: 12, fontSize: 12, color: C.muted, marginTop: 4 }}>
            <span>Current: <b style={{ color: C.text }}>{forecast.current_score}</b></span>
            <span>Trend: <b style={{ color: trendColor }}>{forecast.trend}</b></span>
            <span>Status: <b style={{ color: C.text }}>{forecast.status}</b></span>
            <span>Model: <b style={{ color: "#00d4ff" }}>{forecast.model_used}</b></span>
            <span>History: {forecast.history_points} pts</span>
          </div>
        </div>

        {chartData.length > 0 ? (
          <ResponsiveContainer width="100%" height={200}>
            <ComposedChart data={chartData} margin={{ top: 5, right: 10, left: -20, bottom: 5 }}>
              <XAxis dataKey="date" tick={{ fontSize: 10, fill: C.muted }} />
              <YAxis domain={[0, 100]} tick={{ fontSize: 10, fill: C.muted }} />
              <Tooltip contentStyle={{ background: C.dark, border: `1px solid ${C.border}`,
                fontSize: 11, color: C.text }} />
              <Area dataKey="upper_95" stroke="none" fill="#00d4ff" fillOpacity={0.1}
                name="Upper 95%" />
              <Area dataKey="lower_95" stroke="none" fill="#0d1117" fillOpacity={1}
                name="Lower 95%" />
              <Line dataKey="point" stroke="#00d4ff" strokeWidth={2} strokeDasharray="5 3"
                dot={{ r: 3 }} name="Predicted" />
              <ReferenceLine y={95} stroke="#ff4444" strokeDasharray="3 3" label={{ value: "Emergency 95", position: "right", fontSize: 9, fill: "#ff4444" }} />
              <ReferenceLine y={80} stroke="#ff8c00" strokeDasharray="3 3" label={{ value: "High 80", position: "right", fontSize: 9, fill: "#ff8c00" }} />
              <ReferenceLine y={60} stroke="#f5c518" strokeDasharray="3 3" label={{ value: "Notify 60", position: "right", fontSize: 9, fill: "#f5c518" }} />
            </ComposedChart>
          </ResponsiveContainer>
        ) : (
          <div style={{ color: C.muted, textAlign: "center", padding: 40, fontSize: 13 }}>
            {forecast.status === "insufficient_data"
              ? `Insufficient data — need ${10 - forecast.history_points} more observations for forecasting`
              : "No forecast available"}
          </div>
        )}

        {forecast.predicted_threshold_crossing && (
          <div style={{ marginTop: 12, background: "#1a0800", border: "1px solid #ff8c0040",
            borderRadius: 6, padding: "10px 12px", fontSize: 12 }}>
            <b style={{ color: "#ff8c00" }}>Predicted crossing:</b>{" "}
            <span style={{ color: C.muted }}>{forecast.predicted_threshold_crossing.threshold_name}</span>
            {" "}threshold ({forecast.predicted_threshold_crossing.threshold_value}) on{" "}
            <span style={{ color: C.text }}>{forecast.predicted_threshold_crossing.crossing_date}</span>
            {" — "}probability{" "}
            <span style={{ color: "#ff8c00", fontWeight: 700 }}>
              {Math.round((forecast.predicted_threshold_crossing.probability || 0) * 100)}%
            </span>
          </div>
        )}
      </div>
    </div>
  );
}
