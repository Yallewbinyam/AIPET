import React from "react";

const C   = { text: "#e6edf3", muted: "#7d8590", border: "#21262d" };
const SC  = { increasing: "#ff4444", stable: "#00d4ff", decreasing: "#00ff88", unknown: "#7d8590" };
const STC = { ok: "#00ff88", low_confidence: "#f5c518", insufficient_data: "#7d8590" };

export default function ForecastTable({ forecasts, onSelect }) {
  if (!forecasts?.length) return (
    <div style={{ color: C.muted, textAlign: "center", padding: 32, fontSize: 13 }}>
      No forecast data yet. Wait for the 5-min recompute to collect history.
    </div>
  );

  return (
    <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
      <thead>
        <tr style={{ color: C.muted, fontSize: 10, fontWeight: 600, textTransform: "uppercase" }}>
          {["Entity", "Score", "Trend", "Status", "Model", "History", "Predicted Crossing"].map(h => (
            <th key={h} style={{ textAlign: "left", padding: "4px 8px", borderBottom: `1px solid ${C.border}` }}>
              {h}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {forecasts.map((f, i) => {
          const crossing = f.predicted_threshold_crossing;
          return (
            <tr key={i} onClick={() => onSelect(f)}
              style={{ cursor: "pointer", borderBottom: `1px solid ${C.border}` }}
              onMouseEnter={e => e.currentTarget.style.background = "#111820"}
              onMouseLeave={e => e.currentTarget.style.background = "transparent"}>
              <td style={{ padding: "7px 8px", color: C.text, fontFamily: "monospace",
                maxWidth: 150, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                {f.entity}
              </td>
              <td style={{ padding: "7px 8px", fontWeight: 700, color: C.text }}>{f.current_score}</td>
              <td style={{ padding: "7px 8px", color: SC[f.trend] ?? C.muted, fontWeight: 600 }}>
                {f.trend ?? "—"}
              </td>
              <td style={{ padding: "7px 8px", color: STC[f.status] ?? C.muted }}>
                {f.status === "insufficient_data" ? "no data" : f.status?.replace("_", " ")}
              </td>
              <td style={{ padding: "7px 8px", color: "#00d4ff", fontFamily: "monospace", fontSize: 10 }}>
                {f.model_used ?? "—"}
              </td>
              <td style={{ padding: "7px 8px", color: C.muted }}>{f.history_points ?? 0} pts</td>
              <td style={{ padding: "7px 8px", fontSize: 11 }}>
                {crossing ? (
                  <span style={{ color: "#ff8c00" }}>
                    {crossing.threshold_name} on {crossing.crossing_date}
                    {" "}({Math.round(crossing.probability * 100)}%)
                  </span>
                ) : <span style={{ color: C.muted }}>None predicted</span>}
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}
