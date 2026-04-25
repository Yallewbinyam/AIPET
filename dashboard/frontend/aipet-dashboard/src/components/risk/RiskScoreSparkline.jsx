import React from "react";

const SCORE_COLOR = (s) => {
  if (s >= 76) return "#ff4444";
  if (s >= 51) return "#ff8c00";
  if (s >= 26) return "#f5c518";
  return "#00ff88";
};

export default function RiskScoreSparkline({ score }) {
  const color = SCORE_COLOR(score ?? 0);
  const pct   = Math.min(100, Math.max(0, score ?? 0));

  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
      <div style={{ flex: 1, background: "#21262d", borderRadius: 4, height: 6 }}>
        <div style={{
          width: `${pct}%`, height: "100%", background: color,
          borderRadius: 4, transition: "width 0.4s ease",
        }} />
      </div>
      <span style={{ color, fontWeight: 700, fontSize: 12, minWidth: 28, textAlign: "right" }}>
        {pct}
      </span>
    </div>
  );
}
