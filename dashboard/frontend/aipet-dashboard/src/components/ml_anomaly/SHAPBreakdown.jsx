import React from "react";

const C = { border: "#21262d", text: "#e6edf3", muted: "#7d8590", card: "#0d1117" };
const MAX_BAR = 200; // px

function formatVal(v) {
  if (typeof v !== "number") return "—";
  return Math.abs(v) >= 10 ? v.toFixed(1) : v.toFixed(4);
}

/**
 * SHAPBreakdown — visual horizontal bar chart of per-feature SHAP values.
 *
 * Props:
 *   contributors   [{feature, shap_value, raw_value, direction}, ...]  (all 12 or top N)
 *   placeholderValues  {feature: value, ...} | null  (from _placeholder_values)
 *   compact        bool  — if true, show top 5 only, no raw value column
 */
export default function SHAPBreakdown({ contributors = [], placeholderValues = null, compact = false }) {
  if (!contributors.length) return null;
  const rows = compact ? contributors.slice(0, 5) : contributors;
  const maxAbs = Math.max(...rows.map(c => Math.abs(c.shap_value || 0)), 0.001);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
      {rows.map((c) => {
        const isAnom = c.direction === "increases_anomaly";
        const barColor = isAnom ? "#ea580c" : "#16a34a";
        const barWidth = Math.round((Math.abs(c.shap_value) / maxAbs) * MAX_BAR);
        const isImputed = placeholderValues && c.feature in placeholderValues;
        return (
          <div key={c.feature} style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 12 }}>
            <div style={{ width: 120, color: C.muted, textAlign: "right", flexShrink: 0 }}>
              {c.feature}
              {isImputed && (
                <span title="Imputed value — feature not yet collected by watch agent (PLB-8)"
                  style={{ marginLeft: 4, color: "#60a5fa", cursor: "help" }}>i</span>
              )}
            </div>
            <div style={{ flex: 1, background: C.border, borderRadius: 3, height: 14, overflow: "hidden" }}>
              <div style={{
                width:  barWidth,
                height: "100%",
                background: barColor,
                borderRadius: 3,
                transition: "width 0.4s ease",
              }} />
            </div>
            <div style={{ width: 60, color: isAnom ? "#fb923c" : "#4ade80", fontWeight: 600, textAlign: "right" }}>
              {isAnom ? "+" : ""}{formatVal(c.shap_value)}
            </div>
            {!compact && (
              <div style={{ width: 70, color: C.muted, textAlign: "right" }}>
                {isImputed ? `~${formatVal(c.raw_value)}` : formatVal(c.raw_value)}
              </div>
            )}
          </div>
        );
      })}
      {!compact && (
        <div style={{ display: "flex", justifyContent: "flex-end", fontSize: 11, color: C.muted, marginTop: 2, gap: 16 }}>
          <span>● Orange = pushes toward anomaly</span>
          <span>● Green = pushes toward normal</span>
        </div>
      )}
    </div>
  );
}
