import React, { useState, useEffect } from "react";
import { Gauge, AlertTriangle } from "lucide-react";

const C = { text: "#e6edf3", muted: "#7d8590", card: "#0d1117", border: "#21262d" };

const SCORE_COLOR = (s) => {
  if (s >= 76) return "#ff4444";
  if (s >= 51) return "#ff8c00";
  if (s >= 26) return "#f5c518";
  return "#00ff88";
};

export default function RiskTopBar({ stats, top }) {
  const [mobile, setMobile] = useState(() => window.innerWidth < 768);
  useEffect(() => {
    const fn = () => setMobile(window.innerWidth < 768);
    window.addEventListener("resize", fn);
    return () => window.removeEventListener("resize", fn);
  }, []);

  const highRisk   = (stats?.by_score_bucket?.["76-100"] ?? 0) + (stats?.by_score_bucket?.["51-75"] ?? 0);
  const topEntity  = top?.[0];
  const maxColor   = SCORE_COLOR(topEntity?.score ?? 0);

  return (
    <div style={{ display: "flex", gap: 12, marginBottom: 16,
      flexWrap: "wrap", flexDirection: mobile ? "column" : "row" }}>
      <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 8,
        padding: "12px 18px", flex: "1 1 180px", minWidth: 150 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 4 }}>
          <Gauge size={14} color="#00d4ff" />
          <span style={{ color: C.muted, fontSize: 11, fontWeight: 600, textTransform: "uppercase" }}>
            Highest Risk
          </span>
        </div>
        {topEntity ? (
          <>
            <div style={{ color: maxColor, fontSize: 28, fontWeight: 800, lineHeight: 1 }}>
              {topEntity.score}
            </div>
            <div style={{ color: C.muted, fontSize: 11, marginTop: 3, overflow: "hidden",
              textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: 160 }}>
              {topEntity.entity}
            </div>
          </>
        ) : (
          <div style={{ color: C.muted, fontSize: 13 }}>No data</div>
        )}
      </div>

      <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 8,
        padding: "12px 18px", flex: "1 1 180px", minWidth: 150 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 4 }}>
          <AlertTriangle size={14} color="#ff8c00" />
          <span style={{ color: C.muted, fontSize: 11, fontWeight: 600, textTransform: "uppercase" }}>
            Above 50
          </span>
        </div>
        <div style={{ color: highRisk > 0 ? "#ff8c00" : "#00ff88", fontSize: 28, fontWeight: 800 }}>
          {highRisk}
        </div>
        <div style={{ color: C.muted, fontSize: 11, marginTop: 3 }}>
          of {stats?.total_entities ?? 0} devices
        </div>
      </div>

      <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 8,
        padding: "12px 18px", flex: "1 1 180px", minWidth: 150 }}>
        <div style={{ color: C.muted, fontSize: 11, fontWeight: 600,
          textTransform: "uppercase", marginBottom: 4 }}>Avg Score</div>
        <div style={{ color: C.text, fontSize: 28, fontWeight: 800 }}>
          {stats?.average_score != null ? stats.average_score.toFixed(1) : "—"}
        </div>
        <div style={{ color: C.muted, fontSize: 11, marginTop: 3 }}>across all entities</div>
      </div>
    </div>
  );
}
