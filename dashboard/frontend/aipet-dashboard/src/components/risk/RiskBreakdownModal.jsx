import React from "react";
import { X, Gauge } from "lucide-react";

const C = { text: "#e6edf3", muted: "#7d8590", card: "#0d1117", border: "#21262d", dark: "#080c10" };

const MOD_COLORS = {
  ml_anomaly: "#00d4ff", live_cves: "#ff4444", threatintel: "#8b5cf6",
  behavioral: "#f5c518", mitre_attack: "#a78bfa", real_scanner: "#00ff88",
  redteam: "#ff8c00", siem: "#6b7280", auth: "#60a5fa", defense: "#34d399",
  multicloud: "#f472b6", otics: "#fb923c", zerotrust: "#c084fc",
  identity_guardian: "#f59e0b", digitaltwin: "#38bdf8",
};

const SCORE_COLOR = (s) => {
  if (s >= 76) return "#ff4444";
  if (s >= 51) return "#ff8c00";
  if (s >= 26) return "#f5c518";
  return "#00ff88";
};

export default function RiskBreakdownModal({ row, onClose }) {
  if (!row) return null;
  const scoreColor = SCORE_COLOR(row.score);

  return (
    <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.7)",
      display: "flex", alignItems: "center", justifyContent: "center", zIndex: 1000 }}>
      <div style={{ background: C.dark, border: `1px solid ${C.border}`, borderRadius: 12,
        padding: 24, width: "100%", maxWidth: 520, maxHeight: "80vh", overflowY: "auto",
        position: "relative" }}>
        <button onClick={onClose} style={{ position: "absolute", top: 12, right: 12,
          background: "none", border: "none", color: C.muted, cursor: "pointer" }}>
          <X size={18} />
        </button>

        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 16 }}>
          <Gauge size={20} color={scoreColor} />
          <span style={{ color: C.text, fontWeight: 700, fontSize: 15 }}>Risk Breakdown</span>
          <span style={{ color: C.muted, fontSize: 13 }}>{row.entity}</span>
          <span style={{ marginLeft: "auto", color: scoreColor, fontWeight: 800, fontSize: 22 }}>
            {row.score}
          </span>
        </div>

        <div style={{ fontSize: 12, color: C.muted, marginBottom: 12 }}>
          {row.event_count_24h} events in last 24h · {row.contributing_modules?.length ?? 0} modules
        </div>

        {row.contributing_modules?.length > 0 && (
          <div style={{ marginBottom: 14 }}>
            <div style={{ color: C.muted, fontSize: 11, fontWeight: 600,
              textTransform: "uppercase", marginBottom: 6 }}>Active Modules</div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 5 }}>
              {row.contributing_modules.map((m) => (
                <span key={m} style={{
                  background: (MOD_COLORS[m] ?? "#6b7280") + "20",
                  border: `1px solid ${(MOD_COLORS[m] ?? "#6b7280")}40`,
                  color: MOD_COLORS[m] ?? "#6b7280",
                  fontSize: 10, padding: "2px 8px", borderRadius: 100, fontWeight: 600,
                }}>
                  {m}
                </span>
              ))}
            </div>
          </div>
        )}

        {row.top_contributors?.length > 0 && (
          <div>
            <div style={{ color: C.muted, fontSize: 11, fontWeight: 600,
              textTransform: "uppercase", marginBottom: 8 }}>Top Contributors</div>
            {row.top_contributors.map((tc, i) => {
              const modColor = MOD_COLORS[tc.source_module] ?? "#6b7280";
              return (
                <div key={i} style={{ display: "flex", alignItems: "center", gap: 8,
                  padding: "6px 0", borderBottom: i < row.top_contributors.length - 1 ? `1px solid ${C.border}` : "none" }}>
                  <span style={{ color: modColor, fontSize: 10, fontWeight: 600,
                    minWidth: 100 }}>{tc.source_module}</span>
                  <span style={{ color: C.muted, fontSize: 11, flex: 1 }}>{tc.event_type}</span>
                  <span style={{ color: C.muted, fontSize: 10 }}>
                    {tc.age_hours != null ? `${tc.age_hours}h ago` : ""}
                  </span>
                  <span style={{ color: scoreColor, fontWeight: 700, fontSize: 12, minWidth: 40, textAlign: "right" }}>
                    +{tc.contribution}
                  </span>
                </div>
              );
            })}
          </div>
        )}

        {row.last_recomputed_at && (
          <div style={{ marginTop: 14, color: C.muted, fontSize: 10 }}>
            Last recomputed: {new Date(row.last_recomputed_at).toLocaleString()}
          </div>
        )}
      </div>
    </div>
  );
}
