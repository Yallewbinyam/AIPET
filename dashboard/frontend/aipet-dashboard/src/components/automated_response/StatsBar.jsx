import React from "react";
import { Zap, Bell, AlertOctagon } from "lucide-react";

const C = { text: "#e6edf3", muted: "#7d8590", card: "#0d1117", border: "#21262d" };

export default function StatsBar({ stats }) {
  if (!stats) return null;
  const { total_responses_24h: total = 0, by_threshold: bt = {}, by_status: bs = {} } = stats;

  const tiles = [
    { label: "Total 24h",   value: total,                           Icon: Zap,          color: "#00d4ff" },
    { label: "Notify",      value: bt["notify"]      ?? 0,          Icon: Bell,         color: "#f5c518" },
    { label: "High Alert",  value: bt["high_alert"]  ?? 0,          Icon: AlertOctagon, color: "#ff8c00" },
    { label: "Emergency",   value: bt["emergency"]   ?? 0,          Icon: AlertOctagon, color: "#ff4444" },
    { label: "Partial/Fail",value: (bs["partial"]??0)+(bs["failed"]??0), Icon: AlertOctagon, color: "#6b7280" },
  ];

  return (
    <div style={{ display: "flex", gap: 10, marginBottom: 16, flexWrap: "wrap" }}>
      {tiles.map(({ label, value, Icon, color }) => (
        <div key={label} style={{ background: C.card, border: `1px solid ${C.border}`,
          borderRadius: 8, padding: "10px 16px", flex: "1 1 100px", minWidth: 90 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 5, marginBottom: 4 }}>
            <Icon size={12} color={color} />
            <span style={{ color: C.muted, fontSize: 10, fontWeight: 600, textTransform: "uppercase" }}>
              {label}
            </span>
          </div>
          <div style={{ color, fontSize: 22, fontWeight: 800 }}>{value}</div>
        </div>
      ))}
    </div>
  );
}
