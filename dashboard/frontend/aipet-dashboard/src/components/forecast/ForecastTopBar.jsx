import React from "react";
import { TrendingUp, AlertTriangle, HelpCircle } from "lucide-react";

const C = { text: "#e6edf3", muted: "#7d8590", card: "#0d1117", border: "#21262d" };

export default function ForecastTopBar({ stats }) {
  if (!stats) return null;
  const { by_trend: bt = {}, by_status: bs = {}, active_alerts_count: alerts = 0 } = stats;

  return (
    <div style={{ display: "flex", gap: 10, marginBottom: 16, flexWrap: "wrap" }}>
      {[
        { label: "Trending Up",   value: bt["increasing"] ?? 0, Icon: TrendingUp,  color: "#ff4444" },
        { label: "Active Alerts", value: alerts,                 Icon: AlertTriangle, color: "#ff8c00" },
        { label: "No Data Yet",   value: bs["insufficient_data"] ?? 0, Icon: HelpCircle, color: "#7d8590" },
        { label: "Devices Tracked", value: stats.total_forecasts ?? 0, Icon: TrendingUp, color: "#00d4ff" },
      ].map(({ label, value, Icon, color }) => (
        <div key={label} style={{ background: C.card, border: `1px solid ${C.border}`,
          borderRadius: 8, padding: "10px 16px", flex: "1 1 110px", minWidth: 100 }}>
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
