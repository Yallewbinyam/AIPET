import React from "react";
import { Bell, CheckCircle, X } from "lucide-react";
import { acknowledgeAlert, dismissAlert } from "./api/forecastApi";

const C = { text: "#e6edf3", muted: "#7d8590", card: "#0d1117", border: "#21262d" };
const TC = { notify: "#f5c518", high_alert: "#ff8c00", emergency: "#ff4444" };

export default function ForecastAlertsList({ alerts, token, onRefresh }) {
  if (!alerts?.length) return (
    <div style={{ color: C.muted, fontSize: 12, padding: "12px 0" }}>
      No active forecast alerts.
    </div>
  );

  const handle = async (fn, id) => {
    await fn(token, id);
    onRefresh();
  };

  return (
    <div>
      {alerts.map(a => {
        const color = TC[a.threshold_name] ?? "#7d8590";
        return (
          <div key={a.id} style={{ display: "flex", alignItems: "center", gap: 10,
            padding: "8px 0", borderBottom: `1px solid ${C.border}` }}>
            <Bell size={13} color={color} />
            <div style={{ flex: 1 }}>
              <span style={{ color, fontWeight: 600, fontSize: 12 }}>{a.threshold_name}</span>
              {" "}
              <span style={{ color: C.muted, fontSize: 11 }}>
                {a.entity} — predicted crossing on {a.predicted_crossing_date?.slice(0, 10)}{" "}
                ({Math.round(a.probability * 100)}%)
              </span>
            </div>
            <button onClick={() => handle(acknowledgeAlert, a.id)}
              title="Acknowledge" style={{ background: "none", border: "none", cursor: "pointer", color: "#00ff88" }}>
              <CheckCircle size={14} />
            </button>
            <button onClick={() => handle(dismissAlert, a.id)}
              title="Dismiss" style={{ background: "none", border: "none", cursor: "pointer", color: C.muted }}>
              <X size={14} />
            </button>
          </div>
        );
      })}
    </div>
  );
}
