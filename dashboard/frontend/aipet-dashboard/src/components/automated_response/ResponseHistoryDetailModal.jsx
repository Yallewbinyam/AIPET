import React from "react";
import { X } from "lucide-react";

const C = { text: "#e6edf3", muted: "#7d8590", dark: "#080c10", border: "#21262d" };
const STATUS_COLOR = { executed: "#00ff88", partial: "#f5c518", failed: "#ff4444" };
const TIER_COLOR   = { notify: "#f5c518", high_alert: "#ff8c00", emergency: "#ff4444" };

export default function ResponseHistoryDetailModal({ row, onClose }) {
  if (!row) return null;
  const tierColor   = TIER_COLOR[row.threshold_name] ?? "#6b7280";
  const statusColor = STATUS_COLOR[row.status] ?? "#6b7280";

  return (
    <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.7)",
      display: "flex", alignItems: "center", justifyContent: "center", zIndex: 1000 }}>
      <div style={{ background: C.dark, border: `1px solid ${C.border}`, borderRadius: 12,
        padding: 24, width: "100%", maxWidth: 500, maxHeight: "80vh", overflowY: "auto",
        position: "relative" }}>
        <button onClick={onClose} style={{ position: "absolute", top: 12, right: 12,
          background: "none", border: "none", color: C.muted, cursor: "pointer" }}>
          <X size={18} />
        </button>
        <div style={{ fontWeight: 700, fontSize: 15, color: C.text, marginBottom: 14 }}>
          Response Detail
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "120px 1fr", gap: "6px 12px", fontSize: 12 }}>
          {[
            ["Entity",    row.entity],
            ["Threshold", <span style={{ color: tierColor }}>{row.threshold_name}</span>],
            ["Score",     <span style={{ fontWeight: 800 }}>{row.triggering_score} ≥ {row.threshold_min_score}</span>],
            ["Status",    <span style={{ color: statusColor }}>{row.status}</span>],
            ["Slack",     row.slack_sent ? "✓ sent" : "— not sent"],
            ["Teams",     row.teams_sent ? "✓ sent" : "— not sent"],
            ["Fired at",  row.fired_at ? new Date(row.fired_at).toLocaleString() : "—"],
          ].map(([k, v]) => (
            <React.Fragment key={k}>
              <span style={{ color: C.muted }}>{k}</span>
              <span style={{ color: C.text }}>{v}</span>
            </React.Fragment>
          ))}
        </div>
        {row.actions_executed?.length > 0 && (
          <div style={{ marginTop: 14 }}>
            <div style={{ color: C.muted, fontSize: 11, fontWeight: 600,
              textTransform: "uppercase", marginBottom: 6 }}>Actions</div>
            {row.actions_executed.map((a, i) => (
              <div key={i} style={{ fontSize: 11, padding: "4px 0",
                borderBottom: `1px solid ${C.border}`, display: "flex", gap: 10 }}>
                <span style={{ color: STATUS_COLOR[a.status] ?? "#6b7280", minWidth: 60, fontWeight: 600 }}>
                  {a.action}
                </span>
                <span style={{ color: C.muted }}>{a.outcome}</span>
              </div>
            ))}
          </div>
        )}
        {row.notification_error && (
          <div style={{ marginTop: 10, background: "#1a0000", border: "1px solid #ff444440",
            borderRadius: 6, padding: "6px 10px", fontSize: 11, color: "#ff8888" }}>
            Notification error: {row.notification_error}
          </div>
        )}
      </div>
    </div>
  );
}
