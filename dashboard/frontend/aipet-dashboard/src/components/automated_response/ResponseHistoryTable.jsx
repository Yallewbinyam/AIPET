import React from "react";

const C = { text: "#e6edf3", muted: "#7d8590", border: "#21262d" };
const STATUS_COLOR = { executed: "#00ff88", partial: "#f5c518", failed: "#ff4444" };
const TIER_COLOR   = { notify: "#f5c518", high_alert: "#ff8c00", emergency: "#ff4444" };

export default function ResponseHistoryTable({ rows, onSelect }) {
  if (!rows?.length) return (
    <div style={{ color: C.muted, textAlign: "center", padding: 24, fontSize: 13 }}>
      No automated responses yet. Devices crossing thresholds will appear here.
    </div>
  );

  return (
    <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
      <thead>
        <tr style={{ color: C.muted, fontSize: 10, fontWeight: 600, textTransform: "uppercase" }}>
          {["Fired at", "Entity", "Threshold", "Score", "Actions", "Slack", "Status"].map(h => (
            <th key={h} style={{ textAlign: "left", padding: "4px 8px",
              borderBottom: `1px solid ${C.border}` }}>{h}</th>
          ))}
        </tr>
      </thead>
      <tbody>
        {rows.map(row => (
          <tr key={row.id} onClick={() => onSelect(row)}
            style={{ cursor: "pointer", borderBottom: `1px solid ${C.border}` }}
            onMouseEnter={e => e.currentTarget.style.background = "#111820"}
            onMouseLeave={e => e.currentTarget.style.background = "transparent"}>
            <td style={{ padding: "7px 8px", color: C.muted, fontSize: 11 }}>
              {row.fired_at ? new Date(row.fired_at).toLocaleString() : "—"}
            </td>
            <td style={{ padding: "7px 8px", color: C.text, fontFamily: "monospace",
              maxWidth: 150, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
              {row.entity}
            </td>
            <td style={{ padding: "7px 8px", color: TIER_COLOR[row.threshold_name] ?? "#6b7280",
              fontWeight: 600 }}>
              {row.threshold_name ?? "—"}
            </td>
            <td style={{ padding: "7px 8px", color: C.text, fontWeight: 700 }}>
              {row.triggering_score}
            </td>
            <td style={{ padding: "7px 8px", color: C.muted }}>
              {(row.actions_executed ?? []).length}
            </td>
            <td style={{ padding: "7px 8px" }}>
              <span style={{ color: row.slack_sent ? "#00ff88" : C.muted }}>
                {row.slack_sent ? "✓" : "—"}
              </span>
            </td>
            <td style={{ padding: "7px 8px" }}>
              <span style={{ color: STATUS_COLOR[row.status] ?? C.muted, fontWeight: 600 }}>
                {row.status}
              </span>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
