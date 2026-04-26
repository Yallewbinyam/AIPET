import React, { useState } from "react";
import RiskScoreSparkline from "./RiskScoreSparkline";

const C = { text: "#e6edf3", muted: "#7d8590", card: "#0d1117", border: "#21262d" };

const TYPE_LABEL = { device: "Device", user: "User", service: "Service",
  scan_target: "Scan", indicator: "IOC" };

const SCORE_COLOR = (s) => s >= 76 ? "#ff4444" : s >= 51 ? "#ff8c00" : s >= 26 ? "#f5c518" : "#00ff88";

export default function RiskScoreTable({ rows, onSelect }) {
  const [filter, setFilter] = useState("");
  const [mobile, setMobile] = useState(() => window.innerWidth < 768);

  React.useEffect(() => {
    const fn = () => setMobile(window.innerWidth < 768);
    window.addEventListener("resize", fn);
    return () => window.removeEventListener("resize", fn);
  }, []);

  const visible = rows.filter((r) =>
    !filter || r.entity?.toLowerCase().includes(filter.toLowerCase())
  );

  return (
    <div>
      <input
        value={filter}
        onChange={(e) => setFilter(e.target.value)}
        placeholder="Filter by entity..."
        style={{ background: "#0d1117", border: "1px solid #21262d", borderRadius: 6,
          color: "#e6edf3", fontSize: 12, padding: "8px 10px", marginBottom: 12,
          width: "100%", boxSizing: "border-box", outline: "none", minHeight: 44 }}
      />
      {visible.length === 0 ? (
        <div style={{ color: C.muted, textAlign: "center", padding: 24, fontSize: 13 }}>
          No entities found. Run a scan or trigger a recompute.
        </div>
      ) : mobile ? (
        /* Mobile: card layout */
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          {visible.map((row) => (
            <div key={row.id} onClick={() => onSelect(row)}
              style={{ background: "#080c10", border: `1px solid ${C.border}`,
                borderRadius: 8, padding: "12px 14px", cursor: "pointer" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
                <span style={{ color: C.text, fontFamily: "monospace", fontSize: 13, fontWeight: 600,
                  overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: "65%" }}>
                  {row.entity}
                </span>
                <span style={{ color: SCORE_COLOR(row.score), fontWeight: 800, fontSize: 22, lineHeight: 1 }}>
                  {row.score}
                </span>
              </div>
              <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                <span style={{ color: C.muted, fontSize: 11 }}>
                  {TYPE_LABEL[row.entity_type] ?? row.entity_type ?? "—"}
                </span>
                <span style={{ color: C.muted, fontSize: 11 }}>·</span>
                <span style={{ color: C.muted, fontSize: 11 }}>{row.event_count_24h ?? 0} events</span>
              </div>
              <div style={{ marginTop: 8 }}>
                <RiskScoreSparkline score={row.score} />
              </div>
            </div>
          ))}
        </div>
      ) : (
        /* Desktop: table layout */
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
          <thead>
            <tr style={{ color: C.muted, fontSize: 10, fontWeight: 600, textTransform: "uppercase" }}>
              <th style={{ textAlign: "left", padding: "4px 8px", borderBottom: `1px solid ${C.border}` }}>Entity</th>
              <th style={{ textAlign: "left", padding: "4px 8px", borderBottom: `1px solid ${C.border}` }}>Type</th>
              <th style={{ textAlign: "left", padding: "4px 8px", borderBottom: `1px solid ${C.border}` }}>Score</th>
              <th style={{ textAlign: "left", padding: "4px 8px", borderBottom: `1px solid ${C.border}`, minWidth: 130 }}>Risk Bar</th>
              <th style={{ textAlign: "left", padding: "4px 8px", borderBottom: `1px solid ${C.border}` }}>Events 24h</th>
              <th style={{ textAlign: "left", padding: "4px 8px", borderBottom: `1px solid ${C.border}` }}>Modules</th>
            </tr>
          </thead>
          <tbody>
            {visible.map((row) => (
              <tr key={row.id}
                onClick={() => onSelect(row)}
                style={{ cursor: "pointer", borderBottom: `1px solid ${C.border}` }}
                onMouseEnter={(e) => e.currentTarget.style.background = "#111820"}
                onMouseLeave={(e) => e.currentTarget.style.background = "transparent"}>
                <td style={{ padding: "8px 8px", color: C.text, fontFamily: "monospace",
                  maxWidth: 180, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {row.entity}
                </td>
                <td style={{ padding: "8px 8px", color: C.muted }}>
                  {TYPE_LABEL[row.entity_type] ?? row.entity_type ?? "—"}
                </td>
                <td style={{ padding: "8px 8px", color: C.text, fontWeight: 700 }}>
                  {row.score}
                </td>
                <td style={{ padding: "8px 8px", minWidth: 130 }}>
                  <RiskScoreSparkline score={row.score} />
                </td>
                <td style={{ padding: "8px 8px", color: C.muted }}>
                  {row.event_count_24h ?? 0}
                </td>
                <td style={{ padding: "8px 8px", color: C.muted, maxWidth: 160,
                  overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {(row.contributing_modules ?? []).join(", ") || "—"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
