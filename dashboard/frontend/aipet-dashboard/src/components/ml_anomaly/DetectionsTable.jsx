import React, { useState } from "react";

const C = { border: "#21262d", text: "#e6edf3", muted: "#7d8590", card: "#0d1117", cardHover: "#111820" };
const SEV_COLOR = { critical: "#dc2626", high: "#ea580c", medium: "#d97706", low: "#16a34a" };
const PAGE = 20;

function ScoreBar({ score }) {
  const color = score > 0.65 ? "#ea580c" : score > 0.45 ? "#d97706" : "#16a34a";
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
      <div style={{ width: 50, height: 6, background: C.border, borderRadius: 3 }}>
        <div style={{ width: `${Math.round(score * 100)}%`, height: "100%", background: color, borderRadius: 3 }} />
      </div>
      <span style={{ fontSize: 11, color: C.muted }}>{score.toFixed(3)}</span>
    </div>
  );
}

function fmtTime(iso) {
  if (!iso) return "—";
  try { return new Date(iso).toLocaleString(); } catch { return iso; }
}

export default function DetectionsTable({ detections = [], onRowClick }) {
  const [shown, setShown] = useState(PAGE);
  const slice = detections.slice(0, shown);
  const hasMore = detections.length > shown;

  if (!detections.length) return (
    <div style={{ textAlign: "center", padding: 32, color: C.muted, fontSize: 13 }}>
      No detections yet — analyse a host to get started.
    </div>
  );

  return (
    <div>
      <div style={{ overflowX: "auto" }}>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
          <thead>
            <tr style={{ borderBottom: `1px solid ${C.border}` }}>
              {["Time", "Host", "Severity", "Score", "Anomaly"].map(h => (
                <th key={h} style={{ padding: "6px 10px", color: C.muted, textAlign: "left", fontWeight: 600, fontSize: 11, textTransform: "uppercase" }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {slice.map(d => (
              <tr key={d.id}
                onClick={() => onRowClick(d.id)}
                style={{ borderBottom: `1px solid ${C.border}`, cursor: "pointer", transition: "background 0.15s" }}
                onMouseEnter={e => e.currentTarget.style.background = C.cardHover}
                onMouseLeave={e => e.currentTarget.style.background = "transparent"}>
                <td style={{ padding: "8px 10px", color: C.muted }}>{fmtTime(d.detected_at)}</td>
                <td style={{ padding: "8px 10px", color: C.text, fontFamily: "monospace" }}>{d.target_ip || d.target_device || "—"}</td>
                <td style={{ padding: "8px 10px" }}>
                  <span style={{ color: SEV_COLOR[d.severity] ?? C.muted, fontWeight: 700, fontSize: 11 }}>{d.severity?.toUpperCase()}</span>
                </td>
                <td style={{ padding: "8px 10px" }}><ScoreBar score={d.anomaly_score ?? 0} /></td>
                <td style={{ padding: "8px 10px" }}>
                  <span style={{ color: d.is_anomaly ? "#fb923c" : "#4ade80", fontWeight: 600 }}>{d.is_anomaly ? "YES" : "No"}</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {hasMore && (
        <button onClick={() => setShown(s => s + PAGE)}
          style={{ background: "transparent", border: `1px solid ${C.border}`, borderRadius: 6, color: C.muted, fontSize: 12, padding: "6px 16px", cursor: "pointer", marginTop: 10 }}>
          Load more ({detections.length - shown} remaining)
        </button>
      )}
    </div>
  );
}
