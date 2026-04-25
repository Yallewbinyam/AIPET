import React, { useState } from "react";
import { ChevronDown, ChevronUp } from "lucide-react";

const C = { border: "#21262d", text: "#e6edf3", muted: "#7d8590", blue: "#00d4ff" };

function pct(v) { return v != null ? `${(v * 100).toFixed(1)}%` : "—"; }
function fmtTime(iso) { try { return new Date(iso).toLocaleString(); } catch { return "—"; } }

export default function ModelVersionsTable({ models = [] }) {
  const [expanded, setExpanded] = useState(false);
  const rows = expanded ? models : models.slice(0, 5);

  if (!models.length) return (
    <div style={{ color: "#7d8590", fontSize: 13, padding: "8px 0" }}>No model versions found.</div>
  );

  return (
    <div>
      <div style={{ overflowX: "auto" }}>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
          <thead>
            <tr style={{ borderBottom: `1px solid ${C.border}` }}>
              {["Version", "Algorithm", "Active", "Precision", "Recall", "F1", "Samples", "Trained At"].map(h => (
                <th key={h} style={{ padding: "5px 10px", color: C.muted, textAlign: "left", fontWeight: 600, fontSize: 11, textTransform: "uppercase" }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map(m => (
              <tr key={m.version_tag}
                style={{ borderBottom: `1px solid ${C.border}`, background: m.is_active ? "rgba(0,212,255,0.04)" : "transparent" }}>
                <td style={{ padding: "7px 10px", color: m.is_active ? C.blue : C.text, fontFamily: "monospace", fontWeight: m.is_active ? 700 : 400 }}>{m.version_tag}</td>
                <td style={{ padding: "7px 10px", color: C.muted }}>{m.algorithm}</td>
                <td style={{ padding: "7px 10px" }}>
                  {m.is_active && <span style={{ color: C.blue, fontWeight: 700, fontSize: 11 }}>ACTIVE</span>}
                </td>
                <td style={{ padding: "7px 10px", color: C.text }}>{pct(m.precision_score)}</td>
                <td style={{ padding: "7px 10px", color: C.text }}>{pct(m.recall_score)}</td>
                <td style={{ padding: "7px 10px", color: m.f1_score >= 0.9 ? "#4ade80" : m.f1_score >= 0.7 ? "#facc15" : C.text }}>{pct(m.f1_score)}</td>
                <td style={{ padding: "7px 10px", color: C.muted }}>{m.training_samples?.toLocaleString() ?? "—"}</td>
                <td style={{ padding: "7px 10px", color: C.muted }}>{fmtTime(m.created_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {models.length > 5 && (
        <button onClick={() => setExpanded(e => !e)}
          className="flex items-center gap-1"
          style={{ background: "transparent", border: "none", color: C.muted, fontSize: 12, cursor: "pointer", marginTop: 6, padding: "4px 0" }}>
          {expanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
          {expanded ? "Show fewer" : `Show all ${models.length} versions`}
        </button>
      )}
    </div>
  );
}
