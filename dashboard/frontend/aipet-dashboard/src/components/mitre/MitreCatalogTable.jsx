import React, { useState } from "react";

const C = { border: "#21262d", text: "#e6edf3", muted: "#7d8590" };
const TACTIC_COLOR = {
  "Initial Access":     "#dc2626", "Execution":        "#ea580c",
  "Persistence":        "#d97706", "Privilege Escalation": "#ca8a04",
  "Defense Evasion":    "#16a34a", "Credential Access": "#0891b2",
  "Discovery":          "#2563eb", "Lateral Movement":  "#7c3aed",
  "Collection":         "#db2777", "Command and Control": "#e11d48",
  "Exfiltration":       "#c2410c", "Impact":            "#b91c1c",
};

export default function MitreCatalogTable({ techniques, onSelect }) {
  const [tacticFilter, setTacticFilter] = useState("");

  const tactics   = [...new Set(techniques.map(t => t.tactic).filter(Boolean))].sort();
  const displayed = tacticFilter ? techniques.filter(t => t.tactic === tacticFilter) : techniques;

  if (!techniques.length) return (
    <div style={{ color: C.muted, fontSize: 13, padding: "16px 0" }}>
      Catalog not loaded — restart the backend to seed.
    </div>
  );

  return (
    <div>
      <div style={{ marginBottom: 10, display: "flex", gap: 8, flexWrap: "wrap" }}>
        <button onClick={() => setTacticFilter("")}
          style={{ padding: "4px 12px", borderRadius: 100, border: "none",
            cursor: "pointer", fontSize: 11, fontWeight: 600,
            background: !tacticFilter ? "#7c3aed" : C.border,
            color: !tacticFilter ? "#fff" : C.muted }}>
          All
        </button>
        {tactics.map(t => (
          <button key={t} onClick={() => setTacticFilter(t === tacticFilter ? "" : t)}
            style={{ padding: "4px 10px", borderRadius: 100, border: "none",
              cursor: "pointer", fontSize: 10, fontWeight: 600,
              background: tacticFilter === t ? (TACTIC_COLOR[t] ?? "#7c3aed") + "30" : C.border,
              color: tacticFilter === t ? (TACTIC_COLOR[t] ?? "#a78bfa") : C.muted,
              borderWidth: 1, borderStyle: "solid",
              borderColor: tacticFilter === t ? (TACTIC_COLOR[t] ?? "#7c3aed") + "60" : "transparent" }}>
            {t}
          </button>
        ))}
      </div>

      <div style={{ overflowX: "auto" }}>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
          <thead>
            <tr style={{ borderBottom: `1px solid ${C.border}` }}>
              {["Technique ID", "Name", "Tactic", "Platforms"].map(h => (
                <th key={h} style={{ textAlign: "left", padding: "6px 10px",
                  color: C.muted, fontWeight: 600, fontSize: 11,
                  textTransform: "uppercase", letterSpacing: "0.05em" }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {displayed.map((t, i) => (
              <tr key={t.technique_id ?? i} onClick={() => onSelect?.(t)}
                style={{ borderBottom: `1px solid ${C.border}20`, cursor: "pointer" }}>
                <td style={{ padding: "7px 10px", fontFamily: "JetBrains Mono, monospace",
                  color: "#dc2626", whiteSpace: "nowrap" }}>
                  {t.technique_id}
                </td>
                <td style={{ padding: "7px 10px", color: C.text, maxWidth: 220,
                  overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {t.name}
                </td>
                <td style={{ padding: "7px 10px" }}>
                  <span style={{ fontSize: 10, padding: "2px 6px", borderRadius: 100,
                    background: (TACTIC_COLOR[t.tactic] ?? "#7c3aed") + "20",
                    color: TACTIC_COLOR[t.tactic] ?? "#a78bfa", fontWeight: 600 }}>
                    {t.tactic}
                  </span>
                </td>
                <td style={{ padding: "7px 10px", color: C.muted, fontSize: 11,
                  maxWidth: 150, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {(t.platforms ?? []).join(", ")}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
