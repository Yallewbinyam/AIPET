import React from "react";

const C = { border: "#21262d", muted: "#7d8590", text: "#e6edf3" };
const TACTIC_COLOR = {
  "Initial Access": "#dc2626", "Execution": "#ea580c",
  "Persistence": "#d97706", "Privilege Escalation": "#ca8a04",
  "Defense Evasion": "#16a34a", "Credential Access": "#0891b2",
  "Discovery": "#2563eb", "Lateral Movement": "#7c3aed",
  "Collection": "#db2777", "Command and Control": "#e11d48",
  "Exfiltration": "#c2410c", "Impact": "#b91c1c",
};

export default function MitreCoverageChart({ stats }) {
  if (!stats?.by_tactic?.length) return (
    <div style={{ color: C.muted, fontSize: 13, padding: "12px 0" }}>No data yet.</div>
  );

  const max = Math.max(...stats.by_tactic.map(t => t.count));

  return (
    <div>
      {stats.by_tactic.map(({ tactic, count }) => (
        <div key={tactic} style={{ marginBottom: 8 }}>
          <div style={{ display: "flex", justifyContent: "space-between",
            fontSize: 11, marginBottom: 3 }}>
            <span style={{ color: C.muted }}>{tactic}</span>
            <span style={{ color: TACTIC_COLOR[tactic] ?? "#a78bfa",
              fontFamily: "JetBrains Mono, monospace", fontWeight: 700 }}>
              {count}
            </span>
          </div>
          <div style={{ background: C.border, borderRadius: 4, height: 6 }}>
            <div style={{ width: `${Math.round((count / max) * 100)}%`, height: "100%",
              background: TACTIC_COLOR[tactic] ?? "#7c3aed",
              borderRadius: 4, transition: "width 0.4s ease" }} />
          </div>
        </div>
      ))}
    </div>
  );
}
