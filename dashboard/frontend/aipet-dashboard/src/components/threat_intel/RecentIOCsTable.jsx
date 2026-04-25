import React from "react";

const C = { border: "#21262d", text: "#e6edf3", muted: "#7d8590" };
const SEV_COLOR  = { Critical: "#dc2626", High: "#ea580c", Medium: "#d97706", Low: "#16a34a" };
const TYPE_COLOR = { ip: "#00e5ff", domain: "#a78bfa", hash: "#f97316", url: "#00ff88" };

function parsePulseName(desc) {
  try { return JSON.parse(desc || "{}").pulse_name || ""; } catch { return ""; }
}

export default function RecentIOCsTable({ iocs }) {
  if (!iocs?.length) return (
    <div style={{ color: C.muted, fontSize: 13, padding: "16px 0" }}>
      No IOCs cached — run a sync to populate the database.
    </div>
  );

  return (
    <div style={{ overflowX: "auto" }}>
      <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
        <thead>
          <tr style={{ borderBottom: `1px solid ${C.border}` }}>
            {["Indicator", "Type", "Pulse", "Severity", "Added"].map(h => (
              <th key={h} style={{ textAlign: "left", padding: "6px 10px",
                color: C.muted, fontWeight: 600, fontSize: 11,
                textTransform: "uppercase", letterSpacing: "0.05em" }}>
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {iocs.map((ioc, i) => {
            const typeClr = TYPE_COLOR[ioc.ioc_type] ?? C.text;
            return (
              <tr key={ioc.id ?? i} style={{ borderBottom: `1px solid ${C.border}20` }}>
                <td style={{ padding: "7px 10px", color: typeClr,
                  fontFamily: "JetBrains Mono, monospace", maxWidth: 220,
                  overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {ioc.value}
                </td>
                <td style={{ padding: "7px 10px" }}>
                  <span style={{ color: typeClr, background: typeClr + "12",
                    borderRadius: 4, padding: "2px 6px", fontSize: 10, fontWeight: 600 }}>
                    {(ioc.ioc_type ?? "?").toUpperCase()}
                  </span>
                </td>
                <td style={{ padding: "7px 10px", color: C.muted, maxWidth: 180,
                  overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {parsePulseName(ioc.description) || ioc.threat_type || "—"}
                </td>
                <td style={{ padding: "7px 10px" }}>
                  <span style={{ color: SEV_COLOR[ioc.severity] ?? C.muted,
                    fontWeight: 700, fontSize: 11 }}>
                    {ioc.severity ?? "—"}
                  </span>
                </td>
                <td style={{ padding: "7px 10px", color: C.muted, fontSize: 11 }}>
                  {ioc.created_at ? new Date(ioc.created_at).toLocaleDateString() : "—"}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
