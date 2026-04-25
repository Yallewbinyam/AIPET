import React, { useState } from "react";

const C = { border: "#21262d", text: "#e6edf3", muted: "#7d8590" };

export default function KevCatalogTable({ entries, onSelect }) {
  if (!entries?.length) return (
    <div style={{ color: C.muted, fontSize: 13, padding: "16px 0" }}>
      No entries — run a sync to populate the KEV catalog.
    </div>
  );

  return (
    <div style={{ overflowX: "auto" }}>
      <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
        <thead>
          <tr style={{ borderBottom: `1px solid ${C.border}` }}>
            {["CVE ID", "Vendor / Product", "Vulnerability", "Added", "Due Date", "Ransomware"].map(h => (
              <th key={h} style={{ textAlign: "left", padding: "6px 10px",
                color: C.muted, fontWeight: 600, fontSize: 11,
                textTransform: "uppercase", letterSpacing: "0.05em" }}>
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {entries.map((e, i) => (
            <tr key={e.cve_id ?? i}
              onClick={() => onSelect?.(e)}
              style={{ borderBottom: `1px solid ${C.border}20`, cursor: "pointer" }}>
              <td style={{ padding: "7px 10px", color: "#dc2626",
                fontFamily: "JetBrains Mono, monospace", whiteSpace: "nowrap" }}>
                {e.cve_id}
              </td>
              <td style={{ padding: "7px 10px", color: C.muted, maxWidth: 140,
                overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                {e.vendor_project} / {e.product}
              </td>
              <td style={{ padding: "7px 10px", color: C.text, maxWidth: 200,
                overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                {e.vulnerability_name}
              </td>
              <td style={{ padding: "7px 10px", color: C.muted, fontSize: 11, whiteSpace: "nowrap" }}>
                {e.date_added || "—"}
              </td>
              <td style={{ padding: "7px 10px", color: C.muted, fontSize: 11, whiteSpace: "nowrap" }}>
                {e.due_date || "—"}
              </td>
              <td style={{ padding: "7px 10px" }}>
                {e.known_ransomware_use === "Known"
                  ? <span style={{ color: "#f97316", fontWeight: 700, fontSize: 10 }}>YES</span>
                  : <span style={{ color: C.muted, fontSize: 10 }}>—</span>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
