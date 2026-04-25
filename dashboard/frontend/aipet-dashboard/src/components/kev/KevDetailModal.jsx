import React from "react";
import { X } from "lucide-react";

const C = { border: "#21262d", text: "#e6edf3", muted: "#7d8590", card: "#0d1117" };

function Row({ label, value }) {
  if (!value) return null;
  return (
    <div style={{ marginBottom: 10 }}>
      <div style={{ fontSize: 10, color: C.muted, fontWeight: 700,
        textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: 3 }}>
        {label}
      </div>
      <div style={{ fontSize: 13, color: C.text }}>{value}</div>
    </div>
  );
}

export default function KevDetailModal({ entry, onClose }) {
  if (!entry) return null;
  return (
    <div style={{ position: "fixed", inset: 0, background: "#000a",
      display: "flex", alignItems: "center", justifyContent: "center", zIndex: 1000 }}
      onClick={onClose}>
      <div style={{ background: "#0d1117", border: `1px solid ${C.border}`,
        borderRadius: 12, padding: 28, maxWidth: 580, width: "90%", maxHeight: "80vh",
        overflowY: "auto" }}
        onClick={e => e.stopPropagation()}>
        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 18 }}>
          <div>
            <div style={{ fontFamily: "JetBrains Mono, monospace",
              color: "#dc2626", fontSize: 15, fontWeight: 700 }}>
              {entry.cve_id}
            </div>
            {entry.known_ransomware_use === "Known" && (
              <span style={{ fontSize: 10, fontWeight: 700, color: "#f97316",
                background: "#f9731620", border: "1px solid #f9731640",
                borderRadius: 4, padding: "2px 6px", marginTop: 4, display: "inline-block" }}>
                RANSOMWARE ASSOCIATED
              </span>
            )}
          </div>
          <button onClick={onClose}
            style={{ background: "none", border: "none", cursor: "pointer", color: C.muted }}>
            <X size={18} />
          </button>
        </div>
        <Row label="Vulnerability" value={entry.vulnerability_name} />
        <Row label="Vendor / Product" value={`${entry.vendor_project} — ${entry.product}`} />
        <Row label="Date Added to KEV" value={entry.date_added} />
        <Row label="Federal Due Date" value={entry.due_date} />
        <Row label="Description" value={entry.short_description} />
        <Row label="Required Action" value={entry.required_action} />
        {entry.notes && <Row label="Notes" value={entry.notes} />}
      </div>
    </div>
  );
}
