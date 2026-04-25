import React from "react";
import { X } from "lucide-react";

const C  = { border: "#21262d", text: "#e6edf3", muted: "#7d8590", card: "#0d1117" };
const SC = { critical:"#dc2626", high:"#ea580c", medium:"#d97706", low:"#16a34a", info:"#6b7280" };

function Row({ label, value }) {
  if (!value && value !== 0) return null;
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

export default function EventDetailModal({ event, onClose }) {
  if (!event) return null;
  const col = SC[event.severity] ?? SC.info;
  return (
    <div style={{ position: "fixed", inset: 0, background: "#000a",
      display: "flex", alignItems: "center", justifyContent: "center", zIndex: 1000 }}
      onClick={onClose}>
      <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 12,
        padding: 28, maxWidth: 560, width: "90%", maxHeight: "80vh", overflowY: "auto" }}
        onClick={e => e.stopPropagation()}>
        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 16 }}>
          <div>
            <span style={{ fontSize: 10, padding: "2px 8px", borderRadius: 100,
              background: col + "20", border: `1px solid ${col}40`,
              color: col, fontWeight: 700, textTransform: "uppercase" }}>
              {event.severity}
            </span>
            <div style={{ fontSize: 16, fontWeight: 700, color: C.text, marginTop: 6 }}>
              {event.title || event.event_type}
            </div>
          </div>
          <button onClick={onClose}
            style={{ background: "none", border: "none", cursor: "pointer", color: C.muted }}>
            <X size={18} />
          </button>
        </div>

        <Row label="Source" value={`${event.source_module} / ${event.source_table} #${event.source_row_id}`} />
        <Row label="Event Type" value={event.event_type} />
        <Row label="Entity" value={event.entity ? `${event.entity} (${event.entity_type})` : null} />
        <Row label="Risk Score" value={event.risk_score != null ? `${event.risk_score}/100` : null} />
        {event.description && <Row label="Description" value={event.description} />}

        {event.mitre_techniques?.length > 0 && (
          <div style={{ marginBottom: 10 }}>
            <div style={{ fontSize: 10, color: C.muted, fontWeight: 700,
              textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: 6 }}>
              MITRE ATT&CK
            </div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
              {event.mitre_techniques.map((t, i) => (
                <span key={i} style={{ fontSize: 10, padding: "2px 7px", borderRadius: 4,
                  background: "#7c3aed20", border: "1px solid #7c3aed40",
                  color: "#a78bfa", fontFamily: "JetBrains Mono, monospace", fontWeight: 700 }}>
                  {t.technique_id}
                </span>
              ))}
            </div>
          </div>
        )}

        <Row label="Timestamp" value={event.created_at ? new Date(event.created_at).toLocaleString() : null} />

        {event.payload && Object.keys(event.payload).length > 0 && (
          <div style={{ marginTop: 10 }}>
            <div style={{ fontSize: 10, color: C.muted, fontWeight: 700,
              textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: 4 }}>
              Payload
            </div>
            <pre style={{ fontSize: 11, color: C.muted, background: "#080f1a",
              borderRadius: 6, padding: 10, overflowX: "auto", maxHeight: 160 }}>
              {JSON.stringify(event.payload, null, 2)}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
}
