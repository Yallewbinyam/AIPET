import React from "react";
import { X } from "lucide-react";

const C = { border: "#21262d", text: "#e6edf3", muted: "#7d8590", card: "#0d1117" };

export default function MitreTechniqueDetailModal({ technique, onClose }) {
  if (!technique) return null;
  return (
    <div style={{ position: "fixed", inset: 0, background: "#000a",
      display: "flex", alignItems: "center", justifyContent: "center", zIndex: 1000 }}
      onClick={onClose}>
      <div style={{ background: C.card, border: `1px solid ${C.border}`,
        borderRadius: 12, padding: 28, maxWidth: 560, width: "90%",
        maxHeight: "80vh", overflowY: "auto" }}
        onClick={e => e.stopPropagation()}>
        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 16 }}>
          <div>
            <div style={{ fontFamily: "JetBrains Mono, monospace",
              color: "#dc2626", fontSize: 13, fontWeight: 700 }}>
              {technique.technique_id}
            </div>
            <div style={{ fontSize: 17, fontWeight: 700, color: C.text, marginTop: 2 }}>
              {technique.name}
            </div>
          </div>
          <button onClick={onClose}
            style={{ background: "none", border: "none", cursor: "pointer", color: C.muted }}>
            <X size={18} />
          </button>
        </div>

        <div style={{ marginBottom: 12 }}>
          <span style={{ fontSize: 11, padding: "2px 8px", borderRadius: 100,
            background: "#7c3aed20", border: "1px solid #7c3aed40",
            color: "#a78bfa", fontWeight: 600 }}>
            {technique.tactic}
          </span>
        </div>

        {technique.description && (
          <p style={{ fontSize: 13, color: "#94a3b8", lineHeight: 1.6, marginBottom: 16 }}>
            {technique.description}
          </p>
        )}

        {technique.platforms?.length > 0 && (
          <div style={{ marginBottom: 12 }}>
            <div style={{ fontSize: 10, color: C.muted, fontWeight: 700,
              textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: 4 }}>
              Platforms
            </div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
              {technique.platforms.map(p => (
                <span key={p} style={{ fontSize: 11, padding: "2px 6px", borderRadius: 4,
                  background: C.border, color: C.muted }}>{p}</span>
              ))}
            </div>
          </div>
        )}

        {technique.url && (
          <a href={technique.url} target="_blank" rel="noreferrer"
            style={{ fontSize: 12, color: "#00e5ff", textDecoration: "none" }}>
            View on attack.mitre.org →
          </a>
        )}
      </div>
    </div>
  );
}
