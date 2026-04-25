import React, { useState } from "react";
import { updateThreshold } from "./api/automatedResponseApi";

const C = { text: "#e6edf3", muted: "#7d8590", card: "#0d1117", border: "#21262d" };
const TIER_COLOR = { notify: "#f5c518", high_alert: "#ff8c00", emergency: "#ff4444" };

export default function ThresholdsCard({ thresholds, token, onRefresh }) {
  const [editing, setEditing] = useState(null);
  const [saving,  setSaving]  = useState(false);

  const save = async (id, body) => {
    setSaving(true);
    await updateThreshold(token, id, body);
    setSaving(false);
    setEditing(null);
    onRefresh();
  };

  return (
    <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 8, padding: 16, marginBottom: 16 }}>
      <div style={{ color: C.muted, fontSize: 11, fontWeight: 600, textTransform: "uppercase", marginBottom: 12 }}>
        Risk Score Thresholds
      </div>
      {thresholds.map((t) => {
        const color = TIER_COLOR[t.name] ?? "#6b7280";
        const isEdit = editing === t.id;
        return (
          <div key={t.id} style={{ display: "flex", alignItems: "center", gap: 12,
            padding: "8px 0", borderBottom: `1px solid ${C.border}` }}>
            <span style={{ color, fontWeight: 700, fontSize: 12, minWidth: 80 }}>
              {t.name}
            </span>
            <span style={{ color: C.muted, fontSize: 11, flex: 1 }}>{t.description}</span>
            {isEdit ? (
              <>
                <input type="number" min={0} max={100} defaultValue={t.min_score}
                  id={`ms-${t.id}`}
                  style={{ width: 50, background: "#111820", border: `1px solid ${C.border}`,
                    color: C.text, borderRadius: 4, padding: "2px 6px", fontSize: 12 }} />
                <button onClick={() => save(t.id, { min_score: parseInt(document.getElementById(`ms-${t.id}`).value) })}
                  disabled={saving}
                  style={{ background: "#00d4ff20", border: "1px solid #00d4ff40",
                    color: "#00d4ff", borderRadius: 4, padding: "2px 8px", fontSize: 11, cursor: "pointer" }}>
                  {saving ? "…" : "Save"}
                </button>
                <button onClick={() => setEditing(null)}
                  style={{ background: "none", border: "none", color: C.muted, cursor: "pointer", fontSize: 11 }}>
                  Cancel
                </button>
              </>
            ) : (
              <>
                <span style={{ color, fontWeight: 800, fontSize: 14 }}>≥{t.min_score}</span>
                <span style={{ color: C.muted, fontSize: 11 }}>{t.cooldown_hours}h cooldown</span>
                <button onClick={() => save(t.id, { enabled: !t.enabled })}
                  style={{ background: t.enabled ? "#00ff8820" : "#ff444420",
                    border: `1px solid ${t.enabled ? "#00ff8840" : "#ff444440"}`,
                    color: t.enabled ? "#00ff88" : "#ff4444",
                    borderRadius: 4, padding: "2px 8px", fontSize: 10, cursor: "pointer" }}>
                  {t.enabled ? "ON" : "OFF"}
                </button>
                <button onClick={() => setEditing(t.id)}
                  style={{ background: "none", border: `1px solid ${C.border}`,
                    color: C.muted, borderRadius: 4, padding: "2px 8px", fontSize: 10, cursor: "pointer" }}>
                  Edit
                </button>
              </>
            )}
          </div>
        );
      })}
    </div>
  );
}
