import React from "react";
import { AlertTriangle, CheckCircle, Info } from "lucide-react";
import SHAPBreakdown from "./SHAPBreakdown";

const SEV = {
  critical: { color: "#dc2626", label: "CRITICAL", Icon: AlertTriangle },
  high:     { color: "#ea580c", label: "HIGH",     Icon: AlertTriangle },
  medium:   { color: "#d97706", label: "MEDIUM",   Icon: Info          },
  low:      { color: "#16a34a", label: "LOW",      Icon: CheckCircle   },
};
const C = { border: "#21262d", text: "#e6edf3", muted: "#7d8590", card: "#0d1117" };

export default function AnomalyResultCard({ result, onExplain }) {
  if (!result) return null;
  const sev = SEV[result.severity] ?? SEV.medium;
  const { Icon } = sev;
  const score = result.anomaly_score ?? 0;
  const synCount = result.synthetic_fields?.length ?? 0;
  const placeholders = result.placeholder_values ?? null;

  return (
    <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 8, padding: 16, marginTop: 12 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 12 }}>
        <Icon size={20} color={sev.color} />
        <span style={{ color: sev.color, fontWeight: 700, fontSize: 15 }}>{sev.label}</span>
        <span style={{ color: C.muted, fontSize: 13 }}>{result.target_ip}</span>
        <span style={{ marginLeft: "auto", color: C.muted, fontSize: 12 }}>
          {result.explainer_type && <span style={{ background: "#1e3a5f", color: "#93c5fd", border: "1px solid #1d4ed8", borderRadius: 4, padding: "1px 6px", fontSize: 11, fontWeight: 600 }}>SHAP-{result.explainer_type}</span>}
        </span>
      </div>

      <div style={{ marginBottom: 12 }}>
        <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12, color: C.muted, marginBottom: 4 }}>
          <span>Anomaly score</span><span>{score.toFixed(4)}</span>
        </div>
        <div style={{ background: C.border, borderRadius: 4, height: 8 }}>
          <div style={{ width: `${Math.round(score * 100)}%`, height: "100%", background: sev.color, borderRadius: 4, transition: "width 0.5s ease" }} />
        </div>
      </div>

      {result.top_contributors?.length > 0 && (
        <div style={{ marginBottom: 10 }}>
          <div style={{ color: C.muted, fontSize: 11, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: 6 }}>Top SHAP Contributors</div>
          <SHAPBreakdown contributors={result.top_contributors} placeholderValues={placeholders} compact />
        </div>
      )}

      {synCount > 0 && (
        <div style={{ background: "#111827", border: "1px solid #374151", borderRadius: 4, padding: "6px 10px", fontSize: 11, color: "#9ca3af", marginBottom: 10 }}>
          Note: {synCount} of 12 features used imputed values — full feature observation requires watch agent (PLB-8).
        </div>
      )}

      {result.detection_id && (
        <button onClick={() => onExplain(result.detection_id)}
          style={{ background: "transparent", border: `1px solid ${C.border}`, borderRadius: 6, color: "#93c5fd", fontSize: 12, padding: "5px 12px", cursor: "pointer" }}>
          View Full Explanation (all 12 features)
        </button>
      )}
    </div>
  );
}
