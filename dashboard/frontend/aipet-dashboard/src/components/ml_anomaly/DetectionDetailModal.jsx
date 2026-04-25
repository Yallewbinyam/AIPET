import React, { useEffect, useState } from "react";
import { X } from "lucide-react";
import { getDetectionExplain } from "./api/mlAnomalyApi";
import SHAPBreakdown from "./SHAPBreakdown";

const C = { border: "#21262d", text: "#e6edf3", muted: "#7d8590", dark: "#080c10", card: "#0d1117" };
const SEV_COLOR = { critical: "#dc2626", high: "#ea580c", medium: "#d97706", low: "#16a34a" };

export default function DetectionDetailModal({ token, detectionId, onClose }) {
  const [data,    setData]    = useState(null);
  const [loading, setLoading] = useState(true);
  const [error,   setError]   = useState("");

  useEffect(() => {
    if (!detectionId) return;
    setLoading(true); setError(""); setData(null);
    getDetectionExplain(token, detectionId)
      .then(setData)
      .catch(e => setError(e.message))
      .finally(() => setLoading(false));
  }, [token, detectionId]);

  function handleBackdrop(e) { if (e.target === e.currentTarget) onClose(); }

  const expl = data?.explanation;
  const sevColor = SEV_COLOR[data?.severity] ?? "#6b7280";

  return (
    <div onClick={handleBackdrop}
      style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.7)", backdropFilter: "blur(4px)", zIndex: 1000, display: "flex", alignItems: "center", justifyContent: "center", padding: 16 }}>
      <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 10, width: "100%", maxWidth: 700, maxHeight: "90vh", overflow: "auto", boxShadow: "0 25px 50px rgba(0,0,0,0.5)" }}>

        {/* Header */}
        <div style={{ display: "flex", alignItems: "center", gap: 10, padding: "14px 18px", borderBottom: `1px solid ${C.border}` }}>
          <span style={{ color: C.text, fontWeight: 700, fontSize: 15, flex: 1 }}>
            Detection #{detectionId}
            {data && <span style={{ color: C.muted, fontWeight: 400 }}> • {data.explanation?.feature_vector_used && Object.keys(data.explanation.feature_vector_used).length > 0 ? data.model_version : ""}</span>}
            {data && <span style={{ color: sevColor, fontWeight: 700 }}> • {data.severity?.toUpperCase()}</span>}
          </span>
          <button onClick={onClose} style={{ background: "transparent", border: "none", color: C.muted, cursor: "pointer", padding: 4 }}><X size={18} /></button>
        </div>

        {/* Body */}
        <div style={{ padding: 18 }}>
          {loading && <div style={{ color: C.muted, textAlign: "center", padding: 32 }}>Loading explanation…</div>}
          {error   && <div style={{ color: "#f87171", padding: 12 }}>{error}</div>}
          {data && (
            <>
              {expl?.format === "zscore_legacy" && (
                <div style={{ background: "#1c1f26", border: "1px solid #374151", borderRadius: 6, padding: "8px 12px", fontSize: 12, color: "#9ca3af", marginBottom: 14 }}>
                  Legacy detection (z-score format, pre-SHAP). SHAP values not available.
                </div>
              )}
              {expl?.format === "shap_v1" && (
                <div style={{ marginBottom: 10 }}>
                  <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12, color: C.muted, marginBottom: 8 }}>
                    <span>Explainer: <strong style={{ color: "#93c5fd" }}>SHAP-{expl.explainer_type}</strong></span>
                    <span>Score: <strong style={{ color: sevColor }}>{data.anomaly_score?.toFixed(4)}</strong></span>
                  </div>
                  <SHAPBreakdown
                    contributors={expl.all_contributors ?? []}
                    placeholderValues={expl.placeholder_values}
                    compact={false}
                  />
                </div>
              )}
              {expl?.format === "zscore_legacy" && (
                <div>
                  {(expl.all_contributors ?? []).map(c => (
                    <div key={c.feature} style={{ display: "flex", justifyContent: "space-between", padding: "4px 0", fontSize: 13, color: C.text }}>
                      <span>{c.feature}</span>
                      <span style={{ color: c.z_score > 0 ? "#fb923c" : "#4ade80" }}>z={c.z_score?.toFixed(3)}</span>
                    </div>
                  ))}
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
