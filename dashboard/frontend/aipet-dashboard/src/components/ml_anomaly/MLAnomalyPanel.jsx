/**
 * MLAnomalyPanel — full ml_anomaly capability panel.
 *
 * Composes: ModelStatusBar, ScanHostForm, DetectionsTable,
 *           DetectionDetailModal, ModelVersionsTable.
 *
 * State owned here; children receive data + callbacks as props.
 */
import React, { useState, useEffect, useCallback } from "react";
import ModelStatusBar      from "./ModelStatusBar";
import ScanHostForm        from "./ScanHostForm";
import DetectionsTable     from "./DetectionsTable";
import DetectionDetailModal from "./DetectionDetailModal";
import ModelVersionsTable  from "./ModelVersionsTable";
import { listModels, listDetections } from "./api/mlAnomalyApi";

const C = { border: "#21262d", text: "#e6edf3", muted: "#7d8590", card: "#0d1117" };

function Section({ title, children }) {
  return (
    <div style={{ marginBottom: 24 }}>
      <div style={{ color: "#7d8590", fontSize: 12, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: 10, borderBottom: `1px solid ${C.border}`, paddingBottom: 6 }}>
        {title}
      </div>
      {children}
    </div>
  );
}

export default function MLAnomalyPanel({ token }) {
  const [models,       setModels]      = useState([]);
  const [detections,   setDetections]  = useState([]);
  const [loadingInit,  setLoadingInit] = useState(true);
  const [initError,    setInitError]   = useState("");
  const [explainId,    setExplainId]   = useState(null);

  const activeModel = models.find(m => m.is_active) ?? null;

  const load = useCallback(async () => {
    try {
      const [mods, dets] = await Promise.all([
        listModels(token),
        listDetections(token, 100),
      ]);
      setModels(Array.isArray(mods) ? mods : []);
      setDetections(Array.isArray(dets.detections ?? dets) ? (dets.detections ?? dets) : []);
      setInitError("");
    } catch (e) {
      setInitError(e.message);
    } finally {
      setLoadingInit(false);
    }
  }, [token]);

  useEffect(() => { load(); }, [load]);

  if (loadingInit) return (
    <div style={{ color: C.muted, padding: 32, textAlign: "center" }}>Loading ML Anomaly data…</div>
  );

  if (initError) return (
    <div style={{ color: "#f87171", background: "#450a0a", border: "1px solid #7f1d1d", borderRadius: 6, padding: 16, fontSize: 13 }}>
      Error loading ML Anomaly panel: {initError}
    </div>
  );

  return (
    <div style={{ maxWidth: 900 }}>
      {/* Model status + train/retrain actions */}
      <Section title="Active Model">
        <ModelStatusBar token={token} activeModel={activeModel} onTrained={load} />
      </Section>

      {/* Host scan */}
      <Section title="Scan Host">
        <ScanHostForm token={token} onNewDetection={load} onExplain={setExplainId} />
      </Section>

      {/* Detections history */}
      <Section title={`Detections (${detections.length})`}>
        <DetectionsTable detections={detections} onRowClick={setExplainId} />
      </Section>

      {/* Model version history */}
      <Section title={`Model Versions (${models.length})`}>
        <ModelVersionsTable models={models} />
      </Section>

      {/* Detail modal */}
      {explainId && (
        <DetectionDetailModal
          token={token}
          detectionId={explainId}
          onClose={() => setExplainId(null)}
        />
      )}
    </div>
  );
}
