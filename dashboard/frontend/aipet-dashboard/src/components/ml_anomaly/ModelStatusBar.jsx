import React, { useState } from "react";
import { RefreshCw, Play } from "lucide-react";
import { trainModel, retrainNow, getRetrainStatus } from "./api/mlAnomalyApi";

const C = { border: "#21262d", text: "#e6edf3", muted: "#7d8590", blue: "#00d4ff", card: "#111820" };

function relativeTime(iso) {
  if (!iso) return "unknown";
  const diff = (Date.now() - new Date(iso).getTime()) / 1000;
  if (diff < 60) return "just now";
  if (diff < 3600) return `${Math.round(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.round(diff / 3600)}h ago`;
  return `${Math.round(diff / 86400)}d ago`;
}

export default function ModelStatusBar({ token, activeModel, onTrained }) {
  const [trainState,  setTrainState]  = useState("idle");  // idle | training | error
  const [retrainMsg,  setRetrainMsg]  = useState("");

  async function handleTrain() {
    setTrainState("training");
    try {
      await trainModel(token);
      onTrained();
      setTrainState("idle");
    } catch (e) {
      setTrainState("error");
      setTimeout(() => setTrainState("idle"), 4000);
    }
  }

  async function handleRetrain() {
    setRetrainMsg("Queuing…");
    try {
      const { task_id } = await retrainNow(token);
      setRetrainMsg("Queued — polling…");
      for (let i = 0; i < 30; i++) {
        await new Promise(r => setTimeout(r, 3000));
        const s = await getRetrainStatus(token, task_id);
        if (s.state === "SUCCESS") {
          setRetrainMsg(`Done: ${s.result?.status ?? "ok"}`);
          onTrained();
          setTimeout(() => setRetrainMsg(""), 5000);
          return;
        }
        if (s.state === "FAILURE") { setRetrainMsg(`Failed: ${s.error}`); return; }
      }
      setRetrainMsg("Timed out");
    } catch (e) {
      setRetrainMsg(`Error: ${e.message}`);
    }
  }

  const m = activeModel;
  return (
    <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 8, padding: "12px 16px", display: "flex", flexWrap: "wrap", gap: 12, alignItems: "center" }}>
      <div style={{ flex: 1, minWidth: 200 }}>
        {m ? (
          <span style={{ color: C.text, fontSize: 13 }}>
            <span style={{ color: C.blue, fontWeight: 700 }}>{m.version_tag}</span>
            {m.f1_score != null && <span style={{ color: C.muted }}> • F1: {(m.f1_score * 100).toFixed(1)}%</span>}
            <span style={{ color: C.muted }}> • Trained {relativeTime(m.created_at)}</span>
            <span style={{ color: C.muted }}> • {m.training_samples?.toLocaleString()} samples</span>
          </span>
        ) : (
          <span style={{ color: C.muted, fontSize: 13 }}>No model trained yet</span>
        )}
      </div>
      <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
        <button onClick={handleTrain} disabled={trainState === "training"}
          className="flex items-center gap-1"
          style={{ background: "#1d4ed8", color: "#fff", border: "none", borderRadius: 6, padding: "6px 14px", fontSize: 12, fontWeight: 600, cursor: "pointer", opacity: trainState === "training" ? 0.6 : 1 }}>
          <Play size={12} />
          {trainState === "training" ? "Training…" : trainState === "error" ? "Error!" : "Train New Model"}
        </button>
        {m && (
          <button onClick={handleRetrain}
            className="flex items-center gap-1"
            style={{ background: "#374151", color: "#e5e7eb", border: `1px solid ${C.border}`, borderRadius: 6, padding: "6px 14px", fontSize: 12, fontWeight: 600, cursor: "pointer" }}>
            <RefreshCw size={12} />
            Schedule Retrain
          </button>
        )}
        {retrainMsg && <span style={{ color: C.muted, fontSize: 12 }}>{retrainMsg}</span>}
      </div>
    </div>
  );
}
