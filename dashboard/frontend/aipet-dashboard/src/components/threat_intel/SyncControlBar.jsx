import React, { useState } from "react";
import { syncNow, getSyncStatus } from "./api/threatIntelApi";

const C = { border: "#21262d", text: "#e6edf3", muted: "#7d8590", card: "#0d1117" };

export default function SyncControlBar({ token, stats, onSynced }) {
  const [syncing, setSyncing] = useState(false);
  const [result,  setResult]  = useState(null);
  const [error,   setError]   = useState("");

  const handleSync = async () => {
    setSyncing(true); setResult(null); setError("");
    try {
      const { task_id } = await syncNow(token);
      for (let i = 0; i < 60; i++) {
        await new Promise(r => setTimeout(r, 3000));
        const s = await getSyncStatus(token, task_id);
        if (s.state === "SUCCESS") { setResult(s.result); onSynced?.(); break; }
        if (s.state === "FAILURE") { setError(s.error || "Sync failed"); break; }
      }
    } catch (e) {
      setError(e.message);
    } finally {
      setSyncing(false);
    }
  };

  const active   = stats?.otx_active;
  const lastSync = stats?.otx_last_sync ? new Date(stats.otx_last_sync).toLocaleString() : "Never synced";
  const iocCount = stats?.otx_ioc_count ?? 0;

  return (
    <div style={{ background: C.card, border: `1px solid ${active ? "#00e5ff25" : "#ff8c0025"}`, borderRadius: 8, padding: 16 }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 8 }}>
        <div>
          <div style={{ fontWeight: 700, fontSize: 14, color: C.text }}>AlienVault OTX</div>
          <div style={{ fontSize: 11, color: C.muted, marginTop: 3 }}>
            {lastSync} · {iocCount} IOCs cached
          </div>
        </div>
        <button onClick={handleSync} disabled={syncing}
          style={{ padding: "7px 16px", borderRadius: 8, border: "none",
            cursor: syncing ? "not-allowed" : "pointer", fontSize: 12, fontWeight: 700,
            background: syncing ? C.border : "linear-gradient(135deg,#00e5ff,#0ea5e9)",
            color: syncing ? C.muted : "#000" }}>
          {syncing ? "Syncing…" : "Sync Now"}
        </button>
      </div>
      {result && (
        <div style={{ fontSize: 11, color: C.muted, padding: "6px 10px", background: C.border, borderRadius: 6 }}>
          Added {result.indicators_added} · Updated {result.indicators_updated} · {result.pulses_processed} pulses · {result.runtime_seconds}s
        </div>
      )}
      {error && <div style={{ fontSize: 11, color: "#f87171", marginTop: 6 }}>{error}</div>}
    </div>
  );
}
