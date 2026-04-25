import React, { useState } from "react";
import { kevSyncNow, getKevSyncStatus } from "./api/kevApi";

const C = { border: "#21262d", text: "#e6edf3", muted: "#7d8590", card: "#0d1117" };

export default function KevSyncBar({ token, stats, onSynced }) {
  const [syncing, setSyncing] = useState(false);
  const [result,  setResult]  = useState(null);
  const [error,   setError]   = useState("");

  const handleSync = async () => {
    setSyncing(true); setResult(null); setError("");
    try {
      const { task_id } = await kevSyncNow(token);
      for (let i = 0; i < 60; i++) {
        await new Promise(r => setTimeout(r, 3000));
        const s = await getKevSyncStatus(token, task_id);
        if (s.state === "SUCCESS") { setResult(s.result); onSynced?.(); break; }
        if (s.state === "FAILURE") { setError(s.error || "Sync failed"); break; }
      }
    } catch (e) {
      setError(e.message);
    } finally {
      setSyncing(false);
    }
  };

  const lastSync = stats?.last_synced_at ? new Date(stats.last_synced_at).toLocaleString() : "Never synced";

  return (
    <div style={{ background: C.card, border: "1px solid #dc262625", borderRadius: 8, padding: 16 }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 8 }}>
        <div>
          <div style={{ fontWeight: 700, fontSize: 14, color: C.text }}>CISA KEV Catalog</div>
          <div style={{ fontSize: 11, color: C.muted, marginTop: 3 }}>
            {lastSync} · {stats?.total ?? 0} entries · {stats?.ransomware_associated ?? 0} ransomware-associated
          </div>
        </div>
        <button onClick={handleSync} disabled={syncing}
          style={{ padding: "7px 16px", borderRadius: 8, border: "none",
            cursor: syncing ? "not-allowed" : "pointer", fontSize: 12, fontWeight: 700,
            background: syncing ? C.border : "linear-gradient(135deg,#dc2626,#ef4444)",
            color: syncing ? C.muted : "#fff" }}>
          {syncing ? "Syncing…" : "Sync Now"}
        </button>
      </div>
      {result && (
        <div style={{ fontSize: 11, color: C.muted, padding: "6px 10px", background: C.border, borderRadius: 6 }}>
          Synced {result.upserted_count} entries from catalog v{result.catalog_version} in {result.runtime_seconds}s
        </div>
      )}
      {error && <div style={{ fontSize: 11, color: "#f87171", marginTop: 6 }}>{error}</div>}
    </div>
  );
}
