import React, { useState } from "react";
import { Search } from "lucide-react";
import { predictReal } from "./api/mlAnomalyApi";
import AnomalyResultCard from "./AnomalyResultCard";

const IP_RE = /^(\d{1,3}\.){3}\d{1,3}$/;
const C = { border: "#21262d", muted: "#7d8590", text: "#e6edf3", card: "#0d1117" };

export default function ScanHostForm({ token, onNewDetection, onExplain }) {
  const [ip,      setIp]      = useState("");
  const [loading, setLoading] = useState(false);
  const [result,  setResult]  = useState(null);
  const [error,   setError]   = useState("");
  const [ipError, setIpError] = useState("");

  async function handleScan(e) {
    e.preventDefault();
    const trimmed = ip.trim();
    if (!IP_RE.test(trimmed)) {
      setIpError("Invalid IP format — enter a dotted-decimal address (e.g. 10.0.3.11)");
      return;
    }
    setIpError("");
    setError("");
    setResult(null);
    setLoading(true);
    try {
      const data = await predictReal(token, { host_ip: trimmed });
      setResult(data);
      onNewDetection?.();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div>
      <div style={{ color: "#7d8590", fontSize: 12, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: 8 }}>
        Scan Host for Anomalies
      </div>
      <form onSubmit={handleScan} style={{ display: "flex", gap: 8 }}>
        <input
          value={ip}
          onChange={e => { setIp(e.target.value); setIpError(""); }}
          placeholder="Enter host IP (e.g. 10.0.3.11)"
          style={{ flex: 1, background: "#030712", border: `1px solid ${C.border}`, borderRadius: 6, color: C.text, fontSize: 13, padding: "8px 12px", outline: "none" }}
          disabled={loading}
        />
        <button type="submit" disabled={loading}
          className="flex items-center gap-2"
          style={{ background: "#7c3aed", color: "#fff", border: "none", borderRadius: 6, padding: "8px 18px", fontSize: 13, fontWeight: 600, cursor: "pointer", opacity: loading ? 0.6 : 1 }}>
          <Search size={14} />
          {loading ? "Analysing…" : "Analyse Host"}
        </button>
      </form>
      {ipError && <div style={{ color: "#f87171", fontSize: 12, marginTop: 6 }}>{ipError}</div>}
      {error   && <div style={{ color: "#f87171", fontSize: 12, marginTop: 6 }}>{error}</div>}
      <AnomalyResultCard result={result} onExplain={onExplain} />
    </div>
  );
}
