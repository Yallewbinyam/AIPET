import React, { useState } from "react";
import { checkHost } from "./api/threatIntelApi";

const C = { border: "#21262d", text: "#e6edf3", muted: "#7d8590", card: "#0d1117" };
const SEV_COLOR = { critical: "#dc2626", high: "#ea580c", medium: "#d97706", low: "#16a34a", none: "#16a34a" };

export default function CheckHostForm({ token }) {
  const [ip,      setIp]      = useState("");
  const [result,  setResult]  = useState(null);
  const [loading, setLoading] = useState(false);
  const [error,   setError]   = useState("");

  const handle = async () => {
    const trimmed = ip.trim();
    if (!trimmed) return;
    setLoading(true); setResult(null); setError("");
    try {
      setResult(await checkHost(token, trimmed));
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  const sev = result ? (SEV_COLOR[result.highest_severity] ?? SEV_COLOR.low) : null;

  return (
    <div style={{ background: C.card, border: "1px solid #a78bfa25", borderRadius: 8, padding: 16 }}>
      <div style={{ fontWeight: 700, fontSize: 14, color: C.text, marginBottom: 10 }}>Check a Host</div>
      <div style={{ display: "flex", gap: 8 }}>
        <input value={ip} onChange={e => setIp(e.target.value)}
          onKeyDown={e => e.key === "Enter" && handle()}
          placeholder="Enter IP address"
          style={{ flex: 1, background: C.border, border: "1px solid #2d3f55",
            borderRadius: 8, padding: "8px 12px", color: C.text,
            fontSize: 13, fontFamily: "JetBrains Mono, monospace" }} />
        <button onClick={handle} disabled={loading || !ip.trim()}
          style={{ padding: "8px 14px", borderRadius: 8, border: "none",
            cursor: (loading || !ip.trim()) ? "not-allowed" : "pointer",
            fontSize: 12, fontWeight: 700, background: "#a78bfa", color: "#fff" }}>
          {loading ? "…" : "Check"}
        </button>
      </div>
      {error && <div style={{ fontSize: 11, color: "#f87171", marginTop: 8 }}>{error}</div>}
      {result && (
        <div style={{ marginTop: 10, fontSize: 12 }}>
          {result.match_count === 0
            ? <span style={{ color: "#16a34a" }}>No matches — host not in threat database.</span>
            : <>
                <span style={{ color: sev, fontWeight: 700 }}>
                  {result.match_count} match(es) — {result.highest_severity.toUpperCase()}
                </span>
                <div style={{ marginTop: 6 }}>
                  {result.matches.slice(0, 3).map((m, i) => (
                    <div key={i} style={{ color: C.muted, marginBottom: 2 }}>
                      {m.indicator_type}:{" "}
                      <span style={{ fontFamily: "monospace" }}>{m.indicator}</span>
                      {" "}— {m.pulse_name}
                    </div>
                  ))}
                </div>
              </>
          }
        </div>
      )}
    </div>
  );
}
