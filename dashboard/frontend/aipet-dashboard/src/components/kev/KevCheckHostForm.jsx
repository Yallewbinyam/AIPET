import React, { useState } from "react";
import { kevCheckHost } from "./api/kevApi";

const C = { border: "#21262d", text: "#e6edf3", muted: "#7d8590", card: "#0d1117" };

export default function KevCheckHostForm({ token }) {
  const [ip,      setIp]      = useState("");
  const [result,  setResult]  = useState(null);
  const [loading, setLoading] = useState(false);
  const [error,   setError]   = useState("");

  const handle = async () => {
    const trimmed = ip.trim();
    if (!trimmed) return;
    setLoading(true); setResult(null); setError("");
    try {
      setResult(await kevCheckHost(token, trimmed));
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ background: C.card, border: "1px solid #dc262625", borderRadius: 8, padding: 16 }}>
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
            fontSize: 12, fontWeight: 700, background: "#dc2626", color: "#fff" }}>
          {loading ? "…" : "Check"}
        </button>
      </div>
      {error && <div style={{ fontSize: 11, color: "#f87171", marginTop: 8 }}>{error}</div>}
      {result && (
        <div style={{ marginTop: 10, fontSize: 12 }}>
          {result.status === "no_scan_data" && (
            <span style={{ color: C.muted }}>No scan data for this host — run a scan first.</span>
          )}
          {result.status === "no_kev_data" && (
            <span style={{ color: "#d97706" }}>KEV catalog empty — run a sync first.</span>
          )}
          {result.status === "checked" && result.kev_hits_count === 0 && (
            <span style={{ color: "#16a34a" }}>
              No actively-exploited CVEs detected ({result.host_total_cves} CVEs checked against {result.kev_catalog_size} KEV entries).
            </span>
          )}
          {result.status === "checked" && result.kev_hits_count > 0 && (
            <>
              <div style={{ color: "#dc2626", fontWeight: 700, marginBottom: 6 }}>
                {result.kev_hits_count} actively-exploited CVE{result.kev_hits_count > 1 ? "s" : ""} detected
                {result.ransomware_associated_count > 0 && (
                  <span style={{ marginLeft: 8, color: "#f97316" }}>
                    ({result.ransomware_associated_count} ransomware-associated)
                  </span>
                )}
              </div>
              {result.kev_hits.slice(0, 3).map((h, i) => (
                <div key={i} style={{ color: C.muted, marginBottom: 3 }}>
                  <span style={{ fontFamily: "monospace", color: "#dc2626" }}>{h.cve_id}</span>
                  {" — "}{(h.vulnerability_name || "").slice(0, 60)}
                  {h.known_ransomware_use === "Known" && (
                    <span style={{ marginLeft: 6, color: "#f97316", fontSize: 10, fontWeight: 700 }}>RANSOMWARE</span>
                  )}
                </div>
              ))}
            </>
          )}
        </div>
      )}
    </div>
  );
}
