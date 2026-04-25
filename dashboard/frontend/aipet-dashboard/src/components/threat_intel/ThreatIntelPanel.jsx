/**
 * ThreatIntelPanel — Capability 4 threat intelligence panel.
 *
 * Composes: SyncControlBar, CheckHostForm, RecentIOCsTable.
 * State owned here; children receive data + callbacks as props.
 */
import React, { useState, useEffect, useCallback } from "react";
import SyncControlBar  from "./SyncControlBar";
import CheckHostForm   from "./CheckHostForm";
import RecentIOCsTable from "./RecentIOCsTable";
import { getStats, getRecentIocs } from "./api/threatIntelApi";

const C = { border: "#21262d", text: "#e6edf3", muted: "#7d8590", card: "#0d1117" };

function Section({ title, children }) {
  return (
    <div style={{ marginBottom: 20 }}>
      <div style={{ color: C.muted, fontSize: 11, fontWeight: 600, textTransform: "uppercase",
        letterSpacing: "0.05em", marginBottom: 8,
        borderBottom: `1px solid ${C.border}`, paddingBottom: 5 }}>
        {title}
      </div>
      {children}
    </div>
  );
}

function StatPill({ label, value, color }) {
  return (
    <div style={{ background: C.card, border: `1px solid ${color}25`,
      borderRadius: 8, padding: "12px 16px", minWidth: 110 }}>
      <div style={{ fontSize: 22, fontWeight: 800, color, fontFamily: "JetBrains Mono, monospace",
        lineHeight: 1, textShadow: `0 0 16px ${color}60` }}>
        {value ?? "—"}
      </div>
      <div style={{ fontSize: 10, color: C.muted, marginTop: 5,
        textTransform: "uppercase", letterSpacing: "0.5px" }}>
        {label}
      </div>
    </div>
  );
}

export default function ThreatIntelPanel({ token }) {
  const [stats,   setStats]   = useState(null);
  const [iocs,    setIocs]    = useState([]);
  const [loading, setLoading] = useState(true);
  const [error,   setError]   = useState("");

  const load = useCallback(async () => {
    try {
      const [s, iocRes] = await Promise.all([
        getStats(token),
        getRecentIocs(token, 50),
      ]);
      setStats(s);
      setIocs(iocRes.iocs ?? []);
      setError("");
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => { load(); }, [load]);

  if (loading) return (
    <div style={{ color: C.muted, padding: 32, textAlign: "center" }}>
      Loading threat intelligence data…
    </div>
  );

  if (error) return (
    <div style={{ color: "#f87171", background: "#450a0a",
      border: "1px solid #7f1d1d", borderRadius: 6, padding: 16, fontSize: 13 }}>
      Error loading threat intelligence: {error}
    </div>
  );

  return (
    <div style={{ maxWidth: 900 }}>
      <div style={{ marginBottom: 20 }}>
        <h2 style={{ margin: "0 0 4px", fontSize: 20, fontWeight: 800, color: C.text }}>
          Threat Intelligence
        </h2>
        <div style={{ fontSize: 12, color: C.muted }}>
          AlienVault OTX · Locally cached indicators of compromise
        </div>
      </div>

      {stats && (
        <div style={{ display: "flex", gap: 12, marginBottom: 20, flexWrap: "wrap" }}>
          <StatPill label="Total IOCs"    value={stats.total_iocs}       color="#a78bfa" />
          <StatPill label="Matches Today" value={stats.matches_today}    color="#ff8c00" />
          <StatPill label="Critical Hits" value={stats.critical_matches} color="#ff3b5c" />
          <StatPill label="Active Feeds"  value={stats.active_feeds}     color="#00e5ff" />
        </div>
      )}

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 20 }}>
        <Section title="OTX Sync">
          <SyncControlBar token={token} stats={stats} onSynced={load} />
        </Section>
        <Section title="Host Lookup">
          <CheckHostForm token={token} />
        </Section>
      </div>

      <Section title={`Recent IOCs — ${iocs.length} shown`}>
        <RecentIOCsTable iocs={iocs} />
      </Section>
    </div>
  );
}
