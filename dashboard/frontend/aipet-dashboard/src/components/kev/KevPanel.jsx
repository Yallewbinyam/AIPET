/**
 * KevPanel — Capability 5 CISA KEV active-exploitation panel.
 *
 * Composes: KevSyncBar, KevCheckHostForm, KevCatalogTable, KevDetailModal.
 * State owned here; children receive data + callbacks as props.
 */
import React, { useState, useEffect, useCallback } from "react";
import KevSyncBar       from "./KevSyncBar";
import KevCheckHostForm from "./KevCheckHostForm";
import KevCatalogTable  from "./KevCatalogTable";
import KevDetailModal   from "./KevDetailModal";
import { getKevStats, getKevCatalog } from "./api/kevApi";

const C = { border: "#21262d", text: "#e6edf3", muted: "#7d8590", card: "#0d1117" };

function Section({ title, children }) {
  return (
    <div style={{ marginBottom: 20 }}>
      <div style={{ color: C.muted, fontSize: 11, fontWeight: 600, textTransform: "uppercase",
        letterSpacing: "0.05em", marginBottom: 8, borderBottom: `1px solid ${C.border}`, paddingBottom: 5 }}>
        {title}
      </div>
      {children}
    </div>
  );
}

function StatPill({ label, value, color }) {
  return (
    <div style={{ background: C.card, border: `1px solid ${color}25`, borderRadius: 8, padding: "12px 16px", minWidth: 110 }}>
      <div style={{ fontSize: 22, fontWeight: 800, color, fontFamily: "JetBrains Mono, monospace",
        lineHeight: 1, textShadow: `0 0 16px ${color}60` }}>
        {value ?? "—"}
      </div>
      <div style={{ fontSize: 10, color: C.muted, marginTop: 5, textTransform: "uppercase", letterSpacing: "0.5px" }}>
        {label}
      </div>
    </div>
  );
}

export default function KevPanel({ token }) {
  const [stats,         setStats]         = useState(null);
  const [entries,       setEntries]       = useState([]);
  const [ransomwareOnly, setRansomwareOnly] = useState(false);
  const [loading,       setLoading]       = useState(true);
  const [error,         setError]         = useState("");
  const [selectedEntry, setSelectedEntry] = useState(null);

  const load = useCallback(async () => {
    try {
      const [s, cat] = await Promise.all([
        getKevStats(token),
        getKevCatalog(token, 50, ransomwareOnly),
      ]);
      setStats(s);
      setEntries(cat.entries ?? []);
      setError("");
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, [token, ransomwareOnly]);

  useEffect(() => { load(); }, [load]);

  if (loading) return (
    <div style={{ color: C.muted, padding: 32, textAlign: "center" }}>Loading KEV catalog…</div>
  );
  if (error) return (
    <div style={{ color: "#f87171", background: "#450a0a", border: "1px solid #7f1d1d",
      borderRadius: 6, padding: 16, fontSize: 13 }}>
      Error loading KEV panel: {error}
    </div>
  );

  return (
    <div style={{ maxWidth: 900 }}>
      <div style={{ marginBottom: 20 }}>
        <h2 style={{ margin: "0 0 4px", fontSize: 20, fontWeight: 800, color: C.text }}>
          Active Exploitation (CISA KEV)
        </h2>
        <div style={{ fontSize: 12, color: C.muted }}>
          CISA Known Exploited Vulnerabilities · Locally cached · Federal patch deadlines
        </div>
      </div>

      {stats && (
        <div style={{ display: "flex", gap: 12, marginBottom: 20, flexWrap: "wrap" }}>
          <StatPill label="Total KEV Entries"   value={stats.total}                 color="#dc2626" />
          <StatPill label="Ransomware Assoc."   value={stats.ransomware_associated} color="#f97316" />
          <StatPill label="Oldest Entry"        value={stats.oldest_entry?.slice(0,10)} color="#7d8590" />
          <StatPill label="Newest Entry"        value={stats.newest_entry?.slice(0,10)} color="#00e5ff" />
        </div>
      )}

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginBottom: 20 }}>
        <Section title="CISA Sync">
          <KevSyncBar token={token} stats={stats} onSynced={load} />
        </Section>
        <Section title="Host Check">
          <KevCheckHostForm token={token} />
        </Section>
      </div>

      <Section title={`KEV Catalog — ${entries.length} shown`}>
        <div style={{ marginBottom: 10 }}>
          <label style={{ fontSize: 12, color: C.muted, cursor: "pointer", userSelect: "none" }}>
            <input type="checkbox" checked={ransomwareOnly}
              onChange={e => setRansomwareOnly(e.target.checked)}
              style={{ marginRight: 6 }} />
            Ransomware-associated only
          </label>
        </div>
        <KevCatalogTable entries={entries} onSelect={setSelectedEntry} />
      </Section>

      {selectedEntry && (
        <KevDetailModal entry={selectedEntry} onClose={() => setSelectedEntry(null)} />
      )}
    </div>
  );
}
