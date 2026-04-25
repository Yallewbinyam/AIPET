/**
 * MitrePanel — Capability 6 MITRE ATT&CK live-mapping panel.
 *
 * Composes: MitreCatalogTable, MitreCoverageChart, MitreTechniqueDetailModal.
 */
import React, { useState, useEffect, useCallback } from "react";
import MitreCatalogTable         from "./MitreCatalogTable";
import MitreCoverageChart        from "./MitreCoverageChart";
import MitreTechniqueDetailModal from "./MitreTechniqueDetailModal";
import { getTechniques, getMitreStats } from "./api/mitreApi";

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
    <div style={{ background: C.card, border: `1px solid ${color}25`, borderRadius: 8,
      padding: "12px 16px", minWidth: 110 }}>
      <div style={{ fontSize: 22, fontWeight: 800, color, fontFamily: "JetBrains Mono, monospace",
        lineHeight: 1, textShadow: `0 0 16px ${color}60` }}>
        {value ?? "—"}
      </div>
      <div style={{ fontSize: 10, color: C.muted, marginTop: 5, textTransform: "uppercase",
        letterSpacing: "0.5px" }}>
        {label}
      </div>
    </div>
  );
}

export default function MitrePanel({ token }) {
  const [techniques,     setTechniques]     = useState([]);
  const [stats,          setStats]          = useState(null);
  const [loading,        setLoading]        = useState(true);
  const [error,          setError]          = useState("");
  const [selectedTech,   setSelectedTech]   = useState(null);

  const load = useCallback(async () => {
    try {
      const [techRes, statsRes] = await Promise.all([
        getTechniques(token),
        getMitreStats(token),
      ]);
      setTechniques(techRes.techniques ?? []);
      setStats(statsRes);
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
      Loading MITRE ATT&CK catalog…
    </div>
  );
  if (error) return (
    <div style={{ color: "#f87171", background: "#450a0a", border: "1px solid #7f1d1d",
      borderRadius: 6, padding: 16, fontSize: 13 }}>
      Error: {error}
    </div>
  );

  const tactics = stats?.by_tactic?.length ?? 0;

  return (
    <div style={{ maxWidth: 960 }}>
      <div style={{ marginBottom: 20 }}>
        <h2 style={{ margin: "0 0 4px", fontSize: 20, fontWeight: 800, color: C.text }}>
          MITRE ATT&CK Mapping
        </h2>
        <div style={{ fontSize: 12, color: C.muted }}>
          Curated catalog · Source-aware technique mapping across all detection capabilities
        </div>
      </div>

      <div style={{ display: "flex", gap: 12, marginBottom: 20, flexWrap: "wrap" }}>
        <StatPill label="Techniques"    value={techniques.length} color="#dc2626" />
        <StatPill label="Tactics"       value={tactics}           color="#a78bfa" />
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: 20, marginBottom: 20 }}>
        <Section title={`Catalog — ${techniques.length} techniques`}>
          <MitreCatalogTable techniques={techniques} onSelect={setSelectedTech} />
        </Section>
        <Section title="Tactic Distribution">
          <MitreCoverageChart stats={stats} />
        </Section>
      </div>

      {selectedTech && (
        <MitreTechniqueDetailModal
          technique={selectedTech}
          onClose={() => setSelectedTech(null)}
        />
      )}
    </div>
  );
}
