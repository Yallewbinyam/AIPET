import React, { useState } from "react";
import { AlertTriangle, CheckCircle, Info, AlertOctagon, Skull, Crosshair, Gauge } from "lucide-react";
import SHAPBreakdown from "./SHAPBreakdown";

const SEV = {
  critical: { color: "#dc2626", label: "CRITICAL", Icon: AlertTriangle },
  high:     { color: "#ea580c", label: "HIGH",     Icon: AlertTriangle },
  medium:   { color: "#d97706", label: "MEDIUM",   Icon: Info          },
  low:      { color: "#16a34a", label: "LOW",      Icon: CheckCircle   },
};
const C = { border: "#21262d", text: "#e6edf3", muted: "#7d8590", card: "#0d1117" };

export default function AnomalyResultCard({ result, onExplain }) {
  const [kevExpanded, setKevExpanded] = useState(false);
  if (!result) return null;
  const sev = SEV[result.severity] ?? SEV.medium;
  const { Icon } = sev;
  const score = result.anomaly_score ?? 0;
  const synCount = result.synthetic_fields?.length ?? 0;
  const placeholders = result.placeholder_values ?? null;

  return (
    <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 8,
      padding: "clamp(10px, 3vw, 16px)", marginTop: 12, overflowX: "hidden" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 12, flexWrap: "wrap" }}>
        <Icon size={20} color={sev.color} />
        <span style={{ color: sev.color, fontWeight: 700, fontSize: 15 }}>{sev.label}</span>
        <span style={{ color: C.muted, fontSize: 13 }}>{result.target_ip}</span>
        <span style={{ marginLeft: "auto", color: C.muted, fontSize: 12 }}>
          {result.explainer_type && <span style={{ background: "#1e3a5f", color: "#93c5fd", border: "1px solid #1d4ed8", borderRadius: 4, padding: "1px 6px", fontSize: 11, fontWeight: 600 }}>SHAP-{result.explainer_type}</span>}
        </span>
      </div>

      <div style={{ marginBottom: 12 }}>
        <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12, color: C.muted, marginBottom: 4 }}>
          <span>Anomaly score</span><span>{score.toFixed(4)}</span>
        </div>
        <div style={{ background: C.border, borderRadius: 4, height: 8 }}>
          <div style={{ width: `${Math.round(score * 100)}%`, height: "100%", background: sev.color, borderRadius: 4, transition: "width 0.5s ease" }} />
        </div>
      </div>

      {result.top_contributors?.length > 0 && (
        <div style={{ marginBottom: 10 }}>
          <div style={{ color: C.muted, fontSize: 11, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: 6 }}>Top SHAP Contributors</div>
          <SHAPBreakdown contributors={result.top_contributors} placeholderValues={placeholders} compact />
        </div>
      )}

      {synCount > 0 && (
        <div style={{ background: "#111827", border: "1px solid #374151", borderRadius: 4, padding: "6px 10px", fontSize: 11, color: "#9ca3af", marginBottom: 10 }}>
          Note: {synCount} of 12 features used imputed values — full feature observation requires watch agent (PLB-8).
        </div>
      )}

      {/* Behavioral baseline section (Capability 2) */}
      {result.behavioral_baseline && result.behavioral_baseline.status !== "error" && (
        <div style={{ background: "#0a1628", border: "1px solid #1e3a5f", borderRadius: 6, padding: "10px 12px", marginBottom: 10 }}>
          <div style={{ color: "#64748b", fontSize: 10, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: 6 }}>
            Behavioral Baseline (Capability 2)
          </div>
          {result.behavioral_baseline.status === "no_baseline" ? (
            <div style={{ fontSize: 11, color: "#64748b" }}>No baseline yet — run build_all after 5+ scans of this host.</div>
          ) : (
            <>
              <div style={{ display: "flex", gap: 16, fontSize: 12, marginBottom: 6 }}>
                <span style={{ color: result.behavioral_baseline.severity === "critical" ? "#dc2626" : result.behavioral_baseline.severity === "high" ? "#ea580c" : result.behavioral_baseline.severity === "medium" ? "#d97706" : "#16a34a", fontWeight: 700, textTransform: "uppercase" }}>
                  {result.behavioral_baseline.severity || "normal"}
                </span>
                {result.behavioral_baseline.baseline_observations != null && (
                  <span style={{ color: "#64748b" }}>{result.behavioral_baseline.baseline_observations} obs · {result.behavioral_baseline.baseline_confidence} confidence</span>
                )}
              </div>
              {result.behavioral_baseline.top_deviations?.length > 0 && (
                <div style={{ display: "flex", flexDirection: "column", gap: 3 }}>
                  {result.behavioral_baseline.top_deviations.slice(0, 3).map((d, i) => (
                    <div key={i} style={{ display: "flex", justifyContent: "space-between", fontSize: 11 }}>
                      <span style={{ color: "#94a3b8", fontFamily: "monospace" }}>{d.feature}</span>
                      <span style={{ color: d.z_score >= 5 ? "#dc2626" : d.z_score >= 3 ? "#ea580c" : "#d97706", fontWeight: 600 }}>{d.z_score.toFixed(1)}σ {d.direction}</span>
                    </div>
                  ))}
                </div>
              )}
            </>
          )}
        </div>
      )}

      {/* Threat Intel section (Capability 4) */}
      {result.threat_intel && (() => {
        const ti = result.threat_intel;
        if (ti.status === "unavailable") return (
          <div style={{ background: "#1a1200", border: "1px solid #78350f40", borderRadius: 6, padding: "8px 12px", marginBottom: 10, fontSize: 11, color: "#92400e" }}>
            Threat intelligence check unavailable — sync may be in progress.
          </div>
        );
        if (ti.match_count === 0) return (
          <div style={{ background: "#0a1a0e", border: "1px solid #16a34a30", borderRadius: 6, padding: "8px 12px", marginBottom: 10, fontSize: 11, color: "#16a34a" }}>
            No matches in current threat intelligence database.
          </div>
        );
        const sevClr = ti.highest_severity === "critical" ? "#dc2626" : ti.highest_severity === "high" ? "#ea580c" : ti.highest_severity === "medium" ? "#d97706" : "#64748b";
        return (
          <div style={{ background: sevClr + "08", border: `1px solid ${sevClr}30`, borderRadius: 6, padding: "10px 12px", marginBottom: 10 }}>
            <div style={{ color: sevClr, fontWeight: 700, fontSize: 12, marginBottom: 6 }}>
              {ti.match_count} threat intelligence {ti.match_count === 1 ? "match" : "matches"} — {ti.highest_severity.toUpperCase()}
            </div>
            {(ti.matches || []).slice(0, 3).map((m, i) => (
              <div key={i} style={{ display: "flex", justifyContent: "space-between", fontSize: 11, marginBottom: 3 }}>
                <span style={{ color: "#94a3b8", fontFamily: "monospace", overflow: "hidden", textOverflow: "ellipsis", maxWidth: "55%" }}>{m.indicator}</span>
                <span style={{ color: "#64748b" }}>{m.indicator_type}</span>
                <span style={{ color: sevClr, fontWeight: 600 }}>{m.severity}</span>
              </div>
            ))}
          </div>
        );
      })()}

      {/* KEV Active Exploitation section (Capability 5) */}
      {result.kev_active_exploitation && (() => {
        const kev = result.kev_active_exploitation;
        if (kev.status === "unavailable") return (
          <div style={{ background: "#1a1200", border: "1px solid #78350f40", borderRadius: 6,
            padding: "8px 12px", marginBottom: 10, fontSize: 11, color: "#92400e" }}>
            KEV check unavailable — catalog may not be synced yet.
          </div>
        );
        if (kev.status === "no_kev_data") return (
          <div style={{ background: "#111827", border: "1px solid #37415140", borderRadius: 6,
            padding: "8px 12px", marginBottom: 10, fontSize: 11, color: "#6b7280" }}>
            KEV catalog empty — trigger a sync from the Active Exploitation panel.
          </div>
        );
        if (!kev.kev_hits_count) return (
          <div style={{ background: "#0a1a0e", border: "1px solid #16a34a30", borderRadius: 6,
            padding: "8px 12px", marginBottom: 10, fontSize: 11, color: "#16a34a" }}>
            No actively-exploited CVEs detected ({kev.host_total_cves ?? 0} CVEs checked against {kev.kev_catalog_size} KEV entries).
          </div>
        );
        const hits = kevExpanded ? kev.kev_hits : kev.kev_hits.slice(0, 3);
        return (
          <div style={{ background: "#1a0000", border: "1px solid #dc262640", borderRadius: 6,
            padding: "10px 12px", marginBottom: 10 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 6 }}>
              <AlertOctagon size={14} color="#dc2626" />
              <span style={{ color: "#dc2626", fontWeight: 700, fontSize: 12 }}>
                {kev.kev_hits_count} actively-exploited CVE{kev.kev_hits_count > 1 ? "s" : ""} detected
              </span>
              {kev.ransomware_associated_count > 0 && (
                <span style={{ display: "flex", alignItems: "center", gap: 3,
                  background: "#f9731620", border: "1px solid #f9731640",
                  borderRadius: 4, padding: "1px 6px", fontSize: 10, color: "#f97316", fontWeight: 700 }}>
                  <Skull size={10} /> {kev.ransomware_associated_count} ransomware
                </span>
              )}
            </div>
            {hits.map((h, i) => (
              <div key={i} style={{ display: "flex", alignItems: "baseline", gap: 8,
                fontSize: 11, marginBottom: 3 }}>
                <span style={{ fontFamily: "monospace", color: "#dc2626", flexShrink: 0 }}>{h.cve_id}</span>
                <span style={{ color: "#94a3b8", overflow: "hidden", textOverflow: "ellipsis",
                  whiteSpace: "nowrap", flex: 1 }}>
                  {h.vulnerability_name}
                </span>
                {h.known_ransomware_use === "Known" && (
                  <Skull size={10} color="#f97316" style={{ flexShrink: 0 }} />
                )}
              </div>
            ))}
            {kev.kev_hits.length > 3 && (
              <button onClick={() => setKevExpanded(x => !x)}
                style={{ background: "none", border: "none", color: "#94a3b8",
                  fontSize: 11, cursor: "pointer", padding: "2px 0", marginTop: 4 }}>
                {kevExpanded ? "Show less" : `Show all ${kev.kev_hits.length} hits`}
              </button>
            )}
          </div>
        );
      })()}

      {/* MITRE ATT&CK mapping section (Capability 6) */}
      {result.mitre_techniques && (() => {
        const mt = result.mitre_techniques;
        const CONF_COLOR = { high: "#dc2626", medium: "#d97706", low: "#6b7280" };
        if (mt.status === "unavailable") return (
          <div style={{ background: "#1a1200", border: "1px solid #78350f40", borderRadius: 6,
            padding: "8px 12px", marginBottom: 10, fontSize: 11, color: "#92400e" }}>
            MITRE ATT&CK mapping unavailable.
          </div>
        );
        if (!mt.technique_count) return (
          <div style={{ background: "#0a1a0e", border: "1px solid #16a34a30", borderRadius: 6,
            padding: "8px 12px", marginBottom: 10, fontSize: 11, color: "#16a34a" }}>
            No specific MITRE ATT&CK techniques mapped for this detection.
          </div>
        );
        return (
          <div style={{ background: "#100014", border: "1px solid #7c3aed30", borderRadius: 6,
            padding: "10px 12px", marginBottom: 10 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 6 }}>
              <Crosshair size={13} color="#a78bfa" />
              <span style={{ color: "#a78bfa", fontWeight: 700, fontSize: 11 }}>
                MITRE ATT&CK — {mt.technique_count} technique{mt.technique_count > 1 ? "s" : ""}
              </span>
            </div>
            {mt.tactics_covered?.length > 0 && (
              <div style={{ display: "flex", flexWrap: "wrap", gap: 4, marginBottom: 8 }}>
                {mt.tactics_covered.map(tac => (
                  <span key={tac} style={{ fontSize: 9, padding: "1px 6px", borderRadius: 100,
                    background: "#7c3aed20", border: "1px solid #7c3aed40",
                    color: "#a78bfa", fontWeight: 600 }}>
                    {tac}
                  </span>
                ))}
              </div>
            )}
            <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
              {(mt.techniques || []).slice(0, 8).map((t, i) => (
                <span key={i} style={{ fontSize: 10, padding: "2px 7px", borderRadius: 4,
                  background: (CONF_COLOR[t.confidence] ?? "#6b7280") + "15",
                  border: `1px solid ${(CONF_COLOR[t.confidence] ?? "#6b7280")}40`,
                  color: CONF_COLOR[t.confidence] ?? "#6b7280",
                  fontFamily: "JetBrains Mono, monospace", fontWeight: 700,
                  title: t.name }}>
                  {t.technique_id}
                </span>
              ))}
            </div>
          </div>
        );
      })()}

      {/* Device Risk Score section (Capability 9) */}
      {result.device_risk_score && (() => {
        const drs = result.device_risk_score;
        if (drs.status === "unavailable") return (
          <div style={{ background: "#111827", border: "1px solid #37415140", borderRadius: 6,
            padding: "8px 12px", marginBottom: 10, fontSize: 11, color: "#6b7280" }}>
            Device risk score unavailable — recompute may be in progress.
          </div>
        );
        if (drs.status === "no_recent_events") return (
          <div style={{ background: "#0a1a0e", border: "1px solid #16a34a30", borderRadius: 6,
            padding: "8px 12px", marginBottom: 10, fontSize: 11, color: "#16a34a" }}>
            No events in last 24h for this device — risk score is 0.
          </div>
        );
        const score = drs.score ?? 0;
        const scoreClr = score >= 76 ? "#ff4444" : score >= 51 ? "#ff8c00" : score >= 26 ? "#f5c518" : "#00ff88";
        return (
          <div style={{ background: scoreClr + "08", border: `1px solid ${scoreClr}30`,
            borderRadius: 6, padding: "10px 12px", marginBottom: 10 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
              <Gauge size={13} color={scoreClr} />
              <span style={{ color: scoreClr, fontWeight: 700, fontSize: 12 }}>
                Device Risk Score
              </span>
              <span style={{ marginLeft: "auto", color: scoreClr, fontWeight: 800, fontSize: 20 }}>
                {score}
              </span>
              <span style={{ color: "#7d8590", fontSize: 10 }}>/100</span>
            </div>
            <div style={{ fontSize: 11, color: "#7d8590", marginBottom: 6 }}>
              Based on {drs.event_count_24h ?? 0} events in last 24h
              {(drs.contributing_modules?.length ?? 0) > 0 &&
                ` from ${drs.contributing_modules.length} module${drs.contributing_modules.length > 1 ? "s" : ""}`}
            </div>
            {(drs.top_contributors?.length ?? 0) > 0 && (
              <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                {drs.top_contributors.slice(0, 3).map((tc, i) => (
                  <span key={i} style={{ fontSize: 10, padding: "1px 7px", borderRadius: 100,
                    background: "#21262d", border: "1px solid #374151",
                    color: "#94a3b8", fontWeight: 600 }}>
                    {tc.source_module} +{tc.contribution}
                  </span>
                ))}
              </div>
            )}
          </div>
        );
      })()}

      {result.detection_id && (
        <button onClick={() => onExplain(result.detection_id)}
          style={{ background: "transparent", border: `1px solid ${C.border}`, borderRadius: 6, color: "#93c5fd", fontSize: 12, padding: "5px 12px", cursor: "pointer" }}>
          View Full Explanation (all 12 features)
        </button>
      )}
    </div>
  );
}
