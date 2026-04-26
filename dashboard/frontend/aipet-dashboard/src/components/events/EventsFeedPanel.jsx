/**
 * EventsFeedPanel — Capability 7a central event pipeline panel.
 * Shows the unified security event feed across all wired modules.
 */
import React, { useState, useEffect, useCallback } from "react";
import { Activity } from "lucide-react";
import EventDetailModal from "./EventDetailModal";
import { getEventFeed, getEventStats } from "./api/eventsApi";

const C  = { border: "#21262d", text: "#e6edf3", muted: "#7d8590", card: "#0d1117" };
const SC = { critical:"#dc2626", high:"#ea580c", medium:"#d97706", low:"#16a34a", info:"#6b7280" };
const MODULE_LABEL = {
  ml_anomaly: "ML Anomaly",  behavioral: "Behavioural AI",
  threatintel: "Threat Intel", live_cves: "CISA KEV",
  mitre_attack: "MITRE ATT&CK",
};

function StatPill({ label, value, color }) {
  return (
    <div style={{ background: C.card, border: `1px solid ${color}25`, borderRadius: 8,
      padding: "12px 16px", minWidth: 100 }}>
      <div style={{ fontSize: 22, fontWeight: 800, color, fontFamily: "JetBrains Mono, monospace",
        lineHeight: 1, textShadow: `0 0 16px ${color}60` }}>{value ?? "—"}</div>
      <div style={{ fontSize: 10, color: C.muted, marginTop: 5,
        textTransform: "uppercase", letterSpacing: "0.5px" }}>{label}</div>
    </div>
  );
}

function SevBadge({ sev }) {
  const c = SC[sev] ?? SC.info;
  return (
    <span style={{ fontSize: 9, padding: "1px 6px", borderRadius: 100,
      background: c + "20", border: `1px solid ${c}40`, color: c,
      fontWeight: 700, textTransform: "uppercase", flexShrink: 0 }}>
      {sev}
    </span>
  );
}

export default function EventsFeedPanel({ token }) {
  const [events,   setEvents]   = useState([]);
  const [stats,    setStats]    = useState(null);
  const [loading,  setLoading]  = useState(true);
  const [error,    setError]    = useState("");
  const [selected, setSelected] = useState(null);
  const [filters,  setFilters]  = useState({ days: "7", severity: "", source_module: "" });
  const [mobile,   setMobile]   = useState(() => window.innerWidth < 768);

  React.useEffect(() => {
    const fn = () => setMobile(window.innerWidth < 768);
    window.addEventListener("resize", fn);
    return () => window.removeEventListener("resize", fn);
  }, []);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const params = {};
      if (filters.days)          params.days = filters.days;
      if (filters.severity)      params.severity = filters.severity;
      if (filters.source_module) params.source_module = filters.source_module;
      const [feedRes, statsRes] = await Promise.all([
        getEventFeed(token, params),
        getEventStats(token, filters.days || 7),
      ]);
      setEvents(feedRes.events ?? []);
      setStats(statsRes);
      setError("");
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, [token, filters]);

  useEffect(() => { load(); }, [load]);

  const totalBySev = (sev) => stats?.by_severity?.find(b => b.severity === sev)?.count ?? 0;

  return (
    <div style={{ maxWidth: 960, width: "100%" }}>
      <div style={{ marginBottom: 20 }}>
        <h2 style={{ margin: "0 0 4px", fontSize: 20, fontWeight: 800, color: C.text }}>
          Security Event Feed
        </h2>
        <div style={{ fontSize: 12, color: C.muted }}>
          Central pipeline — ML Anomaly · Behavioural AI · Threat Intel · CISA KEV · MITRE ATT&CK
        </div>
      </div>

      {stats && (
        <div style={{ display: "flex", gap: 12, marginBottom: 20, flexWrap: "wrap" }}>
          <StatPill label="Total Events"  value={stats.total}            color="#00e5ff" />
          <StatPill label="Critical"      value={totalBySev("critical")} color="#dc2626" />
          <StatPill label="High"          value={totalBySev("high")}     color="#ea580c" />
          <StatPill label="Medium"        value={totalBySev("medium")}   color="#d97706" />
        </div>
      )}

      {/* Filters — horizontal scroll on mobile */}
      <div style={{ display: "flex", gap: 10, marginBottom: 16,
        flexWrap: mobile ? "nowrap" : "wrap",
        overflowX: mobile ? "auto" : "visible",
        paddingBottom: mobile ? 4 : 0 }}>
        {[
          { key: "days", label: "Days", opts: [["1","1d"],["7","7d"],["30","30d"]] },
          { key: "severity", label: "Severity",
            opts: [["","All"],["critical","Critical"],["high","High"],["medium","Medium"],["low","Low"],["info","Info"]] },
          { key: "source_module", label: "Module",
            opts: [["","All"],["ml_anomaly","ML Anomaly"],["behavioral","Behavioural"],
                   ["threatintel","Threat Intel"],["live_cves","KEV"],["mitre_attack","MITRE"]] },
        ].map(({ key, label, opts }) => (
          <div key={key}>
            <div style={{ fontSize: 10, color: C.muted, marginBottom: 3,
              textTransform: "uppercase", letterSpacing: "0.05em" }}>{label}</div>
            <select value={filters[key]}
              onChange={e => setFilters(f => ({ ...f, [key]: e.target.value }))}
              style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 6,
                color: C.text, fontSize: 12, padding: "5px 10px", cursor: "pointer" }}>
              {opts.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
            </select>
          </div>
        ))}
        <div style={{ alignSelf: "flex-end" }}>
          <button onClick={load}
            style={{ padding: "6px 14px", borderRadius: 6, border: "none",
              cursor: "pointer", fontSize: 12, fontWeight: 700,
              background: "linear-gradient(135deg,#00e5ff,#0ea5e9)", color: "#000" }}>
            Refresh
          </button>
        </div>
      </div>

      {loading && (
        <div style={{ color: C.muted, padding: 32, textAlign: "center" }}>
          Loading events…
        </div>
      )}

      {error && !loading && (
        <div style={{ color: "#f87171", background: "#450a0a", border: "1px solid #7f1d1d",
          borderRadius: 6, padding: 14, fontSize: 13 }}>
          {error}
        </div>
      )}

      {!loading && !error && events.length === 0 && (
        <div style={{ color: C.muted, fontSize: 13, padding: "24px 0", textAlign: "center" }}>
          No events in this time window. Run a scan or trigger a detection to populate the feed.
        </div>
      )}

      {!loading && events.length > 0 && (
        <div style={{ border: `1px solid ${C.border}`, borderRadius: 8, overflow: "hidden" }}>
          {events.map((ev, i) => (
            <div key={ev.id}
              onClick={() => setSelected(ev)}
              style={{ display: "flex", alignItems: "flex-start", gap: 12,
                padding: "11px 14px", borderBottom: i < events.length - 1 ? `1px solid ${C.border}20` : "none",
                cursor: "pointer", background: i % 2 === 0 ? C.card : "#080f1a",
                transition: "background 0.15s" }}>
              <div style={{ paddingTop: 2, flexShrink: 0 }}>
                <Activity size={13} color={SC[ev.severity] ?? SC.info} />
              </div>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 3 }}>
                  <SevBadge sev={ev.severity} />
                  <span style={{ fontSize: 11, color: C.muted }}>
                    {MODULE_LABEL[ev.source_module] ?? ev.source_module}
                  </span>
                  {ev.entity && (
                    <span style={{ fontSize: 11, color: "#00e5ff",
                      fontFamily: "JetBrains Mono, monospace" }}>
                      {ev.entity}
                    </span>
                  )}
                </div>
                <div style={{ fontSize: 13, color: C.text, overflow: "hidden",
                  textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {ev.title || ev.event_type}
                </div>
              </div>
              <div style={{ fontSize: 10, color: C.muted, flexShrink: 0, paddingTop: 4 }}>
                {ev.created_at ? new Date(ev.created_at).toLocaleTimeString() : ""}
              </div>
            </div>
          ))}
        </div>
      )}

      {selected && (
        <EventDetailModal event={selected} onClose={() => setSelected(null)} />
      )}
    </div>
  );
}
