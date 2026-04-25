import React, { useState, useEffect, useCallback } from "react";
import { TrendingUp, RefreshCw } from "lucide-react";
import ForecastTopBar      from "./ForecastTopBar";
import ForecastTable       from "./ForecastTable";
import ForecastDetailModal from "./ForecastDetailModal";
import ForecastAlertsList  from "./ForecastAlertsList";
import { fetchForecasts, fetchAlerts, fetchStats, triggerRecompute } from "./api/forecastApi";

const C = { text: "#e6edf3", muted: "#7d8590", card: "#0d1117", border: "#21262d" };

export default function RiskForecastPanel({ token }) {
  const [forecasts, setForecasts] = useState([]);
  const [alerts,    setAlerts]    = useState([]);
  const [stats,     setStats]     = useState(null);
  const [selected,  setSelected]  = useState(null);
  const [loading,   setLoading]   = useState(true);
  const [recomp,    setRecomp]    = useState(false);
  const [error,     setError]     = useState(null);
  const [tab,       setTab]       = useState("forecasts");

  const load = useCallback(async () => {
    if (!token) return;
    setLoading(true); setError(null);
    try {
      const [f, a, s] = await Promise.all([
        fetchForecasts(token), fetchAlerts(token, "active"), fetchStats(token),
      ]);
      setForecasts(f.forecasts ?? []);
      setAlerts(a.alerts ?? []);
      setStats(s);
    } catch { setError("Failed to load forecast data."); }
    finally  { setLoading(false); }
  }, [token]);

  useEffect(() => { load(); }, [load]);

  const handleRecompute = async () => {
    setRecomp(true);
    try { await triggerRecompute(token); setTimeout(load, 10000); } catch (_) {}
    finally { setRecomp(false); }
  };

  return (
    <div style={{ padding: 24, maxWidth: 1100, margin: "0 auto" }}>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 20 }}>
        <TrendingUp size={22} color="#00d4ff" />
        <span style={{ color: C.text, fontWeight: 700, fontSize: 18 }}>Risk Forecast</span>
        <span style={{ color: C.muted, fontSize: 12, marginLeft: 6 }}>
          ARIMA(1,1,1) · 7-day horizon · 8h decay-weighted history
        </span>
        <div style={{ marginLeft: "auto", display: "flex", gap: 8 }}>
          <button onClick={load} style={{ background: "transparent", border: `1px solid ${C.border}`,
            borderRadius: 6, color: C.muted, fontSize: 11, padding: "5px 10px", cursor: "pointer" }}>
            Refresh
          </button>
          <button onClick={handleRecompute} disabled={recomp}
            style={{ background: "transparent", border: "1px solid #00d4ff40",
              borderRadius: 6, color: "#00d4ff", fontSize: 11, padding: "5px 10px",
              cursor: "pointer", display: "flex", alignItems: "center", gap: 5 }}>
            <RefreshCw size={12} style={recomp ? { animation: "spin 1s linear infinite" } : {}} />
            {recomp ? "Queuing…" : "Recompute"}
          </button>
        </div>
      </div>

      <ForecastTopBar stats={stats} />

      {error && (
        <div style={{ background: "#1a0000", border: "1px solid #ff444440",
          borderRadius: 6, padding: "10px 14px", marginBottom: 14, color: "#ff8888", fontSize: 12 }}>
          {error}
        </div>
      )}

      {/* Tabs */}
      <div style={{ display: "flex", gap: 0, marginBottom: 16, borderBottom: `1px solid ${C.border}` }}>
        {["forecasts", "alerts"].map(t => (
          <button key={t} onClick={() => setTab(t)}
            style={{ background: "none", border: "none", cursor: "pointer",
              color: tab === t ? "#00d4ff" : C.muted,
              borderBottom: tab === t ? "2px solid #00d4ff" : "2px solid transparent",
              padding: "8px 16px", fontSize: 12, fontWeight: 600, textTransform: "capitalize" }}>
            {t} {t === "alerts" && alerts.length > 0 && (
              <span style={{ background: "#ff4444", color: "#fff", borderRadius: 100,
                padding: "1px 6px", fontSize: 10, marginLeft: 4 }}>{alerts.length}</span>
            )}
          </button>
        ))}
      </div>

      <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 8, padding: 16 }}>
        {loading ? (
          <div style={{ color: C.muted, textAlign: "center", padding: 32, fontSize: 13 }}>
            Loading forecasts…
          </div>
        ) : tab === "forecasts" ? (
          <ForecastTable forecasts={forecasts} onSelect={setSelected} />
        ) : (
          <ForecastAlertsList alerts={alerts} token={token} onRefresh={load} />
        )}
      </div>

      {selected && <ForecastDetailModal forecast={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}
