import React, { useState, useEffect, useCallback } from "react";
import { Zap, RefreshCw } from "lucide-react";
import StatsBar                  from "./StatsBar";
import ThresholdsCard            from "./ThresholdsCard";
import ResponseHistoryTable      from "./ResponseHistoryTable";
import ResponseHistoryDetailModal from "./ResponseHistoryDetailModal";
import { fetchThresholds, fetchHistory, fetchStats, triggerCheck } from "./api/automatedResponseApi";

const C = { text: "#e6edf3", muted: "#7d8590", card: "#0d1117", border: "#21262d" };

export default function AutomatedResponsePanel({ token }) {
  const [thresholds, setThresholds] = useState([]);
  const [history,    setHistory]    = useState([]);
  const [stats,      setStats]      = useState(null);
  const [selected,   setSelected]   = useState(null);
  const [loading,    setLoading]    = useState(true);
  const [checking,   setChecking]   = useState(false);
  const [error,      setError]      = useState(null);
  const [mobile,     setMobile]     = useState(() => window.innerWidth < 768);

  React.useEffect(() => {
    const fn = () => setMobile(window.innerWidth < 768);
    window.addEventListener("resize", fn);
    return () => window.removeEventListener("resize", fn);
  }, []);

  const load = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    setError(null);
    try {
      const [t, h, s] = await Promise.all([
        fetchThresholds(token),
        fetchHistory(token, { limit: 50 }),
        fetchStats(token),
      ]);
      setThresholds(t.thresholds ?? []);
      setHistory(h.history ?? []);
      setStats(s);
    } catch {
      setError("Failed to load. Is the backend running?");
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => { load(); }, [load]);

  const handleCheckNow = async () => {
    setChecking(true);
    try { await triggerCheck(token); setTimeout(load, 10000); } catch (_) {}
    finally { setChecking(false); }
  };

  return (
    <div style={{ padding: "clamp(12px, 3vw, 24px)", maxWidth: 1100, margin: "0 auto" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 20,
        flexWrap: "wrap" }}>
        <Zap size={22} color="#f5c518" />
        <span style={{ color: C.text, fontWeight: 700, fontSize: 18 }}>
          Automated Response
        </span>
        <span style={{ color: C.muted, fontSize: 12, marginLeft: 6 }}>
          Risk threshold monitoring · Per-entity 4h cooldown
        </span>
        <div style={{ marginLeft: "auto", display: "flex", gap: 8 }}>
          <button onClick={load} disabled={loading}
            style={{ background: "transparent", border: `1px solid ${C.border}`,
              borderRadius: 6, color: C.muted, fontSize: 11, padding: "5px 10px", cursor: "pointer" }}>
            Refresh
          </button>
          <button onClick={handleCheckNow} disabled={checking}
            style={{ background: "transparent", border: "1px solid #f5c51840",
              borderRadius: 6, color: "#f5c518", fontSize: 11, padding: "5px 10px",
              cursor: "pointer", display: "flex", alignItems: "center", gap: 5 }}>
            <RefreshCw size={12} style={checking ? { animation: "spin 1s linear infinite" } : {}} />
            {checking ? "Queuing…" : "Check now"}
          </button>
        </div>
      </div>

      <StatsBar stats={stats} />

      {error && (
        <div style={{ background: "#1a0000", border: "1px solid #ff444440",
          borderRadius: 6, padding: "10px 14px", marginBottom: 14, color: "#ff8888", fontSize: 12 }}>
          {error}
        </div>
      )}

      {!loading && <ThresholdsCard thresholds={thresholds} token={token} onRefresh={load} />}

      <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 8, padding: 16 }}>
        <div style={{ color: C.muted, fontSize: 11, fontWeight: 600,
          textTransform: "uppercase", marginBottom: 12 }}>Response History</div>
        {loading ? (
          <div style={{ color: C.muted, textAlign: "center", padding: 24, fontSize: 13 }}>
            Loading…
          </div>
        ) : (
          <ResponseHistoryTable rows={history} onSelect={setSelected} />
        )}
      </div>

      {selected && <ResponseHistoryDetailModal row={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}
