import React, { useState, useEffect, useCallback } from "react";
import { RefreshCw, Gauge } from "lucide-react";
import RiskTopBar       from "./RiskTopBar";
import RiskScoreTable   from "./RiskScoreTable";
import RiskBreakdownModal from "./RiskBreakdownModal";
import { fetchScores, fetchTop, fetchStats, triggerRecompute } from "./api/riskApi";

const C = { text: "#e6edf3", muted: "#7d8590", card: "#0d1117",
  border: "#21262d", dark: "#080c10" };

export default function RiskScoreDashboard({ token }) {
  const [scores,   setScores]   = useState([]);
  const [top,      setTop]      = useState([]);
  const [stats,    setStats]    = useState(null);
  const [selected, setSelected] = useState(null);
  const [loading,  setLoading]  = useState(true);
  const [recomputing, setRecomputing] = useState(false);
  const [minScore, setMinScore] = useState(0);
  const [error,    setError]    = useState(null);

  const load = useCallback(async () => {
    if (!token) return;
    setLoading(true);
    setError(null);
    try {
      const [s, t, st] = await Promise.all([
        fetchScores(token, { limit: 100, minScore }),
        fetchTop(token, 5),
        fetchStats(token),
      ]);
      setScores(s.scores ?? []);
      setTop(t.top ?? []);
      setStats(st);
    } catch (err) {
      setError("Failed to load risk scores. Is the backend running?");
    } finally {
      setLoading(false);
    }
  }, [token, minScore]);

  useEffect(() => { load(); }, [load]);

  const handleRecompute = async () => {
    setRecomputing(true);
    try {
      await triggerRecompute(token);
      setTimeout(load, 8000);
    } catch (_) {}
    finally { setRecomputing(false); }
  };

  return (
    <div style={{ padding: 24, maxWidth: 1100, margin: "0 auto" }}>
      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 20 }}>
        <Gauge size={22} color="#00d4ff" />
        <span style={{ color: C.text, fontWeight: 700, fontSize: 18 }}>
          Device Risk Score Dashboard
        </span>
        <span style={{ color: C.muted, fontSize: 12, marginLeft: 6 }}>
          Unified real-time risk · 8h half-life decay
        </span>
        <div style={{ marginLeft: "auto", display: "flex", gap: 8, alignItems: "center" }}>
          <select
            value={minScore}
            onChange={(e) => setMinScore(Number(e.target.value))}
            style={{ background: C.card, border: `1px solid ${C.border}`, color: C.muted,
              borderRadius: 6, padding: "4px 8px", fontSize: 11 }}>
            <option value={0}>All scores</option>
            <option value={26}>Score ≥ 26</option>
            <option value={51}>Score ≥ 51</option>
            <option value={76}>Score ≥ 76</option>
          </select>
          <button
            onClick={handleRecompute}
            disabled={recomputing}
            style={{ background: "transparent", border: `1px solid ${C.border}`,
              borderRadius: 6, color: "#00d4ff", fontSize: 11, padding: "5px 10px",
              cursor: "pointer", display: "flex", alignItems: "center", gap: 5 }}>
            <RefreshCw size={12} style={recomputing ? { animation: "spin 1s linear infinite" } : {}} />
            {recomputing ? "Queuing…" : "Recompute now"}
          </button>
        </div>
      </div>

      {/* Headline metrics */}
      <RiskTopBar stats={stats} top={top} />

      {/* Error */}
      {error && (
        <div style={{ background: "#1a0000", border: "1px solid #ff444440",
          borderRadius: 6, padding: "10px 14px", marginBottom: 14, color: "#ff8888", fontSize: 12 }}>
          {error}
        </div>
      )}

      {/* Score table */}
      <div style={{ background: C.card, border: `1px solid ${C.border}`,
        borderRadius: 8, padding: 16 }}>
        {loading ? (
          <div style={{ color: C.muted, textAlign: "center", padding: 32, fontSize: 13 }}>
            Loading risk scores…
          </div>
        ) : (
          <RiskScoreTable rows={scores} onSelect={setSelected} />
        )}
      </div>

      {/* Breakdown modal */}
      {selected && <RiskBreakdownModal row={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}
