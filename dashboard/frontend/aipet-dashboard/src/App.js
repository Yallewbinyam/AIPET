
import { useState, useEffect, useCallback } from "react";
import axios from "axios";
import {
  PieChart, Pie, Cell, Tooltip, ResponsiveContainer,
  BarChart, Bar, XAxis, YAxis, CartesianGrid
} from "recharts";
import {
  Shield, Server, AlertTriangle, CheckCircle,
  Activity, Download, Play, RefreshCw,
  ChevronDown, ChevronUp, Cpu, Lock,
  Wifi, Globe, FileText, Zap, Eye,
  TrendingUp, AlertOctagon, Info, CreditCard,
  Star, Check, X
} from "lucide-react";

const API      = "http://localhost:5001/api";
const AUTH_API = "http://localhost:5001/api/auth";
const PAY_API  = "http://localhost:5001/payments";

// Axios interceptor — automatically logs out user if token expires.
// This runs globally on every API response. If we get a 401 (Unauthorized),
// it means the token has expired. We clear localStorage and reload the page
// which sends the user back to the login screen.
axios.interceptors.response.use(
  response => response,
  error => {
    if (error.response?.status === 401) {
      localStorage.removeItem("aipet_token");
      window.location.reload();
    }
    return Promise.reject(error);
  }
);

const COLORS = {
  critical: "#ef4444",
  high:     "#f97316",
  medium:   "#eab308",
  low:      "#22c55e",
  info:     "#6b7280",
  blue:     "#3b82f6",
  purple:   "#8b5cf6",
  dark:     "#0f172a",
  darker:   "#020617",
  card:     "#1e293b",
  border:   "#334155",
  text:     "#f1f5f9",
  muted:    "#94a3b8",
};

const SEVERITY_CONFIG = {
  CRITICAL: { color: COLORS.critical, bg: "bg-red-500/10",    border: "border-red-500/30",    icon: AlertOctagon, label: "CRITICAL" },
  HIGH:     { color: COLORS.high,     bg: "bg-orange-500/10", border: "border-orange-500/30", icon: AlertTriangle, label: "HIGH"     },
  MEDIUM:   { color: COLORS.medium,   bg: "bg-yellow-500/10", border: "border-yellow-500/30", icon: Zap,          label: "MEDIUM"   },
  LOW:      { color: COLORS.low,      bg: "bg-green-500/10",  border: "border-green-500/30",  icon: Info,         label: "LOW"      },
  INFO:     { color: COLORS.info,     bg: "bg-gray-500/10",   border: "border-gray-500/30",   icon: Info,         label: "INFO"     },
};

function SeverityBadge({ severity }) {
  const cfg = SEVERITY_CONFIG[severity] || SEVERITY_CONFIG.INFO;
  const Icon = cfg.icon;
  return (
    <span className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-xs font-bold border ${cfg.bg} ${cfg.border}`}
      style={{ color: cfg.color }}>
      <Icon size={10} />
      {severity}
    </span>
  );
}

function AnimatedNumber({ value, duration = 1000 }) {
  const [display, setDisplay] = useState(0);
  useEffect(() => {
    let start = 0;
    const step = value / (duration / 16);
    const timer = setInterval(() => {
      start += step;
      if (start >= value) { setDisplay(value); clearInterval(timer); }
      else setDisplay(Math.floor(start));
    }, 16);
    return () => clearInterval(timer);
  }, [value, duration]);
  return <span>{display}</span>;
}

function RiskGauge({ risk, color, score }) {
  const [animated, setAnimated] = useState(0);
  useEffect(() => {
    setTimeout(() => setAnimated(score), 300);
  }, [score]);
  const circumference = 2 * Math.PI * 54;
  const offset = circumference - (animated / 100) * circumference;
  return (
    <div className="flex flex-col items-center justify-center p-8">
      <div className="relative w-48 h-48">
        <svg className="w-full h-full transform -rotate-90" viewBox="0 0 120 120">
          <circle cx="60" cy="60" r="54" fill="none" stroke="#1e293b" strokeWidth="12"/>
          <circle cx="60" cy="60" r="54" fill="none" stroke={color} strokeWidth="12"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            strokeLinecap="round"
            style={{ transition: "stroke-dashoffset 1.5s ease-in-out" }}/>
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-5xl font-black" style={{ color }}>{animated}</span>
          <span className="text-xs font-medium" style={{ color: COLORS.muted }}>RISK SCORE</span>
        </div>
      </div>
      <div className="mt-4 text-center">
        <div className="text-2xl font-black tracking-wider" style={{ color }}>{risk}</div>
        <div className="text-sm mt-1" style={{ color: COLORS.muted }}>Overall Risk Level</div>
      </div>
    </div>
  );
}

function StatCard({ title, value, icon: Icon, color, subtitle }) {
  return (
    <div className="rounded-2xl p-6 border"
      style={{ backgroundColor: COLORS.card, borderColor: COLORS.border }}>
      <div className="flex items-start justify-between mb-4">
        <div className="p-3 rounded-xl" style={{ backgroundColor: color + "20" }}>
          <Icon size={22} style={{ color }} />
        </div>
        <TrendingUp size={14} style={{ color: COLORS.muted }} />
      </div>
      <div className="text-4xl font-black mb-1" style={{ color: COLORS.text }}>
        <AnimatedNumber value={typeof value === "number" ? value : 0} />
        {typeof value === "string" && value}
      </div>
      <div className="text-sm font-medium" style={{ color: COLORS.muted }}>{title}</div>
      {subtitle && <div className="text-xs mt-1" style={{ color: COLORS.muted }}>{subtitle}</div>}
    </div>
  );
}

function FixPanel({ finding, token, onClose, onStatusUpdate }) {
  const [remediation, setRemediation]       = useState(null);
  const [loading, setLoading]               = useState(true);
  const [status, setStatus]                 = useState(finding.fix_status || "open");
  const [notes, setNotes]                   = useState(finding.fix_notes || "");
  const [saving, setSaving]                 = useState(false);
  const [copied, setCopied]                 = useState(false);
  const [activeTab, setActiveTab]           = useState("fix");
  const [explanation, setExplanation]       = useState(null);
  const [explainLoading, setExplainLoading] = useState(false);
  const [explainError, setExplainError]     = useState(null);
  const cfg = SEVERITY_CONFIG[finding.severity] || SEVERITY_CONFIG.INFO;

  useEffect(() => {
    const fetchRemediation = async () => {
      try {
        const res = await axios.get(`${API}/remediation/${finding.id}`, {
          headers: { Authorization: `Bearer ${token}` }
        });
        setRemediation(res.data.remediation);
      } catch (err) {
        console.error("Failed to fetch remediation:", err);
      } finally {
        setLoading(false);
      }
    };
    fetchRemediation();
  }, [finding.id, token]);

  const handleCopy = () => {
    if (remediation?.fix_commands) {
      navigator.clipboard.writeText(remediation.fix_commands);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };
  const fetchExplanation = async () => {
    if (explanation) return; // already loaded
    setExplainLoading(true);
    setExplainError(null);
    try {
      const res = await axios.get(`${API}/explain/finding/${finding.id}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setExplanation(res.data.content);
    } catch (err) {
      if (err.response?.status === 403 && err.response?.data?.upgrade) {
        setExplainError("upgrade");
      } else {
        setExplainError("Failed to load explanation. Please try again.");
      }
    } finally {
      setExplainLoading(false);
    }
  };

  const handleStatusUpdate = async (newStatus) => {
    setSaving(true);
    try {
      await axios.patch(`${API}/findings/${finding.id}/status`, {
        fix_status: newStatus,
        fix_notes: notes
      }, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setStatus(newStatus);
      if (onStatusUpdate) onStatusUpdate(finding.id, newStatus);
    } catch (err) {
      console.error("Failed to update status:", err);
    } finally {
      setSaving(false);
    }
  };

  const STATUS_CONFIG = {
    open:          { label: "Open",          color: COLORS.critical },
    in_progress:   { label: "In Progress",   color: COLORS.high     },
    fixed:         { label: "Fixed",         color: COLORS.low      },
    accepted_risk: { label: "Accepted Risk", color: COLORS.muted    },
  };

  const difficultyColor = {
    "Quick Win": COLORS.low,
    "Moderate":  COLORS.high,
    "Complex":   COLORS.critical,
  };

  return (
    <div className="fixed inset-0 z-50 flex justify-end"
      style={{ backgroundColor: "rgba(0,0,0,0.6)", backdropFilter: "blur(4px)" }}>
      <div className="w-full max-w-lg h-full overflow-y-auto flex flex-col"
        style={{ backgroundColor: COLORS.dark, borderLeft: `1px solid ${COLORS.border}` }}>

        {/* Header */}
        <div className="sticky top-0 z-10 p-6 border-b flex items-start justify-between"
          style={{ backgroundColor: COLORS.dark, borderColor: COLORS.border }}>
          <div>
            <div className="flex items-center gap-2 mb-1">
              <div className="w-2 h-2 rounded-full" style={{ backgroundColor: cfg.color }} />
              <span className="text-xs font-bold uppercase tracking-wider" style={{ color: cfg.color }}>
                {finding.severity}
              </span>
            </div>
            <h2 className="text-lg font-black" style={{ color: COLORS.text }}>
              {finding.attack}
            </h2>
            <p className="text-xs mt-1" style={{ color: COLORS.muted }}>
              {finding.module} — {finding.target}
            </p>
          </div>
          <button onClick={onClose}
            className="p-2 rounded-lg hover:bg-white/10 transition-colors"
            style={{ color: COLORS.muted }}>
            ✕
          </button>
        </div>

        {/* Body */}
        {/* Tabs */}
        <div className="flex border-b" style={{ borderColor: COLORS.border }}>
          <button
            onClick={() => setActiveTab("fix")}
            className="px-6 py-3 text-xs font-bold transition-all"
            style={{
              color: activeTab === "fix" ? COLORS.blue : COLORS.muted,
              borderBottom: activeTab === "fix" ? `2px solid ${COLORS.blue}` : "2px solid transparent"
            }}>
            Fix Guide
          </button>
          <button
            onClick={() => { setActiveTab("explain"); fetchExplanation(); }}
            className="px-6 py-3 text-xs font-bold transition-all"
            style={{
              color: activeTab === "explain" ? COLORS.blue : COLORS.muted,
              borderBottom: activeTab === "explain" ? `2px solid ${COLORS.blue}` : "2px solid transparent"
            }}>
            AI Explanation
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 p-6 space-y-6">

          {activeTab === "explain" ? (
            <div className="space-y-4">
              {explainLoading ? (
                <div className="text-center py-12" style={{ color: COLORS.muted }}>
                  <div className="text-2xl mb-3">🤖</div>
                  <div className="text-sm">Claude is generating your explanation...</div>
                  <div className="text-xs mt-1" style={{ color: COLORS.muted }}>This takes 2-3 seconds</div>
                </div>
              ) : explainError === "upgrade" ? (
                <div className="rounded-xl p-6 border text-center"
                  style={{ backgroundColor: COLORS.card, borderColor: COLORS.border }}>
                  <div className="text-2xl mb-3">⭐</div>
                  <div className="text-sm font-bold mb-2" style={{ color: COLORS.text }}>
                    Professional Feature
                  </div>
                  <div className="text-xs mb-4" style={{ color: COLORS.muted }}>
                    AI Explanations are available on Professional and Enterprise plans.
                  </div>
                  <div className="text-xs px-4 py-2 rounded-lg inline-block"
                    style={{ backgroundColor: COLORS.blue + "20", color: COLORS.blue }}>
                    Upgrade to unlock
                  </div>
                </div>
              ) : explainError ? (
                <div className="text-center py-12">
                  <div className="text-sm" style={{ color: COLORS.critical }}>{explainError}</div>
                </div>
              ) : explanation ? (
                <div className="space-y-4">
                  {explanation.split("\n\n").map((section, i) => {
                    const lines    = section.split("\n");
                    const heading  = lines[0];
                    const body     = lines.slice(1).join("\n");
                    const isHeading = heading && !heading.includes(" ") === false &&
                      (heading.startsWith("WHY") || heading.startsWith("WHAT"));
                    return (
                      <div key={i} className="rounded-xl p-4 border"
                        style={{ backgroundColor: COLORS.card, borderColor: COLORS.border }}>
                        {isHeading && (
                          <div className="text-xs font-bold uppercase tracking-wider mb-2"
                            style={{ color: COLORS.blue }}>
                            {heading}
                          </div>
                        )}
                        <p className="text-sm leading-relaxed"
                          style={{ color: COLORS.text }}>
                          {body || heading}
                        </p>
                      </div>
                    );
                  })}
                  <div className="text-xs text-center pt-2" style={{ color: COLORS.muted }}>
                    Generated by Claude AI · Powered by Anthropic
                  </div>
                </div>
              ) : (
                <div className="text-center py-12" style={{ color: COLORS.muted }}>
                  <div className="text-sm">Click AI Explanation tab to generate</div>
                </div>
              )}
            </div>
          ) : loading ? (
            <div className="text-center py-12" style={{ color: COLORS.muted }}>
              Loading fix data...
            </div>
          ) : (
            <>
              {/* Why This Is Dangerous */}
              <div className="rounded-xl p-4 border"
                style={{ backgroundColor: cfg.color + "08", borderColor: cfg.color + "30" }}>
                <h3 className="text-xs font-bold uppercase tracking-wider mb-2"
                  style={{ color: cfg.color }}>
                  Why This Is Dangerous
                </h3>
                <p className="text-sm leading-relaxed" style={{ color: COLORS.text }}>
                  {remediation?.explanation}
                </p>
              </div>

              {/* Time and Difficulty */}
              <div className="flex gap-3">
                <div className="flex-1 rounded-xl p-4 border text-center"
                  style={{ backgroundColor: COLORS.card, borderColor: COLORS.border }}>
                  <div className="text-2xl font-black" style={{ color: COLORS.blue }}>
                    {remediation?.time_estimate_minutes}
                  </div>
                  <div className="text-xs mt-1" style={{ color: COLORS.muted }}>minutes to fix</div>
                </div>
                <div className="flex-1 rounded-xl p-4 border text-center"
                  style={{ backgroundColor: COLORS.card, borderColor: COLORS.border }}>
                  <div className="text-sm font-bold"
                    style={{ color: difficultyColor[remediation?.difficulty] || COLORS.muted }}>
                    {remediation?.difficulty}
                  </div>
                  <div className="text-xs mt-1" style={{ color: COLORS.muted }}>difficulty</div>
                </div>
                <div className="flex-1 rounded-xl p-4 border text-center"
                  style={{ backgroundColor: COLORS.card, borderColor: COLORS.border }}>
                  <div className="text-xs font-bold" style={{ color: COLORS.muted }}>
                    {remediation?.source}
                  </div>
                  <div className="text-xs mt-1" style={{ color: COLORS.muted }}>source</div>
                </div>
              </div>

              {/* Fix Commands */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <h3 className="text-xs font-bold uppercase tracking-wider"
                    style={{ color: COLORS.text }}>
                    Fix Commands
                  </h3>
                  <button onClick={handleCopy}
                    className="px-3 py-1.5 rounded-lg text-xs font-bold transition-all"
                    style={{
                      backgroundColor: copied ? COLORS.low + "20" : COLORS.blue + "20",
                      color: copied ? COLORS.low : COLORS.blue,
                      border: `1px solid ${copied ? COLORS.low + "40" : COLORS.blue + "40"}`
                    }}>
                    {copied ? "✓ Copied" : "Copy Commands"}
                  </button>
                </div>
                <div className="rounded-xl p-4 font-mono text-xs leading-relaxed overflow-x-auto"
                  style={{ backgroundColor: "#0a0a0a", color: "#00ff88", border: `1px solid ${COLORS.border}` }}>
                  {remediation?.fix_commands?.split("\n").map((line, i) => (
                    <div key={i} style={{ color: line.startsWith("#") ? COLORS.muted : "#00ff88" }}>
                      {line || "\u00a0"}
                    </div>
                  ))}
                </div>
              </div>

              {/* Fix Notes */}
              <div>
                <h3 className="text-xs font-bold uppercase tracking-wider mb-2"
                  style={{ color: COLORS.text }}>
                  Notes
                </h3>
                <textarea
                  value={notes}
                  onChange={e => setNotes(e.target.value)}
                  placeholder="Add notes about what you did to fix this..."
                  rows={3}
                  className="w-full px-4 py-3 rounded-xl text-sm outline-none resize-none"
                  style={{
                    backgroundColor: COLORS.card,
                    color: COLORS.text,
                    border: `1px solid ${COLORS.border}`
                  }}
                />
              </div>

              {/* Status Buttons */}
              <div>
                <h3 className="text-xs font-bold uppercase tracking-wider mb-3"
                  style={{ color: COLORS.text }}>
                  Mark As
                </h3>
                <div className="grid grid-cols-2 gap-2">
                  {Object.entries(STATUS_CONFIG).map(([key, val]) => (
                    <button key={key}
                      onClick={() => handleStatusUpdate(key)}
                      disabled={saving}
                      className="py-3 rounded-xl text-xs font-bold transition-all"
                      style={{
                        backgroundColor: status === key ? val.color + "20" : COLORS.card,
                        color: status === key ? val.color : COLORS.muted,
                        border: `1px solid ${status === key ? val.color + "40" : COLORS.border}`,
                        opacity: saving ? 0.6 : 1
                      }}>
                      {status === key ? "✓ " : ""}{val.label}
                    </button>
                  ))}
                </div>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

function ScorePanel({ findings, token, scans }) {
  const [showTagModal, setShowTagModal]   = useState(false);
  const [showScore, setShowScore]         = useState(false);
  const [tags, setTags]                   = useState({});
  const [industry, setIndustry]           = useState("General Business");
  const [industries, setIndustries]       = useState([]);
  const [businessFunctions, setBusinessFunctions] = useState([]);
  const [scoreResult, setScoreResult]     = useState(null);
  const [calculating, setCalculating]     = useState(false);
  const [saving, setSaving]               = useState(false);
  const [error, setError]                 = useState(null);

  const latestScan = scans && scans.find(s => s.status === "completed" || s.status === "complete");
  const scanId     = latestScan?.id;

  // Get unique device IPs from findings
  const devices = [...new Set(findings.map(f => f.target).filter(Boolean))];

  // Load options and existing tags on mount
  useState(() => {
    const load = async () => {
      try {
        const headers = { Authorization: `Bearer ${token}` };
        const [optRes, tagRes] = await Promise.all([
          axios.get(`${API}/score/options`, { headers }),
          axios.get(`${API}/score/tags`,    { headers }),
        ]);
        setIndustries(optRes.data.industries || []);
        setBusinessFunctions(optRes.data.business_functions || []);
        // Pre-populate tags from saved data
        const savedTags = {};
        let savedIndustry = "General Business";
        (tagRes.data || []).forEach(t => {
          savedTags[t.device_ip] = t.business_function;
          savedIndustry = t.industry;
        });
        setTags(savedTags);
        setIndustry(savedIndustry);
      } catch (e) {
        console.error("Failed to load score options:", e);
      }
    };
    load();
  }, [token]);

  const saveTags = async () => {
    setSaving(true);
    try {
      const headers = { Authorization: `Bearer ${token}` };
      const tagList = Object.entries(tags).map(([ip, fn]) => ({
        device_ip: ip, business_function: fn
      }));
      await axios.post(`${API}/score/tags`, { tags: tagList, industry }, { headers });
      setShowTagModal(false);
    } catch (err) {
      if (err.response?.status === 403) {
        setError("upgrade");
      } else {
        setError("Failed to save tags. Please try again.");
      }
    } finally {
      setSaving(false);
    }
  };

  const calculateScore = async () => {
    if (!scanId) { setError("No completed scan found."); return; }
    setCalculating(true);
    setError(null);
    try {
      const headers = { Authorization: `Bearer ${token}` };
      const res = await axios.post(
        `${API}/score/calculate/${scanId}`,
        { industry },
        { headers }
      );
      setScoreResult(res.data);
      setShowScore(true);
    } catch (err) {
      if (err.response?.status === 403) setError("upgrade");
      else setError("Failed to calculate score. Please try again.");
    } finally {
      setCalculating(false);
    }
  };

  const severityColor = { Critical: COLORS.critical, High: COLORS.high, Medium: COLORS.medium, Low: COLORS.low };

  return (
    <>
      {/* Device Tagging Modal */}
      {showTagModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center"
          style={{ backgroundColor: "rgba(0,0,0,0.8)", backdropFilter: "blur(4px)" }}>
          <div className="w-full max-w-lg mx-4 rounded-2xl overflow-hidden"
            style={{ backgroundColor: COLORS.dark, border: `1px solid ${COLORS.border}`, maxHeight: "85vh", overflowY: "auto" }}>
            <div className="p-6 border-b flex items-center justify-between"
              style={{ borderColor: COLORS.border }}>
              <div>
                <h2 className="text-lg font-black" style={{ color: COLORS.text }}>Tag Your Devices</h2>
                <p className="text-xs mt-1" style={{ color: COLORS.muted }}>Tell us what each device does to calculate accurate financial risk</p>
              </div>
              <button onClick={() => setShowTagModal(false)}
                className="p-2 rounded-lg hover:bg-white/10" style={{ color: COLORS.muted }}>✕</button>
            </div>
            <div className="p-6 space-y-4">
              {/* Industry selector */}
              <div>
                <label className="text-xs font-bold uppercase tracking-wider mb-2 block" style={{ color: COLORS.text }}>
                  Your Industry
                </label>
                <select value={industry} onChange={e => setIndustry(e.target.value)}
                  className="w-full px-4 py-3 rounded-xl text-sm outline-none"
                  style={{ backgroundColor: COLORS.card, color: COLORS.text, border: `1px solid ${COLORS.border}` }}>
                  {industries.map(ind => <option key={ind} value={ind}>{ind}</option>)}
                </select>
              </div>
              {/* Device tags */}
              <div>
                <label className="text-xs font-bold uppercase tracking-wider mb-2 block" style={{ color: COLORS.text }}>
                  Device Functions
                </label>
                {devices.length === 0 ? (
                  <p className="text-sm" style={{ color: COLORS.muted }}>No devices found. Run a scan first.</p>
                ) : (
                  <div className="space-y-2">
                    {devices.map(ip => (
                      <div key={ip} className="flex items-center gap-3">
                        <div className="text-xs font-mono flex-shrink-0 w-28" style={{ color: COLORS.muted }}>{ip}</div>
                        <select
                          value={tags[ip] || "Unknown"}
                          onChange={e => setTags(prev => ({ ...prev, [ip]: e.target.value }))}
                          className="flex-1 px-3 py-2 rounded-lg text-xs outline-none"
                          style={{ backgroundColor: COLORS.card, color: COLORS.text, border: `1px solid ${COLORS.border}` }}>
                          {businessFunctions.map(fn => <option key={fn} value={fn}>{fn}</option>)}
                        </select>
                      </div>
                    ))}
                  </div>
                )}
              </div>
              <button onClick={saveTags} disabled={saving}
                className="w-full py-3 rounded-xl text-sm font-bold transition-all"
                style={{ backgroundColor: COLORS.blue, color: "#fff", opacity: saving ? 0.6 : 1 }}>
                {saving ? "Saving..." : "Save Tags & Close"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Score Panel */}
      <div className="rounded-xl border p-4" style={{ backgroundColor: COLORS.card, borderColor: COLORS.border }}>
        <div className="flex items-center justify-between mb-3">
          <div>
            <div className="text-sm font-bold" style={{ color: COLORS.text }}>Financial Risk Exposure</div>
            <div className="text-xs mt-0.5" style={{ color: COLORS.muted }}>
              {scoreResult ? `Industry: ${scoreResult.industry}` : "Tag your devices to calculate financial impact"}
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button onClick={() => setShowTagModal(true)}
              className="px-3 py-1.5 rounded-lg text-xs font-bold transition-all"
              style={{ backgroundColor: COLORS.blue + "20", color: COLORS.blue, border: `1px solid ${COLORS.blue + "40"}` }}>
              Tag Devices
            </button>
            <button onClick={calculateScore} disabled={calculating}
              className="px-3 py-1.5 rounded-lg text-xs font-bold transition-all"
              style={{ backgroundColor: COLORS.purple + "20", color: COLORS.purple, border: `1px solid ${COLORS.purple + "40"}`, opacity: calculating ? 0.6 : 1 }}>
              {calculating ? "Calculating..." : "Calculate Score"}
            </button>
          </div>
        </div>

        {error === "upgrade" ? (
          <div className="text-center py-6">
            <div className="text-xs" style={{ color: COLORS.muted }}>AIPET Score is available on Professional and Enterprise plans.</div>
          </div>
        ) : error ? (
          <div className="text-center py-4">
            <div className="text-xs" style={{ color: COLORS.critical }}>{error}</div>
          </div>
        ) : scoreResult ? (
          <div className="space-y-3">
            {/* Total exposure */}
            <div className="rounded-xl p-4 text-center"
              style={{ backgroundColor: COLORS.critical + "10", border: `1px solid ${COLORS.critical + "30"}` }}>
              <div className="text-xs font-bold uppercase tracking-wider mb-1" style={{ color: COLORS.critical }}>
                Total Financial Exposure
              </div>
              <div className="text-3xl font-black" style={{ color: COLORS.critical }}>
                {scoreResult.total_exposure_fmt}
              </div>
              <div className="text-xs mt-1" style={{ color: COLORS.muted }}>
                Based on {scoreResult.industry} industry breach cost data
              </div>
            </div>

            {/* Per-finding breakdown */}
            <div className="space-y-2">
              {scoreResult.findings_breakdown?.map((f, i) => {
                const maxExposure = scoreResult.findings_breakdown[0]?.exposure_gbp || 1;
                const barWidth    = Math.round((f.exposure_gbp / maxExposure) * 100);
                return (
                  <div key={i} className="rounded-lg p-3 border"
                    style={{ backgroundColor: COLORS.dark, borderColor: COLORS.border }}>
                    <div className="flex items-center justify-between mb-1.5">
                      <div className="flex items-center gap-2">
                        <div className="w-2 h-2 rounded-full flex-shrink-0"
                          style={{ backgroundColor: severityColor[f.severity] || COLORS.muted }} />
                        <span className="text-xs font-semibold" style={{ color: COLORS.text }}>{f.attack}</span>
                        <span className="text-xs" style={{ color: COLORS.muted }}>{f.target}</span>
                      </div>
                      <span className="text-xs font-black" style={{ color: severityColor[f.severity] || COLORS.text }}>
                        {f.exposure_fmt}
                      </span>
                    </div>
                    <div className="w-full h-1.5 rounded-full overflow-hidden" style={{ backgroundColor: COLORS.border }}>
                      <div className="h-full rounded-full"
                        style={{ width: `${barWidth}%`, backgroundColor: severityColor[f.severity] || COLORS.muted }} />
                    </div>
                    <div className="text-xs mt-1" style={{ color: COLORS.muted }}>
                      {f.device_function} · {f.breach_probability}% breach probability
                      {f.fix_status === "fixed" && <span style={{ color: COLORS.low }}> · Fixed ✓</span>}
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Summary */}
            <div className="grid grid-cols-2 gap-2">
              {[
                { label: "Critical Exposure", value: `£${(scoreResult.summary?.critical_exposure || 0).toLocaleString()}`, color: COLORS.critical },
                { label: "High Exposure",     value: `£${(scoreResult.summary?.high_exposure     || 0).toLocaleString()}`, color: COLORS.high     },
                { label: "Medium Exposure",   value: `£${(scoreResult.summary?.medium_exposure   || 0).toLocaleString()}`, color: COLORS.medium   },
                { label: "Fixed Savings",     value: `£${(scoreResult.summary?.fixed_savings     || 0).toLocaleString()}`, color: COLORS.low      },
              ].map(item => (
                <div key={item.label} className="rounded-lg p-3 border"
                  style={{ backgroundColor: COLORS.dark, borderColor: COLORS.border }}>
                  <div className="text-xs" style={{ color: COLORS.muted }}>{item.label}</div>
                  <div className="text-sm font-black mt-1" style={{ color: item.color }}>{item.value}</div>
                </div>
              ))}
            </div>
          </div>
        ) : (
          <div className="text-center py-6">
            <div className="text-2xl mb-2">💰</div>
            <div className="text-xs" style={{ color: COLORS.muted }}>
              Click "Tag Devices" to assign business functions, then "Calculate Score" to see financial impact
            </div>
          </div>
        )}
      </div>
    </>
  );
}

function RiskReductionBar({ findings, token, scans }) {
  const [showReport, setShowReport]     = useState(false);
  const [report, setReport]             = useState(null);
  const [reportLoading, setReportLoading] = useState(false);
  const [reportError, setReportError]   = useState(null);
  const [copied, setCopied]             = useState(false);

  // Get the most recent completed scan ID
  const latestScan = scans && scans.find(s => s.status === "completed" || s.status === "complete");
  const scanId     = latestScan?.id;
  const fixed       = findings.filter(f => f.fix_status === "fixed").length;
  const accepted    = findings.filter(f => f.fix_status === "accepted_risk").length;
  const inProgress  = findings.filter(f => f.fix_status === "in_progress").length;
  const total       = findings.length;
  const resolved    = fixed + accepted;

  const severityWeights = { Critical: 20, High: 10, Medium: 5, Low: 2 };
  const totalRisk    = findings.reduce((sum, f) => sum + (severityWeights[f.severity] || 5), 0);
  const reducedRisk  = findings
    .filter(f => f.fix_status === "fixed" || f.fix_status === "accepted_risk")
    .reduce((sum, f) => sum + (severityWeights[f.severity] || 5), 0);
  const pct = totalRisk > 0 ? Math.round((reducedRisk / totalRisk) * 100) : 0;
  const generateReport = async () => {
    if (!scanId) {
      setReportError("No completed scan found. Run a scan first.");
      setShowReport(true);
      return;
    }
    setShowReport(true);
    setReportLoading(true);
    setReportError(null);
    try {
      const res = await axios.post(
        `${API}/explain/report/${scanId}`,
        {},
        { headers: { Authorization: `Bearer ${token}` } }
      );
      setReport(res.data.content);
    } catch (err) {
      if (err.response?.status === 403 && err.response?.data?.upgrade) {
        setReportError("upgrade");
      } else {
        setReportError("Failed to generate report. Please try again.");
      }
    } finally {
      setReportLoading(false);
    }
  };

  const handleCopyReport = () => {
    if (report) {
      navigator.clipboard.writeText(report);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  if (total === 0) return null;

  const barColor = pct >= 75 ? COLORS.low : pct >= 40 ? COLORS.high : COLORS.critical;


  return (
    <>
      {/* Executive Report Modal */}
      {showReport && (
        <div className="fixed inset-0 z-50 flex items-center justify-center"
          style={{ backgroundColor: "rgba(0,0,0,0.8)", backdropFilter: "blur(4px)" }}>
          <div className="w-full max-w-2xl mx-4 rounded-2xl overflow-hidden flex flex-col"
            style={{ backgroundColor: COLORS.dark, border: `1px solid ${COLORS.border}`, maxHeight: "85vh" }}>
            <div className="p-6 border-b flex items-center justify-between flex-shrink-0"
              style={{ borderColor: COLORS.border }}>
              <div>
                <h2 className="text-lg font-black" style={{ color: COLORS.text }}>
                  Executive Security Report
                </h2>
                <p className="text-xs mt-1" style={{ color: COLORS.muted }}>
                  Generated by Claude AI · Board-level summary
                </p>
              </div>
              <div className="flex items-center gap-2">
                {report && (
                  <button onClick={handleCopyReport}
                    className="px-3 py-1.5 rounded-lg text-xs font-bold transition-all"
                    style={{
                      backgroundColor: copied ? COLORS.low + "20" : COLORS.blue + "20",
                      color: copied ? COLORS.low : COLORS.blue,
                      border: `1px solid ${copied ? COLORS.low + "40" : COLORS.blue + "40"}`
                    }}>
                    {copied ? "✓ Copied" : "Copy Report"}
                  </button>
                )}
                <button onClick={() => setShowReport(false)}
                  className="p-2 rounded-lg hover:bg-white/10 transition-colors"
                  style={{ color: COLORS.muted }}>
                  ✕
                </button>
              </div>
            </div>
            <div className="flex-1 overflow-y-auto p-6">
              {reportLoading ? (
                <div className="text-center py-16">
                  <div className="text-4xl mb-4">🤖</div>
                  <div className="text-sm font-bold mb-2" style={{ color: COLORS.text }}>
                    Claude is writing your executive report...
                  </div>
                  <div className="text-xs" style={{ color: COLORS.muted }}>
                    This takes 3-5 seconds
                  </div>
                </div>
              ) : reportError === "upgrade" ? (
                <div className="text-center py-16">
                  <div className="text-4xl mb-4">⭐</div>
                  <div className="text-sm font-bold mb-2" style={{ color: COLORS.text }}>
                    Professional Feature
                  </div>
                  <div className="text-xs" style={{ color: COLORS.muted }}>
                    Executive Reports are available on Professional and Enterprise plans.
                  </div>
                </div>
              ) : reportError ? (
                <div className="text-center py-16">
                  <div className="text-sm" style={{ color: COLORS.critical }}>{reportError}</div>
                </div>
              ) : report ? (
                <div className="space-y-4">
                {(() => {
                    const headingKeywords = ["EXECUTIVE SUMMARY", "KEY RISKS IDENTIFIED", "IMMEDIATE ACTIONS REQUIRED", "OVERALL SECURITY ASSESSMENT"];
                    const lines = report.split("\n");
                    const sections = [];
                    let currentHeading = null;
                    let currentBody = [];

                    lines.forEach(line => {
                      const isHeading = headingKeywords.some(k => line.trim() === k);
                      if (isHeading) {
                        if (currentHeading || currentBody.length > 0) {
                          sections.push({ heading: currentHeading, body: currentBody.join("\n").trim() });
                        }
                        currentHeading = line.trim();
                        currentBody = [];
                      } else if (line.trim()) {
                        currentBody.push(line);
                      }
                    });
                    if (currentHeading || currentBody.length > 0) {
                      sections.push({ heading: currentHeading, body: currentBody.join("\n").trim() });
                    }

                    return sections.map((section, i) => (
                      <div key={i} className="rounded-xl p-4 border"
                        style={{ backgroundColor: COLORS.card, borderColor: COLORS.border }}>
                        {section.heading && (
                          <div className="text-xs font-bold uppercase tracking-wider mb-3"
                            style={{ color: COLORS.blue }}>
                            {section.heading}
                          </div>
                        )}
                        <div className="text-sm leading-relaxed whitespace-pre-line"
                          style={{ color: COLORS.text }}>
                          {section.body}
                        </div>
                      </div>
                    ));
                  })()}
                  <div className="text-xs text-center pt-2" style={{ color: COLORS.muted }}>
                    Generated by Claude AI · Powered by Anthropic
                  </div>
                </div>
              ) : null}
            </div>
          </div>
        </div>
      )}

      {/* Risk Reduction Bar */}
      <div className="rounded-xl p-4 border" style={{ backgroundColor: COLORS.card, borderColor: COLORS.border }}>
        <div className="flex items-center justify-between mb-3">
          <div>
            <div className="text-sm font-bold" style={{ color: COLORS.text }}>
              Risk Reduction
            </div>
            <div className="text-xs mt-0.5" style={{ color: COLORS.muted }}>
              {resolved} of {total} findings resolved
              {inProgress > 0 && ` · ${inProgress} in progress`}
            </div>
          </div>
          <div className="flex items-center gap-3">
            <button onClick={generateReport}
              className="px-3 py-1.5 rounded-lg text-xs font-bold transition-all"
              style={{
                backgroundColor: COLORS.purple + "20",
                color: COLORS.purple,
                border: `1px solid ${COLORS.purple + "40"}`
              }}>
              Executive Report
            </button>
            <div className="text-2xl font-black" style={{ color: barColor }}>
              {pct}%
            </div>
          </div>
        </div>
        <div className="w-full h-2 rounded-full overflow-hidden" style={{ backgroundColor: COLORS.border }}>
          <div className="h-full rounded-full transition-all duration-700"
            style={{ width: `${pct}%`, backgroundColor: barColor }} />
        </div>
        <div className="flex items-center gap-4 mt-3">
          {[
            { label: "Open",        value: findings.filter(f => f.fix_status === "open").length, color: COLORS.critical },
            { label: "In Progress", value: inProgress,                                            color: COLORS.high     },
            { label: "Fixed",       value: fixed,                                                 color: COLORS.low      },
            { label: "Accepted",    value: accepted,                                              color: COLORS.muted    },
          ].map(item => (
            <div key={item.label} className="flex items-center gap-1.5">
              <div className="w-2 h-2 rounded-full" style={{ backgroundColor: item.color }} />
              <span className="text-xs" style={{ color: COLORS.muted }}>
                {item.label}: <span style={{ color: COLORS.text }}>{item.value}</span>
              </span>
            </div>
          ))}
        </div>
      </div>
    </>
  );
}

function FindingRow({ finding, token, onStatusUpdate }) {
  const [open, setOpen]           = useState(false);
  const [showFix, setShowFix]     = useState(false);
  const [fixStatus, setFixStatus] = useState(finding.fix_status || "open");
  const cfg = SEVERITY_CONFIG[finding.severity] || SEVERITY_CONFIG.INFO;

  const STATUS_COLORS = {
    open:          COLORS.critical,
    in_progress:   COLORS.high,
    fixed:         COLORS.low,
    accepted_risk: COLORS.muted,
  };

  const handleStatusUpdate = (findingId, newStatus) => {
    setFixStatus(newStatus);
    if (onStatusUpdate) onStatusUpdate(findingId, newStatus);
  };

  return (
    <>
      {showFix && (
        <FixPanel
          finding={{ ...finding, fix_status: fixStatus }}
          token={token}
          onClose={() => setShowFix(false)}
          onStatusUpdate={handleStatusUpdate}
        />
      )}
      <div className="rounded-xl border overflow-hidden transition-all duration-200"
        style={{ backgroundColor: COLORS.card, borderColor: open ? cfg.color + "40" : COLORS.border }}>
        <div className="flex items-center justify-between p-4"
          style={{ cursor: "pointer" }}
          onClick={() => setOpen(!open)}>
          <div className="flex items-center gap-3">
            <div className="w-1 h-10 rounded-full flex-shrink-0" style={{ backgroundColor: cfg.color }} />
            <div>
              <div className="font-semibold text-sm" style={{ color: COLORS.text }}>{finding.attack}</div>
              <div className="text-xs mt-0.5" style={{ color: COLORS.muted }}>
                {finding.module} — {finding.target}
              </div>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {/* Fix status badge */}
            <div className="px-2 py-1 rounded-lg text-xs font-bold"
              style={{
                backgroundColor: (STATUS_COLORS[fixStatus] || COLORS.muted) + "20",
                color: STATUS_COLORS[fixStatus] || COLORS.muted,
                border: `1px solid ${(STATUS_COLORS[fixStatus] || COLORS.muted) + "40"}`
              }}>
              {fixStatus.replace("_", " ")}
            </div>
            <SeverityBadge severity={finding.severity} />
            {/* View Fix button */}
            <button
              onClick={e => { e.stopPropagation(); setShowFix(true); }}
              className="px-3 py-1.5 rounded-lg text-xs font-bold transition-all"
              style={{
                backgroundColor: COLORS.blue + "20",
                color: COLORS.blue,
                border: `1px solid ${COLORS.blue + "40"}`
              }}>
              View Fix
            </button>
            {open
              ? <ChevronUp size={16} style={{ color: COLORS.muted }} />
              : <ChevronDown size={16} style={{ color: COLORS.muted }} />}
          </div>
        </div>
        {open && (
          <div className="px-4 pb-4 pt-2 border-t" style={{ borderColor: COLORS.border }}>
            <p className="text-sm leading-relaxed" style={{ color: COLORS.muted }}>{finding.description}</p>
          </div>
        )}
      </div>
    </>
  );
}

function ShapBar({ feature, value }) {
  const isPositive = value > 0;
  const width = Math.min(Math.abs(value) * 300, 100);
  return (
    <div className="flex items-center gap-3 py-1.5">
      <div className="w-52 text-xs truncate flex-shrink-0" style={{ color: COLORS.muted }}>
        {feature.replace(/_/g, " ")}
      </div>
      <div className="flex-1 flex items-center gap-2">
        <div className="flex-1 h-2 rounded-full overflow-hidden" style={{ backgroundColor: COLORS.border }}>
          <div className="h-full rounded-full transition-all duration-700"
            style={{
              width: `${width}%`,
              backgroundColor: isPositive ? COLORS.critical : COLORS.low,
              marginLeft: isPositive ? "0" : "auto"
            }} />
        </div>
        <div className="text-xs font-mono w-14 text-right flex-shrink-0"
          style={{ color: isPositive ? COLORS.critical : COLORS.low }}>
          {isPositive ? "+" : ""}{(value * 100).toFixed(1)}%
        </div>
      </div>
    </div>
  );
}
function ApiKeysPage({ token, userPlan }) {
  const [keys,     setKeys]     = useState([]);
  const [loading,  setLoading]  = useState(true);
  const [newKey,   setNewKey]   = useState(null);
  const [keyName,  setKeyName]  = useState("");
  const [creating, setCreating] = useState(false);
  const [error,    setError]    = useState("");

  // Fetch all API keys on load
  useEffect(() => {
    fetchKeys();
  }, []);

  const fetchKeys = async () => {
    setLoading(true);
    try {
      const res = await axios.get("http://localhost:5001/api/keys", {
        headers: { Authorization: `Bearer ${token}` }
      });
      setKeys(res.data.keys);
    } catch (e) {
      setError(e.response?.data?.error || "Failed to create API key.");
    } finally {
      setLoading(false);
    }
  };

  const createKey = async () => {
    if (!keyName.trim()) {
      setError("Please enter a name for your API key.");
      return;
    }
    setCreating(true);
    setError("");
    try {
      const res = await axios.post(
        "http://localhost:5001/api/keys",
        { name: keyName },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      setNewKey(res.data.key);
      setKeyName("");
      fetchKeys();
    } catch (e) {
      setError(e.response?.data?.error || "Failed to create API key.");
    } finally {
      setCreating(false);
    }
  };

  const revokeKey = async (keyId, keyName) => {
    if (!window.confirm(`Revoke API key "${keyName}"? This cannot be undone.`)) return;
    try {
      await axios.delete(`http://localhost:5001/api/keys/${keyId}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      fetchKeys();
    } catch (e) {
      setError("Failed to revoke API key.");
    }
  };

  // Non-enterprise users see upgrade prompt
  if (userPlan !== "enterprise") {
    return (
      <div className="rounded-2xl border p-8 text-center max-w-lg mx-auto"
        style={{ backgroundColor: COLORS.card, borderColor: COLORS.border }}>
        <Lock size={48} style={{ color: COLORS.purple }} className="mx-auto mb-4" />
        <h3 className="text-xl font-black mb-2" style={{ color: COLORS.text }}>
          API Access — Enterprise Only
        </h3>
        <p className="text-sm mb-6" style={{ color: COLORS.muted }}>
          API keys allow you to integrate AIPET into your own systems,
          CI/CD pipelines, and security tools. Available on the Enterprise plan.
        </p>
        <button
          onClick={() => window.location.href = "/pricing"}
          className="px-6 py-3 rounded-xl font-bold text-sm"
          style={{ backgroundColor: COLORS.purple, color: "white" }}>
          Upgrade to Enterprise — £499/month
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-3xl">

      {/* Header */}
      <div className="rounded-2xl border p-6"
        style={{ backgroundColor: COLORS.card, borderColor: COLORS.border }}>
        <h3 className="font-black text-lg mb-1" style={{ color: COLORS.text }}>
          API Keys
        </h3>
        <p className="text-sm" style={{ color: COLORS.muted }}>
          Use API keys to authenticate programmatic access to AIPET.
          Keep your keys secret — treat them like passwords.
        </p>
      </div>

      {/* New key revealed — show once */}
      {newKey && (
        <div className="rounded-2xl border p-6"
          style={{
            backgroundColor: COLORS.low + "10",
            borderColor: COLORS.low + "40"
          }}>
          <div className="flex items-center gap-2 mb-3">
            <CheckCircle size={18} style={{ color: COLORS.low }} />
            <span className="font-bold text-sm" style={{ color: COLORS.low }}>
              API key created — copy it now, it will not be shown again
            </span>
          </div>
          <div className="p-3 rounded-xl font-mono text-xs break-all"
            style={{ backgroundColor: COLORS.darker, color: COLORS.text }}>
            {newKey}
          </div>
          <button
            onClick={() => { navigator.clipboard.writeText(newKey); }}
            className="mt-3 px-4 py-2 rounded-xl text-xs font-bold"
            style={{ backgroundColor: COLORS.low, color: "white" }}>
            Copy to clipboard
          </button>
          <button
            onClick={() => setNewKey(null)}
            className="mt-3 ml-2 px-4 py-2 rounded-xl text-xs font-bold"
            style={{ backgroundColor: COLORS.border, color: COLORS.muted }}>
            I have copied it
          </button>
        </div>
      )}

      {/* Error message */}
      {error && (
        <div className="p-3 rounded-xl text-sm"
          style={{
            backgroundColor: COLORS.critical + "15",
            borderColor: COLORS.critical + "40",
            color: COLORS.critical,
            border: "1px solid"
          }}>
          {error}
        </div>
      )}

      {/* Create new key */}
      <div className="rounded-2xl border p-6"
        style={{ backgroundColor: COLORS.card, borderColor: COLORS.border }}>
        <h4 className="font-bold mb-4" style={{ color: COLORS.text }}>
          Generate new API key
        </h4>
        <div className="flex gap-3">
          <input
            type="text"
            value={keyName}
            onChange={e => setKeyName(e.target.value)}
            placeholder="e.g. Production CI/CD, SIEM Integration"
            className="flex-1 px-4 py-3 rounded-xl text-sm outline-none"
            style={{
              backgroundColor: COLORS.darker,
              color: COLORS.text,
              border: `1px solid ${COLORS.border}`
            }}
          />
          <button
            onClick={createKey}
            disabled={creating}
            className="px-6 py-3 rounded-xl font-bold text-sm transition-all"
            style={{
              backgroundColor: creating ? COLORS.border : COLORS.blue,
              color: creating ? COLORS.muted : "white"
            }}>
            {creating ? "Creating..." : "Generate"}
          </button>
        </div>
      </div>

      {/* List of keys */}
      <div className="rounded-2xl border overflow-hidden"
        style={{ backgroundColor: COLORS.card, borderColor: COLORS.border }}>
        <div className="p-4 border-b flex items-center justify-between"
          style={{ borderColor: COLORS.border }}>
          <span className="font-bold text-sm" style={{ color: COLORS.text }}>
            Active API keys ({keys.length}/10)
          </span>
        </div>

        {loading ? (
          <div className="p-8 text-center">
            <p className="text-sm" style={{ color: COLORS.muted }}>Loading...</p>
          </div>
        ) : keys.length === 0 ? (
          <div className="p-8 text-center">
            <p className="text-sm" style={{ color: COLORS.muted }}>
              No API keys yet. Generate your first key above.
            </p>
          </div>
        ) : (
          <div className="divide-y" style={{ borderColor: COLORS.border }}>
            {keys.map(key => (
              <div key={key.id}
                className="p-4 flex items-center justify-between">
                <div>
                  <div className="font-semibold text-sm mb-1"
                    style={{ color: COLORS.text }}>
                    {key.name}
                  </div>
                  <div className="text-xs font-mono mb-1"
                    style={{ color: COLORS.muted }}>
                    {key.key_preview}
                  </div>
                  <div className="text-xs" style={{ color: COLORS.muted }}>
                    Created {key.created_at?.split("T")[0]} · Last used: {key.last_used === "Never" ? "Never" : key.last_used?.split("T")[0]}
                  </div>
                </div>
                <button
                  onClick={() => revokeKey(key.id, key.name)}
                  className="px-4 py-2 rounded-xl text-xs font-bold transition-all border"
                  style={{
                    backgroundColor: "transparent",
                    borderColor: COLORS.critical + "40",
                    color: COLORS.critical
                  }}>
                  Revoke
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Usage example */}
      <div className="rounded-2xl border p-6"
        style={{ backgroundColor: COLORS.card, borderColor: COLORS.border }}>
        <h4 className="font-bold mb-3" style={{ color: COLORS.text }}>
          How to use your API key
        </h4>
        <p className="text-xs mb-3" style={{ color: COLORS.muted }}>
          Include your API key in the request header:
        </p>
        <div className="p-3 rounded-xl font-mono text-xs"
          style={{ backgroundColor: COLORS.darker, color: COLORS.low }}>
          {`curl https://aipet.io/api/scan/start \\`}<br/>
          {`  -H "X-API-Key: aipet_ent_your_key_here" \\`}<br/>
          {`  -d '{"target": "192.168.1.0/24", "mode": "live"}'`}
        </div>
      </div>

    </div>
  );
}
function LegalPage({ page, onBack }) {
  const content = {
    privacy: {
      title: "Privacy Policy",
      lastUpdated: "April 2026",
      body: `
AIPET Cloud ("we", "our", "us") is committed to protecting your privacy.
This policy explains how we collect, use, and protect your personal data
in accordance with the UK GDPR and Data Protection Act 2018.

1. DATA WE COLLECT
We collect the following personal data when you use AIPET Cloud:
- Name and email address (registration)
- Payment information (processed by Stripe — we never store card details)
- Scan targets and results (IoT network data you submit for scanning)
- Usage data (login times, scan history, API key usage)
- Technical data (IP address, browser type, device information)

2. HOW WE USE YOUR DATA
We use your data to:
- Provide and improve the AIPET Cloud service
- Process payments via Stripe
- Send security alerts and service notifications
- Comply with legal obligations

3. DATA SHARING
We share your data only with:
- Stripe (payment processing) — https://stripe.com/privacy
- DigitalOcean (hosting) — https://www.digitalocean.com/legal/privacy-policy
We never sell your data to third parties.

4. DATA RETENTION
We retain your data for as long as your account is active.
You can request deletion of your account and data at any time
by contacting us via GitHub Issues.

5. YOUR RIGHTS (UK GDPR)
You have the right to:
- Access your personal data
- Correct inaccurate data
- Request deletion of your data
- Object to processing
- Data portability

6. COOKIES
We use essential cookies only. See our Cookie Policy for details.

7. CONTACT
For data protection enquiries, open a GitHub issue at:
https://github.com/Yallewbinyam/AIPET/issues

This policy was last updated: April 2026.
      `
    },
    terms: {
      title: "Terms of Service",
      lastUpdated: "April 2026",
      body: `
By using AIPET Cloud, you agree to these Terms of Service.

1. ACCEPTABLE USE
AIPET Cloud is a penetration testing tool. You must only use it
against systems you own or have explicit written permission to test.
Using AIPET against systems without authorisation is illegal and
violates these terms.

2. ACCOUNT RESPONSIBILITIES
You are responsible for:
- Keeping your login credentials secure
- All activity under your account
- Ensuring your use complies with applicable laws

3. SUBSCRIPTIONS AND PAYMENTS
- Free plan: 5 scans per month, no payment required
- Professional: £49/month, billed monthly via Stripe
- Enterprise: £499/month, billed monthly via Stripe
- Subscriptions renew automatically until cancelled
- Cancellation takes effect at the end of the billing period

4. REFUNDS
Refund requests made within 14 days of payment will be considered.
Contact us via GitHub Issues with your request.

5. INTELLECTUAL PROPERTY
AIPET Cloud is open source under the MIT Licence.
The core engine is available at https://github.com/Yallewbinyam/AIPET

6. DISCLAIMER
AIPET Cloud is provided "as is". We make no warranties about
completeness, reliability, or accuracy of security assessments.
Security testing should always be performed by qualified professionals.

7. LIMITATION OF LIABILITY
To the maximum extent permitted by law, AIPET Cloud shall not be
liable for any indirect, incidental, or consequential damages
arising from use of the service.

8. GOVERNING LAW
These terms are governed by the laws of England and Wales.

Last updated: April 2026.
      `
    },
    cookies: {
      title: "Cookie Policy",
      lastUpdated: "April 2026",
      body: `
AIPET Cloud uses cookies to provide a secure and functional service.

1. WHAT ARE COOKIES
Cookies are small text files stored on your device when you visit
a website. They help websites remember your preferences and
keep you logged in.

2. COOKIES WE USE

Essential Cookies (required for the service to work):
- Authentication token: Keeps you logged in during your session.
  Duration: 15 minutes (expires automatically)
  Cannot be disabled — required for security

3. COOKIES WE DO NOT USE
We do not use:
- Advertising or tracking cookies
- Social media cookies
- Analytics cookies
- Third-party marketing cookies

4. MANAGING COOKIES
You can clear cookies at any time through your browser settings.
Clearing the authentication cookie will log you out of AIPET Cloud.

5. STRIPE COOKIES
Our payment processor Stripe may set cookies when you visit the
checkout page. These are subject to Stripe's cookie policy:
https://stripe.com/cookies-policy/legal

6. CHANGES TO THIS POLICY
We will update this policy if we change how we use cookies.
The date at the top of this page shows when it was last updated.

Last updated: April 2026.
      `
    }
  };

  const current = content[page];
  if (!current) return null;

  return (
    <div className="min-h-screen" style={{ backgroundColor: COLORS.darker }}>
      <div className="max-w-3xl mx-auto px-8 py-12">
        <button onClick={onBack}
          className="flex items-center gap-2 text-sm mb-8 transition-all"
          style={{ color: COLORS.muted }}>
          ← Back
        </button>
        <h1 className="text-3xl font-black mb-2" style={{ color: COLORS.text }}>
          {current.title}
        </h1>
        <p className="text-sm mb-8" style={{ color: COLORS.muted }}>
          Last updated: {current.lastUpdated}
        </p>
        <div className="rounded-2xl border p-8"
          style={{ backgroundColor: COLORS.card, borderColor: COLORS.border }}>
          <pre className="text-sm leading-relaxed whitespace-pre-wrap"
            style={{ color: COLORS.muted, fontFamily: "inherit" }}>
            {current.body.trim()}
          </pre>
        </div>
      </div>
    </div>
  );
}
function Toast({ toast }) {
  if (!toast) return null;

  const colors = {
    success: { bg: COLORS.low + "20", border: COLORS.low + "40", text: COLORS.low },
    error:   { bg: COLORS.critical + "20", border: COLORS.critical + "40", text: COLORS.critical },
    info:    { bg: COLORS.blue + "20", border: COLORS.blue + "40", text: COLORS.blue },
  };

  const style = colors[toast.type] || colors.info;

  return (
    <div
      style={{
        position: "fixed",
        bottom: "24px",
        right: "24px",
        zIndex: 9999,
        padding: "14px 20px",
        borderRadius: "12px",
        border: `1px solid ${style.border}`,
        backgroundColor: style.bg,
        color: style.text,
        fontSize: "14px",
        fontWeight: "600",
        maxWidth: "360px",
        boxShadow: "0 4px 24px rgba(0,0,0,0.4)",
      }}>
      {toast.message}
    </div>
  );
}
function LandingPage({ onGetStarted, onLogin, setLegalPage }) {
  return (
    <div className="min-h-screen" style={{ backgroundColor: COLORS.darker }}>

      {/* Navigation */}
      <nav className="flex items-center justify-between px-8 py-5 border-b"
        style={{ borderColor: COLORS.border }}>
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-xl flex items-center justify-center"
            style={{ backgroundColor: COLORS.blue }}>
            <Shield size={18} color="white" />
          </div>
          <span className="font-black text-xl" style={{ color: COLORS.text }}>AIPET</span>
        </div>
        <div className="flex items-center gap-4">
          <button onClick={onLogin}
            className="text-sm font-semibold px-4 py-2 rounded-xl transition-all"
            style={{ color: COLORS.muted }}>
            Sign In
          </button>
          <button onClick={onGetStarted}
            className="text-sm font-bold px-5 py-2 rounded-xl transition-all"
            style={{ backgroundColor: COLORS.blue, color: "white" }}>
            Get Started Free
          </button>
        </div>
      </nav>

      {/* Hero section */}
      <div className="max-w-5xl mx-auto px-8 py-24 text-center">
        <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full border mb-8"
          style={{
            backgroundColor: COLORS.blue + "15",
            borderColor: COLORS.blue + "40"
          }}>
          <div className="w-2 h-2 rounded-full animate-pulse"
            style={{ backgroundColor: COLORS.blue }} />
          <span className="text-xs font-bold" style={{ color: COLORS.blue }}>
            MSc Cyber Security Research — Coventry University
          </span>
        </div>

        <h1 className="text-5xl font-black mb-6 leading-tight"
          style={{ color: COLORS.text }}>
          AI-Powered IoT Security
          <br />
          <span style={{ color: COLORS.blue }}>for the Modern Enterprise</span>
        </h1>

        <p className="text-lg mb-10 max-w-2xl mx-auto leading-relaxed"
          style={{ color: COLORS.muted }}>
          AIPET automates the discovery, testing, and prioritisation of
          vulnerabilities across your IoT devices — with explainable AI
          that tells you not just what is vulnerable, but exactly why.
        </p>

        <div className="flex items-center justify-center gap-4">
          <button onClick={onGetStarted}
            className="px-8 py-4 rounded-xl font-bold text-base transition-all"
            style={{ backgroundColor: COLORS.blue, color: "white" }}>
            Start for Free — No Card Required
          </button>
          <button onClick={onLogin}
            className="px-8 py-4 rounded-xl font-bold text-base border transition-all"
            style={{
              backgroundColor: "transparent",
              borderColor: COLORS.border,
              color: COLORS.muted
            }}>
            Sign In
          </button>
        </div>
      </div>

      {/* Feature grid */}
      <div className="max-w-5xl mx-auto px-8 pb-20">
        <div className="grid grid-cols-3 gap-6 mb-20">
          {[
            {
              icon: Shield,
              color: COLORS.blue,
              title: "7 Attack Modules",
              desc: "MQTT, CoAP, HTTP, Firmware, Recon — full IoT coverage out of the box."
            },
            {
              icon: Zap,
              color: COLORS.critical,
              title: "Explainable AI",
              desc: "SHAP-powered predictions tell you exactly why each device is at risk."
            },
            {
              icon: Lock,
              color: COLORS.low,
              title: "OWASP IoT Top 10",
              desc: "Complete coverage of all 10 OWASP IoT vulnerability categories."
            },
            {
              icon: Activity,
              color: COLORS.purple,
              title: "Real-time Dashboard",
              desc: "Live scan status, findings, and AI analysis in one place."
            },
            {
              icon: CreditCard,
              color: COLORS.high,
              title: "Enterprise API",
              desc: "Integrate AIPET into your CI/CD pipelines with API key access."
            },
            {
              icon: FileText,
              color: COLORS.muted,
              title: "PDF Reports",
              desc: "Professional assessment reports ready to share with clients."
            },
          ].map((feature, i) => (
            <div key={i} className="rounded-2xl border p-6 transition-all"
              style={{ backgroundColor: COLORS.card, borderColor: COLORS.border }}>
              <div className="w-10 h-10 rounded-xl flex items-center justify-center mb-4"
                style={{ backgroundColor: feature.color + "20" }}>
                <feature.icon size={20} style={{ color: feature.color }} />
              </div>
              <h3 className="font-bold mb-2" style={{ color: COLORS.text }}>
                {feature.title}
              </h3>
              <p className="text-sm leading-relaxed" style={{ color: COLORS.muted }}>
                {feature.desc}
              </p>
            </div>
          ))}
        </div>

        {/* Pricing section */}
        <div className="text-center mb-12">
          <h2 className="text-3xl font-black mb-3" style={{ color: COLORS.text }}>
            Simple, transparent pricing
          </h2>
          <p className="text-sm" style={{ color: COLORS.muted }}>
            Start free. Upgrade when you need more.
          </p>
        </div>

        <div className="grid grid-cols-3 gap-6 mb-20">
          {[
            {
              name: "Free",
              price: "£0",
              period: "forever",
              color: COLORS.muted,
              features: ["5 scans/month", "Basic AI analysis", "PDF reports"],
              cta: "Get Started",
            },
            {
              name: "Professional",
              price: "£49",
              period: "per month",
              color: COLORS.blue,
              popular: true,
              features: ["Unlimited scans", "Full SHAP AI", "All report formats", "Email support"],
              cta: "Start Free Trial",
            },
            {
              name: "Enterprise",
              price: "£499",
              period: "per month",
              color: COLORS.purple,
              features: ["Unlimited scans", "API access", "Priority support", "SLA guarantee"],
              cta: "Contact Sales",
            },
          ].map((plan, i) => (
            <div key={i}
              className="rounded-2xl border p-6 flex flex-col relative overflow-hidden"
              style={{
                backgroundColor: COLORS.card,
                borderColor: plan.popular ? plan.color : COLORS.border,
                boxShadow: plan.popular ? `0 0 30px ${plan.color}20` : "none"
              }}>
              {plan.popular && (
                <div className="absolute top-0 right-0 px-3 py-1 text-xs font-bold rounded-bl-xl"
                  style={{ backgroundColor: plan.color, color: "white" }}>
                  POPULAR
                </div>
              )}
              <h3 className="font-black text-lg mb-2" style={{ color: plan.color }}>
                {plan.name}
              </h3>
              <div className="flex items-baseline gap-1 mb-6">
                <span className="text-3xl font-black" style={{ color: COLORS.text }}>
                  {plan.price}
                </span>
                <span className="text-sm" style={{ color: COLORS.muted }}>
                  /{plan.period}
                </span>
              </div>
              <div className="flex-1 space-y-2 mb-6">
                {plan.features.map((f, j) => (
                  <div key={j} className="flex items-center gap-2">
                    <Check size={14} style={{ color: plan.color }} />
                    <span className="text-sm" style={{ color: COLORS.muted }}>{f}</span>
                  </div>
                ))}
              </div>
              <button onClick={onGetStarted}
                className="w-full py-3 rounded-xl font-bold text-sm transition-all"
                style={{
                  backgroundColor: plan.popular ? plan.color : "transparent",
                  color: plan.popular ? "white" : plan.color,
                  border: `1px solid ${plan.color}`
                }}>
                {plan.cta}
              </button>
            </div>
          ))}
        </div>

        {/* Footer */}
        <div className="text-center border-t pt-8"
          style={{ borderColor: COLORS.border }}>
          <div className="flex items-center justify-center gap-6 mb-4">
            <button onClick={() => setLegalPage('privacy')}
              className="text-xs transition-all"
              style={{ color: COLORS.muted }}>
              Privacy Policy
            </button>
            <button onClick={() => setLegalPage('terms')}
              className="text-xs transition-all"
              style={{ color: COLORS.muted }}>
              Terms of Service
            </button>
            <button onClick={() => setLegalPage('cookies')}
              className="text-xs transition-all"
              style={{ color: COLORS.muted }}>
              Cookie Policy
            </button>
            <a href="https://github.com/Yallewbinyam/AIPET"
              className="text-xs"
              style={{ color: COLORS.blue }}>
              GitHub
            </a>
          </div>
          <p className="text-xs" style={{ color: COLORS.muted }}>
            AIPET Cloud v2.0.0 — Developed as part of MSc Cyber Security research
            at Coventry University · MIT Licence
          </p>
        </div>
      </div>
    </div>
  );
}
function LoginPage({ onLogin }) {
  const [isRegister, setIsRegister] = useState(false);
  const [email,      setEmail]      = useState("");
  const [password,   setPassword]   = useState("");
  const [name,       setName]       = useState("");
  const [error,      setError]      = useState("");
  const [loading,    setLoading]    = useState(false);

  const handleSubmit = async () => {
    setError("");
    if (!email || !password) { setError("Email and password are required"); return; }
    if (isRegister && !name) { setError("Name is required"); return; }

    setLoading(true);
    try {
      const endpoint = isRegister ? `${AUTH_API}/register` : `${AUTH_API}/login`;
      const payload  = isRegister
        ? { email, password, name }
        : { email, password };

      const res = await axios.post(endpoint, payload);
      const jwt = res.data.token;

      // Save token to localStorage so it persists across page refreshes
      localStorage.setItem("aipet_token", jwt);
      onLogin(jwt);
    } catch (e) {
      setError(e.response?.data?.error || "Something went wrong. Try again.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center"
      style={{ backgroundColor: COLORS.darker }}>
      <div className="w-full max-w-md">

        {/* Logo */}
        <div className="text-center mb-8">
          <div className="w-16 h-16 rounded-2xl flex items-center justify-center mx-auto mb-4"
            style={{ backgroundColor: COLORS.blue }}>
            <Shield size={32} color="white" />
          </div>
          <h1 className="text-3xl font-black" style={{ color: COLORS.text }}>AIPET</h1>
          <p className="text-sm mt-1" style={{ color: COLORS.muted }}>
            AI-Powered IoT Security Platform
          </p>
        </div>

        {/* Form card */}
        <div className="rounded-2xl border p-8"
          style={{ backgroundColor: COLORS.card, borderColor: COLORS.border }}>

          <h2 className="text-xl font-black mb-6" style={{ color: COLORS.text }}>
            {isRegister ? "Create your account" : "Sign in to AIPET"}
          </h2>

          {/* Error message */}
          {error && (
            <div className="mb-4 p-3 rounded-xl border text-sm"
              style={{
                backgroundColor: COLORS.critical + "15",
                borderColor: COLORS.critical + "40",
                color: COLORS.critical
              }}>
              {error}
            </div>
          )}

          {/* Name field (register only) */}
          {isRegister && (
            <div className="mb-4">
              <label className="block text-xs font-bold uppercase tracking-wider mb-2"
                style={{ color: COLORS.muted }}>Full Name</label>
              <input
                type="text"
                value={name}
                onChange={e => setName(e.target.value)}
                placeholder="John Smith"
                className="w-full px-4 py-3 rounded-xl text-sm outline-none"
                style={{
                  backgroundColor: COLORS.darker,
                  color: COLORS.text,
                  border: `1px solid ${COLORS.border}`
                }}
              />
            </div>
          )}

          {/* Email field */}
          <div className="mb-4">
            <label className="block text-xs font-bold uppercase tracking-wider mb-2"
              style={{ color: COLORS.muted }}>Email</label>
            <input
              type="email"
              value={email}
              onChange={e => setEmail(e.target.value)}
              placeholder="you@example.com"
              className="w-full px-4 py-3 rounded-xl text-sm outline-none"
              style={{
                backgroundColor: COLORS.darker,
                color: COLORS.text,
                border: `1px solid ${COLORS.border}`
              }}
            />
          </div>

          {/* Password field */}
          <div className="mb-6">
            <label className="block text-xs font-bold uppercase tracking-wider mb-2"
              style={{ color: COLORS.muted }}>Password</label>
            <input
              type="password"
              value={password}
              onChange={e => setPassword(e.target.value)}
              placeholder="Minimum 8 characters"
              className="w-full px-4 py-3 rounded-xl text-sm outline-none"
              style={{
                backgroundColor: COLORS.darker,
                color: COLORS.text,
                border: `1px solid ${COLORS.border}`
              }}
            />
          </div>

          {/* Submit button */}
          <button
            onClick={handleSubmit}
            disabled={loading}
            className="w-full py-3 rounded-xl font-bold text-sm transition-all"
            style={{
              backgroundColor: loading ? COLORS.border : COLORS.blue,
              color: loading ? COLORS.muted : "white",
              cursor: loading ? "not-allowed" : "pointer"
            }}>
            {loading
              ? "Please wait..."
              : isRegister ? "Create Account" : "Sign In"}
          </button>

          {/* Toggle login/register */}
          <div className="mt-4 text-center">
            <button
              onClick={() => { setIsRegister(!isRegister); setError(""); }}
              className="text-sm transition-all"
              style={{ color: COLORS.blue }}>
              {isRegister
                ? "Already have an account? Sign in"
                : "Don't have an account? Register"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
function PricingPage({ currentPlan, onUpgrade, usageLoaded }) {
  const plans = [
    {
      id:       "free",
      name:     "Free",
      price:    "£0",
      period:   "forever",
      color:    COLORS.muted,
      features: [
        "5 scans per month",
        "Single network scanning",
        "Basic AI analysis",
        "PDF reports",
        "Community support",
      ],
      cta:      "Current Plan",
      disabled: true,
    },
    {
      id:       "professional",
      name:     "Professional",
      price:    "£49",
      period:   "per month",
      color:    COLORS.blue,
      popular:  true,
      features: [
        "Unlimited scans",
        "Parallel scanning (3 networks)",
        "Full SHAP AI explanations",
        "All report formats",
        "Email support",
        "Priority queue",
      ],
      cta:      "Upgrade to Pro",
      disabled: false,
    },
    {
      id:       "enterprise",
      name:     "Enterprise",
      price:    "£499",
      period:   "per month",
      color:    COLORS.purple,
      features: [
        "Unlimited scans",
        "Parallel scanning (10 networks)",
        "Full AI analysis + SHAP",
        "API access",
        "Priority support",
        "SLA guarantee",
        "Custom integrations",
      ],
      cta:      "Upgrade to Enterprise",
      disabled: false,
    },
  ];

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="text-center">
        <h2 className="text-3xl font-black mb-2" style={{ color: COLORS.text }}>
          Choose Your Plan
        </h2>
        <p className="text-sm" style={{ color: COLORS.muted }}>
          Upgrade anytime. Cancel anytime. No hidden fees.
        </p>
      </div>

      {/* Plan cards */}
      <div className="grid grid-cols-3 gap-6">
        {plans.map((plan) => {
          const isCurrentPlan = currentPlan === plan.id;
          return (
            <div key={plan.id}
              className="rounded-2xl border flex flex-col relative overflow-hidden transition-all duration-200"
              style={{
                backgroundColor: COLORS.card,
                borderColor: isCurrentPlan ? plan.color : plan.popular ? plan.color + "50" : COLORS.border,
                boxShadow: plan.popular ? `0 0 30px ${plan.color}20` : "none",
              }}>

              {/* Popular badge */}
              {plan.popular && (
                <div className="absolute top-0 right-0 px-3 py-1 text-xs font-bold rounded-bl-xl"
                  style={{ backgroundColor: plan.color, color: "white" }}>
                  POPULAR
                </div>
              )}

              {/* Current plan badge */}
              {isCurrentPlan && (
                <div className="absolute top-0 left-0 px-3 py-1 text-xs font-bold rounded-br-xl"
                  style={{ backgroundColor: plan.color + "30", color: plan.color }}>
                  YOUR PLAN
                </div>
              )}

              <div className="p-6 flex flex-col flex-1">
                {/* Plan name and price */}
                <div className="mb-6 mt-4">
                  <h3 className="text-lg font-black mb-3" style={{ color: plan.color }}>
                    {plan.name}
                  </h3>
                  <div className="flex items-baseline gap-1">
                    <span className="text-4xl font-black" style={{ color: COLORS.text }}>
                      {plan.price}
                    </span>
                    <span className="text-sm" style={{ color: COLORS.muted }}>
                      /{plan.period}
                    </span>
                  </div>
                </div>

                {/* Features */}
                <div className="flex-1 space-y-3 mb-6">
                  {plan.features.map((feature, i) => (
                    <div key={i} className="flex items-center gap-3">
                      <div className="w-5 h-5 rounded-full flex items-center justify-center flex-shrink-0"
                        style={{ backgroundColor: plan.color + "20" }}>
                        <Check size={12} style={{ color: plan.color }} />
                      </div>
                      <span className="text-sm" style={{ color: COLORS.muted }}>
                        {feature}
                      </span>
                    </div>
                  ))}
                </div>

                {/* CTA button */}
                <button
                  onClick={() => !plan.disabled && !isCurrentPlan && onUpgrade(plan.id)}
                  disabled={plan.disabled || isCurrentPlan}
                  className="w-full py-3 rounded-xl font-bold text-sm transition-all duration-200"
                  style={{
                    backgroundColor: isCurrentPlan
                      ? plan.color + "20"
                      : plan.disabled
                      ? COLORS.border
                      : plan.color,
                    color: isCurrentPlan
                      ? plan.color
                      : plan.disabled
                      ? COLORS.muted
                      : "white",
                    cursor: plan.disabled || isCurrentPlan ? "default" : "pointer",
                  }}>
                  {isCurrentPlan ? "Current Plan" : plan.cta}
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function BillingPage({ usage, onUpgrade, onCancel, onPortal, showToast }) {
  if (!usage) return (
    <div className="flex items-center justify-center h-64">
      <div className="text-sm" style={{ color: COLORS.muted }}>Loading billing info...</div>
    </div>
  );

  const isFreePlan   = usage.plan === "free";
  const scansPercent = isFreePlan && usage.scans_limit
    ? (usage.scans_used / usage.scans_limit) * 100
    : 0;

  const planColors = {
    free:         COLORS.muted,
    professional: COLORS.blue,
    enterprise:   COLORS.purple,
  };
  const planColor = planColors[usage.plan] || COLORS.muted;

  return (
    <div className="space-y-6 max-w-2xl">

      {/* Current plan card */}
      <div className="rounded-2xl border p-6"
        style={{ backgroundColor: COLORS.card, borderColor: planColor + "50" }}>
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 rounded-xl flex items-center justify-center"
              style={{ backgroundColor: planColor + "20" }}>
              <CreditCard size={22} style={{ color: planColor }} />
            </div>
            <div>
              <div className="text-xs font-bold uppercase tracking-wider mb-1"
                style={{ color: COLORS.muted }}>Current Plan</div>
              <div className="text-2xl font-black capitalize" style={{ color: planColor }}>
                {usage.plan}
              </div>
            </div>
          </div>
          {usage.is_paid && (
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg"
              style={{ backgroundColor: COLORS.low + "20" }}>
              <div className="w-2 h-2 rounded-full" style={{ backgroundColor: COLORS.low }} />
              <span className="text-xs font-bold" style={{ color: COLORS.low }}>Active</span>
            </div>
          )}
        </div>

        {/* Scan usage */}
        <div className="mb-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm font-semibold" style={{ color: COLORS.text }}>
              Scans this month
            </span>
            <span className="text-sm font-bold" style={{ color: COLORS.text }}>
              {usage.scans_used}
              {usage.scans_limit ? ` / ${usage.scans_limit}` : " / Unlimited"}
            </span>
          </div>

          {isFreePlan && (
            <div className="h-2 rounded-full overflow-hidden"
              style={{ backgroundColor: COLORS.border }}>
              <div className="h-full rounded-full transition-all duration-700"
                style={{
                  width: `${Math.min(scansPercent, 100)}%`,
                  backgroundColor: scansPercent >= 100
                    ? COLORS.critical
                    : scansPercent >= 80
                    ? COLORS.high
                    : COLORS.blue,
                }} />
            </div>
          )}

          {!isFreePlan && (
            <div className="h-2 rounded-full"
              style={{ backgroundColor: COLORS.blue + "40" }}>
              <div className="h-full rounded-full w-full"
                style={{ backgroundColor: COLORS.blue }} />
            </div>
          )}
        </div>

        {/* Days until reset */}
        <div className="flex items-center gap-2 text-xs" style={{ color: COLORS.muted }}>
          <RefreshCw size={12} />
          <span>Resets in {usage.days_until_reset} days</span>
        </div>
      </div>

      {/* Upgrade prompt for free users */}
      {isFreePlan && (
        <div className="rounded-2xl border p-6"
          style={{ backgroundColor: COLORS.blue + "08", borderColor: COLORS.blue + "30" }}>
          <div className="flex items-center gap-3 mb-4">
            <Star size={20} style={{ color: COLORS.blue }} />
            <h3 className="font-bold" style={{ color: COLORS.text }}>
              Upgrade to Professional
            </h3>
          </div>
          <p className="text-sm mb-4" style={{ color: COLORS.muted }}>
            Get unlimited scans, parallel scanning, and full AI analysis for £49/month.
          </p>
          <button onClick={() => onUpgrade("professional")}
            className="w-full py-3 rounded-xl font-bold text-sm transition-all"
            style={{ backgroundColor: COLORS.blue, color: "white" }}>
            Upgrade Now — £49/month
          </button>
        </div>
      )}

      {/* Paid plan actions */}
      {usage.is_paid && (
        <div className="rounded-2xl border p-6 space-y-3"
          style={{ backgroundColor: COLORS.card, borderColor: COLORS.border }}>
          <h3 className="font-bold mb-4" style={{ color: COLORS.text }}>
            Manage Subscription
          </h3>

          <button onClick={onPortal}
            className="w-full py-3 rounded-xl font-semibold text-sm transition-all border"
            style={{
              backgroundColor: "transparent",
              borderColor: COLORS.border,
              color: COLORS.text,
            }}>
            Open Billing Portal
          </button>

          
            
        </div>
      )}

      {/* API access badge */}
      {usage.has_api_access && (
        <div className="rounded-2xl border p-4 flex items-center gap-3"
          style={{ backgroundColor: COLORS.purple + "10", borderColor: COLORS.purple + "30" }}>
          <Lock size={18} style={{ color: COLORS.purple }} />
          <div>
            <div className="text-sm font-bold" style={{ color: COLORS.purple }}>
              API Access Enabled
            </div>
            <div className="text-xs" style={{ color: COLORS.muted }}>
              Enterprise plan includes full API access
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function ScanModal({ onClose, onScan, scanning }) {
  const [target, setTarget] = useState("");
  const [mode, setMode] = useState("demo");
  return (
    <div className="fixed inset-0 flex items-center justify-center z-50"
      style={{ backgroundColor: "rgba(0,0,0,0.8)", backdropFilter: "blur(4px)" }}>
      <div className="rounded-2xl p-6 w-96 border shadow-2xl"
        style={{ backgroundColor: COLORS.card, borderColor: COLORS.border }}>
        <div className="flex items-center gap-3 mb-6">
          <div className="p-2 rounded-xl" style={{ backgroundColor: COLORS.blue + "20" }}>
            <Shield size={20} style={{ color: COLORS.blue }} />
          </div>
          <div>
            <h3 className="font-bold" style={{ color: COLORS.text }}>Start New Scan</h3>
            <p className="text-xs" style={{ color: COLORS.muted }}>Configure your assessment</p>
          </div>
        </div>
        <div className="mb-4">
          <label className="block text-xs font-semibold mb-2 uppercase tracking-wider"
            style={{ color: COLORS.muted }}>Scan Mode</label>
          <div className="grid grid-cols-2 gap-2">
            {["demo", "live"].map(m => (
              <button key={m} onClick={() => setMode(m)}
                className="py-3 rounded-xl text-sm font-semibold transition-all"
                style={{
                  backgroundColor: mode === m ? COLORS.blue : COLORS.border,
                  color: mode === m ? "white" : COLORS.muted
                }}>
                {m === "demo" ? "Demo Mode" : "Live Scan"}
              </button>
            ))}
          </div>
        </div>
        {mode === "live" && (
          <div className="mb-4">
            <label className="block text-xs font-semibold mb-2 uppercase tracking-wider"
              style={{ color: COLORS.muted }}>Target IP / Range</label>
            <input type="text" value={target} onChange={e => setTarget(e.target.value)}
              placeholder="e.g. 192.168.1.0/24"
              className="w-full px-4 py-3 rounded-xl text-sm outline-none transition-all"
              style={{
                backgroundColor: COLORS.darker,
                color: COLORS.text,
                border: `1px solid ${COLORS.border}`
              }} />
          </div>
        )}
        <div className="flex gap-2 mt-6">
          <button onClick={onClose}
            className="flex-1 py-3 rounded-xl text-sm font-semibold transition-all"
            style={{ backgroundColor: COLORS.border, color: COLORS.muted }}>
            Cancel
          </button>
          <button onClick={() => { onScan(mode, target); onClose(); }}
            className="flex-1 py-3 rounded-xl text-sm font-semibold transition-all"
            style={{ backgroundColor: COLORS.blue, color: "white" }}>
            Launch Scan
          </button>
        </div>
      </div>
    </div>
  );
}

const NAV_ITEMS = [
  { id: "dashboard", label: "Dashboard",   icon: Activity      },
  { id: "devices",   label: "Devices",     icon: Cpu           },
  { id: "findings",  label: "Findings",    icon: AlertTriangle },
  { id: "ai",        label: "AI Analysis", icon: Shield        },
  { id: "reports",   label: "Reports",     icon: FileText      },
  { id: "pricing",   label: "Pricing",     icon: Zap           },
  { id: "billing",   label: "Billing",     icon: Lock          },
  { id: "apikeys",   label: "API Keys",    icon: CreditCard    },
];

export default function App() {
  const [data,       setData]       = useState({});
  const [activeTab,  setActiveTab]  = useState("dashboard");
  const [showScan,   setShowScan]   = useState(false);
  const [loading,    setLoading]    = useState(true);
  const [scanning,   setScanning]   = useState(false);
  const [filter,     setFilter]     = useState("ALL");
  const [searchText, setSearchText] = useState("");
  const [usage,      setUsage]      = useState(null);
  const [token, setToken] = useState(localStorage.getItem("aipet_token") || "");
  const [showLanding, setShowLanding] = useState(!localStorage.getItem("aipet_token"));
  const [legalPage, setLegalPage] = useState(null);
  const [toast, setToast] = useState(null);

  const showToast = (message, type = "success") => {
    setToast({ message, type });
    setTimeout(() => setToast(null), 4000);
  };
  const usageLoaded = usage !== null;

  const handleLogin = (jwt) => {
    setToken(jwt);
  };

  const handleLogout = () => {
    localStorage.removeItem("aipet_token");
    setToken("");
    setUsage(null);
  };
  
  const fetchAll = useCallback(async () => {
    const headers = { Authorization: `Bearer ${token}` };
    try {
      const [s, d, f, a, r, sc, scans] = await Promise.all([
        axios.get(`${API}/summary`,     { headers }),
        axios.get(`${API}/devices`,     { headers }),
        axios.get(`${API}/findings`,    { headers }),
        axios.get(`${API}/ai`,          { headers }),
        axios.get(`${API}/reports`,     { headers }),
        axios.get(`${API}/scan/status`, { headers }),
        axios.get(`${API}/scans`,       { headers }),
      ]);
      setData({
        summary:    s.data,
        devices:    Array.isArray(d.data) ? d.data : [],
        findings:   Array.isArray(f.data) ? f.data : [],
        aiResults:  Array.isArray(a.data) ? a.data : [],
        reports:    Array.isArray(r.data) ? r.data : [],
        scanStatus: sc.data,
        scans:      Array.isArray(scans.data) ? scans.data : [],
      });;
      setScanning(sc.data?.running || false);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  }, [token]);

 useEffect(() => {
    fetchAll();
    const interval = setInterval(fetchAll, 60000);
    return () => clearInterval(interval);
  }, [fetchAll]);

  const fetchUsage = useCallback(async () => {
    if (!token) return;
    try {
      const res = await axios.get(`http://localhost:5001/api/user/usage`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setUsage(res.data);
    } catch (e) {
      console.error("Usage fetch failed:", e);
    }
  }, [token]);

  useEffect(() => {
    fetchUsage();
  }, [fetchUsage]);

  const handleUpgrade = async (plan) => {
    try {
      const res = await axios.post(
        `http://localhost:5001/payments/create-checkout-session`,
        { plan },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      window.location.href = res.data.checkout_url;
       } catch (e) {
      showToast("Payment error. Please try again.", "error");
    }
  };

  const handlePortal = async () => {
    try {
      const res = await axios.post(
        `http://localhost:5001/payments/portal`,
        {},
        { headers: { Authorization: `Bearer ${token}` } }
      );
      window.location.href = res.data.portal_url;
      } catch (e) {
      showToast("Could not open billing portal.", "error");
    }
  };

  const handleCancel = async () => {
    if (!window.confirm("Are you sure you want to cancel your subscription?")) return;
    try {
      await axios.post(
        `http://localhost:5001/payments/cancel`,
        {

        },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      showToast("Subscription cancelled. You keep access until the end of your billing period.", "info");;
     } catch (e) {
      showToast("Could not cancel subscription.", "error");
    }
  };

 const startScan = async (mode, target) => {
    // Check scan limit before starting
    if (usage && usage.plan === "free" && usage.scans_used >= 5) {
      setActiveTab("pricing");
      return;
    }

    setScanning(true);
    try {
      await axios.post(`${API}/scan/start`, { mode, target }, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setTimeout(fetchAll, 3000);
      // Refresh usage after scan
      setTimeout(fetchUsage, 3000);
    } catch (e) {
      if (e.response?.status === 403) {
        // Backend blocked the scan — redirect to pricing
        setActiveTab("pricing");
      }
      setScanning(false);
    }
  };

  const { summary, devices=[], findings=[], aiResults=[], reports=[], scanStatus } = data;

  const riskScores = { CRITICAL: 95, HIGH: 75, MEDIUM: 45, LOW: 15 };
  const riskScore  = summary ? riskScores[summary.overall_risk] || 0 : 0;
  const riskColor  = summary?.risk_color || COLORS.muted;

  const pieData = summary ? [
    { name: "Critical", value: summary.findings?.critical || 0, color: COLORS.critical },
    { name: "High",     value: summary.findings?.high     || 0, color: COLORS.high     },
    { name: "Medium",   value: summary.findings?.medium   || 0, color: COLORS.medium   },
    { name: "Low",      value: summary.findings?.low      || 0, color: COLORS.low      },
  ].filter(d => d.value > 0) : [];

  const filteredFindings = findings.filter(f => {
    const matchSev  = filter === "ALL" || f.severity.toUpperCase() === filter;
    const matchText = searchText === "" ||
      f.attack.toLowerCase().includes(searchText.toLowerCase()) ||
      f.finding.toLowerCase().includes(searchText.toLowerCase());
    return matchSev && matchText;
  });

  // If no token, show landing page or login page
  if (!token) {
    if (legalPage) {
      return (
        <LegalPage
          page={legalPage}
          onBack={() => setLegalPage(null)}
        />
      );
    }
    if (showLanding) {
      return (
        <LandingPage
          onGetStarted={() => setShowLanding(false)}
          onLogin={() => setShowLanding(false)}
          setLegalPage={setLegalPage}
        />
      );
    }
    return <LoginPage onLogin={handleLogin} />;
  }

  if (loading) return (
    <div className="min-h-screen flex items-center justify-center"
      style={{ backgroundColor: COLORS.darker }}>
      <div className="text-center">
        <div className="relative w-20 h-20 mx-auto mb-6">
          <Shield size={80} style={{ color: COLORS.blue }} className="animate-pulse" />
        </div>
        <div className="text-xl font-bold mb-2" style={{ color: COLORS.text }}>AIPET</div>
        <div className="text-sm" style={{ color: COLORS.muted }}>Loading security dashboard...</div>
      </div>
    </div>
  );

  return (
    <div className="flex min-h-screen" style={{ backgroundColor: COLORS.darker, color: COLORS.text }}>

      {/* Sidebar */}
      <div className="w-64 flex flex-col border-r flex-shrink-0"
        style={{ backgroundColor: COLORS.dark, borderColor: COLORS.border }}>

        {/* Logo */}
        <div className="p-6 border-b" style={{ borderColor: COLORS.border }}>
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl flex items-center justify-center"
              style={{ backgroundColor: COLORS.blue }}>
              <Shield size={20} color="white" />
            </div>
            <div>
              <div className="font-black text-lg tracking-tight" style={{ color: COLORS.text }}>AIPET</div>
              <div className="text-xs" style={{ color: COLORS.muted }}>v1.0.0 — IoT Security</div>
            </div>
          </div>
        </div>

        {/* Status indicator */}
        {scanning && (
          <div className="mx-4 mt-4 p-3 rounded-xl border"
            style={{ backgroundColor: COLORS.blue + "15", borderColor: COLORS.blue + "40" }}>
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 rounded-full animate-pulse" style={{ backgroundColor: COLORS.blue }} />
              <span className="text-xs font-semibold" style={{ color: COLORS.blue }}>Scan in progress...</span>
            </div>
          </div>
        )}

        {/* Navigation */}
        <nav className="flex-1 p-4 space-y-1">
          {NAV_ITEMS.map(({ id, label, icon: Icon }) => {
            const active = activeTab === id;
            return (
              <button key={id} onClick={() => setActiveTab(id)}
                className="w-full flex items-center gap-3 px-4 py-3 rounded-xl text-sm font-semibold transition-all duration-200"
                style={{
                  backgroundColor: active ? COLORS.blue + "20" : "transparent",
                  color: active ? COLORS.blue : COLORS.muted,
                  borderLeft: active ? `3px solid ${COLORS.blue}` : "3px solid transparent"
                }}>
                <Icon size={18} />
                {label}
                {id === "findings" && findings.length > 0 && (
                  <span className="ml-auto text-xs px-2 py-0.5 rounded-full"
                    style={{ backgroundColor: COLORS.critical + "20", color: COLORS.critical }}>
                    {findings.filter(f => f.severity === "CRITICAL").length}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
        {/* Logout button */}
        <div className="px-4 pb-2">
          <button onClick={handleLogout}
            className="w-full flex items-center justify-center gap-2 py-2 rounded-xl text-xs font-medium transition-all"
            style={{ color: COLORS.critical, backgroundColor: COLORS.critical + "10" }}>
            <X size={12} />
            Sign Out
          </button>
        </div>

        {/* Scan button */}
        <div className="p-4 border-t" style={{ borderColor: COLORS.border }}>
          <button onClick={() => setShowScan(true)} disabled={scanning}
            className="w-full flex items-center justify-center gap-2 py-3 rounded-xl font-bold text-sm transition-all duration-200"
            style={{
              backgroundColor: scanning ? COLORS.border : COLORS.blue,
              color: scanning ? COLORS.muted : "white",
              opacity: scanning ? 0.7 : 1
            }}>
            {scanning
              ? <><RefreshCw size={16} className="animate-spin" /> Scanning...</>
              : <><Play size={16} /> New Scan</>}
          </button>
          <button onClick={fetchAll}
            className="w-full flex items-center justify-center gap-2 py-2 mt-2 rounded-xl text-xs font-medium transition-all"
            style={{ color: COLORS.muted }}>
            <RefreshCw size={12} /> Refresh Data
          </button>
        </div>
      </div>

      {/* Main content */}
      <div className="flex-1 overflow-auto">

        {/* Header */}
        <div className="sticky top-0 z-10 px-8 py-4 border-b flex items-center justify-between"
          style={{ backgroundColor: COLORS.dark + "ee", borderColor: COLORS.border, backdropFilter: "blur(12px)" }}>
          <div>
            <h1 className="text-xl font-black capitalize tracking-tight" style={{ color: COLORS.text }}>
              {NAV_ITEMS.find(n => n.id === activeTab)?.label}
            </h1>
            <p className="text-xs mt-0.5" style={{ color: COLORS.muted }}>
              {summary?.last_scan ? `Last scan: ${summary.last_scan}` : "No scans yet — run a scan to begin"}
            </p>
          </div>
          <div className="flex items-center gap-3">
            {/* Plan badge */}
            {usage && (
              <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg border"
                style={{
                  borderColor: (usage.plan === 'enterprise' ? COLORS.purple : usage.plan === 'professional' ? COLORS.blue : COLORS.muted) + "40",
                  backgroundColor: (usage.plan === 'enterprise' ? COLORS.purple : usage.plan === 'professional' ? COLORS.blue : COLORS.muted) + "15"
                }}>
                <span className="text-xs font-bold capitalize"
                  style={{ color: usage.plan === 'enterprise' ? COLORS.purple : usage.plan === 'professional' ? COLORS.blue : COLORS.muted }}>
                  {usage.plan}
                </span>
              </div>
            )}
            {/* Risk badge */}
            {summary && (
              <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg border"
                style={{ borderColor: riskColor + "40", backgroundColor: riskColor + "10" }}>
                <div className="w-2 h-2 rounded-full" style={{ backgroundColor: riskColor }} />
                <span className="text-xs font-bold" style={{ color: riskColor }}>
                  {summary.overall_risk}
                </span>
              </div>
            )}
            {/* User greeting */}
            {summary?.user && (
              <div className="text-xs font-semibold" style={{ color: COLORS.muted }}>
                {summary.user.name}
              </div>
            )}
          </div>
        </div>

        <div className="p-8">

          {/* DASHBOARD */}
          {activeTab === "dashboard" && !summary && !loading && (
            <div className="flex flex-col items-center justify-center h-96 text-center">
              <div className="w-20 h-20 rounded-2xl flex items-center justify-center mb-6"
                style={{ backgroundColor: COLORS.blue + "20" }}>
                <Shield size={40} style={{ color: COLORS.blue }} />
              </div>
              <h2 className="text-2xl font-black mb-3" style={{ color: COLORS.text }}>
                Welcome to AIPET Cloud
              </h2>
              <p className="text-sm mb-8 max-w-md" style={{ color: COLORS.muted }}>
                Run your first IoT security scan to see your risk dashboard,
                discovered devices, and AI-powered vulnerability analysis.
              </p>
              <button onClick={() => setShowScan(true)}
                className="flex items-center gap-2 px-8 py-4 rounded-xl font-bold text-sm transition-all"
                style={{ backgroundColor: COLORS.blue, color: "white" }}>
                <Play size={16} />
                Run Your First Scan
              </button>
            </div>
          )}
          {activeTab === "dashboard" && summary && (
            <div className="space-y-6">
              <div className="grid grid-cols-4 gap-4">
                {/* Risk gauge */}
                <div className="rounded-2xl border col-span-1"
                  style={{ backgroundColor: COLORS.card, borderColor: COLORS.border }}>
                  <RiskGauge risk={summary.overall_risk} color={riskColor} score={riskScore} />
                </div>

                {/* Stat cards */}
                <div className="col-span-3 grid grid-cols-3 gap-4">
                  <StatCard title="Devices Discovered" value={summary.devices}
                    icon={Cpu} color={COLORS.purple} />
                  <StatCard title="Critical Findings" value={summary.findings?.critical || 0}
                    icon={AlertOctagon} color={COLORS.critical} />
                  <StatCard title="Total Findings" value={summary.findings?.total || 0}
                    icon={Eye} color={COLORS.blue} />
                  <StatCard title="High Severity" value={summary.findings?.high || 0}
                    icon={AlertTriangle} color={COLORS.high} />
                  <StatCard title="Medium Severity" value={summary.findings?.medium || 0}
                    icon={Zap} color={COLORS.medium} />
                  <StatCard title="Modules Run" value={summary.modules_run?.length || 0}
                    icon={Activity} color={COLORS.low} />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-6">
                {/* Pie chart */}
                <div className="rounded-2xl p-6 border"
                  style={{ backgroundColor: COLORS.card, borderColor: COLORS.border }}>
                  <h3 className="font-bold mb-4 flex items-center gap-2" style={{ color: COLORS.text }}>
                    <AlertTriangle size={16} style={{ color: COLORS.high }} />
                    Findings by Severity
                  </h3>
                  {pieData.length > 0 ? (
                    <ResponsiveContainer width="100%" height={220}>
                      <PieChart>
                        <Pie data={pieData} cx="50%" cy="50%" outerRadius={85}
                          innerRadius={45} dataKey="value" paddingAngle={3}
                          label={({ name, value }) => `${name}: ${value}`}
                          labelLine={{ stroke: COLORS.muted }}>
                          {pieData.map((entry, i) => <Cell key={i} fill={entry.color} />)}
                        </Pie>
                        <Tooltip contentStyle={{
                          backgroundColor: COLORS.card,
                          border: `1px solid ${COLORS.border}`,
                          borderRadius: "12px",
                          color: COLORS.text
                        }} />
                      </PieChart>
                    </ResponsiveContainer>
                  ) : (
                    <div className="flex items-center justify-center h-48">
                      <p style={{ color: COLORS.muted }}>No findings yet</p>
                    </div>
                  )}
                </div>

                {/* Modules */}
                <div className="rounded-2xl p-6 border"
                  style={{ backgroundColor: COLORS.card, borderColor: COLORS.border }}>
                  <h3 className="font-bold mb-4 flex items-center gap-2" style={{ color: COLORS.text }}>
                    <CheckCircle size={16} style={{ color: COLORS.low }} />
                    Modules Executed
                  </h3>
                  <div className="space-y-2">
                    {(summary.modules_run || []).map((m, i) => (
                      <div key={i} className="flex items-center gap-3 p-3 rounded-xl"
                        style={{ backgroundColor: COLORS.darker }}>
                        <CheckCircle size={16} style={{ color: COLORS.low }} />
                        <span className="text-sm font-medium" style={{ color: COLORS.text }}>{m}</span>
                        <span className="ml-auto text-xs px-2 py-0.5 rounded-full"
                          style={{ backgroundColor: COLORS.low + "20", color: COLORS.low }}>
                          DONE
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* DEVICES */}
          {activeTab === "devices" && (
            <div className="space-y-4">
              {devices.length === 0 ? (
                <div className="rounded-2xl p-16 border text-center"
                  style={{ backgroundColor: COLORS.card, borderColor: COLORS.border }}>
                  <Cpu size={48} style={{ color: COLORS.muted }} className="mx-auto mb-4" />
                  <p className="font-semibold" style={{ color: COLORS.muted }}>No devices found. Run a scan first.</p>
                </div>
              ) : devices.map((device, i) => (
                <div key={i} className="rounded-2xl p-6 border transition-all hover:border-blue-500/30"
                  style={{ backgroundColor: COLORS.card, borderColor: COLORS.border }}>
                  <div className="flex items-start justify-between mb-5">
                    <div className="flex items-center gap-4">
                      <div className="w-14 h-14 rounded-2xl flex items-center justify-center"
                        style={{ backgroundColor: COLORS.blue + "20" }}>
                        <Server size={26} style={{ color: COLORS.blue }} />
                      </div>
                      <div>
                        <div className="font-black text-xl" style={{ color: COLORS.text }}>{device.ip}</div>
                        <div className="text-sm mt-0.5" style={{ color: COLORS.muted }}>{device.device_type}</div>
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      {device.ai_severity && <SeverityBadge severity={device.ai_severity} />}
                      <div className="text-right">
                        <div className="text-2xl font-black" style={{ color: riskColor }}>{device.risk_score}</div>
                        <div className="text-xs" style={{ color: COLORS.muted }}>Risk Score</div>
                      </div>
                    </div>
                  </div>

                  <div className="grid grid-cols-3 gap-3 mb-4">
                    {[
                      { label: "Open Ports", value: device.ports?.join(", ") || "None" },
                      { label: "Risk Label", value: device.risk_label || "N/A" },
                      { label: "AI Confidence", value: device.ai_confidence ? `${(device.ai_confidence * 100).toFixed(1)}%` : "N/A" },
                    ].map(({ label, value }) => (
                      <div key={label} className="p-4 rounded-xl"
                        style={{ backgroundColor: COLORS.darker }}>
                        <div className="text-xs mb-1" style={{ color: COLORS.muted }}>{label}</div>
                        <div className="font-bold text-sm" style={{ color: COLORS.text }}>{value}</div>
                      </div>
                    ))}
                  </div>

                  {device.ai_explanation && (
                    <div className="p-4 rounded-xl border"
                      style={{ backgroundColor: COLORS.blue + "08", borderColor: COLORS.blue + "30" }}>
                      <div className="text-xs font-bold mb-2 uppercase tracking-wider" style={{ color: COLORS.blue }}>
                        AI Explanation
                      </div>
                      <pre className="text-xs leading-relaxed whitespace-pre-wrap font-mono"
                        style={{ color: COLORS.muted }}>{device.ai_explanation}</pre>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}

          {/* FINDINGS */}
          {activeTab === "findings" && (
            <div className="space-y-4">
             {/* Risk Reduction Score + Executive Report */}
              <RiskReductionBar findings={findings} token={token} scans={data?.scans || []} />

              {/* AIPET Score — Financial Risk */}
              <ScorePanel findings={findings} token={token} scans={data?.scans || []} />
              
              {/* Controls */}
              <div className="flex items-center gap-3">
                <input
                  type="text"
                  placeholder="Search findings..."
                  value={searchText}
                  onChange={e => setSearchText(e.target.value)}
                  className="flex-1 px-4 py-2.5 rounded-xl text-sm outline-none"
                  style={{
                    backgroundColor: COLORS.card,
                    color: COLORS.text,
                    border: `1px solid ${COLORS.border}`
                  }}
                />
                <div className="flex gap-2">
                  {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map(s => (
                    <button key={s} onClick={() => setFilter(s)}
                      className="px-3 py-2 rounded-xl text-xs font-bold transition-all"
                      style={{
                        backgroundColor: filter === s
                          ? (SEVERITY_CONFIG[s]?.color || COLORS.blue) + "20"
                          : COLORS.card,
                        color: filter === s
                          ? (SEVERITY_CONFIG[s]?.color || COLORS.blue)
                          : COLORS.muted,
                        border: `1px solid ${filter === s
                          ? (SEVERITY_CONFIG[s]?.color || COLORS.blue) + "40"
                          : COLORS.border}`
                      }}>
                      {s}
                      {s !== "ALL" && (
                        <span className="ml-1">
                          ({findings.filter(f => f.severity === s).length})
                        </span>
                      )}
                    </button>
                  ))}
                </div>
              </div>

              {filteredFindings.length === 0 ? (
                <div className="rounded-2xl p-16 border text-center"
                  style={{ backgroundColor: COLORS.card, borderColor: COLORS.border }}>
                  <CheckCircle size={48} style={{ color: COLORS.muted }} className="mx-auto mb-4" />
                  <p style={{ color: COLORS.muted }}>No findings match your filter.</p>
                </div>
              ) : filteredFindings.map((f, i) => <FindingRow key={i} finding={f} token={token} onStatusUpdate={() => {}} />)}
            </div>
          )}

          {/* AI ANALYSIS */}
          {activeTab === "ai" && (
            <div className="space-y-6">
              {aiResults.length === 0 ? (
                <div className="rounded-2xl p-16 border text-center"
                  style={{ backgroundColor: COLORS.card, borderColor: COLORS.border }}>
                  <Shield size={48} style={{ color: COLORS.muted }} className="mx-auto mb-4" />
                  <p style={{ color: COLORS.muted }}>No AI results yet. Run a scan first.</p>
                </div>
              ) : aiResults.map((result, i) => {
                const pred     = result.prediction || {};
                const contribs = pred.shap_contributions || {};
                const top6     = Object.entries(contribs)
                  .sort((a, b) => Math.abs(b[1]) - Math.abs(a[1]))
                  .slice(0, 6);
                const cfg = SEVERITY_CONFIG[pred.predicted_severity] || SEVERITY_CONFIG.INFO;

                return (
                  <div key={i} className="rounded-2xl border overflow-hidden"
                    style={{ backgroundColor: COLORS.card, borderColor: COLORS.border }}>
                    {/* Header */}
                    <div className="p-6 border-b flex items-center justify-between"
                      style={{ borderColor: COLORS.border, backgroundColor: cfg.color + "08" }}>
                      <div className="flex items-center gap-4">
                        <div className="w-12 h-12 rounded-xl flex items-center justify-center"
                          style={{ backgroundColor: cfg.color + "20" }}>
                          <Shield size={24} style={{ color: cfg.color }} />
                        </div>
                        <div>
                          <div className="font-black text-lg" style={{ color: COLORS.text }}>{result.ip}</div>
                          <div className="text-sm" style={{ color: COLORS.muted }}>{result.device_type}</div>
                        </div>
                      </div>
                      <div className="text-right">
                        <SeverityBadge severity={pred.predicted_severity} />
                        <div className="text-sm mt-1" style={{ color: COLORS.muted }}>
                          {((pred.confidence || 0) * 100).toFixed(1)}% confidence
                        </div>
                      </div>
                    </div>

                    <div className="p-6 grid grid-cols-2 gap-6">
                      {/* SHAP bars */}
                      <div>
                        <h4 className="text-xs font-bold uppercase tracking-wider mb-4"
                          style={{ color: COLORS.muted }}>
                          Key Factors (SHAP Values)
                        </h4>
                        <div className="space-y-1">
                          {top6.map(([feature, value], j) => (
                            <ShapBar key={j} feature={feature} value={value} />
                          ))}
                        </div>
                        <div className="flex items-center gap-4 mt-3 text-xs" style={{ color: COLORS.muted }}>
                          <span className="flex items-center gap-1">
                            <span className="w-3 h-1.5 rounded inline-block" style={{ backgroundColor: COLORS.critical }} />
                            Increases severity
                          </span>
                          <span className="flex items-center gap-1">
                            <span className="w-3 h-1.5 rounded inline-block" style={{ backgroundColor: COLORS.low }} />
                            Reduces severity
                          </span>
                        </div>
                      </div>

                      {/* Probability breakdown */}
                      <div>
                        <h4 className="text-xs font-bold uppercase tracking-wider mb-4"
                          style={{ color: COLORS.muted }}>
                          Severity Probability
                        </h4>
                        <div className="space-y-3">
                          {Object.entries(pred.probabilities || {}).map(([sev, prob]) => {
                            const scfg = SEVERITY_CONFIG[sev] || SEVERITY_CONFIG.INFO;
                            return (
                              <div key={sev}>
                                <div className="flex justify-between text-xs mb-1">
                                  <span style={{ color: scfg.color }}>{sev}</span>
                                  <span style={{ color: COLORS.muted }}>{(prob * 100).toFixed(1)}%</span>
                                </div>
                                <div className="h-2 rounded-full overflow-hidden"
                                  style={{ backgroundColor: COLORS.border }}>
                                  <div className="h-full rounded-full transition-all duration-700"
                                    style={{
                                      width: `${prob * 100}%`,
                                      backgroundColor: scfg.color
                                    }} />
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          {/* REPORTS */}
          {activeTab === "reports" && (
            <div className="space-y-3">
              {reports.length === 0 ? (
                <div className="rounded-2xl p-16 border text-center"
                  style={{ backgroundColor: COLORS.card, borderColor: COLORS.border }}>
                  <FileText size={48} style={{ color: COLORS.muted }} className="mx-auto mb-4" />
                  <p style={{ color: COLORS.muted }}>No reports yet. Run a scan first.</p>
                </div>
              ) : reports.map((report, i) => (
                <div key={i} className="rounded-xl p-4 border flex items-center justify-between transition-all hover:border-blue-500/30"
                  style={{ backgroundColor: COLORS.card, borderColor: COLORS.border }}>
                  <div className="flex items-center gap-4">
                    <div className="w-10 h-10 rounded-xl flex items-center justify-center"
                      style={{ backgroundColor: COLORS.blue + "20" }}>
                      <FileText size={18} style={{ color: COLORS.blue }} />
                    </div>
                    <div>
                      <div className="font-semibold text-sm" style={{ color: COLORS.text }}>{report.filename}</div>
                      <div className="text-xs mt-0.5" style={{ color: COLORS.muted }}>
                        {report.created} · {(report.size / 1024).toFixed(1)} KB
                      </div>
                    </div>
                  </div>
                  <a href={`${API}/reports/${report.filename}`} download
                    className="flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-semibold transition-all"
                    style={{ backgroundColor: COLORS.blue, color: "white" }}>
                    <Download size={14} />
                    Download
                  </a>
                </div>
              ))}
            </div>
      )}
      {/* Loading state */}
      {!usageLoaded && (
        <div className="text-center py-4">
          <p className="text-sm" style={{ color: COLORS.muted }}>
            Loading your plan details...
          </p>
        </div>
      )}

          {/* PRICING */}
          {activeTab === "pricing" && (
            <PricingPage
              currentPlan={usage?.plan || "free"}
              onUpgrade={handleUpgrade}
              usageLoaded={usage !== null}
            />
          )}

          {/* BILLING */}
          {activeTab === "billing" && (
            <BillingPage
              usage={usage}
              onUpgrade={handleUpgrade}
              onCancel={handleCancel}
              onPortal={handlePortal}
            />
          )}
          {/* API KEYS */}
          {activeTab === "apikeys" && (
            <ApiKeysPage
              token={token}
              userPlan={usage?.plan || "free"}
            />
          )}

        </div>
      </div>
    {showScan && <ScanModal onClose={() => setShowScan(false)} onScan={startScan} scanning={scanning} />}
      <Toast toast={toast} />
    </div>
  );
}
