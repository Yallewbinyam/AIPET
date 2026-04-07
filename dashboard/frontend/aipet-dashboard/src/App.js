
import { useState, useEffect, useCallback, useRef } from "react";
import { useTranslation } from "react-i18next";
import "./i18n";
import axios from "axios";
import * as d3 from "d3";
// Load JetBrains Mono font for technical aesthetic
const fontLink = document.createElement("link");
fontLink.href = "https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Inter:wght@400;500;600;700&family=Noto+Sans+KR:wght@400;500;700&family=Noto+Sans+SC:wght@400;500;700&family=Noto+Sans+Arabic:wght@400;500;700&display=swap";
fontLink.rel = "stylesheet";
document.head.appendChild(fontLink);
const autofillStyle = document.createElement("style");
autofillStyle.textContent = `
  input:-webkit-autofill,
  input:-webkit-autofill:hover,
  input:-webkit-autofill:focus {
    -webkit-box-shadow: 0 0 0 1000px #030712 inset !important;
    -webkit-text-fill-color: #ffffff !important;
    caret-color: #ffffff !important;
  }
`;
document.head.appendChild(autofillStyle);
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
  // Alert colours
  critical: "#ff4444",
  high:     "#ff8c00",
  medium:   "#f5c518",
  low:      "#00ff88",
  info:     "#6b7280",

  // Brand colours
  blue:     "#00d4ff",
  purple:   "#8b5cf6",
  cyan:     "#00d4ff",

  // Background layers
  dark:     "#080c10",
  darker:   "#04060a",
  card:     "#0d1117",
  cardHover:"#111820",

  // Borders
  border:   "#21262d",
  borderHover: "#30363d",

  // Typography
  text:     "#e6edf3",
  muted:    "#7d8590",
  subtle:   "#484f58",
}

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
function AskPanel({ token }) {
  const [messages, setMessages]   = useState([]);
  const [question, setQuestion]   = useState("");
  const [loading, setLoading]     = useState(false);
  const [error, setError]         = useState(null);
  const messagesEndRef             = useRef(null);

  const headers = { Authorization: `Bearer ${token}` };

  const SUGGESTED_QUESTIONS = [
    "What should I fix first this week?",
    "Which device is most at risk right now?",
    "Write a one-paragraph summary for my board",
    "How much financial risk can I eliminate today?",
    "What would an attacker target first on my network?",
    "Explain our biggest vulnerability in plain English",
  ];

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const sendQuestion = async (q) => {
    const questionText = q || question.trim();
    if (!questionText || loading) return;

    setQuestion("");
    setError(null);

    // Add user message
    const newMessages = [...messages, { role: "user", content: questionText }];
    setMessages(newMessages);
    setLoading(true);

    try {
      const res = await axios.post(`${API}/ask`, {
        question: questionText,
        history:  messages.slice(-10)
      }, { headers });

      // Add assistant response
      setMessages(prev => [...prev, {
        role:    "assistant",
        content: res.data.answer,
        tokens:  res.data.tokens_used,
      }]);
    } catch (err) {
      if (err.response?.status === 403) {
        setError("upgrade");
      } else {
        setError("Failed to get answer. Please try again.");
        // Remove the user message if failed
        setMessages(messages);
      }
    } finally {
      setLoading(false);
    }
  };

  const clearConversation = () => {
    setMessages([]);
    setError(null);
  };

  if (error === "upgrade") return (
    <div className="rounded-2xl p-16 border text-center"
      style={{ backgroundColor: COLORS.card, borderColor: COLORS.border }}>
      <Shield size={48} style={{ color: COLORS.muted }} className="mx-auto mb-4" />
      <div className="text-sm font-bold mb-2" style={{ color: COLORS.text }}>Professional Feature</div>
      <div className="text-xs" style={{ color: COLORS.muted }}>
        AIPET Ask is available on Professional and Enterprise plans.
      </div>
    </div>
  );

  return (
    <div className="flex flex-col space-y-4">

      {/* Header */}
      <div className="rounded-xl border p-5 flex items-center justify-between"
        style={{ backgroundColor: COLORS.card, borderColor: COLORS.cyan + "30", background: `linear-gradient(135deg, ${COLORS.card} 0%, rgba(0,229,255,0.03) 100%)` }}>
        <div>
          <div className="flex items-center gap-2 mb-1">
            <div className="w-2 h-2 rounded-full" style={{ backgroundColor: COLORS.cyan, boxShadow: `0 0 8px ${COLORS.cyan}` }} />
            <div className="text-base font-black" style={{ color: COLORS.text, fontFamily: "'JetBrains Mono', monospace", letterSpacing: "0.05em" }}>AIPET Ask</div>
          </div>
          <div className="text-xs mt-0.5" style={{ color: COLORS.muted }}>
            Ask any security question — Claude AI answers using your actual device data, findings, and financial exposure
          </div>
        </div>
        {messages.length > 0 && (
          <button onClick={clearConversation}
            className="px-3 py-1.5 rounded-lg text-xs font-bold transition-all"
            style={{
              backgroundColor: "transparent",
              color: COLORS.muted,
              border: `1px solid ${COLORS.border}`
            }}>
            Clear Chat
          </button>
        )}
      </div>

      {/* Suggested questions */}
      {messages.length === 0 && (
        <div className="rounded-xl border p-4"
          style={{ backgroundColor: COLORS.card, borderColor: COLORS.border }}>
          <div className="text-xs font-bold uppercase tracking-widest mb-3" style={{ color: COLORS.cyan, opacity: 0.7, fontFamily: "'JetBrains Mono', monospace" }}>
            Suggested Questions
          </div>
          <div className="grid grid-cols-2 gap-2">
            {SUGGESTED_QUESTIONS.map((q, i) => (
              <button key={i} onClick={() => sendQuestion(q)}
                className="text-left px-4 py-3 rounded-lg text-xs transition-all"
                style={{
                  backgroundColor: COLORS.dark,
                  color: COLORS.text,
                  border: `1px solid ${COLORS.border}`,
                  lineHeight: "1.5",
                }}
                onMouseEnter={e => {
                  e.currentTarget.style.borderColor = COLORS.cyan + "60";
                  e.currentTarget.style.backgroundColor = `rgba(0,229,255,0.05)`;
                  e.currentTarget.style.color = COLORS.cyan;
                }}
                onMouseLeave={e => {
                  e.currentTarget.style.borderColor = COLORS.border;
                  e.currentTarget.style.backgroundColor = COLORS.dark;
                  e.currentTarget.style.color = COLORS.text;
                }}>
                {q}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Conversation */}
      {messages.length > 0 && (
        <div className="rounded-xl border overflow-hidden"
          style={{ backgroundColor: COLORS.card, borderColor: COLORS.border }}>
          <div className="p-4 space-y-4 max-h-96 overflow-y-auto">
            {messages.map((msg, i) => (
              <div key={i} className={`flex ${msg.role === "user" ? "justify-end" : "justify-start"}`}>
                <div className={`max-w-3xl rounded-xl p-3 text-xs leading-relaxed ${
                  msg.role === "user" ? "ml-8" : "mr-8"
                }`}
                  style={{
                    backgroundColor: msg.role === "user"
                      ? COLORS.blue + "20"
                      : COLORS.dark,
                    color: COLORS.text,
                    border: `1px solid ${msg.role === "user" ? COLORS.blue + "40" : COLORS.border}`
                  }}>
                  {msg.role === "assistant" && (
                    <div className="text-xs font-bold mb-1" style={{ color: COLORS.blue }}>
                      AIPET Ask
                    </div>
                  )}
                  <div className="whitespace-pre-wrap">{msg.content}</div>
                  {msg.tokens && (
                    <div className="text-xs mt-2" style={{ color: COLORS.muted }}>
                      {msg.tokens} tokens
                    </div>
                  )}
                </div>
              </div>
            ))}

            {loading && (
              <div className="flex justify-start">
                <div className="rounded-xl p-3 text-xs"
                  style={{ backgroundColor: COLORS.dark, color: COLORS.muted, border: `1px solid ${COLORS.border}` }}>
                  <div className="font-bold mb-1" style={{ color: COLORS.blue }}>AIPET Ask</div>
                  Thinking...
                </div>
              </div>
            )}

            {error && error !== "upgrade" && (
              <div className="text-xs text-center py-2" style={{ color: COLORS.critical }}>
                {error}
              </div>
            )}

            <div ref={messagesEndRef} />
          </div>
        </div>
      )}

      {/* Input */}
      <div className="rounded-xl border p-4 flex items-end gap-3"
        style={{ backgroundColor: COLORS.card, borderColor: COLORS.cyan + "30" }}>
        <textarea
          value={question}
          onChange={e => setQuestion(e.target.value)}
          onKeyDown={e => {
            if (e.key === "Enter" && !e.shiftKey) {
              e.preventDefault();
              sendQuestion();
            }
          }}
          placeholder="Ask a security question... (Enter to send, Shift+Enter for new line)"
          rows={2}
          className="flex-1 text-sm outline-none resize-none bg-transparent"
          style={{ color: COLORS.text, fontFamily: "inherit" }}
          disabled={loading}
        />
        <button
          onClick={() => sendQuestion()}
          disabled={loading || !question.trim()}
          className="px-5 py-2.5 rounded-lg text-sm font-bold transition-all flex-shrink-0"
          style={{
            backgroundColor: loading || !question.trim() ? COLORS.border : COLORS.cyan,
            color: loading || !question.trim() ? COLORS.muted : "#030712",
            opacity: loading ? 0.6 : 1,
            boxShadow: loading || !question.trim() ? "none" : "0 0 16px rgba(0,229,255,0.3)",
          }}>
          {loading ? "Thinking..." : "Ask →"}
        </button>
      </div>

      <div className="text-xs text-center" style={{ color: COLORS.subtle }}>
        Powered by Claude AI · Your data stays private · Responses reference your actual devices and findings
      </div>
    </div>
  );
}
function WatchPanel({ token }) {
  const [status, setStatus]       = useState(null);
  const [alerts, setAlerts]       = useState([]);
  const [loading, setLoading]     = useState(true);
  const [building, setBuilding]   = useState(false);
  const [error, setError]         = useState(null);
  const [message, setMessage]     = useState(null);

  const headers = { Authorization: `Bearer ${token}` };

  useEffect(() => {
    fetchStatus();
    fetchAlerts();
  }, [token]);

  const fetchStatus = async () => {
    try {
      const res = await axios.get(`${API}/watch/status`, { headers });
      setStatus(res.data);
    } catch (err) {
      if (err.response?.status === 403) setError("upgrade");
      else setError("Failed to load watch status.");
    } finally {
      setLoading(false);
    }
  };

  const fetchAlerts = async () => {
    try {
      const res = await axios.get(`${API}/watch/alerts`, { headers });
      setAlerts(res.data);
    } catch (err) {
      console.error("Failed to load watch alerts:", err);
    }
  };

  const buildBaselines = async () => {
    setBuilding(true);
    setMessage(null);
    try {
      const res = await axios.post(`${API}/watch/baselines/build`, {}, { headers });
      setMessage(`✓ Built baselines for ${res.data.devices} devices`);
      await fetchStatus();
    } catch (err) {
      if (err.response?.status === 403) setError("upgrade");
      else setMessage("Failed to build baselines. Run a scan first.");
    } finally {
      setBuilding(false);
    }
  };

  const acknowledgeAlert = async (alertId) => {
    try {
      await axios.patch(`${API}/watch/alerts/${alertId}/acknowledge`, {}, { headers });
      setAlerts(prev => prev.map(a => a.id === alertId ? { ...a, is_acknowledged: true } : a));
    } catch (err) {
      console.error("Failed to acknowledge alert:", err);
    }
  };

  const severityColor = {
    Critical: COLORS.critical,
    High:     COLORS.high,
    Medium:   COLORS.medium,
    Low:      COLORS.low,
  };

  const statusColor = (baseline) => {
    const risk = baseline.baseline_data?.risk_score || 0;
    if (risk >= 25) return COLORS.critical;
    if (risk >= 15) return COLORS.high;
    if (risk >= 8)  return COLORS.medium;
    return COLORS.low;
  };

  if (loading) return (
    <div className="flex items-center justify-center h-64" style={{ color: COLORS.muted }}>
      Loading watch status...
    </div>
  );

  if (error === "upgrade") return (
    <div className="rounded-2xl p-16 border text-center"
      style={{ backgroundColor: COLORS.card, borderColor: COLORS.border }}>
      <Shield size={48} style={{ color: COLORS.muted }} className="mx-auto mb-4" />
      <div className="text-sm font-bold mb-2" style={{ color: COLORS.text }}>Enterprise Feature</div>
      <div className="text-xs mb-4" style={{ color: COLORS.muted }}>
        AIPET Watch is available on the Enterprise plan (£499/month).
      </div>
      <div className="text-xs" style={{ color: COLORS.muted }}>
        Includes 24/7 passive network monitoring, baseline profiling, and anomaly detection.
      </div>
    </div>
  );

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="rounded-xl border p-4 flex items-center justify-between"
        style={{ backgroundColor: COLORS.card, borderColor: COLORS.border }}>
        <div>
          <div className="text-sm font-bold" style={{ color: COLORS.text }}>
            AIPET Watch — Network Monitoring
          </div>
          <div className="text-xs mt-0.5" style={{ color: COLORS.muted }}>
            {status ? `${status.devices_monitored} devices monitored · ${status.unacked_alerts} unacknowledged alerts` : "No baselines built yet"}
          </div>
        </div>
        <button onClick={buildBaselines} disabled={building}
          className="px-4 py-2 rounded-xl text-xs font-bold transition-all"
          style={{
            backgroundColor: COLORS.blue + "20",
            color: COLORS.blue,
            border: `1px solid ${COLORS.blue + "40"}`,
            opacity: building ? 0.6 : 1
          }}>
          {building ? "Building..." : "Build Baselines"}
        </button>
      </div>

      {/* Message */}
      {message && (
        <div className="rounded-xl border p-3"
          style={{
            backgroundColor: message.startsWith("✓") ? COLORS.low + "10" : COLORS.critical + "10",
            borderColor: message.startsWith("✓") ? COLORS.low + "40" : COLORS.critical + "40"
          }}>
          <div className="text-xs" style={{ color: message.startsWith("✓") ? COLORS.low : COLORS.critical }}>
            {message}
          </div>
        </div>
      )}

      {/* Stats */}
      {status && (
        <div className="grid grid-cols-3 gap-3">
          {[
            { label: "Devices Monitored", value: status.devices_monitored, color: COLORS.blue    },
            { label: "Unacked Alerts",    value: status.unacked_alerts,    color: COLORS.critical },
            { label: "Total Alerts",      value: status.total_alerts,      color: COLORS.muted   },
          ].map(item => (
            <div key={item.label} className="rounded-xl p-4 border text-center"
              style={{ backgroundColor: COLORS.card, borderColor: COLORS.border }}>
              <div className="text-2xl font-black" style={{ color: item.color }}>{item.value}</div>
              <div className="text-xs mt-1" style={{ color: COLORS.muted }}>{item.label}</div>
            </div>
          ))}
        </div>
      )}

      {/* Device baselines */}
      {status?.baselines?.length > 0 && (
        <div className="rounded-xl border p-4" style={{ backgroundColor: COLORS.card, borderColor: COLORS.border }}>
          <div className="text-xs font-bold uppercase tracking-wider mb-3" style={{ color: COLORS.text }}>
            Monitored Devices
          </div>
          <div className="space-y-2">
            {status.baselines.map((baseline, i) => (
              <div key={i} className="rounded-lg p-3 border flex items-center justify-between"
                style={{ backgroundColor: COLORS.dark, borderColor: COLORS.border }}>
                <div className="flex items-center gap-3">
                  <div className="w-2 h-2 rounded-full flex-shrink-0"
                    style={{ backgroundColor: statusColor(baseline) }} />
                  <div>
                    <div className="text-xs font-mono font-bold" style={{ color: COLORS.text }}>
                      {baseline.device_ip}
                    </div>
                    <div className="text-xs" style={{ color: COLORS.muted }}>
                      {baseline.device_function}
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-4">
                  <div className="text-right">
                    <div className="text-xs font-bold"
                      style={{ color: severityColor[baseline.baseline_data?.worst_severity] || COLORS.muted }}>
                      {baseline.baseline_data?.worst_severity}
                    </div>
                    <div className="text-xs" style={{ color: COLORS.muted }}>
                      Risk: {baseline.baseline_data?.risk_score}
                    </div>
                  </div>
                  <div className="text-right">
                    <div className="text-xs font-bold" style={{ color: COLORS.text }}>
                      {baseline.baseline_data?.finding_count} finding{baseline.baseline_data?.finding_count !== 1 ? 's' : ''}
                    </div>
                    <div className="text-xs" style={{ color: COLORS.muted }}>
                      {baseline.baseline_data?.protocols?.join(", ")}
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Agent instructions */}
      <div className="rounded-xl border p-4" style={{ backgroundColor: COLORS.card, borderColor: COLORS.border }}>
        <div className="text-xs font-bold uppercase tracking-wider mb-3" style={{ color: COLORS.blue }}>
          Deploy the Watch Agent
        </div>
        <div className="text-xs leading-relaxed mb-3" style={{ color: COLORS.muted }}>
          The AIPET Watch agent runs on your local network and monitors traffic passively.
          It is completely invisible to devices — they cannot detect it.
        </div>
        <div className="rounded-lg p-3 font-mono text-xs"
          style={{ backgroundColor: "#0a0a0a", color: "#00ff88", border: `1px solid ${COLORS.border}` }}>
          <div style={{ color: COLORS.muted }}># Install Scapy</div>
          <div>pip install scapy</div>
          <div className="mt-2" style={{ color: COLORS.muted }}># Run the agent (requires sudo)</div>
          <div>sudo python3 dashboard/backend/watch/agent.py \</div>
          <div>  --api-url https://aipet.io \</div>
          <div>  --token YOUR_API_TOKEN</div>
          <div className="mt-2" style={{ color: COLORS.muted }}># Test mode (no sudo required)</div>
          <div>python3 dashboard/backend/watch/agent.py \</div>
          <div>  --test \</div>
          <div>  --api-url http://localhost:5001 \</div>
          <div>  --token YOUR_API_TOKEN</div>
        </div>
      </div>

      {/* Alerts */}
      {alerts.length > 0 && (
        <div className="rounded-xl border p-4" style={{ backgroundColor: COLORS.card, borderColor: COLORS.border }}>
          <div className="text-xs font-bold uppercase tracking-wider mb-3" style={{ color: COLORS.critical }}>
            Watch Alerts
          </div>
          <div className="space-y-2">
            {alerts.map(alert => (
              <div key={alert.id} className="rounded-lg p-3 border"
                style={{
                  backgroundColor: COLORS.dark,
                  borderColor: alert.is_acknowledged ? COLORS.border : (severityColor[alert.severity] || COLORS.border) + "40",
                  opacity: alert.is_acknowledged ? 0.6 : 1
                }}>
                <div className="flex items-start justify-between gap-3">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-xs font-bold px-2 py-0.5 rounded"
                        style={{
                          backgroundColor: (severityColor[alert.severity] || COLORS.muted) + "20",
                          color: severityColor[alert.severity] || COLORS.muted
                        }}>
                        {alert.severity}
                      </span>
                      <span className="text-xs font-mono" style={{ color: COLORS.text }}>
                        {alert.device_ip}
                      </span>
                      <span className="text-xs" style={{ color: COLORS.muted }}>
                        {alert.alert_type.replace(/_/g, " ")}
                      </span>
                    </div>
                    <div className="text-xs" style={{ color: COLORS.muted }}>
                      {alert.description}
                    </div>
                  </div>
                  {!alert.is_acknowledged && (
                    <button onClick={() => acknowledgeAlert(alert.id)}
                      className="px-3 py-1.5 rounded-lg text-xs font-bold flex-shrink-0"
                      style={{
                        backgroundColor: COLORS.low + "20",
                        color: COLORS.low,
                        border: `1px solid ${COLORS.low + "40"}`
                      }}>
                      Acknowledge
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {alerts.length === 0 && status?.devices_monitored > 0 && (
        <div className="rounded-2xl p-12 border text-center"
          style={{ backgroundColor: COLORS.card, borderColor: COLORS.border }}>
          <div className="text-2xl mb-3">🛡️</div>
          <div className="text-sm font-bold mb-2" style={{ color: COLORS.text }}>All Clear</div>
          <div className="text-xs" style={{ color: COLORS.muted }}>
            No anomalies detected. Your network behaviour matches the baseline.
          </div>
        </div>
      )}
    </div>
  );
}
function PredictPanel({ token, scans }) {
  const [alerts, setAlerts]         = useState([]);
  const [loading, setLoading]       = useState(true);
  const [scanning, setScanning]     = useState(false);
  const [error, setError]           = useState(null);
  const [scanResult, setScanResult] = useState(null);

  const latestScan = scans && scans.find(s => s.status === "completed" || s.status === "complete");
  const scanId     = latestScan?.id;

  const headers = { Authorization: `Bearer ${token}` };

  useEffect(() => {
    fetchAlerts();
  }, [token]);

  const fetchAlerts = async () => {
    try {
      const res = await axios.get(`${API}/predict/alerts`, { headers });
      setAlerts(res.data);
    } catch (err) {
      if (err.response?.status === 403) setError("upgrade");
      else setError("Failed to load CVE alerts.");
    } finally {
      setLoading(false);
    }
  };

  const runScan = async () => {
    if (!scanId) { setError("No completed scan found. Run a scan first."); return; }
    setScanning(true);
    setScanResult(null);
    try {
      const res = await axios.post(
        `${API}/predict/scan/${scanId}`,
        { days: 7 },
        { headers }
      );
      setScanResult(res.data);
      await fetchAlerts();
    } catch (err) {
      if (err.response?.status === 403) setError("upgrade");
      else setError("Failed to run CVE scan.");
    } finally {
      setScanning(false);
    }
  };

  const markReviewed = async (alertId) => {
    try {
      await axios.patch(`${API}/predict/alerts/${alertId}/review`, {}, { headers });
      setAlerts(prev => prev.map(a => a.id === alertId ? { ...a, is_reviewed: true } : a));
    } catch (err) {
      console.error("Failed to mark reviewed:", err);
    }
  };

  const dismissAlert = async (alertId) => {
    try {
      await axios.delete(`${API}/predict/alerts/${alertId}`, { headers });
      setAlerts(prev => prev.filter(a => a.id !== alertId));
    } catch (err) {
      console.error("Failed to dismiss alert:", err);
    }
  };

  const severityColor = {
    Critical: COLORS.critical,
    High:     COLORS.high,
    Medium:   COLORS.medium,
    Low:      COLORS.low,
  };

  const weaponisationColor = (pct) => {
    if (pct >= 70) return COLORS.critical;
    if (pct >= 40) return COLORS.high;
    if (pct >= 20) return COLORS.medium;
    return COLORS.low;
  };

  if (loading) return (
    <div className="flex items-center justify-center h-64" style={{ color: COLORS.muted }}>
      Loading CVE intelligence...
    </div>
  );

  if (error === "upgrade") return (
    <div className="rounded-2xl p-16 border text-center"
      style={{ backgroundColor: COLORS.card, borderColor: COLORS.border }}>
      <AlertTriangle size={48} style={{ color: COLORS.muted }} className="mx-auto mb-4" />
      <div className="text-sm font-bold mb-2" style={{ color: COLORS.text }}>Professional Feature</div>
      <div className="text-xs" style={{ color: COLORS.muted }}>
        AIPET Predict is available on Professional and Enterprise plans.
      </div>
    </div>
  );

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="rounded-xl border p-4 flex items-center justify-between"
        style={{ backgroundColor: COLORS.card, borderColor: COLORS.border }}>
        <div>
          <div className="text-sm font-bold" style={{ color: COLORS.text }}>CVE Intelligence Feed</div>
          <div className="text-xs mt-0.5" style={{ color: COLORS.muted }}>
            {alerts.length > 0
              ? `${alerts.filter(a => !a.is_reviewed).length} unreviewed alerts · ${alerts.length} total`
              : "No CVE alerts yet — click Check for New CVEs"}
          </div>
        </div>
        <button onClick={runScan} disabled={scanning}
          className="px-4 py-2 rounded-xl text-xs font-bold transition-all"
          style={{
            backgroundColor: COLORS.blue + "20",
            color: COLORS.blue,
            border: `1px solid ${COLORS.blue + "40"}`,
            opacity: scanning ? 0.6 : 1
          }}>
          {scanning ? "Scanning NVD..." : "Check for New CVEs"}
        </button>
      </div>

      {/* Scan result */}
      {scanResult && (
        <div className="rounded-xl border p-4"
          style={{ backgroundColor: COLORS.low + "10", borderColor: COLORS.low + "40" }}>
          <div className="text-xs font-bold" style={{ color: COLORS.low }}>
            ✓ Scan Complete
          </div>
          <div className="text-xs mt-1" style={{ color: COLORS.muted }}>
            Checked {scanResult.cves_checked} CVEs from last {scanResult.days_checked} days.
            Found {scanResult.new_alerts} new alerts matching your devices.
          </div>
        </div>
      )}

      {error && error !== "upgrade" && (
        <div className="rounded-xl border p-4"
          style={{ backgroundColor: COLORS.critical + "10", borderColor: COLORS.critical + "40" }}>
          <div className="text-xs" style={{ color: COLORS.critical }}>{error}</div>
        </div>
      )}

      {/* Alerts list */}
      {alerts.length === 0 ? (
        <div className="rounded-2xl p-16 border text-center"
          style={{ backgroundColor: COLORS.card, borderColor: COLORS.border }}>
          <div className="text-2xl mb-3">🛡️</div>
          <div className="text-sm font-bold mb-2" style={{ color: COLORS.text }}>
            No CVE Alerts
          </div>
          <div className="text-xs" style={{ color: COLORS.muted }}>
            Click "Check for New CVEs" to scan the NVD for vulnerabilities matching your devices.
          </div>
        </div>
      ) : (
        <div className="space-y-3">
          {alerts.map(alert => (
            <div key={alert.id} className="rounded-xl border overflow-hidden"
              style={{
                backgroundColor: COLORS.card,
                borderColor: alert.is_reviewed ? COLORS.border : (severityColor[alert.severity] || COLORS.border) + "40",
                opacity: alert.is_reviewed ? 0.7 : 1
              }}>
              {/* Alert header */}
              <div className="p-4">
                <div className="flex items-start justify-between gap-3">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-xs font-black px-2 py-0.5 rounded"
                        style={{
                          backgroundColor: (severityColor[alert.severity] || COLORS.muted) + "20",
                          color: severityColor[alert.severity] || COLORS.muted
                        }}>
                        {alert.severity}
                      </span>
                      <span className="text-xs font-mono font-bold" style={{ color: COLORS.text }}>
                        {alert.cve_id}
                      </span>
                      <span className="text-xs" style={{ color: COLORS.muted }}>
                        CVSS {alert.cvss_score}
                      </span>
                      {alert.is_reviewed && (
                        <span className="text-xs" style={{ color: COLORS.low }}>✓ Reviewed</span>
                      )}
                    </div>
                    <div className="text-xs leading-relaxed mb-2" style={{ color: COLORS.text }}>
                      {alert.description?.substring(0, 200)}
                      {alert.description?.length > 200 ? "..." : ""}
                    </div>

                    {/* Weaponisation probability */}
                    <div className="flex items-center gap-3 mb-2">
                      <div className="text-xs" style={{ color: COLORS.muted }}>
                        Weaponisation probability:
                      </div>
                      <div className="flex items-center gap-2">
                        <div className="w-24 h-1.5 rounded-full overflow-hidden"
                          style={{ backgroundColor: COLORS.border }}>
                          <div className="h-full rounded-full"
                            style={{
                              width: `${alert.weaponisation_pct}%`,
                              backgroundColor: weaponisationColor(alert.weaponisation_pct)
                            }} />
                        </div>
                        <span className="text-xs font-bold"
                          style={{ color: weaponisationColor(alert.weaponisation_pct) }}>
                          {alert.weaponisation_pct}%
                        </span>
                      </div>
                    </div>

                    {/* Affected devices */}
                    {alert.affected_devices?.length > 0 && (
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-xs" style={{ color: COLORS.muted }}>Affects:</span>
                        {alert.affected_devices.map((d, i) => (
                          <span key={i} className="text-xs px-2 py-0.5 rounded font-mono"
                            style={{ backgroundColor: COLORS.dark, color: COLORS.text }}>
                            {d.ip}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* Actions */}
                  <div className="flex flex-col gap-2 flex-shrink-0">
                    <a href={alert.nvd_url} target="_blank" rel="noopener noreferrer"
                      className="px-3 py-1.5 rounded-lg text-xs font-bold text-center transition-all"
                      style={{
                        backgroundColor: COLORS.blue + "20",
                        color: COLORS.blue,
                        border: `1px solid ${COLORS.blue + "40"}`
                      }}>
                      View CVE
                    </a>
                    {!alert.is_reviewed && (
                      <button onClick={() => markReviewed(alert.id)}
                        className="px-3 py-1.5 rounded-lg text-xs font-bold transition-all"
                        style={{
                          backgroundColor: COLORS.low + "20",
                          color: COLORS.low,
                          border: `1px solid ${COLORS.low + "40"}`
                        }}>
                        Mark Reviewed
                      </button>
                    )}
                    <button onClick={() => dismissAlert(alert.id)}
                      className="px-3 py-1.5 rounded-lg text-xs font-bold transition-all"
                      style={{
                        backgroundColor: COLORS.critical + "10",
                        color: COLORS.muted,
                        border: `1px solid ${COLORS.border}`
                      }}>
                      Dismiss
                    </button>
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
function NetworkMap({ token, scans }) {
  const svgRef = useRef(null);
  const [graphData, setGraphData]       = useState(null);
  const [loading, setLoading]           = useState(true);
  const [error, setError]               = useState(null);
  const [animating, setAnimating]       = useState(false);
  const [selectedNode, setSelectedNode] = useState(null);
  const [activePathIndex, setActivePathIndex] = useState(0);

  const latestScan = scans && scans.find(s => s.status === "completed" || s.status === "complete");
  const scanId     = latestScan?.id;

  useEffect(() => {
    const fetchMap = async () => {
      if (!scanId) {
        setLoading(false);
        setError("No completed scan found. Run a scan first.");
        return;
      }
      try {
        const res = await axios.get(`${API}/map/${scanId}`, {
          headers: { Authorization: `Bearer ${token}` }
        });
        setGraphData(res.data);
      } catch (err) {
        if (err.response?.status === 403) setError("upgrade");
        else setError("Failed to load network map.");
      } finally {
        setLoading(false);
      }
    };
    fetchMap();
  }, [scanId, token]);

  useEffect(() => {
    if (!graphData || !svgRef.current) return;
    drawGraph(graphData);
  }, [graphData]);

  const drawGraph = (data) => {
    const { nodes, edges } = data;
    if (!nodes || nodes.length === 0) return;

    const svg    = d3.select(svgRef.current);
    const width  = svgRef.current.clientWidth  || 800;
    const height = svgRef.current.clientHeight || 500;

    svg.selectAll("*").remove();

    // Add zoom behaviour
    const g = svg.append("g");
    svg.call(d3.zoom().scaleExtent([0.3, 3]).on("zoom", (event) => {
      g.attr("transform", event.transform);
    }));

    // Arrow marker for directed edges
    svg.append("defs").append("marker")
      .attr("id", "arrowhead")
      .attr("viewBox", "0 -5 10 10")
      .attr("refX", 25)
      .attr("refY", 0)
      .attr("markerWidth", 6)
      .attr("markerHeight", 6)
      .attr("orient", "auto")
      .append("path")
      .attr("d", "M0,-5L10,0L0,5")
      .attr("fill", "#6b7280");

    // Force simulation
    const simulation = d3.forceSimulation(nodes)
      .force("link",   d3.forceLink(edges).id(d => d.id).distance(150))
      .force("charge", d3.forceManyBody().strength(-400))
      .force("center", d3.forceCenter(width / 2, height / 2))
      .force("collision", d3.forceCollide().radius(50));

    // Draw edges
    const link = g.append("g")
      .selectAll("line")
      .data(edges)
      .enter()
      .append("line")
      .attr("stroke", "#374151")
      .attr("stroke-width", 2)
      .attr("marker-end", "url(#arrowhead)");

    // Draw nodes
    const node = g.append("g")
      .selectAll("g")
      .data(nodes)
      .enter()
      .append("g")
      .style("cursor", "pointer")
      .call(d3.drag()
        .on("start", (event, d) => {
          if (!event.active) simulation.alphaTarget(0.3).restart();
          d.fx = d.x; d.fy = d.y;
        })
        .on("drag", (event, d) => {
          d.fx = event.x; d.fy = event.y;
        })
        .on("end", (event, d) => {
          if (!event.active) simulation.alphaTarget(0);
          d.fx = null; d.fy = null;
        })
      )
      .on("click", (event, d) => {
        setSelectedNode(d);
      });

    // Node outer ring for critical assets
    node.filter(d => d.is_critical)
      .append("circle")
      .attr("r", 32)
      .attr("fill", "none")
      .attr("stroke", "#f59e0b")
      .attr("stroke-width", 2)
      .attr("stroke-dasharray", "4,4");

    // Node circles
    node.append("circle")
      .attr("r", d => d.is_entry ? 28 : 20)
      .attr("fill", d => d.color + "33")
      .attr("stroke", d => d.color)
      .attr("stroke-width", d => d.is_entry ? 3 : 2);

    // Entry point warning icon
    node.filter(d => d.is_entry)
      .append("text")
      .attr("text-anchor", "middle")
      .attr("dy", "0.35em")
      .attr("font-size", "16px")
      .text("⚠");

    // Non-entry node label
    node.filter(d => !d.is_entry)
      .append("text")
      .attr("text-anchor", "middle")
      .attr("dy", "0.35em")
      .attr("font-size", "10px")
      .attr("fill", d => d.color)
      .attr("font-weight", "bold")
      .text(d => d.severity[0]);

    // IP label below node
    node.append("text")
      .attr("text-anchor", "middle")
      .attr("dy", d => d.is_entry ? "4em" : "3.2em")
      .attr("font-size", "10px")
      .attr("fill", "#9ca3af")
      .text(d => d.label);

    // Function label
    node.append("text")
      .attr("text-anchor", "middle")
      .attr("dy", d => d.is_entry ? "5.2em" : "4.4em")
      .attr("font-size", "9px")
      .attr("fill", "#6b7280")
      .text(d => d.device_function !== "Unknown" ? d.device_function.split("/")[0].trim() : "");

    // Tick function
    simulation.on("tick", () => {
      link
        .attr("x1", d => d.source.x)
        .attr("y1", d => d.source.y)
        .attr("x2", d => d.target.x)
        .attr("y2", d => d.target.y);

      node.attr("transform", d => `translate(${d.x},${d.y})`);
    });
  };

  const animateAttackPath = () => {
    if (!graphData || !graphData.attack_paths.length) return;
    const path      = graphData.attack_paths[activePathIndex];
    if (!path) return;

    setAnimating(true);

    const svg = d3.select(svgRef.current);
    svg.selectAll(".attack-dot").remove();
    svg.selectAll("line").attr("stroke", "#374151").attr("stroke-width", 2);

    // Find the nodes in the path
    const nodeMap  = {};
    graphData.nodes.forEach(n => { nodeMap[n.id] = n; });

    // Highlight path edges
    const pathSet = new Set();
    for (let i = 0; i < path.path.length - 1; i++) {
      pathSet.add(`${path.path[i]}-${path.path[i+1]}`);
      pathSet.add(`${path.path[i+1]}-${path.path[i]}`);
    }

    svg.select("g").selectAll("line").each(function(d) {
      const key = `${d.source.id || d.source}-${d.target.id || d.target}`;
      if (pathSet.has(key)) {
        d3.select(this).attr("stroke", "#ef4444").attr("stroke-width", 3);
      }
    });

    setTimeout(() => {
      setAnimating(false);
      setActivePathIndex((activePathIndex + 1) % graphData.attack_paths.length);
    }, 2000);
  };

  const severityColors = { Critical: COLORS.critical, High: COLORS.high, Medium: COLORS.medium, Low: COLORS.low };

  if (loading) return (
    <div className="flex items-center justify-center h-64" style={{ color: COLORS.muted }}>
      Loading network map...
    </div>
  );

  if (error === "upgrade") return (
    <div className="rounded-2xl p-16 border text-center" style={{ backgroundColor: COLORS.card, borderColor: COLORS.border }}>
      <Shield size={48} style={{ color: COLORS.muted }} className="mx-auto mb-4" />
      <div className="text-sm font-bold mb-2" style={{ color: COLORS.text }}>Professional Feature</div>
      <div className="text-xs" style={{ color: COLORS.muted }}>AIPET Map is available on Professional and Enterprise plans.</div>
    </div>
  );

  if (error) return (
    <div className="rounded-2xl p-16 border text-center" style={{ backgroundColor: COLORS.card, borderColor: COLORS.border }}>
      <div className="text-sm" style={{ color: COLORS.muted }}>{error}</div>
    </div>
  );

  if (!graphData || graphData.nodes.length === 0) return (
    <div className="rounded-2xl p-16 border text-center" style={{ backgroundColor: COLORS.card, borderColor: COLORS.border }}>
      <Shield size={48} style={{ color: COLORS.muted }} className="mx-auto mb-4" />
      <div className="text-sm" style={{ color: COLORS.muted }}>No devices found. Run a scan first.</div>
    </div>
  );

  return (
    <div className="space-y-4">
      {/* Stats bar */}
      <div className="grid grid-cols-4 gap-3">
        {[
          { label: "Devices",       value: graphData.stats.total_devices,   color: COLORS.blue     },
          { label: "Entry Points",  value: graphData.stats.entry_points,    color: COLORS.critical },
          { label: "Critical Assets", value: graphData.stats.critical_assets, color: COLORS.high   },
          { label: "Attack Paths",  value: graphData.stats.attack_paths,    color: COLORS.purple   },
        ].map(item => (
          <div key={item.label} className="rounded-xl p-3 border text-center"
            style={{ backgroundColor: COLORS.card, borderColor: COLORS.border }}>
            <div className="text-2xl font-black" style={{ color: item.color }}>{item.value}</div>
            <div className="text-xs mt-1" style={{ color: COLORS.muted }}>{item.label}</div>
          </div>
        ))}
      </div>

      {/* Map canvas */}
      <div className="rounded-2xl border overflow-hidden"
        style={{ backgroundColor: COLORS.card, borderColor: COLORS.border }}>
        <div className="p-4 border-b flex items-center justify-between"
          style={{ borderColor: COLORS.border }}>
          <div>
            <div className="text-sm font-bold" style={{ color: COLORS.text }}>Network Attack Map</div>
            <div className="text-xs mt-0.5" style={{ color: COLORS.muted }}>
              Click nodes to inspect · Drag to rearrange · Scroll to zoom
            </div>
          </div>
          <div className="flex items-center gap-2">
            {graphData.attack_paths.length > 0 && (
              <button onClick={animateAttackPath} disabled={animating}
                className="px-3 py-1.5 rounded-lg text-xs font-bold transition-all"
                style={{
                  backgroundColor: COLORS.critical + "20",
                  color: COLORS.critical,
                  border: `1px solid ${COLORS.critical + "40"}`,
                  opacity: animating ? 0.6 : 1
                }}>
                {animating ? "Animating..." : "▶ Animate Attack"}
              </button>
            )}
            {/* Legend */}
            <div className="flex items-center gap-3 text-xs" style={{ color: COLORS.muted }}>
              <span>⚠ Entry Point</span>
              <span style={{ color: "#f59e0b" }}>◯ Critical Asset</span>
            </div>
          </div>
        </div>
        <svg ref={svgRef} width="100%" height="500"
          style={{ backgroundColor: COLORS.dark }} />
      </div>

      {/* Attack paths */}
      {graphData.attack_paths.length > 0 && (
        <div className="rounded-xl border p-4" style={{ backgroundColor: COLORS.card, borderColor: COLORS.border }}>
          <div className="text-xs font-bold uppercase tracking-wider mb-3" style={{ color: COLORS.critical }}>
            Attack Paths Detected
          </div>
          <div className="space-y-2">
            {graphData.attack_paths.map((path, i) => (
              <div key={i} className="rounded-lg p-3 border"
                style={{ backgroundColor: COLORS.dark, borderColor: COLORS.border }}>
                <div className="flex items-center gap-2 text-xs">
                  {path.path.map((node, j) => (
                    <span key={j} className="flex items-center gap-2">
                      <span className="font-mono px-2 py-0.5 rounded"
                        style={{ backgroundColor: COLORS.critical + "20", color: COLORS.critical }}>
                        {node}
                      </span>
                      {j < path.path.length - 1 && (
                        <span style={{ color: COLORS.muted }}>→</span>
                      )}
                    </span>
                  ))}
                  <span className="ml-2" style={{ color: COLORS.muted }}>
                    → {path.target_function}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Recommendations */}
      {graphData.recommendations.length > 0 && (
        <div className="rounded-xl border p-4" style={{ backgroundColor: COLORS.card, borderColor: COLORS.border }}>
          <div className="text-xs font-bold uppercase tracking-wider mb-3" style={{ color: COLORS.blue }}>
            Priority Recommendations
          </div>
          <div className="space-y-2">
            {graphData.recommendations.map((rec, i) => (
              <div key={i} className="rounded-lg p-3 border flex items-start gap-3"
                style={{ backgroundColor: COLORS.dark, borderColor: COLORS.border }}>
                <div className="w-6 h-6 rounded-full flex items-center justify-center flex-shrink-0 text-xs font-black"
                  style={{ backgroundColor: COLORS.blue + "20", color: COLORS.blue }}>
                  {i + 1}
                </div>
                <div>
                  <div className="text-xs font-semibold" style={{ color: COLORS.text }}>{rec.message}</div>
                  <div className="text-xs mt-0.5" style={{ color: COLORS.muted }}>
                    Device: {rec.device} · Severity: {rec.severity}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Selected node details */}
      {selectedNode && (
        <div className="rounded-xl border p-4" style={{ backgroundColor: COLORS.card, borderColor: COLORS.border }}>
          <div className="flex items-center justify-between mb-3">
            <div className="text-xs font-bold uppercase tracking-wider" style={{ color: COLORS.text }}>
              Device Details — {selectedNode.id}
            </div>
            <button onClick={() => setSelectedNode(null)}
              className="text-xs" style={{ color: COLORS.muted }}>✕</button>
          </div>
          <div className="grid grid-cols-3 gap-3 mb-3">
            {[
              { label: "Function",    value: selectedNode.device_function },
              { label: "Severity",    value: selectedNode.severity        },
              { label: "Risk Score",  value: selectedNode.risk_score      },
            ].map(item => (
              <div key={item.label} className="rounded-lg p-3 border"
                style={{ backgroundColor: COLORS.dark, borderColor: COLORS.border }}>
                <div className="text-xs" style={{ color: COLORS.muted }}>{item.label}</div>
                <div className="text-sm font-bold mt-1"
                  style={{ color: severityColors[item.value] || COLORS.text }}>
                  {item.value}
                </div>
              </div>
            ))}
          </div>
          <div className="space-y-1">
            {selectedNode.findings?.map((f, i) => (
              <div key={i} className="rounded-lg p-2 border text-xs"
                style={{ backgroundColor: COLORS.dark, borderColor: COLORS.border }}>
                <span style={{ color: severityColors[f.severity] || COLORS.text }}>{f.severity}</span>
                <span className="mx-2" style={{ color: COLORS.muted }}>·</span>
                <span style={{ color: COLORS.text }}>{f.attack}</span>
                <span className="mx-2" style={{ color: COLORS.muted }}>·</span>
                <span style={{ color: f.fix_status === "fixed" ? COLORS.low : COLORS.muted }}>
                  {f.fix_status}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
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
                Based on {scoreResult.industry} industry breach cost data (IBM & NCSC 2024)
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
            <div className="rounded-lg p-3 border text-xs leading-relaxed"
              style={{ backgroundColor: COLORS.dark, borderColor: COLORS.border, color: COLORS.muted }}>
              ⚠️ Estimates based on UK average breach costs from IBM Cost of a Data Breach Report 2024 and NCSC UK Cyber Security Breaches Survey 2024. Actual costs may vary. Intended to support security investment decisions, not to predict exact breach costs.
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

function NetworkCanvas() {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    let animationId;
    let nodes = [];
    let packets = [];
    let tick = 0;

    const resize = () => {
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
    };
    resize();
    window.addEventListener('resize', resize);

    // Node types
    const NODE_TYPES = [
      { type: 'device',    color: '#00e5ff', glow: '#00e5ff', radius: 3,  count: 35 },
      { type: 'gateway',   color: '#a855f7', glow: '#a855f7', radius: 5,  count: 8  },
      { type: 'vulnerable',color: '#ff4444', glow: '#ff4444', radius: 4,  count: 6  },
      { type: 'secure',    color: '#00ff88', glow: '#00ff88', radius: 3,  count: 8  },
    ];

    // Create nodes
    NODE_TYPES.forEach(nt => {
      for (let i = 0; i < nt.count; i++) {
        nodes.push({
          x: Math.random() * canvas.width,
          y: Math.random() * canvas.height,
          vx: (Math.random() - 0.5) * 0.3,
          vy: (Math.random() - 0.5) * 0.3,
          radius: nt.radius,
          color: nt.color,
          glow: nt.glow,
          type: nt.type,
          pulse: Math.random() * Math.PI * 2,
          pulseSpeed: 0.02 + Math.random() * 0.02,
          opacity: 0.7 + Math.random() * 0.3,
        });
      }
    });

    const drawGlow = (x, y, radius, color, intensity) => {
      const gradient = ctx.createRadialGradient(x, y, 0, x, y, radius * 4);
      gradient.addColorStop(0, color.replace(')', `, ${intensity})`).replace('rgb', 'rgba'));
      gradient.addColorStop(1, 'rgba(0,0,0,0)');
      ctx.beginPath();
      ctx.arc(x, y, radius * 4, 0, Math.PI * 2);
      ctx.fillStyle = gradient;
      ctx.fill();
    };

    const hexToRgb = hex => {
      const r = parseInt(hex.slice(1,3),16);
      const g = parseInt(hex.slice(3,5),16);
      const b = parseInt(hex.slice(5,7),16);
      return `${r},${g},${b}`;
    };

    const draw = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      tick++;

      // Spawn data packets occasionally
      if (tick % 60 === 0 && nodes.length > 1) {
        const from = nodes[Math.floor(Math.random() * nodes.length)];
        const to = nodes[Math.floor(Math.random() * nodes.length)];
        if (from !== to) {
          packets.push({ x: from.x, y: from.y, tx: to.x, ty: to.y, progress: 0, color: from.color, speed: 0.015 });
        }
      }

      // Draw connections
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const dx = nodes[i].x - nodes[j].x;
          const dy = nodes[i].y - nodes[j].y;
          const dist = Math.sqrt(dx * dx + dy * dy);
          if (dist < 180) {
            const alpha = 0.2 * (1 - dist / 180);
            const grad = ctx.createLinearGradient(nodes[i].x, nodes[i].y, nodes[j].x, nodes[j].y);
            grad.addColorStop(0, `rgba(${hexToRgb(nodes[i].color)}, ${alpha})`);
            grad.addColorStop(1, `rgba(${hexToRgb(nodes[j].color)}, ${alpha})`);
            ctx.beginPath();
            ctx.moveTo(nodes[i].x, nodes[i].y);
            ctx.lineTo(nodes[j].x, nodes[j].y);
            ctx.strokeStyle = grad;
            ctx.lineWidth = 0.8;
            ctx.stroke();
          }
        }
      }

      // Draw data packets
      packets = packets.filter(p => p.progress < 1);
      packets.forEach(p => {
        p.progress += p.speed;
        p.tx = p.tx || p.x;
        p.ty = p.ty || p.y;
        const x = p.x + (p.tx - p.x) * p.progress;
        const y = p.y + (p.ty - p.y) * p.progress;
        ctx.beginPath();
        ctx.arc(x, y, 2, 0, Math.PI * 2);
        ctx.fillStyle = p.color;
        ctx.fill();
        // Packet glow
        const pg = ctx.createRadialGradient(x, y, 0, x, y, 8);
        pg.addColorStop(0, `rgba(${hexToRgb(p.color)}, 0.4)`);
        pg.addColorStop(1, 'rgba(0,0,0,0)');
        ctx.beginPath();
        ctx.arc(x, y, 8, 0, Math.PI * 2);
        ctx.fillStyle = pg;
        ctx.fill();
      });

      // Draw nodes
      nodes.forEach(node => {
        node.x += node.vx;
        node.y += node.vy;
        if (node.x < 0 || node.x > canvas.width) node.vx *= -1;
        if (node.y < 0 || node.y > canvas.height) node.vy *= -1;
        node.pulse += node.pulseSpeed;

        const pulseFactor = 1 + 0.3 * Math.sin(node.pulse);
        const r = node.radius * pulseFactor;
        const rgb = hexToRgb(node.color);

        // Outer glow
        const glowGrad = ctx.createRadialGradient(node.x, node.y, 0, node.x, node.y, r * 6);
        glowGrad.addColorStop(0, `rgba(${rgb}, 0.3)`);
        glowGrad.addColorStop(1, 'rgba(0,0,0,0)');
        ctx.beginPath();
        ctx.arc(node.x, node.y, r * 6, 0, Math.PI * 2);
        ctx.fillStyle = glowGrad;
        ctx.fill();

        // Node ring (for gateway and vulnerable)
        if (node.type === 'gateway' || node.type === 'vulnerable') {
          ctx.beginPath();
          ctx.arc(node.x, node.y, r * 2.5, 0, Math.PI * 2);
          ctx.strokeStyle = `rgba(${rgb}, 0.3)`;
          ctx.lineWidth = 1;
          ctx.stroke();
        }

        // Attack pulse for vulnerable nodes
        if (node.type === 'vulnerable') {
          const pulseR = r * (3 + 2 * Math.abs(Math.sin(node.pulse * 2)));
          ctx.beginPath();
          ctx.arc(node.x, node.y, pulseR, 0, Math.PI * 2);
          ctx.strokeStyle = `rgba(255, 68, 68, ${0.3 * (1 - Math.abs(Math.sin(node.pulse * 2)))})`;
          ctx.lineWidth = 1.5;
          ctx.stroke();
        }

        // Core node
        ctx.beginPath();
        ctx.arc(node.x, node.y, r, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(${rgb}, ${node.opacity})`;
        ctx.fill();

        // Inner highlight
        ctx.beginPath();
        ctx.arc(node.x - r * 0.3, node.y - r * 0.3, r * 0.4, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(255, 255, 255, 0.4)`;
        ctx.fill();
      });

      animationId = requestAnimationFrame(draw);
    };

    draw();
    return () => {
      cancelAnimationFrame(animationId);
      window.removeEventListener('resize', resize);
    };
  }, []);

  return (
    <canvas ref={canvasRef} style={{
      position: "fixed",
      top: 0,
      left: 0,
      width: "100%",
      height: "100%",
      pointerEvents: "none",
      zIndex: 0,
      opacity: 0.5,
    }} />
  );
}


// ============================================================
// ABOUT PAGE
// ============================================================

// ============================================================
// PLATFORM PAGE
// ============================================================
function PlatformPage({ onBack, onGetStarted }) {
  const [expanded, setExpanded] = useState(null);

  const MODULES = [
    {
      id: "scan",
      name: "AIPET Scan",
      tagline: "Discover every IoT device in your network",
      icon: "🔍",
      color: "#00e5ff",
      description: "AIPET Scan automatically discovers and fingerprints every IoT device on your network. Using seven specialised attack modules — MQTT, CoAP, HTTP, Firmware Analysis, Recon, AI Engine, and Report Generation — it performs a comprehensive security assessment in under 60 seconds.",
      features: [
        "Automatic device discovery across all subnets",
        "7 specialised IoT attack modules",
        "MQTT, CoAP, HTTP, and Firmware analysis",
        "Complete scan in under 60 seconds",
        "Supports parallel scanning across multiple networks",
        "Full audit trail and scan history",
      ],
      stats: [{ value: "60s", label: "Scan time" }, { value: "7", label: "Attack modules" }, { value: "100%", label: "OWASP coverage" }],
    },
    {
      id: "explain",
      name: "AIPET Explain",
      tagline: "AI-powered explanations for every vulnerability",
      icon: "🧠",
      color: "#a855f7",
      description: "Powered by Claude AI and SHAP explainability, AIPET Explain transforms complex vulnerability data into clear, actionable intelligence. It tells you not just what is vulnerable — but exactly why, using machine learning predictions that security teams and executives both understand.",
      features: [
        "Claude AI-powered plain English explanations",
        "SHAP values showing exactly why each device is at risk",
        "Executive summary reports for board presentations",
        "Technical deep-dive for security engineers",
        "Automated report generation in PDF format",
        "Context-aware remediation recommendations",
      ],
      stats: [{ value: "SHAP", label: "Explainability" }, { value: "Claude", label: "AI engine" }, { value: "PDF", label: "Export format" }],
    },
    {
      id: "score",
      name: "AIPET Score",
      tagline: "Quantify the financial impact of every vulnerability",
      icon: "💰",
      color: "#f59e0b",
      description: "AIPET Score calculates the real financial exposure of your IoT vulnerabilities using IBM Cost of a Data Breach 2024 and NCSC data. It gives your CISO and board a clear answer to the question: what would this breach actually cost us?",
      features: [
        "Financial risk calculation using IBM/NCSC 2024 data",
        "Per-device and per-finding cost breakdown",
        "Industry-specific breach cost benchmarking",
        "Risk prioritisation by financial impact",
        "Board-ready financial exposure reports",
        "ROI calculation for security investments",
      ],
      stats: [{ value: "£$€¥", label: "Multi-currency" }, { value: "IBM", label: "Data source" }, { value: "2024", label: "Latest data" }],
    },
    {
      id: "map",
      name: "AIPET Map",
      tagline: "Visualise attack paths across your IoT network",
      icon: "🗺️",
      color: "#00e5ff",
      description: "AIPET Map uses D3.js to render a live, interactive network topology showing exactly how an attacker would move through your IoT infrastructure. See the complete attack chain — from initial access to full network compromise — visualised in real time.",
      features: [
        "Interactive D3.js network topology visualisation",
        "Complete attack path mapping",
        "Device relationship and dependency mapping",
        "Critical path identification",
        "Export network diagram as PNG/PDF",
        "Real-time updates as new devices are discovered",
      ],
      stats: [{ value: "D3.js", label: "Technology" }, { value: "Live", label: "Updates" }, { value: "Interactive", label: "Visualisation" }],
    },
    {
      id: "predict",
      name: "AIPET Predict",
      tagline: "Live CVE intelligence matched to your devices",
      icon: "⚡",
      color: "#f59e0b",
      description: "AIPET Predict connects to the NIST National Vulnerability Database in real time, matching newly published CVEs against your specific device inventory. Know within minutes when a new vulnerability affects your infrastructure — before attackers exploit it.",
      features: [
        "Real-time NVD API integration",
        "Automatic CVE matching to your device inventory",
        "CVSS score and weaponisation percentage tracking",
        "Priority alerting for critical vulnerabilities",
        "Historical CVE trend analysis",
        "Automated notification for new critical CVEs",
      ],
      stats: [{ value: "NVD", label: "Data source" }, { value: "Real-time", label: "Updates" }, { value: "CVSS", label: "Scoring" }],
    },
    {
      id: "watch",
      name: "AIPET Watch",
      tagline: "Continuous anomaly detection for your IoT network",
      icon: "👁️",
      color: "#00ff88",
      description: "AIPET Watch uses Scapy-based passive network monitoring to establish behavioural baselines for every IoT device and detect anomalies in real time. When a device starts behaving unusually — unexpected ports, unusual traffic patterns — you know immediately.",
      features: [
        "Passive network monitoring using Scapy",
        "Automatic baseline establishment per device",
        "Real-time anomaly detection and alerting",
        "Device behaviour profiling",
        "Network traffic analysis",
        "Incident timeline and forensic data",
      ],
      stats: [{ value: "Scapy", label: "Technology" }, { value: "24/7", label: "Monitoring" }, { value: "Real-time", label: "Alerts" }],
    },
    {
      id: "ask",
      name: "AIPET Ask",
      tagline: "Your AI security assistant, always available",
      icon: "💬",
      color: "#a855f7",
      description: "AIPET Ask is a Claude AI-powered security assistant that answers any question about your IoT security posture in natural language. Ask about your vulnerabilities, compliance status, remediation steps, or anything else — and get expert-level answers instantly.",
      features: [
        "Claude AI-powered natural language interface",
        "Context-aware answers based on your actual scan data",
        "Compliance guidance for NIS2, NIST, ISO 27001",
        "Remediation step-by-step assistance",
        "Security best practice recommendations",
        "Available 24/7, no waiting for a consultant",
      ],
      stats: [{ value: "Claude", label: "AI engine" }, { value: "24/7", label: "Available" }, { value: "NL", label: "Interface" }],
    },
  ];

  return (
    <div style={{ backgroundColor: COLORS.darker, minHeight: "100vh", fontFamily: "Inter, sans-serif" }}>
      <NetworkCanvas />
      <div style={{ position: "relative", zIndex: 1 }}>

        {/* Navbar */}
        <nav style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "20px 48px", borderBottom: `1px solid ${COLORS.border}`, backgroundColor: COLORS.darker + "f8", backdropFilter: "blur(16px)", position: "sticky", top: 0, zIndex: 50 }}>
          <div style={{ display: "flex", alignItems: "center", gap: "12px", cursor: "pointer" }} onClick={onBack}>
            <div style={{ width: "36px", height: "36px", borderRadius: "10px", backgroundColor: COLORS.blue, display: "flex", alignItems: "center", justifyContent: "center" }}>
              <Shield size={18} color="white" />
            </div>
            <span style={{ fontSize: "20px", fontWeight: "900", color: COLORS.text }}>AIPET</span>
          </div>
          <div style={{ display: "flex", gap: "16px" }}>
            <button onClick={onBack} style={{ color: COLORS.muted, background: "none", border: "none", cursor: "pointer", fontSize: "15px" }}>← Back</button>
            <button onClick={onGetStarted} style={{ backgroundColor: COLORS.blue, color: "white", border: "none", cursor: "pointer", fontSize: "15px", fontWeight: "700", padding: "10px 24px", borderRadius: "10px" }}>Get Started Free</button>
          </div>
        </nav>

        {/* Hero */}
        <div style={{ maxWidth: "1100px", margin: "0 auto", padding: "80px 48px 60px", textAlign: "center" }}>
          <div style={{ display: "inline-flex", alignItems: "center", gap: "8px", padding: "6px 16px", borderRadius: "100px", border: `1px solid ${COLORS.blue}40`, backgroundColor: COLORS.blue + "10", marginBottom: "32px" }}>
            <div style={{ width: "8px", height: "8px", borderRadius: "50%", backgroundColor: COLORS.blue }} />
            <span style={{ color: COLORS.blue, fontSize: "13px", fontWeight: "600" }}>The Platform</span>
          </div>
          <h1 style={{ fontSize: "52px", fontWeight: "900", color: COLORS.text, lineHeight: "1.1", marginBottom: "24px", letterSpacing: "-0.03em" }}>
            Seven Modules.
            <span style={{ color: COLORS.blue }}> One Platform.</span>
          </h1>
          <p style={{ fontSize: "18px", color: COLORS.muted, lineHeight: "1.7", maxWidth: "680px", margin: "0 auto 48px" }}>
            Every module in AIPET is designed to work together — from discovery to explanation to compliance. Click any module to explore its capabilities.
          </p>
          {/* Module quick nav */}
          <div style={{ display: "flex", flexWrap: "wrap", gap: "8px", justifyContent: "center" }}>
            {MODULES.map((m, i) => (
              <button key={i} onClick={() => setExpanded(expanded === m.id ? null : m.id)}
                style={{ padding: "8px 16px", borderRadius: "100px", fontSize: "13px", fontWeight: "600", cursor: "pointer", backgroundColor: expanded === m.id ? m.color + "20" : COLORS.card, color: expanded === m.id ? m.color : COLORS.muted, border: `1px solid ${expanded === m.id ? m.color : COLORS.border}`, transition: "all 0.2s" }}>
                {m.icon} {m.name}
              </button>
            ))}
          </div>
        </div>

        {/* Modules */}
        <div style={{ maxWidth: "1100px", margin: "0 auto", padding: "0 48px 80px" }}>
          {MODULES.map((module, i) => (
            <div key={i} style={{ marginBottom: "16px", borderRadius: "20px", border: `1px solid ${expanded === module.id ? module.color + "60" : COLORS.border}`, backgroundColor: COLORS.card, overflow: "hidden", transition: "all 0.3s", boxShadow: expanded === module.id ? `0 0 40px ${module.color}15` : "none" }}>

              {/* Module header — always visible */}
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "24px 32px", cursor: "pointer" }}
                onClick={() => setExpanded(expanded === module.id ? null : module.id)}>
                <div style={{ display: "flex", alignItems: "center", gap: "20px" }}>
                  <div style={{ width: "52px", height: "52px", borderRadius: "14px", backgroundColor: module.color + "20", display: "flex", alignItems: "center", justifyContent: "center", fontSize: "24px", flexShrink: 0 }}>
                    {module.icon}
                  </div>
                  <div>
                    <div style={{ fontSize: "18px", fontWeight: "800", color: module.color, marginBottom: "4px" }}>{module.name}</div>
                    <div style={{ fontSize: "14px", color: COLORS.muted }}>{module.tagline}</div>
                  </div>
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: "24px" }}>
                  {module.stats.map((s, j) => (
                    <div key={j} style={{ textAlign: "center" }}>
                      <div style={{ fontSize: "16px", fontWeight: "800", color: module.color }}>{s.value}</div>
                      <div style={{ fontSize: "11px", color: COLORS.muted, textTransform: "uppercase", letterSpacing: "0.05em" }}>{s.label}</div>
                    </div>
                  ))}
                  <div style={{ color: COLORS.muted, fontSize: "20px", transition: "transform 0.3s", transform: expanded === module.id ? "rotate(180deg)" : "rotate(0deg)" }}>▾</div>
                </div>
              </div>

              {/* Expanded content */}
              {expanded === module.id && (
                <div style={{ padding: "0 32px 32px", borderTop: `1px solid ${module.color}20` }}>
                  <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "32px", paddingTop: "32px" }}>
                    <div>
                      <p style={{ color: COLORS.muted, fontSize: "15px", lineHeight: "1.8", marginBottom: "24px" }}>{module.description}</p>
                      <button onClick={onGetStarted} style={{ backgroundColor: module.color, color: "white", border: "none", cursor: "pointer", fontSize: "14px", fontWeight: "700", padding: "12px 24px", borderRadius: "10px" }}>
                        Try {module.name} Free →
                      </button>
                    </div>
                    <div>
                      <div style={{ fontSize: "13px", fontWeight: "700", color: COLORS.muted, textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: "16px" }}>Key Capabilities</div>
                      {module.features.map((f, j) => (
                        <div key={j} style={{ display: "flex", alignItems: "flex-start", gap: "10px", marginBottom: "12px" }}>
                          <div style={{ width: "18px", height: "18px", borderRadius: "50%", backgroundColor: module.color + "20", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0, marginTop: "2px" }}>
                            <Check size={10} style={{ color: module.color }} />
                          </div>
                          <span style={{ color: COLORS.text, fontSize: "14px", lineHeight: "1.5" }}>{f}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>

        {/* Tech stack */}
        <div style={{ backgroundColor: COLORS.card, padding: "80px 48px" }}>
          <div style={{ maxWidth: "1100px", margin: "0 auto", textAlign: "center" }}>
            <h2 style={{ fontSize: "36px", fontWeight: "900", color: COLORS.text, marginBottom: "12px" }}>Built on Enterprise Technology</h2>
            <p style={{ color: COLORS.muted, fontSize: "16px", marginBottom: "48px" }}>Production-grade stack, research-grade intelligence</p>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "20px" }}>
              {[
                { category: "Backend", items: ["Flask + Gunicorn", "PostgreSQL 17", "Celery + Redis", "Docker"] },
                { category: "AI & ML", items: ["Claude AI (Anthropic)", "SHAP Explainability", "Random Forest", "NVD API"] },
                { category: "Frontend", items: ["React", "D3.js", "Stripe Billing", "react-i18next"] },
                { category: "Security", items: ["JWT Authentication", "Rate Limiting", "Nginx + SSL", "13/13 Audit Checks"] },
              ].map((stack, i) => (
                <div key={i} style={{ padding: "24px", borderRadius: "16px", border: `1px solid ${COLORS.border}`, backgroundColor: COLORS.darker, textAlign: "left" }}>
                  <div style={{ fontSize: "12px", fontWeight: "700", color: COLORS.blue, textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: "16px" }}>{stack.category}</div>
                  {stack.items.map((item, j) => (
                    <div key={j} style={{ color: COLORS.muted, fontSize: "14px", marginBottom: "8px", display: "flex", alignItems: "center", gap: "8px" }}>
                      <div style={{ width: "4px", height: "4px", borderRadius: "50%", backgroundColor: COLORS.blue }} />
                      {item}
                    </div>
                  ))}
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* CTA */}
        <div style={{ maxWidth: "900px", margin: "80px auto", padding: "0 48px" }}>
          <div style={{ background: `linear-gradient(135deg, ${COLORS.blue}15, ${COLORS.purple}10)`, border: `1px solid ${COLORS.blue}30`, borderRadius: "24px", padding: "64px 48px", textAlign: "center" }}>
            <h2 style={{ fontSize: "36px", fontWeight: "900", color: COLORS.text, marginBottom: "16px" }}>See All 7 Modules in Action</h2>
            <p style={{ color: COLORS.muted, fontSize: "16px", marginBottom: "32px" }}>Free forever. No credit card. Full platform access in 60 seconds.</p>
            <button onClick={onGetStarted} style={{ backgroundColor: COLORS.blue, color: "white", border: "none", cursor: "pointer", fontSize: "16px", fontWeight: "700", padding: "14px 36px", borderRadius: "12px", boxShadow: `0 0 32px ${COLORS.blue}40` }}>
              Get Started Free →
            </button>
          </div>
        </div>

        {/* Footer */}
        <div style={{ borderTop: `1px solid ${COLORS.border}`, padding: "24px 48px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <p style={{ color: COLORS.muted, fontSize: "13px" }}>© 2026 AIPET Cloud · MIT Licence</p>
          <button onClick={onBack} style={{ color: COLORS.blue, background: "none", border: "none", cursor: "pointer", fontSize: "13px" }}>← Back to Home</button>
        </div>

      </div>
    </div>
  );
}

// ============================================================
// SOLUTIONS PAGE
// ============================================================
function SolutionsPage({ onBack, onGetStarted }) {
  const [activeTab, setActiveTab] = useState("healthcare");

  const SOLUTIONS = {
    healthcare: {
      label: "Healthcare & NHS",
      icon: "🏥",
      color: "#00e5ff",
      hero: "Protect Medical IoT Devices. Meet NIS2. Prevent the Next Ransomware Attack.",
      stat1: { value: "£92M", label: "Average NHS breach cost" },
      stat2: { value: "NIS2", label: "Legal requirement" },
      stat3: { value: "100%", label: "Compliance coverage" },
      challenge: "NHS trusts and healthcare organisations face a perfect storm: thousands of connected medical devices, mandatory NIS2 compliance, and the constant threat of ransomware that can shut down critical patient care systems. In 2017, WannaCry shut down 80% of NHS services. Your IoT devices are the attack surface.",
      pain: [
        "Infusion pumps, patient monitors, and CCTV systems on unsecured networks",
        "NIS2 directive now legally mandates IoT security assessments",
        "Enterprise security tools cost £50,000+ per year — beyond NHS budgets",
        "IT teams lack visibility into what IoT devices are even on the network",
        "One compromised device can cascade across the entire trust",
      ],
      solution: [
        "Discover every medical IoT device on your network in 60 seconds",
        "Generate NIS2 compliance reports automatically — audit-ready instantly",
        "AI explains each vulnerability in plain English for non-technical staff",
        "Financial risk scoring shows the board exactly what a breach would cost",
        "Professional plan starts at £49/month — affordable for any NHS trust",
      ],
      quote: "AIPET gives healthcare organisations enterprise-grade IoT security at a price that actually fits NHS budgets — with the NIS2 compliance reporting they legally need.",
    },
    manufacturing: {
      label: "Manufacturing & OT",
      icon: "🏭",
      color: "#f59e0b",
      hero: "Secure Your Industrial Control Systems Before They Become Attack Vectors.",
      stat1: { value: "502", label: "Modbus TCP port exposed" },
      stat2: { value: "OT/ICS", label: "Full coverage" },
      stat3: { value: "Modbus", label: "Protocol support" },
      challenge: "Manufacturing facilities run on Modbus PLCs, SCADA systems, and industrial IoT sensors that were never designed with security in mind. A single compromised PLC can halt an entire production line — costing thousands per hour. And with Cyber Essentials now required for UK government contracts, the stakes have never been higher.",
      pain: [
        "Modbus TCP devices with no authentication — anyone can read or write registers",
        "Legacy PLCs and SCADA systems running unpatched firmware for years",
        "Production lines that cannot afford downtime for security updates",
        "Cyber Essentials certification required for government supply chain contracts",
        "OT and IT networks increasingly converging — expanding the attack surface",
      ],
      solution: [
        "AIPET Protocols scans Modbus TCP, Zigbee, and LoRaWAN industrial devices",
        "Identifies exposed holding registers and coil write access without disrupting operations",
        "Maps complete attack paths from IoT device to corporate network",
        "Generates Cyber Essentials-aligned security reports",
        "Enterprise plan includes API access for SCADA integration",
      ],
      quote: "Industrial IoT security doesn't require shutting down production. AIPET scans passively, reports precisely, and tells you exactly what to fix first.",
    },
    buildings: {
      label: "Smart Buildings",
      icon: "🏢",
      color: "#a855f7",
      hero: "Your Building's Smart Devices Are Your Biggest Security Blind Spot.",
      stat1: { value: "Zigbee", label: "Protocol support" },
      stat2: { value: "LoRaWAN", label: "Protocol support" },
      stat3: { value: "1700", label: "LoRaWAN port" },
      challenge: "Modern smart buildings run thousands of Zigbee sensors, LoRaWAN devices, and IP-connected systems for HVAC, access control, lighting, and CCTV. These devices are rarely audited, often running default credentials, and provide attackers with a foothold into corporate networks.",
      pain: [
        "Zigbee networks with unencrypted keys and rogue device vulnerabilities",
        "LoRaWAN devices susceptible to replay attacks and weak AppKey management",
        "Building management systems connected to corporate networks without isolation",
        "Thousands of devices installed by contractors with no security review",
        "No visibility into what protocols and devices are actually operating",
      ],
      solution: [
        "AIPET Protocols specifically supports Zigbee and LoRaWAN scanning",
        "Detects unencrypted network keys, rogue devices, and replay vulnerabilities",
        "Maps all building IoT devices and their network relationships",
        "Generates ISO 27001-aligned compliance reports for building audits",
        "One platform covers IT, OT, and building management system security",
      ],
      quote: "Smart building security starts with knowing what's on your network. AIPET gives you complete visibility — and tells you exactly what to fix.",
    },
    universities: {
      label: "Universities & Research",
      icon: "🎓",
      color: "#00ff88",
      hero: "Universities Are the #1 Target for Ransomware. Your IoT Lab is the Entry Point.",
      stat1: { value: "Top 3", label: "Ransomware target" },
      stat2: { value: "£49", label: "Per month" },
      stat3: { value: "Research", label: "Academic backing" },
      challenge: "Universities operate open networks with thousands of IoT devices — research equipment, smart campus sensors, student accommodation devices — and limited security budgets. Newcastle, Hertfordshire, and dozens of other UK universities have been hit by ransomware that entered through poorly secured IoT devices.",
      pain: [
        "Open academic networks with minimal access control",
        "Research IoT devices connected directly to university networks",
        "Student-owned devices creating unmanaged endpoints",
        "Limited IT security budgets compared to enterprise organisations",
        "GDPR and data protection obligations for student and research data",
      ],
      solution: [
        "Affordable Professional plan at £49/month — within any university IT budget",
        "Scans research lab IoT devices without disrupting ongoing experiments",
        "Academic research backing gives peer credibility to security findings",
        "GDPR-aligned compliance reporting for data protection officers",
        "Special research collaboration pricing available — contact us",
      ],
      quote: "Built as MSc research at Coventry University, AIPET understands the unique security challenges of academic environments — and is priced for them.",
    },
    msps: {
      label: "Managed Service Providers",
      icon: "🔧",
      color: "#00e5ff",
      hero: "Add IoT Security to Your Service Portfolio. One Platform, All Your Clients.",
      stat1: { value: "£499", label: "Enterprise plan" },
      stat2: { value: "API", label: "Full access" },
      stat3: { value: "Multi", label: "Client support" },
      challenge: "MSPs are increasingly asked by clients about IoT security — but most lack the tools to deliver it affordably. Enterprise IoT security platforms require per-client licensing that makes the economics impossible. AIPET's Enterprise plan gives MSPs a single platform to protect all their clients.",
      pain: [
        "Clients asking about IoT security but no affordable tool to offer",
        "Per-client enterprise licensing makes IoT security economically unviable",
        "No API access to integrate IoT security into existing MSP workflows",
        "Compliance requirements (NIS2, ISO 27001) becoming client demands",
        "Competitor MSPs starting to offer IoT security — risk of losing clients",
      ],
      solution: [
        "Enterprise plan at £499/month includes full API access",
        "Integrate AIPET scanning into your existing RMM and PSA tools",
        "Generate white-label compliance reports for your clients",
        "One platform covers NHS, manufacturing, and smart building clients",
        "Reseller pricing available for MSPs with 5+ clients",
      ],
      quote: "AIPET gives MSPs a competitive edge — add IoT security to your portfolio at a price that makes commercial sense for you and your clients.",
    },
  };

  const tabs = Object.keys(SOLUTIONS);
  const active = SOLUTIONS[activeTab];

  return (
    <div style={{ backgroundColor: COLORS.darker, minHeight: "100vh", fontFamily: "Inter, sans-serif" }}>
      <NetworkCanvas />
      <div style={{ position: "relative", zIndex: 1 }}>

        {/* Navbar */}
        <nav style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "20px 48px", borderBottom: `1px solid ${COLORS.border}`, backgroundColor: COLORS.darker + "f8", backdropFilter: "blur(16px)", position: "sticky", top: 0, zIndex: 50 }}>
          <div style={{ display: "flex", alignItems: "center", gap: "12px", cursor: "pointer" }} onClick={onBack}>
            <div style={{ width: "36px", height: "36px", borderRadius: "10px", backgroundColor: COLORS.blue, display: "flex", alignItems: "center", justifyContent: "center" }}>
              <Shield size={18} color="white" />
            </div>
            <span style={{ fontSize: "20px", fontWeight: "900", color: COLORS.text }}>AIPET</span>
          </div>
          <div style={{ display: "flex", gap: "16px" }}>
            <button onClick={onBack} style={{ color: COLORS.muted, background: "none", border: "none", cursor: "pointer", fontSize: "15px" }}>← Back</button>
            <button onClick={onGetStarted} style={{ backgroundColor: COLORS.blue, color: "white", border: "none", cursor: "pointer", fontSize: "15px", fontWeight: "700", padding: "10px 24px", borderRadius: "10px" }}>Get Started Free</button>
          </div>
        </nav>

        {/* Hero */}
        <div style={{ maxWidth: "1100px", margin: "0 auto", padding: "80px 48px 60px", textAlign: "center" }}>
          <div style={{ display: "inline-flex", alignItems: "center", gap: "8px", padding: "6px 16px", borderRadius: "100px", border: `1px solid ${COLORS.blue}40`, backgroundColor: COLORS.blue + "10", marginBottom: "32px" }}>
            <div style={{ width: "8px", height: "8px", borderRadius: "50%", backgroundColor: COLORS.blue }} />
            <span style={{ color: COLORS.blue, fontSize: "13px", fontWeight: "600" }}>Solutions by Industry</span>
          </div>
          <h1 style={{ fontSize: "52px", fontWeight: "900", color: COLORS.text, lineHeight: "1.1", marginBottom: "24px", letterSpacing: "-0.03em" }}>
            Built for
            <span style={{ color: COLORS.blue }}> Your Industry</span>
          </h1>
          <p style={{ fontSize: "18px", color: COLORS.muted, lineHeight: "1.7", maxWidth: "680px", margin: "0 auto" }}>
            Every industry has unique IoT security challenges. AIPET is designed to address them all — with industry-specific compliance, protocols, and reporting.
          </p>
        </div>

        {/* Industry tabs */}
        <div style={{ maxWidth: "1100px", margin: "0 auto", padding: "0 48px" }}>
          <div style={{ display: "flex", gap: "8px", marginBottom: "32px", flexWrap: "wrap" }}>
            {tabs.map(tab => (
              <button key={tab} onClick={() => setActiveTab(tab)}
                style={{ padding: "10px 20px", borderRadius: "100px", fontSize: "14px", fontWeight: "600", cursor: "pointer", backgroundColor: activeTab === tab ? SOLUTIONS[tab].color + "20" : COLORS.card, color: activeTab === tab ? SOLUTIONS[tab].color : COLORS.muted, border: `1px solid ${activeTab === tab ? SOLUTIONS[tab].color : COLORS.border}`, transition: "all 0.2s" }}>
                {SOLUTIONS[tab].icon} {SOLUTIONS[tab].label}
              </button>
            ))}
          </div>

          {/* Active solution content */}
          <div style={{ borderRadius: "24px", border: `1px solid ${active.color}30`, backgroundColor: COLORS.card, overflow: "hidden", boxShadow: `0 0 60px ${active.color}10` }}>

            {/* Solution hero */}
            <div style={{ padding: "48px", background: `linear-gradient(135deg, ${active.color}12, transparent)`, borderBottom: `1px solid ${active.color}20` }}>
              <div style={{ fontSize: "48px", marginBottom: "16px" }}>{active.icon}</div>
              <h2 style={{ fontSize: "28px", fontWeight: "900", color: COLORS.text, marginBottom: "32px", maxWidth: "700px", lineHeight: "1.3" }}>{active.hero}</h2>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(3, auto)", gap: "32px" }}>
                {[active.stat1, active.stat2, active.stat3].map((s, i) => (
                  <div key={i}>
                    <div style={{ fontSize: "24px", fontWeight: "900", color: active.color, marginBottom: "4px" }}>{s.value}</div>
                    <div style={{ color: COLORS.muted, fontSize: "13px", textTransform: "uppercase", letterSpacing: "0.05em" }}>{s.label}</div>
                  </div>
                ))}
              </div>
            </div>

            {/* Challenge + Solution */}
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0" }}>
              <div style={{ padding: "40px 48px", borderRight: `1px solid ${COLORS.border}` }}>
                <div style={{ fontSize: "12px", fontWeight: "700", color: "#ff4444", textTransform: "uppercase", letterSpacing: "0.1em", marginBottom: "20px" }}>⚠ The Challenge</div>
                <p style={{ color: COLORS.muted, fontSize: "15px", lineHeight: "1.8", marginBottom: "24px" }}>{active.challenge}</p>
                <div style={{ space: "12px" }}>
                  {active.pain.map((p, i) => (
                    <div key={i} style={{ display: "flex", gap: "10px", marginBottom: "12px", alignItems: "flex-start" }}>
                      <div style={{ color: "#ff4444", fontSize: "16px", flexShrink: 0, marginTop: "2px" }}>✕</div>
                      <span style={{ color: COLORS.muted, fontSize: "14px", lineHeight: "1.5" }}>{p}</span>
                    </div>
                  ))}
                </div>
              </div>
              <div style={{ padding: "40px 48px" }}>
                <div style={{ fontSize: "12px", fontWeight: "700", color: active.color, textTransform: "uppercase", letterSpacing: "0.1em", marginBottom: "20px" }}>✓ The AIPET Solution</div>
                <div style={{ marginBottom: "24px" }}>
                  {active.solution.map((s, i) => (
                    <div key={i} style={{ display: "flex", gap: "10px", marginBottom: "12px", alignItems: "flex-start" }}>
                      <div style={{ width: "18px", height: "18px", borderRadius: "50%", backgroundColor: active.color + "20", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0, marginTop: "2px" }}>
                        <Check size={10} style={{ color: active.color }} />
                      </div>
                      <span style={{ color: COLORS.text, fontSize: "14px", lineHeight: "1.5" }}>{s}</span>
                    </div>
                  ))}
                </div>
                <blockquote style={{ borderLeft: `3px solid ${active.color}`, paddingLeft: "16px", color: COLORS.muted, fontSize: "14px", lineHeight: "1.7", fontStyle: "italic", margin: "24px 0" }}>
                  "{active.quote}"
                </blockquote>
                <button onClick={onGetStarted} style={{ backgroundColor: active.color, color: "white", border: "none", cursor: "pointer", fontSize: "15px", fontWeight: "700", padding: "12px 28px", borderRadius: "10px" }}>
                  Get Started Free →
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Compliance coverage */}
        <div style={{ maxWidth: "1100px", margin: "80px auto 0", padding: "0 48px" }}>
          <div style={{ textAlign: "center", marginBottom: "48px" }}>
            <h2 style={{ fontSize: "32px", fontWeight: "900", color: COLORS.text, marginBottom: "12px" }}>Compliance Coverage Across Every Industry</h2>
            <p style={{ color: COLORS.muted, fontSize: "16px" }}>One platform. Every major security framework.</p>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "20px", marginBottom: "80px" }}>
            {[
              { name: "NIS2", region: "European Union", desc: "Mandatory for operators of essential services. AIPET generates audit-ready NIS2 compliance reports automatically.", color: COLORS.blue },
              { name: "NIST CSF 2.0", region: "United States", desc: "Required for US federal contractors. AIPET maps findings to all 6 NIST functions: Govern, Identify, Protect, Detect, Respond, Recover.", color: COLORS.purple },
              { name: "ISO 27001", region: "Global", desc: "The international standard for information security. AIPET covers all relevant ISO 27001 controls for IoT security.", color: COLORS.low },
            ].map((item, i) => (
              <div key={i} style={{ padding: "28px", borderRadius: "16px", border: `1px solid ${item.color}30`, backgroundColor: COLORS.card }}>
                <div style={{ fontSize: "22px", fontWeight: "900", color: item.color, marginBottom: "4px" }}>{item.name}</div>
                <div style={{ fontSize: "12px", color: COLORS.muted, textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: "16px" }}>{item.region}</div>
                <p style={{ color: COLORS.muted, fontSize: "14px", lineHeight: "1.6" }}>{item.desc}</p>
              </div>
            ))}
          </div>
        </div>

        {/* CTA */}
        <div style={{ maxWidth: "900px", margin: "0 auto 80px", padding: "0 48px" }}>
          <div style={{ background: `linear-gradient(135deg, ${COLORS.blue}15, ${COLORS.purple}10)`, border: `1px solid ${COLORS.blue}30`, borderRadius: "24px", padding: "64px 48px", textAlign: "center" }}>
            <h2 style={{ fontSize: "36px", fontWeight: "900", color: COLORS.text, marginBottom: "16px" }}>Ready to Protect Your Organisation?</h2>
            <p style={{ color: COLORS.muted, fontSize: "16px", marginBottom: "32px" }}>Free forever. No credit card. Full compliance reporting from day one.</p>
            <div style={{ display: "flex", justifyContent: "center", gap: "16px" }}>
              <button onClick={onGetStarted} style={{ backgroundColor: COLORS.blue, color: "white", border: "none", cursor: "pointer", fontSize: "16px", fontWeight: "700", padding: "14px 36px", borderRadius: "12px", boxShadow: `0 0 32px ${COLORS.blue}40` }}>
                Get Started Free →
              </button>
              <button onClick={onGetStarted} style={{ backgroundColor: "transparent", color: COLORS.blue, border: `2px solid ${COLORS.blue}`, cursor: "pointer", fontSize: "16px", fontWeight: "700", padding: "14px 36px", borderRadius: "12px" }}>
                Request Demo
              </button>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div style={{ borderTop: `1px solid ${COLORS.border}`, padding: "24px 48px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <p style={{ color: COLORS.muted, fontSize: "13px" }}>© 2026 AIPET Cloud · MIT Licence</p>
          <button onClick={onBack} style={{ color: COLORS.blue, background: "none", border: "none", cursor: "pointer", fontSize: "13px" }}>← Back to Home</button>
        </div>

      </div>
    </div>
  );
}

function AboutPage({ onBack, onGetStarted }) {
  return (
    <div style={{ backgroundColor: COLORS.darker, minHeight: "100vh", fontFamily: "Inter, sans-serif" }}>
      <NetworkCanvas />
      <div style={{ position: "relative", zIndex: 1 }}>

        {/* Navbar */}
        <nav style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "20px 48px", borderBottom: `1px solid ${COLORS.border}`, backgroundColor: COLORS.darker + "f8", backdropFilter: "blur(16px)", position: "sticky", top: 0, zIndex: 50 }}>
          <div style={{ display: "flex", alignItems: "center", gap: "12px", cursor: "pointer" }} onClick={onBack}>
            <div style={{ width: "36px", height: "36px", borderRadius: "10px", backgroundColor: COLORS.blue, display: "flex", alignItems: "center", justifyContent: "center" }}>
              <Shield size={18} color="white" />
            </div>
            <span style={{ fontSize: "20px", fontWeight: "900", color: COLORS.text }}>AIPET</span>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: "16px" }}>
            <button onClick={onBack} style={{ color: COLORS.muted, background: "none", border: "none", cursor: "pointer", fontSize: "15px", display: "flex", alignItems: "center", gap: "6px" }}>
              ← Back
            </button>
            <button onClick={onGetStarted} style={{ backgroundColor: COLORS.blue, color: "white", border: "none", cursor: "pointer", fontSize: "15px", fontWeight: "700", padding: "10px 24px", borderRadius: "10px" }}>
              Get Started Free
            </button>
          </div>
        </nav>

        {/* Hero */}
        <div style={{ maxWidth: "900px", margin: "0 auto", padding: "80px 48px 60px", textAlign: "center" }}>
          <div style={{ display: "inline-flex", alignItems: "center", gap: "8px", padding: "6px 16px", borderRadius: "100px", border: `1px solid ${COLORS.blue}40`, backgroundColor: COLORS.blue + "10", marginBottom: "32px" }}>
            <div style={{ width: "8px", height: "8px", borderRadius: "50%", backgroundColor: COLORS.blue }} />
            <span style={{ color: COLORS.blue, fontSize: "13px", fontWeight: "600" }}>About AIPET</span>
          </div>
          <h1 style={{ fontSize: "52px", fontWeight: "900", color: COLORS.text, lineHeight: "1.1", marginBottom: "24px", letterSpacing: "-0.03em" }}>
            Democratising
            <span style={{ color: COLORS.blue }}> Enterprise IoT Security</span>
          </h1>
          <p style={{ fontSize: "18px", color: COLORS.muted, lineHeight: "1.8", maxWidth: "700px", margin: "0 auto" }}>
            Built as advanced cybersecurity research at Coventry University, AIPET delivers enterprise-grade IoT security to every organisation — regardless of size or budget.
          </p>
        </div>

        {/* Mission Statement */}
        <div style={{ maxWidth: "900px", margin: "0 auto 80px", padding: "0 48px" }}>
          <div style={{ background: `linear-gradient(135deg, ${COLORS.blue}12, ${COLORS.purple}08)`, border: `1px solid ${COLORS.blue}30`, borderRadius: "24px", padding: "48px" }}>
            <div style={{ fontSize: "13px", fontWeight: "700", color: COLORS.blue, letterSpacing: "0.1em", textTransform: "uppercase", marginBottom: "24px" }}>Our Mission</div>
            <blockquote style={{ fontSize: "20px", color: COLORS.text, lineHeight: "1.8", fontStyle: "italic", margin: "0 0 32px 0", borderLeft: `3px solid ${COLORS.blue}`, paddingLeft: "24px" }}>
              "The IoT security market is broken. Enterprises spend millions on tools that tell them what is vulnerable — but not why, not what it costs, and not how to fix it. Meanwhile, thousands of hospitals, manufacturers, and critical infrastructure operators remain exposed because enterprise pricing puts proper security out of reach.
              <br /><br />
              AIPET was built to change that. Our AI doesn't just find vulnerabilities. It explains the complete attack chain, quantifies financial exposure, maps against NIS2, NIST CSF 2.0, and ISO 27001, and provides exact remediation steps. In plain English. In 60 seconds.
              <br /><br />
              Because every organisation — regardless of size or budget — deserves to know exactly how they would be attacked, and exactly how to stop it."
            </blockquote>
            <div style={{ display: "flex", alignItems: "center", gap: "16px" }}>
              <div style={{ width: "48px", height: "48px", borderRadius: "50%", backgroundColor: COLORS.blue, display: "flex", alignItems: "center", justifyContent: "center", fontSize: "20px", fontWeight: "900", color: "white" }}>B</div>
              <div>
                <div style={{ color: COLORS.text, fontWeight: "700", fontSize: "16px" }}>Binyam Yallew</div>
                <div style={{ color: COLORS.muted, fontSize: "14px" }}>Founder, AIPET Cloud · MSc Cyber Security (Ethical Hacking), Coventry University</div>
              </div>
            </div>
          </div>
        </div>

        {/* The Builder */}
        <div style={{ maxWidth: "900px", margin: "0 auto 80px", padding: "0 48px" }}>
          <h2 style={{ fontSize: "36px", fontWeight: "900", color: COLORS.text, marginBottom: "48px", textAlign: "center" }}>The Builder</h2>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 2fr", gap: "48px", alignItems: "start" }}>
            <div style={{ textAlign: "center" }}>
              <div style={{ width: "120px", height: "120px", borderRadius: "50%", backgroundColor: COLORS.blue + "20", border: `2px solid ${COLORS.blue}`, display: "flex", alignItems: "center", justifyContent: "center", margin: "0 auto 16px", fontSize: "48px", fontWeight: "900", color: COLORS.blue }}>B</div>
              <div style={{ color: COLORS.text, fontWeight: "700", fontSize: "18px" }}>Binyam Yallew</div>
              <div style={{ color: COLORS.blue, fontSize: "14px", marginBottom: "16px" }}>Founder & Lead Developer</div>
              <a href="https://github.com/Yallewbinyam/AIPET" target="_blank" rel="noreferrer"
                style={{ display: "inline-flex", alignItems: "center", gap: "6px", color: COLORS.muted, fontSize: "13px", textDecoration: "none", padding: "6px 12px", borderRadius: "8px", border: `1px solid ${COLORS.border}` }}
                onMouseEnter={e => e.currentTarget.style.borderColor = COLORS.blue}
                onMouseLeave={e => e.currentTarget.style.borderColor = COLORS.border}>
                GitHub →
              </a>
            </div>
            <div>
              <p style={{ color: COLORS.muted, fontSize: "16px", lineHeight: "1.8", marginBottom: "24px" }}>
                Software developer, ethical hacker, security researcher, and founder of AIPET. Currently completing an MSc in Cyber Security with specialisation in Ethical Hacking at Coventry University (2024–2026).
              </p>
              <p style={{ color: COLORS.muted, fontSize: "16px", lineHeight: "1.8", marginBottom: "32px" }}>
                AIPET was developed as an MSc dissertation project under academic supervision at Coventry University — combining real-world penetration testing expertise with AI/ML research to create a platform that addresses genuine gaps in the IoT security market.
              </p>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px" }}>
                {[
                  { label: "Institution", value: "Coventry University" },
                  { label: "Degree", value: "MSc Cyber Security" },
                  { label: "Specialisation", value: "Ethical Hacking" },
                  { label: "Supervisor", value: "Dr Dan" },
                  { label: "Graduation", value: "November 2026" },
                  { label: "Contact", value: "yallewb@coventry.ac.uk" },
                ].map((item, i) => (
                  <div key={i} style={{ padding: "16px", borderRadius: "12px", backgroundColor: COLORS.card, border: `1px solid ${COLORS.border}` }}>
                    <div style={{ color: COLORS.muted, fontSize: "11px", fontWeight: "700", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: "4px" }}>{item.label}</div>
                    <div style={{ color: COLORS.text, fontSize: "14px", fontWeight: "600" }}>{item.value}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* What makes AIPET different */}
        <div style={{ backgroundColor: COLORS.card, padding: "80px 48px" }}>
          <div style={{ maxWidth: "900px", margin: "0 auto" }}>
            <h2 style={{ fontSize: "36px", fontWeight: "900", color: COLORS.text, marginBottom: "12px", textAlign: "center" }}>What Makes AIPET Different</h2>
            <p style={{ color: COLORS.muted, fontSize: "16px", textAlign: "center", marginBottom: "48px" }}>The only IoT security platform that explains the complete attack story</p>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "24px" }}>
              {[
                { icon: "🧠", title: "Explainable AI", desc: "SHAP-powered explanations tell you exactly why each device is vulnerable — not just that it is. No other platform does this.", color: COLORS.blue },
                { icon: "💰", title: "Financial Risk Scoring", desc: "Quantifies the financial impact of each vulnerability using IBM and NCSC 2024 breach data. Your board will understand this.", color: COLORS.purple },
                { icon: "📋", title: "Instant Compliance", desc: "Generates NIS2, NIST CSF 2.0, and ISO 27001 compliance reports automatically. What used to take weeks now takes seconds.", color: COLORS.low },
                { icon: "⚡", title: "60 Second Scans", desc: "Full IoT network assessment in under 60 seconds. Enterprise tools take days to deploy. AIPET takes minutes.", color: COLORS.high },
                { icon: "🌍", title: "Global Ready", desc: "Available in 10 languages, 4 currencies, and compliant with regulations across EU, USA, and Asia.", color: COLORS.blue },
                { icon: "🔬", title: "Academic Research", desc: "Built on peer-reviewed cybersecurity research at Coventry University. Not just a product — a scientific contribution.", color: COLORS.purple },
              ].map((item, i) => (
                <div key={i} style={{ padding: "28px", borderRadius: "16px", border: `1px solid ${item.color}30`, backgroundColor: COLORS.darker, transition: "all 0.2s" }}
                  onMouseEnter={e => { e.currentTarget.style.borderColor = item.color; e.currentTarget.style.transform = "translateY(-4px)"; }}
                  onMouseLeave={e => { e.currentTarget.style.borderColor = item.color + "30"; e.currentTarget.style.transform = "translateY(0)"; }}>
                  <div style={{ fontSize: "32px", marginBottom: "16px" }}>{item.icon}</div>
                  <h3 style={{ fontSize: "16px", fontWeight: "700", color: COLORS.text, marginBottom: "8px" }}>{item.title}</h3>
                  <p style={{ color: COLORS.muted, fontSize: "14px", lineHeight: "1.6" }}>{item.desc}</p>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Academic backing */}
        <div style={{ maxWidth: "900px", margin: "0 auto", padding: "80px 48px" }}>
          <div style={{ textAlign: "center", marginBottom: "48px" }}>
            <h2 style={{ fontSize: "36px", fontWeight: "900", color: COLORS.text, marginBottom: "12px" }}>Academic Backing</h2>
            <p style={{ color: COLORS.muted, fontSize: "16px" }}>Research-grade security, accessible pricing</p>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "24px", textAlign: "center" }}>
            {[
              { value: "NIS2", label: "EU Compliance", color: COLORS.blue },
              { value: "NIST", label: "USA Framework", color: COLORS.purple },
              { value: "ISO 27001", label: "Global Standard", color: COLORS.low },
            ].map((item, i) => (
              <div key={i} style={{ padding: "32px", borderRadius: "16px", border: `1px solid ${item.color}40`, backgroundColor: COLORS.card }}>
                <div style={{ fontSize: "28px", fontWeight: "900", color: item.color, marginBottom: "8px" }}>{item.value}</div>
                <div style={{ color: COLORS.muted, fontSize: "14px" }}>{item.label}</div>
              </div>
            ))}
          </div>
          <div style={{ textAlign: "center", marginTop: "48px", padding: "32px", borderRadius: "16px", border: `1px solid ${COLORS.border}`, backgroundColor: COLORS.card }}>
            <div style={{ color: COLORS.muted, fontSize: "15px", lineHeight: "1.8" }}>
              AIPET is developed under academic supervision at <span style={{ color: COLORS.blue, fontWeight: "700" }}>Coventry University</span> as part of an MSc Cyber Security dissertation.
              Supervised by <span style={{ color: COLORS.text, fontWeight: "700" }}>Dr Dan</span>.
              Contact: <a href="mailto:yallewb@coventry.ac.uk" style={{ color: COLORS.blue }}>yallewb@coventry.ac.uk</a>
            </div>
          </div>
        </div>

        {/* CTA */}
        <div style={{ background: `linear-gradient(135deg, ${COLORS.blue}15, ${COLORS.purple}10)`, border: `1px solid ${COLORS.blue}30`, borderRadius: "24px", padding: "64px 48px", textAlign: "center", margin: "0 48px 80px", maxWidth: "804px", marginLeft: "auto", marginRight: "auto" }}>
          <h2 style={{ fontSize: "32px", fontWeight: "900", color: COLORS.text, marginBottom: "16px" }}>Ready to secure your IoT infrastructure?</h2>
          <p style={{ color: COLORS.muted, fontSize: "16px", marginBottom: "32px" }}>Join organisations already using AIPET to protect their IoT devices.</p>
          <button onClick={onGetStarted} style={{ backgroundColor: COLORS.blue, color: "white", border: "none", cursor: "pointer", fontSize: "16px", fontWeight: "700", padding: "14px 36px", borderRadius: "12px", boxShadow: `0 0 32px ${COLORS.blue}40` }}>
            Get Started Free →
          </button>
        </div>

        {/* Footer */}
        <div style={{ borderTop: `1px solid ${COLORS.border}`, padding: "24px 48px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <p style={{ color: COLORS.muted, fontSize: "13px" }}>© 2026 AIPET Cloud · MIT Licence</p>
          <button onClick={onBack} style={{ color: COLORS.blue, background: "none", border: "none", cursor: "pointer", fontSize: "13px" }}>← Back to Home</button>
        </div>

      </div>
    </div>
  );
}

// ============================================================
// CONTACT PAGE
// ============================================================
function ContactPage({ onBack }) {
  const [form, setForm] = useState({ name: "", email: "", organisation: "", subject: "General Inquiry", message: "" });
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(false);

  const subjects = ["General Inquiry", "Request Demo", "Technical Support", "Partnership", "Research Collaboration", "Press & Media"];

  const handleSubmit = async () => {
    if (!form.name || !form.email || !form.message) {
      setStatus({ type: "error", text: "Please fill in all required fields." });
      return;
    }
    setLoading(true);
    // Simulate sending
    await new Promise(r => setTimeout(r, 1500));
    setStatus({ type: "success", text: "Message sent successfully! We will respond within 24 hours." });
    setLoading(false);
    setForm({ name: "", email: "", organisation: "", subject: "General Inquiry", message: "" });
  };

  const inputStyle = { width: "100%", padding: "14px 16px", borderRadius: "12px", border: `1px solid ${COLORS.border}`, backgroundColor: COLORS.darker, color: COLORS.text, fontSize: "15px", fontFamily: "Inter, sans-serif", outline: "none", boxSizing: "border-box", WebkitBoxShadow: `0 0 0 1000px ${COLORS.darker} inset`, WebkitTextFillColor: COLORS.text };

  return (
    <div style={{ backgroundColor: COLORS.darker, minHeight: "100vh", fontFamily: "Inter, sans-serif" }}>
      <NetworkCanvas />
      <div style={{ position: "relative", zIndex: 1 }}>

        {/* Navbar */}
        <nav style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "20px 48px", borderBottom: `1px solid ${COLORS.border}`, backgroundColor: COLORS.darker + "f8", backdropFilter: "blur(16px)", position: "sticky", top: 0, zIndex: 50 }}>
          <div style={{ display: "flex", alignItems: "center", gap: "12px", cursor: "pointer" }} onClick={onBack}>
            <div style={{ width: "36px", height: "36px", borderRadius: "10px", backgroundColor: COLORS.blue, display: "flex", alignItems: "center", justifyContent: "center" }}>
              <Shield size={18} color="white" />
            </div>
            <span style={{ fontSize: "20px", fontWeight: "900", color: COLORS.text }}>AIPET</span>
          </div>
          <button onClick={onBack} style={{ color: COLORS.muted, background: "none", border: "none", cursor: "pointer", fontSize: "15px" }}>← Back</button>
        </nav>

        {/* Hero */}
        <div style={{ maxWidth: "900px", margin: "0 auto", padding: "80px 48px 60px", textAlign: "center" }}>
          <div style={{ display: "inline-flex", alignItems: "center", gap: "8px", padding: "6px 16px", borderRadius: "100px", border: `1px solid ${COLORS.blue}40`, backgroundColor: COLORS.blue + "10", marginBottom: "32px" }}>
            <div style={{ width: "8px", height: "8px", borderRadius: "50%", backgroundColor: COLORS.blue }} />
            <span style={{ color: COLORS.blue, fontSize: "13px", fontWeight: "600" }}>Get In Touch</span>
          </div>
          <h1 style={{ fontSize: "48px", fontWeight: "900", color: COLORS.text, lineHeight: "1.1", marginBottom: "20px", letterSpacing: "-0.03em" }}>
            Let's Talk About
            <span style={{ color: COLORS.blue }}> IoT Security</span>
          </h1>
          <p style={{ fontSize: "17px", color: COLORS.muted, lineHeight: "1.7" }}>
            Whether you want a demo, have a technical question, or want to explore a research collaboration — we respond within 24 hours.
          </p>
        </div>

        {/* Content */}
        <div style={{ maxWidth: "900px", margin: "0 auto", padding: "0 48px 80px", display: "grid", gridTemplateColumns: "1fr 1.5fr", gap: "48px", alignItems: "start" }}>

          {/* Left — contact info */}
          <div>
            <h3 style={{ fontSize: "20px", fontWeight: "800", color: COLORS.text, marginBottom: "24px" }}>Contact Information</h3>
            {[
              { icon: "📧", label: "Email", value: "yallewb@coventry.ac.uk", link: "mailto:yallewb@coventry.ac.uk" },
              { icon: "🎓", label: "Institution", value: "Coventry University", link: null },
              { icon: "🔬", label: "Research", value: "MSc Cyber Security (Ethical Hacking)", link: null },
              { icon: "👨‍💻", label: "GitHub", value: "github.com/Yallewbinyam/AIPET", link: "https://github.com/Yallewbinyam/AIPET" },
            ].map((item, i) => (
              <div key={i} style={{ display: "flex", gap: "16px", marginBottom: "24px", padding: "16px", borderRadius: "12px", border: `1px solid ${COLORS.border}`, backgroundColor: COLORS.card }}>
                <div style={{ fontSize: "24px" }}>{item.icon}</div>
                <div>
                  <div style={{ color: COLORS.muted, fontSize: "12px", fontWeight: "700", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: "4px" }}>{item.label}</div>
                  {item.link ? (
                    <a href={item.link} target="_blank" rel="noreferrer" style={{ color: COLORS.blue, fontSize: "14px", textDecoration: "none" }}>{item.value}</a>
                  ) : (
                    <div style={{ color: COLORS.text, fontSize: "14px", fontWeight: "600" }}>{item.value}</div>
                  )}
                </div>
              </div>
            ))}

            {/* Response time */}
            <div style={{ padding: "20px", borderRadius: "12px", backgroundColor: COLORS.blue + "10", border: `1px solid ${COLORS.blue}30` }}>
              <div style={{ color: COLORS.blue, fontSize: "13px", fontWeight: "700", marginBottom: "8px" }}>⚡ Response Time</div>
              <div style={{ color: COLORS.muted, fontSize: "13px", lineHeight: "1.6" }}>We typically respond within 24 hours on weekdays. For urgent security matters, email directly.</div>
            </div>
          </div>

          {/* Right — contact form */}
          <div style={{ padding: "36px", borderRadius: "20px", border: `1px solid ${COLORS.border}`, backgroundColor: COLORS.card, boxShadow: `0 0 40px ${COLORS.blue}08` }}>
            <h3 style={{ fontSize: "20px", fontWeight: "800", color: COLORS.text, marginBottom: "24px" }}>Send a Message</h3>

            {status && (
              <div style={{ padding: "14px 16px", borderRadius: "12px", marginBottom: "20px", backgroundColor: status.type === "success" ? COLORS.low + "20" : COLORS.critical + "20", border: `1px solid ${status.type === "success" ? COLORS.low : COLORS.critical}40`, color: status.type === "success" ? COLORS.low : COLORS.critical, fontSize: "14px" }}>
                {status.text}
              </div>
            )}

            <div style={{ marginBottom: "16px" }}>
              <label style={{ display: "block", color: COLORS.muted, fontSize: "12px", fontWeight: "700", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: "8px" }}>Full Name *</label>
              <input value={form.name} onChange={e => setForm({...form, name: e.target.value})} placeholder="John Smith" style={inputStyle} />
            </div>

            <div style={{ marginBottom: "16px" }}>
              <label style={{ display: "block", color: COLORS.muted, fontSize: "12px", fontWeight: "700", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: "8px" }}>Email Address *</label>
              <input type="email" value={form.email} onChange={e => setForm({...form, email: e.target.value})} placeholder="you@company.com" style={inputStyle} />
            </div>

            <div style={{ marginBottom: "16px" }}>
              <label style={{ display: "block", color: COLORS.muted, fontSize: "12px", fontWeight: "700", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: "8px" }}>Organisation</label>
              <input value={form.organisation} onChange={e => setForm({...form, organisation: e.target.value})} placeholder="Your company or institution" style={inputStyle} />
            </div>

            <div style={{ marginBottom: "16px" }}>
              <label style={{ display: "block", color: COLORS.muted, fontSize: "12px", fontWeight: "700", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: "8px" }}>Subject</label>
              <select value={form.subject} onChange={e => setForm({...form, subject: e.target.value})} style={{ ...inputStyle }}>
                {subjects.map((s, i) => <option key={i} value={s}>{s}</option>)}
              </select>
            </div>

            <div style={{ marginBottom: "24px" }}>
              <label style={{ display: "block", color: COLORS.muted, fontSize: "12px", fontWeight: "700", textTransform: "uppercase", letterSpacing: "0.08em", marginBottom: "8px" }}>Message *</label>
              <textarea value={form.message} onChange={e => setForm({...form, message: e.target.value})} placeholder="Tell us about your IoT security needs..." rows={5} style={{ ...inputStyle, resize: "vertical" }} />
            </div>

            <button onClick={handleSubmit} disabled={loading}
              style={{ width: "100%", padding: "14px", borderRadius: "12px", backgroundColor: loading ? COLORS.border : COLORS.blue, color: "white", border: "none", cursor: loading ? "not-allowed" : "pointer", fontSize: "16px", fontWeight: "700", fontFamily: "Inter, sans-serif", boxShadow: loading ? "none" : `0 0 24px ${COLORS.blue}40` }}>
              {loading ? "Sending..." : "Send Message →"}
            </button>
          </div>
        </div>

        {/* Footer */}
        <div style={{ borderTop: `1px solid ${COLORS.border}`, padding: "24px 48px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <p style={{ color: COLORS.muted, fontSize: "13px" }}>© 2026 AIPET Cloud · MIT Licence</p>
          <button onClick={onBack} style={{ color: COLORS.blue, background: "none", border: "none", cursor: "pointer", fontSize: "13px" }}>← Back to Home</button>
        </div>

      </div>
    </div>
  );
}

function LandingPage({ onGetStarted, onLogin, setLegalPage, setActivePage }) {
  const { t, i18n } = useTranslation();
  const [currency, setCurrency] = useState({ code: 'GBP', symbol: '£' });

  const CURRENCY_PRICES = {
    GBP: { professional: '49', enterprise: '499' },
    USD: { professional: '59', enterprise: '599' },
    EUR: { professional: '55', enterprise: '549' },
    JPY: { professional: '8,900', enterprise: '89,000' },
  };

  useEffect(() => {
    fetch('http://localhost:5001/payments/detect-currency')
      .then(r => r.json())
      .then(d => setCurrency({ code: d.currency, symbol: d.symbol }))
      .catch(() => setCurrency({ code: 'GBP', symbol: '£' }));
  }, []);

  const [langOpen, setLangOpen] = useState(false);
  const [activeDropdown, setActiveDropdown] = useState(null);

  const NAV_MENUS = {
    platform: [
      { label: "AIPET Scan", desc: "Discover IoT vulnerabilities", action: () => setActivePage('platform') },
      { label: "AIPET Explain", desc: "AI-powered explanations", action: () => setActivePage('platform') },
      { label: "AIPET Score", desc: "Financial risk exposure", action: () => setActivePage('platform') },
      { label: "AIPET Map", desc: "Network attack paths", action: () => setActivePage('platform') },
      { label: "AIPET Predict", desc: "Live CVE intelligence", action: () => setActivePage('platform') },
      { label: "AIPET Watch", desc: "Anomaly detection", action: () => setActivePage('platform') },
      { label: "AIPET Ask", desc: "AI security assistant", action: () => setActivePage('platform') },
    ],
    solutions: [
      { label: "Healthcare & NHS", desc: "NIS2 compliant IoT audits", action: () => setActivePage('solutions') },
      { label: "Manufacturing", desc: "OT/ICS security", action: () => setActivePage('solutions') },
      { label: "Smart Buildings", desc: "Zigbee & LoRaWAN security", action: () => setActivePage('solutions') },
      { label: "Universities", desc: "Research lab IoT protection", action: () => setActivePage('solutions') },
      { label: "MSPs", desc: "Multi-client security platform", action: () => setActivePage('solutions') },
    ],
    company: [
      { label: "About AIPET", desc: "Our mission and research", action: () => setActivePage('about') },
      { label: "Contact Us", desc: "Get in touch", action: () => setActivePage('contact') },
      { label: "GitHub", desc: "Open source contributions", action: () => window.open('https://github.com/Yallewbinyam/AIPET', '_blank') },
    ],
  };

  const LANGUAGES = [
    { code: 'en', label: 'EN', name: 'English' },
    { code: 'fr', label: 'FR', name: 'Français' },
    { code: 'de', label: 'DE', name: 'Deutsch' },
    { code: 'ja', label: 'JA', name: '日本語' },
    { code: 'es', label: 'ES', name: 'Español' },
    { code: 'zh', label: 'ZH', name: '中文' },
    { code: 'ar', label: 'AR', name: 'العربية' },
    { code: 'pt', label: 'PT', name: 'Português' },
    { code: 'it', label: 'IT', name: 'Italiano' },
    { code: 'nl', label: 'NL', name: 'Nederlands' },
  ];

  return (
    <div className="min-h-screen" style={{ backgroundColor: COLORS.darker, fontFamily: "Inter, sans-serif", position: "relative" }} onClick={() => { setActiveDropdown(null); setLangOpen(false); }}>
      <NetworkCanvas />
      <div style={{ position: "relative", zIndex: 1 }}>

      {/* TOP ANNOUNCEMENT BAR */}
      <div style={{ width: "100%", background: `linear-gradient(90deg, ${COLORS.blue}cc, #0099cc, ${COLORS.blue}cc)`, borderBottom: `1px solid ${COLORS.blue}`, color: "white", textAlign: "center", padding: "10px 32px", fontSize: "14px", fontWeight: "600" }}>
        🔒 &nbsp; AIPET Cloud v3.0.0 — AI-Powered IoT Security Platform &nbsp;&nbsp;·&nbsp;&nbsp; NIS2 &nbsp;|&nbsp; NIST CSF 2.0 &nbsp;|&nbsp; ISO 27001 Compliant &nbsp;&nbsp;·&nbsp;&nbsp;
        <span style={{ textDecoration: "underline", cursor: "pointer", fontWeight: "700" }} onClick={onGetStarted}>Start Free Trial →</span>
      </div>

      {/* MAIN NAVBAR */}
      <nav className="flex items-center px-8 py-5 sticky top-0 z-50"
        style={{ borderBottom: `1px solid ${COLORS.blue}30`, backgroundColor: COLORS.darker + "f8", backdropFilter: "blur(16px)", gap: "24px", boxShadow: `0 4px 24px rgba(0,229,255,0.05)` }}
        onClick={e => e.stopPropagation()}>
        <div className="flex items-center gap-3" style={{ flexShrink: 0 }}>
          <div className="w-10 h-10 rounded-xl flex items-center justify-center" style={{ backgroundColor: COLORS.blue }}>
            <Shield size={20} color="white" />
          </div>
          <span style={{ color: COLORS.text, fontSize: "22px", fontWeight: "900", letterSpacing: "-0.02em" }}>AIPET</span>
        </div>
        <div className="flex items-center justify-center" style={{ flex: 1, paddingLeft: "80px" }}>
          <div className="hidden md:flex items-center gap-6">
            {[
              { label: t("nav.features"), id: "features", menu: null },
              { label: t("nav.platform"), id: null, menu: "platform" },
              { label: t("nav.howItWorks"), id: "how-it-works", menu: null },
              { label: t("nav.solutions"), id: null, menu: "solutions" },
              { label: t("nav.pricing"), id: "pricing", menu: null },
              { label: t("nav.company"), id: null, menu: "company" },
            ].map((link, i) => (
              <div key={i} style={{ position: "relative" }}>
                <button
                  onClick={() => { if (link.id) { document.getElementById(link.id)?.scrollIntoView({ behavior: "smooth" }); setActiveDropdown(null); } else { setActiveDropdown(activeDropdown === link.menu ? null : link.menu); }}}
                  style={{ color: activeDropdown === link.menu ? COLORS.blue : COLORS.text, background: "none", border: "none", cursor: "pointer", fontSize: "15px", fontWeight: "500", display: "flex", alignItems: "center", gap: "4px" }}
                  onMouseEnter={e => { e.currentTarget.style.color = COLORS.blue; }}
                  onMouseLeave={e => { if (activeDropdown !== link.menu) e.currentTarget.style.color = COLORS.text; }}>
                  {link.label}
                  {link.menu && <span style={{ fontSize: "10px" }}>▾</span>}
                </button>
                {link.menu && activeDropdown === link.menu && (
                  <div className="absolute top-full mt-2 rounded-xl border p-3"
                    style={{ backgroundColor: COLORS.card, borderColor: COLORS.border, minWidth: "220px", left: "50%", transform: "translateX(-50%)", zIndex: 999, boxShadow: "0 8px 32px rgba(0,0,0,0.4)" }}>
                    {NAV_MENUS[link.menu].map((item, j) => (
                      <div key={j} className="px-3 py-2 rounded-lg cursor-pointer"
                        onClick={() => { if (item.action) { item.action(); setActiveDropdown(null); } }}
                        onMouseEnter={e => e.currentTarget.style.backgroundColor = COLORS.blue + "15"}
                        onMouseLeave={e => e.currentTarget.style.backgroundColor = "transparent"}>
                        <div style={{ color: COLORS.text, fontSize: "14px", fontWeight: "600" }}>{item.label}</div>
                        <div style={{ color: COLORS.muted, fontSize: "12px" }}>{item.desc}</div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
        <div className="flex items-center gap-3" style={{ flexShrink: 0 }}>
          <div style={{ position: "relative" }}>
            <button onClick={e => { e.stopPropagation(); setLangOpen(!langOpen); setActiveDropdown(null); }}
              style={{ background: "none", border: `1px solid ${langOpen ? COLORS.blue : COLORS.border}`, cursor: "pointer", color: COLORS.muted, fontSize: "14px", padding: "6px 12px", borderRadius: "8px", display: "flex", alignItems: "center", gap: "6px" }}>
              🌍 {LANGUAGES.find(l => l.code === i18n.language)?.label || "EN"}
            </button>
            {langOpen && (
              <div style={{ position: "absolute", top: "100%", right: 0, marginTop: "8px", backgroundColor: COLORS.card, border: `1px solid ${COLORS.border}`, minWidth: "160px", zIndex: 999, boxShadow: "0 8px 32px rgba(0,0,0,0.4)", borderRadius: "12px", padding: "8px" }}
                onClick={e => e.stopPropagation()}>
                {LANGUAGES.map((lang, j) => (
                  <button key={j} onClick={() => { i18n.changeLanguage(lang.code); setLangOpen(false); }}
                    style={{ width: "100%", textAlign: "left", padding: "8px 12px", borderRadius: "8px", background: i18n.language === lang.code ? COLORS.blue + "20" : "none", color: i18n.language === lang.code ? COLORS.blue : COLORS.text, border: "none", cursor: "pointer", display: "flex", justifyContent: "space-between", alignItems: "center", fontSize: "14px" }}
                    onMouseEnter={e => { if (i18n.language !== lang.code) e.currentTarget.style.backgroundColor = COLORS.blue + "10"; }}
                    onMouseLeave={e => { if (i18n.language !== lang.code) e.currentTarget.style.backgroundColor = "transparent"; }}>
                    <span style={{ fontWeight: "700" }}>{lang.label}</span>
                    <span style={{ color: COLORS.muted, fontSize: "12px" }}>{lang.name}</span>
                  </button>
                ))}
              </div>
            )}
          </div>
          <button onClick={onLogin} style={{ color: COLORS.muted, background: "none", border: "none", cursor: "pointer", fontSize: "15px", fontWeight: "500", padding: "8px 12px" }}>
            {t('nav.signIn')}
          </button>
          <button onClick={onGetStarted} style={{ backgroundColor: COLORS.blue, color: "white", border: "none", cursor: "pointer", fontSize: "15px", fontWeight: "700", padding: "10px 22px", borderRadius: "10px" }}>
            {t('nav.getStarted')}
          </button>
        </div>
      </nav>

      {/* HERO SECTION */}
      <div style={{ background: `radial-gradient(ellipse at 50% 0%, ${COLORS.blue}12 0%, transparent 60%)`, padding: "80px 32px 60px", textAlign: "center", maxWidth: "1200px", margin: "0 auto" }}>
        <div style={{ display: "inline-flex", alignItems: "center", gap: "8px", padding: "6px 16px", borderRadius: "100px", border: `1px solid ${COLORS.blue}40`, backgroundColor: COLORS.blue + "10", marginBottom: "32px" }}>
          <div style={{ width: "8px", height: "8px", borderRadius: "50%", backgroundColor: COLORS.blue, animation: "pulse 2s infinite" }} />
          <span style={{ color: COLORS.blue, fontSize: "13px", fontWeight: "600" }}>{t('hero.badge')}</span>
        </div>
        <h1 style={{ fontSize: "clamp(36px, 5vw, 64px)", fontWeight: "900", color: COLORS.text, lineHeight: "1.1", marginBottom: "24px", letterSpacing: "-0.03em" }}>
          {t('hero.title1')}
          <br />
          <span style={{ color: COLORS.blue }}>{t('hero.title2')}</span>
        </h1>
        <p style={{ fontSize: "18px", color: COLORS.muted, maxWidth: "640px", margin: "0 auto 40px", lineHeight: "1.7" }}>
          {t('hero.subtitle')}
        </p>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: "16px", flexWrap: "wrap" }}>
          <button onClick={onGetStarted}
            style={{ backgroundColor: COLORS.blue, color: "white", border: "none", cursor: "pointer", fontSize: "16px", fontWeight: "700", padding: "14px 32px", borderRadius: "12px", boxShadow: `0 0 32px ${COLORS.blue}40` }}>
            {t('hero.cta')}
          </button>
          <button onClick={onGetStarted}
            style={{ backgroundColor: "transparent", color: COLORS.blue, border: `2px solid ${COLORS.blue}`, cursor: "pointer", fontSize: "16px", fontWeight: "700", padding: "14px 32px", borderRadius: "12px" }}>
            {t('nav.requestDemo')} →
          </button>
        </div>
        {/* Trust badges */}
        <div style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: "32px", marginTop: "48px", flexWrap: "wrap" }}>
          {["NIS2 Compliant", "NIST CSF 2.0", "ISO 27001", "OWASP IoT Top 10"].map((badge, i) => (
            <div key={i} style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <div style={{ width: "6px", height: "6px", borderRadius: "50%", backgroundColor: COLORS.low }} />
              <span style={{ color: COLORS.muted, fontSize: "13px", fontWeight: "500" }}>{badge}</span>
            </div>
          ))}
        </div>
      </div>

      {/* STATS BAR */}
      <div style={{ borderTop: `1px solid ${COLORS.blue}20`, borderBottom: `1px solid ${COLORS.blue}20`, backgroundColor: COLORS.blue + "05", padding: "24px 32px" }}>
        <div style={{ maxWidth: "1200px", margin: "0 auto", display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "16px", textAlign: "center" }}>
          {[
            { value: "60 sec", label: t('stats.scanSpeed') },
            { value: "7", label: t('stats.attackModules') },
            { value: "3", label: t('stats.frameworks') },
            { value: "100%", label: t('stats.nis2') },
          ].map((stat, i) => (
            <div key={i}>
              <div style={{ fontSize: "28px", fontWeight: "900", color: COLORS.blue, marginBottom: "4px" }}>{stat.value}</div>
              <div style={{ fontSize: "13px", color: COLORS.muted }}>{stat.label}</div>
            </div>
          ))}
        </div>
      </div>

      {/* HOW IT WORKS */}
      <div id="how-it-works" style={{ maxWidth: "1200px", margin: "0 auto", padding: "80px 32px" }}>
        <div style={{ textAlign: "center", marginBottom: "60px" }}>
          <h2 style={{ fontSize: "36px", fontWeight: "900", color: COLORS.text, marginBottom: "12px" }}>{t('howItWorks.title')}</h2>
          <p style={{ color: COLORS.muted, fontSize: "16px" }}>{t('howItWorks.subtitle')}</p>
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "32px" }}>
          {[
            { step: "01", title: t('howItWorks.step1Title'), desc: t('howItWorks.step1Desc'), color: COLORS.blue },
            { step: "02", title: t('howItWorks.step2Title'), desc: t('howItWorks.step2Desc'), color: COLORS.purple },
            { step: "03", title: t('howItWorks.step3Title'), desc: t('howItWorks.step3Desc'), color: COLORS.low },
          ].map((item, i) => (
            <div key={i} style={{ padding: "32px", borderRadius: "16px", border: `1px solid ${item.color}30`, backgroundColor: item.color + "08", position: "relative" }}>
              <div style={{ fontSize: "48px", fontWeight: "900", color: item.color, opacity: 0.3, marginBottom: "16px", lineHeight: 1 }}>{item.step}</div>
              <h3 style={{ fontSize: "20px", fontWeight: "800", color: item.color, marginBottom: "12px" }}>{item.title}</h3>
              <p style={{ color: COLORS.muted, fontSize: "15px", lineHeight: "1.6" }}>{item.desc}</p>
              {i < 2 && <div style={{ position: "absolute", right: "-20px", top: "50%", transform: "translateY(-50%)", color: COLORS.border, fontSize: "24px", zIndex: 1 }}>→</div>}
            </div>
          ))}
        </div>
      </div>

      {/* FEATURES */}
      <div id="features" style={{ backgroundColor: COLORS.card, padding: "80px 32px" }}>
        <div style={{ maxWidth: "1200px", margin: "0 auto" }}>
          <div style={{ textAlign: "center", marginBottom: "60px" }}>
            <h2 style={{ fontSize: "36px", fontWeight: "900", color: COLORS.text, marginBottom: "12px" }}>{t("featuresTitle")}</h2>
            <p style={{ color: COLORS.muted, fontSize: "16px" }}>{t("featuresSubtitle")}</p>
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "24px" }}>
            {[
              { icon: Shield, color: COLORS.blue, title: t('features.attackModules'), desc: t('features.attackModulesDesc') },
              { icon: Zap, color: COLORS.critical, title: t('features.explainableAI'), desc: t('features.explainableAIDesc') },
              { icon: Lock, color: COLORS.low, title: t('features.owasp'), desc: t('features.owaspDesc') },
              { icon: Activity, color: COLORS.purple, title: t('features.dashboard'), desc: t('features.dashboardDesc') },
              { icon: CreditCard, color: COLORS.high, title: t('features.api'), desc: t('features.apiDesc') },
              { icon: FileText, color: COLORS.blue, title: t('features.reports'), desc: t('features.reportsDesc') },
            ].map((feature, i) => (
              <div key={i} style={{ padding: "28px", borderRadius: "16px", border: `1px solid ${feature.color}30`, backgroundColor: COLORS.darker, transition: "all 0.2s" }}
                onMouseEnter={e => { e.currentTarget.style.borderColor = feature.color; e.currentTarget.style.transform = "translateY(-4px)"; e.currentTarget.style.boxShadow = `0 16px 40px ${feature.color}15`; }}
                onMouseLeave={e => { e.currentTarget.style.borderColor = feature.color + "30"; e.currentTarget.style.transform = "translateY(0)"; e.currentTarget.style.boxShadow = "none"; }}>
                <div style={{ width: "48px", height: "48px", borderRadius: "12px", backgroundColor: feature.color + "20", display: "flex", alignItems: "center", justifyContent: "center", marginBottom: "16px" }}>
                  <feature.icon size={22} style={{ color: feature.color }} />
                </div>
                <h3 style={{ fontSize: "16px", fontWeight: "700", color: COLORS.text, marginBottom: "8px" }}>{feature.title}</h3>
                <p style={{ color: COLORS.muted, fontSize: "14px", lineHeight: "1.6" }}>{feature.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* PRICING */}
      <div id="pricing" style={{ maxWidth: "1200px", margin: "0 auto", padding: "80px 32px" }}>
        <div style={{ textAlign: "center", marginBottom: "48px" }}>
          <h2 style={{ fontSize: "36px", fontWeight: "900", color: COLORS.text, marginBottom: "12px" }}>{t('pricing.title')}</h2>
          <p style={{ color: COLORS.muted, fontSize: "16px" }}>{t('pricing.subtitle')}</p>
        </div>
        {/* Currency switcher */}
        <div style={{ display: "flex", justifyContent: "center", gap: "8px", marginBottom: "40px" }}>
          {[
            { code: 'GBP', symbol: '£', label: 'GBP' },
            { code: 'USD', symbol: '$', label: 'USD' },
            { code: 'EUR', symbol: '€', label: 'EUR' },
            { code: 'JPY', symbol: '¥', label: 'JPY' },
          ].map(c => (
            <button key={c.code} onClick={() => setCurrency(c)}
              style={{ padding: "8px 16px", borderRadius: "8px", fontSize: "14px", fontWeight: "700", cursor: "pointer", backgroundColor: currency.code === c.code ? COLORS.blue : COLORS.card, color: currency.code === c.code ? "white" : COLORS.muted, border: `1px solid ${currency.code === c.code ? COLORS.blue : COLORS.border}` }}>
              {c.symbol} {c.label}
            </button>
          ))}
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "24px" }}>
          {[
            { name: t('plans.free'), price: `${currency.symbol}0`, period: t('pricing.forever'), color: COLORS.muted, features: t('planFeatures.free', { returnObjects: true }), cta: t('pricing.getStarted') },
            { name: t('plans.professional'), price: `${currency.symbol}${CURRENCY_PRICES[currency.code].professional}`, period: t('pricing.perMonth'), color: COLORS.blue, popular: true, features: t('planFeatures.pro', { returnObjects: true }), cta: t('pricing.startTrial') },
            { name: t('plans.enterprise'), price: `${currency.symbol}${CURRENCY_PRICES[currency.code].enterprise}`, period: t('pricing.perMonth'), color: COLORS.purple, features: t('planFeatures.ent', { returnObjects: true }), cta: t('pricing.contactSales') },
          ].map((plan, i) => (
            <div key={i} style={{ padding: "32px", borderRadius: "20px", border: `1px solid ${plan.color}50`, backgroundColor: COLORS.card, position: "relative", boxShadow: plan.popular ? `0 0 40px ${plan.color}20` : "none", transform: plan.popular ? "scale(1.03)" : "scale(1)" }}>
              {plan.popular && (
                <div style={{ position: "absolute", top: "-12px", left: "50%", transform: "translateX(-50%)", backgroundColor: plan.color, color: "white", padding: "4px 16px", borderRadius: "100px", fontSize: "12px", fontWeight: "700" }}>
                  {t("pricing.popular")}
                </div>
              )}
              <h3 style={{ fontSize: "18px", fontWeight: "800", color: plan.color, marginBottom: "8px" }}>{plan.name}</h3>
              <div style={{ display: "flex", alignItems: "baseline", gap: "4px", marginBottom: "24px" }}>
                <span style={{ fontSize: "40px", fontWeight: "900", color: COLORS.text }}>{plan.price}</span>
                <span style={{ color: COLORS.muted, fontSize: "14px" }}>/{plan.period}</span>
              </div>
              <div style={{ marginBottom: "24px" }}>
                {(Array.isArray(plan.features) ? plan.features : []).map((f, j) => (
                  <div key={j} style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "8px" }}>
                    <div style={{ width: "16px", height: "16px", borderRadius: "50%", backgroundColor: plan.color + "20", display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0 }}>
                      <Check size={10} style={{ color: plan.color }} />
                    </div>
                    <span style={{ color: COLORS.muted, fontSize: "14px" }}>{f}</span>
                  </div>
                ))}
              </div>
              <button onClick={onGetStarted} style={{ width: "100%", padding: "12px", borderRadius: "12px", fontSize: "15px", fontWeight: "700", cursor: "pointer", backgroundColor: plan.popular ? plan.color : "transparent", color: plan.popular ? "white" : plan.color, border: `2px solid ${plan.color}` }}>
                {plan.cta}
              </button>
            </div>
          ))}
        </div>
      </div>

      {/* FINAL CTA */}
      <div style={{ background: `linear-gradient(135deg, ${COLORS.blue}15, ${COLORS.purple}10)`, border: `1px solid ${COLORS.blue}30`, borderRadius: "24px", padding: "64px 32px", textAlign: "center", margin: "0 32px 80px", maxWidth: "1136px", marginLeft: "auto", marginRight: "auto" }}>
        <h2 style={{ fontSize: "36px", fontWeight: "900", color: COLORS.text, marginBottom: "16px" }}>{t('cta.title')}</h2>
        <p style={{ color: COLORS.muted, fontSize: "16px", marginBottom: "32px" }}>{t('cta.subtitle')}</p>
        <div style={{ display: "flex", justifyContent: "center", gap: "16px" }}>
          <button onClick={onGetStarted} style={{ backgroundColor: COLORS.blue, color: "white", border: "none", cursor: "pointer", fontSize: "16px", fontWeight: "700", padding: "14px 36px", borderRadius: "12px", boxShadow: `0 0 32px ${COLORS.blue}40` }}>
            {t('cta.getStarted')}
          </button>
          <button onClick={onLogin} style={{ backgroundColor: "transparent", color: COLORS.blue, border: `2px solid ${COLORS.blue}`, cursor: "pointer", fontSize: "16px", fontWeight: "700", padding: "14px 36px", borderRadius: "12px" }}>
            {t('cta.signIn')}
          </button>
        </div>
      </div>

      {/* FOOTER */}
      <div style={{ borderTop: `1px solid ${COLORS.border}`, backgroundColor: COLORS.card, padding: "60px 32px 32px" }}>
        <div style={{ maxWidth: "1200px", margin: "0 auto" }}>
          <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr 1fr 1fr", gap: "48px", marginBottom: "48px" }}>
            {/* Brand */}
            <div>
              <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "16px" }}>
                <div style={{ width: "36px", height: "36px", borderRadius: "10px", backgroundColor: COLORS.blue, display: "flex", alignItems: "center", justifyContent: "center" }}>
                  <Shield size={18} color="white" />
                </div>
                <span style={{ fontSize: "20px", fontWeight: "900", color: COLORS.text }}>AIPET</span>
              </div>
              <p style={{ color: COLORS.muted, fontSize: "14px", lineHeight: "1.7", maxWidth: "280px" }}>
                {t('footerTagline')}
              </p>
              <div style={{ display: "flex", gap: "8px", marginTop: "16px" }}>
                {["NIS2", "NIST", "ISO 27001"].map((b, i) => (
                  <span key={i} style={{ padding: "4px 10px", borderRadius: "6px", fontSize: "11px", fontWeight: "700", backgroundColor: COLORS.blue + "20", color: COLORS.blue, border: `1px solid ${COLORS.blue}30` }}>{b}</span>
                ))}
              </div>
            </div>
            {/* Solutions */}
            <div>
              <h4 style={{ color: COLORS.text, fontSize: "14px", fontWeight: "700", marginBottom: "16px", textTransform: "uppercase", letterSpacing: "0.05em" }}>{t('footerSolutions')}</h4>
              {t('footerItems.solutions', { returnObjects: true }).map((item, i) => (
                <div key={i} onClick={() => setActivePage('solutions')} style={{ color: COLORS.muted, fontSize: "14px", marginBottom: "10px", cursor: "pointer" }}
                  onMouseEnter={e => e.currentTarget.style.color = COLORS.blue}
                  onMouseLeave={e => e.currentTarget.style.color = COLORS.muted}>
                  {item}
                </div>
              ))}
            </div>
            {/* Platform */}
            <div>
              <h4 style={{ color: COLORS.text, fontSize: "14px", fontWeight: "700", marginBottom: "16px", textTransform: "uppercase", letterSpacing: "0.05em" }}>{t('footerPlatform')}</h4>
              {t('footerItems.platform', { returnObjects: true }).map((item, i) => (
                <div key={i} onClick={() => setActivePage('platform')} style={{ color: COLORS.muted, fontSize: "14px", marginBottom: "10px", cursor: "pointer" }}
                  onMouseEnter={e => e.currentTarget.style.color = COLORS.blue}
                  onMouseLeave={e => e.currentTarget.style.color = COLORS.muted}>
                  {item}
                </div>
              ))}
            </div>
            {/* Company */}
            <div>
              <h4 style={{ color: COLORS.text, fontSize: "14px", fontWeight: "700", marginBottom: "16px", textTransform: "uppercase", letterSpacing: "0.05em" }}>{t('footerCompany')}</h4>
              {[
                { label: t('footerItems.company', { returnObjects: true })[0], action: () => setActivePage('about') },
                { label: t('footerItems.company', { returnObjects: true })[1], action: () => setActivePage('about') },
                { label: t('footerItems.company', { returnObjects: true })[2], action: () => setActivePage('contact') },
                { label: t('footerItems.company', { returnObjects: true })[3], action: () => setActivePage('contact') },
                { label: t('footerItems.company', { returnObjects: true })[4], action: () => window.open('https://github.com/Yallewbinyam/AIPET', '_blank') },
              ].map((item, i) => (
                <div key={i} onClick={item.action} style={{ color: COLORS.muted, fontSize: "14px", marginBottom: "10px", cursor: "pointer" }}
                  onMouseEnter={e => e.currentTarget.style.color = COLORS.blue}
                  onMouseLeave={e => e.currentTarget.style.color = COLORS.muted}>
                  {item.label}
                </div>
              ))}
            </div>
          </div>
          {/* Bottom bar */}
          <div style={{ borderTop: `1px solid ${COLORS.border}`, paddingTop: "24px", display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "16px" }}>
            <p style={{ color: COLORS.muted, fontSize: "13px" }}>
              © 2026 AIPET Cloud · AIPET Cloud v3.0.0 — Developed as part of MSc Cyber Security research at Coventry University · MIT Licence
            </p>
            <div style={{ display: "flex", gap: "24px" }}>
              {[
                { label: t('footer.privacy'), page: 'privacy' },
                { label: t('footer.terms'), page: 'terms' },
                { label: t('footer.cookie'), page: 'cookies' },
              ].map((link, i) => (
                <button key={i} onClick={() => setLegalPage(link.page)}
                  style={{ color: COLORS.muted, background: "none", border: "none", cursor: "pointer", fontSize: "13px" }}
                  onMouseEnter={e => e.currentTarget.style.color = COLORS.blue}
                  onMouseLeave={e => e.currentTarget.style.color = COLORS.muted}>
                  {link.label}
                </button>
              ))}
              <a href="https://github.com/Yallewbinyam/AIPET" style={{ color: COLORS.blue, fontSize: "13px" }}>GitHub</a>
            </div>
          </div>
        </div>
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

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const ssoToken = params.get('sso_token');
    if (ssoToken) {
      localStorage.setItem('aipet_token', ssoToken);
      window.history.replaceState({}, '', '/');
      onLogin(ssoToken);
    }
  }, []);

  const handleGoogleLogin = () => {
    window.location.href = 'http://localhost:5001/api/auth/google';
  };

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
          style={{
            backgroundColor: COLORS.card,
            borderColor: COLORS.blue + "40",
            boxShadow: `0 0 40px ${COLORS.blue}15`,
          }}>

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

          {/* Divider */}
          <div className="flex items-center gap-3 my-4">
            <div className="flex-1 h-px" style={{ backgroundColor: COLORS.border }}/>
            <span className="text-xs" style={{ color: COLORS.muted }}>or</span>
            <div className="flex-1 h-px" style={{ backgroundColor: COLORS.border }}/>
          </div>
          {/* Google SSO */}
          <button onClick={handleGoogleLogin}
            className="w-full py-3 rounded-xl font-bold text-sm transition-all flex items-center justify-center gap-3"
            style={{ backgroundColor: COLORS.dark, color: COLORS.text, border: `1px solid ${COLORS.border}` }}>
            <svg width="18" height="18" viewBox="0 0 18 18">
              <path fill="#4285F4" d="M16.51 8H8.98v3h4.3c-.18 1-.74 1.48-1.6 2.04v2.01h2.6a7.8 7.8 0 002.38-5.88c0-.57-.05-.66-.15-1.18z"/>
              <path fill="#34A853" d="M8.98 17c2.16 0 3.97-.72 5.3-1.94l-2.6-2a4.8 4.8 0 01-7.18-2.54H1.83v2.07A8 8 0 008.98 17z"/>
              <path fill="#FBBC05" d="M4.5 10.52a4.8 4.8 0 010-3.04V5.41H1.83a8 8 0 000 7.18l2.67-2.07z"/>
              <path fill="#EA4335" d="M8.98 4.18c1.17 0 2.23.4 3.06 1.2l2.3-2.3A8 8 0 001.83 5.4L4.5 7.49a4.77 4.77 0 014.48-3.3z"/>
            </svg>
            Continue with Google
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


function ProtocolsPage({ token, showToast, currentPlan }) {
  const [protocol, setProtocol] = useState("modbus");
  const [target,   setTarget]   = useState("");
  const [scanning, setScanning] = useState(false);
  const [result,   setResult]   = useState(null);
  const [history,  setHistory]  = useState([]);

  const PROTOCOLS = {
    modbus:  { name: "Modbus TCP",  color: COLORS.critical, desc: "Industrial control systems, PLCs, power grids", port: 502  },
    zigbee:  { name: "Zigbee",      color: COLORS.blue,     desc: "Smart home, building automation, IoT sensors",  port: null },
    lorawan: { name: "LoRaWAN",     color: COLORS.low,      desc: "Smart cities, agriculture, long-range IoT",     port: 1700 },
  };

  const SEVERITY_COLORS = {
    critical: COLORS.critical,
    high:     COLORS.high,
    medium:   COLORS.medium,
    low:      COLORS.low,
  };

  useEffect(() => {
    fetch("http://localhost:5001/api/protocols/history", {
      headers: { Authorization: `Bearer ${token}` }
    })
      .then(r => r.json())
      .then(setHistory)
      .catch(() => {});
  }, [token]);

  const runScan = async () => {
    if (!target.trim()) return showToast("Please enter a target", "error");
    setScanning(true);
    setResult(null);
    try {
      const r = await fetch("http://localhost:5001/api/protocols/scan", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ protocol, target }),
      });
      const d = await r.json();
      if (!r.ok) throw new Error(d.error);
      setResult(d);
      setHistory(h => [{ ...d, protocol, target }, ...h.slice(0, 19)]);
      showToast(`${PROTOCOLS[protocol].name} scan complete`, "success");
    } catch (e) {
      showToast(e.message || "Scan failed", "error");
    } finally {
      setScanning(false);
    }
  };

  if (currentPlan === "free") {
    return (
      <div className="flex flex-col items-center justify-center h-64 gap-4">
        <Cpu size={48} style={{ color: COLORS.muted }} />
        <p style={{ color: COLORS.muted }}>Protocol scanning requires Professional or Enterprise plan.</p>
        <button className="px-6 py-3 rounded-xl font-bold text-sm"
          style={{ backgroundColor: COLORS.blue, color: "white" }}>
          Upgrade to Professional
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-2xl font-black mb-1" style={{ color: COLORS.text }}>IoT Protocols</h2>
        <p className="text-sm" style={{ color: COLORS.muted }}>Scan Zigbee, LoRaWAN, and Modbus industrial IoT networks</p>
      </div>

      {/* Protocol selector */}
      <div className="rounded-2xl border p-6 space-y-4" style={{ backgroundColor: COLORS.card, borderColor: COLORS.border }}>
        <div className="grid grid-cols-3 gap-4">
          {Object.entries(PROTOCOLS).map(([key, p]) => (
            <button key={key} onClick={() => setProtocol(key)}
              className="rounded-xl border p-4 text-left transition-all"
              style={{
                backgroundColor: protocol === key ? p.color + "15" : COLORS.dark,
                borderColor: protocol === key ? p.color : COLORS.border,
              }}>
              <div className="font-bold text-sm mb-1" style={{ color: p.color }}>{p.name}</div>
              <div className="text-xs mb-2" style={{ color: COLORS.muted }}>{p.desc}</div>
              {p.port && (
                <div className="text-xs font-mono px-2 py-0.5 rounded inline-block"
                  style={{ backgroundColor: p.color + "20", color: p.color }}>
                  Port {p.port}
                </div>
              )}
            </button>
          ))}
        </div>

        {/* Target input */}
        <div className="flex gap-4">
          <input
            value={target}
            onChange={e => setTarget(e.target.value)}
            onKeyDown={e => e.key === "Enter" && runScan()}
            placeholder={protocol === "zigbee" ? "e.g. 192.168.1.1 (coordinator IP)" : protocol === "lorawan" ? "e.g. 192.168.1.1 (gateway IP)" : "e.g. 192.168.1.100 (PLC IP)"}
            className="flex-1 px-4 py-3 rounded-xl text-sm"
            style={{ backgroundColor: COLORS.dark, color: COLORS.text, border: `1px solid ${COLORS.border}` }}
          />
          <button onClick={runScan} disabled={scanning}
            className="px-6 py-3 rounded-xl font-bold text-sm transition-all"
            style={{
              backgroundColor: PROTOCOLS[protocol].color,
              color: "white",
              opacity: scanning ? 0.7 : 1,
            }}>
            {scanning ? "Scanning..." : `Scan ${PROTOCOLS[protocol].name}`}
          </button>
        </div>
      </div>

      {/* Results */}
      {result && (
        <div className="rounded-2xl border p-6 space-y-6" style={{ backgroundColor: COLORS.card, borderColor: COLORS.border }}>
          {/* Summary */}
          <div className="flex items-center justify-between">
            <div>
              <div className="text-lg font-black" style={{ color: COLORS.text }}>
                {PROTOCOLS[protocol].name} Scan Results
              </div>
              <div className="text-sm" style={{ color: COLORS.muted }}>
                Target: {result.target} · {result.device_count} devices found
              </div>
            </div>
            <div className="px-4 py-2 rounded-xl font-bold text-sm"
              style={{
                backgroundColor: SEVERITY_COLORS[result.risk_level] + "20",
                color: SEVERITY_COLORS[result.risk_level],
                border: `1px solid ${SEVERITY_COLORS[result.risk_level]}40`,
              }}>
              {result.risk_level?.toUpperCase()} RISK
            </div>
          </div>

          {/* Devices */}
          <div>
            <div className="text-sm font-bold mb-3" style={{ color: COLORS.text }}>Discovered Devices</div>
            <div className="grid grid-cols-2 gap-3">
              {result.devices?.map((d, i) => (
                <div key={i} className="rounded-xl px-4 py-3 flex items-center justify-between"
                  style={{ backgroundColor: COLORS.dark, border: `1px solid ${COLORS.border}` }}>
                  <div>
                    <div className="text-sm font-bold font-mono" style={{ color: PROTOCOLS[protocol].color }}>{d.id}</div>
                    <div className="text-xs" style={{ color: COLORS.muted }}>{d.address} · {d.type}</div>
                  </div>
                  {d.rssi && (
                    <div className="text-xs font-mono" style={{ color: COLORS.muted }}>{d.rssi} dBm</div>
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* Findings */}
          <div>
            <div className="text-sm font-bold mb-3" style={{ color: COLORS.text }}>Security Findings</div>
            <div className="space-y-2">
              {result.findings?.map((f, i) => (
                <div key={i} className="rounded-xl px-4 py-3"
                  style={{ backgroundColor: COLORS.dark, border: `1px solid ${SEVERITY_COLORS[f.severity]}30` }}>
                  <div className="flex items-center justify-between mb-1">
                    <div className="text-sm font-bold" style={{ color: COLORS.text }}>{f.title}</div>
                    <div className="text-xs font-bold px-2 py-0.5 rounded-full"
                      style={{
                        backgroundColor: SEVERITY_COLORS[f.severity] + "20",
                        color: SEVERITY_COLORS[f.severity],
                      }}>
                      {f.severity.toUpperCase()}
                    </div>
                  </div>
                  <div className="text-xs" style={{ color: COLORS.muted }}>{f.description}</div>
                  <div className="text-xs font-mono mt-1" style={{ color: COLORS.muted }}>{f.id}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* History */}
      {history.length > 0 && !result && (
        <div className="rounded-2xl border p-6" style={{ backgroundColor: COLORS.card, borderColor: COLORS.border }}>
          <div className="text-sm font-bold mb-4" style={{ color: COLORS.text }}>Recent Protocol Scans</div>
          <div className="space-y-2">
            {history.slice(0, 5).map((s, i) => (
              <div key={i} className="flex items-center justify-between rounded-xl px-4 py-3"
                style={{ backgroundColor: COLORS.dark, border: `1px solid ${COLORS.border}` }}>
                <div>
                  <div className="text-sm font-bold" style={{ color: COLORS.text }}>
                    {s.protocol?.toUpperCase()} — {s.target}
                  </div>
                  <div className="text-xs" style={{ color: COLORS.muted }}>
                    {s.device_count} devices · {s.created_at?.slice(0, 10)}
                  </div>
                </div>
                <div className="text-xs font-bold px-2 py-1 rounded-full"
                  style={{
                    backgroundColor: SEVERITY_COLORS[s.risk_level] + "20",
                    color: SEVERITY_COLORS[s.risk_level],
                  }}>
                  {s.risk_level?.toUpperCase()}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function CompliancePage({ token, showToast, currentPlan }) {
  const [scans,     setScans]     = useState([]);
  const [scanId,    setScanId]    = useState("");
  const [framework, setFramework] = useState("nis2");
  const [report,    setReport]    = useState(null);
  const [loading,   setLoading]   = useState(false);

  const FRAMEWORKS = {
    nis2:     { name: "NIS2",         region: "EU",     color: COLORS.blue   },
    nist:     { name: "NIST CSF 2.0", region: "USA",    color: COLORS.purple },
    iso27001: { name: "ISO 27001",    region: "Global", color: COLORS.low    },
  };

  useEffect(() => {
    fetch("http://localhost:5001/api/scans", {
      headers: { Authorization: `Bearer ${token}` }
    })
      .then(r => r.json())
      .then(d => {
        const completed = d.filter(s => s.status === "completed");
        setScans(completed);
        if (completed.length > 0) setScanId(completed[0].id);
      })
      .catch(() => {});
  }, [token]);

  const generate = async () => {
    if (!scanId) return showToast("Please select a scan", "error");
    setLoading(true);
    setReport(null);
    try {
      const r = await fetch("http://localhost:5001/api/compliance/generate", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ scan_id: parseInt(scanId), framework }),
      });
      const d = await r.json();
      if (!r.ok) throw new Error(d.error);
      setReport(d);
      showToast("Compliance report generated", "success");
    } catch (e) {
      showToast(e.message || "Failed to generate report", "error");
    } finally {
      setLoading(false);
    }
  };

  if (currentPlan === "free") {
    return (
      <div className="flex flex-col items-center justify-center h-64 gap-4">
        <Lock size={48} style={{ color: COLORS.muted }} />
        <p style={{ color: COLORS.muted }}>Compliance reports require Professional or Enterprise plan.</p>
        <button onClick={() => {}} className="px-6 py-3 rounded-xl font-bold text-sm"
          style={{ backgroundColor: COLORS.blue, color: "white" }}>
          Upgrade to Professional
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-2xl font-black mb-1" style={{ color: COLORS.text }}>Compliance</h2>
        <p className="text-sm" style={{ color: COLORS.muted }}>Generate compliance reports for NIS2, NIST CSF 2.0, and ISO 27001</p>
      </div>

      {/* Framework selector */}
      <div className="rounded-2xl border p-6" style={{ backgroundColor: COLORS.card, borderColor: COLORS.border }}>
        <div className="grid grid-cols-3 gap-4 mb-6">
          {Object.entries(FRAMEWORKS).map(([key, fw]) => (
            <button key={key} onClick={() => setFramework(key)}
              className="rounded-xl border p-4 text-left transition-all"
              style={{
                backgroundColor: framework === key ? fw.color + "15" : COLORS.dark,
                borderColor: framework === key ? fw.color : COLORS.border,
              }}>
              <div className="font-bold text-sm mb-1" style={{ color: fw.color }}>{fw.name}</div>
              <div className="text-xs" style={{ color: COLORS.muted }}>{fw.region}</div>
            </button>
          ))}
        </div>

        {/* Scan selector */}
        <div className="flex gap-4">
          <select value={scanId} onChange={e => setScanId(e.target.value)}
            className="flex-1 px-4 py-3 rounded-xl text-sm"
            style={{ backgroundColor: COLORS.dark, color: COLORS.text, border: `1px solid ${COLORS.border}` }}>
            {scans.length === 0
              ? <option>No completed scans</option>
              : scans.map(s => (
                  <option key={s.id} value={s.id}>
                    Scan #{s.id} — {s.target} ({s.completed_at?.slice(0,10)})
                  </option>
                ))
            }
          </select>
          <button onClick={generate} disabled={loading}
            className="px-6 py-3 rounded-xl font-bold text-sm transition-all"
            style={{ backgroundColor: FRAMEWORKS[framework].color, color: "white", opacity: loading ? 0.7 : 1 }}>
            {loading ? "Generating..." : "Generate Report"}
          </button>
        </div>
      </div>

      {/* Report */}
      {report && (
        <div className="rounded-2xl border p-6 space-y-6" style={{ backgroundColor: COLORS.card, borderColor: COLORS.border }}>
          {/* Score */}
          <div className="flex items-center justify-between">
            <div>
              <div className="text-lg font-black" style={{ color: COLORS.text }}>
                {FRAMEWORKS[framework].name} Compliance Report
              </div>
              <div className="text-sm" style={{ color: COLORS.muted }}>
                Scan #{report.scan_id} · {report.passed}/{report.total} controls passed
              </div>
            </div>
            <div className="text-center">
              <div className="text-4xl font-black" style={{
                color: report.score >= 80 ? COLORS.low : report.score >= 60 ? COLORS.high : COLORS.critical
              }}>
                {report.score}%
              </div>
              <div className="text-xs" style={{ color: COLORS.muted }}>compliance score</div>
            </div>
          </div>

          {/* Summary bars */}
          <div className="grid grid-cols-3 gap-4">
            {[
              { label: "Passed",  value: report.passed,           color: COLORS.low      },
              { label: "Failed",  value: report.failed,           color: COLORS.critical },
              { label: "Total",   value: report.total,            color: COLORS.blue     },
            ].map((s, i) => (
              <div key={i} className="rounded-xl p-4 text-center"
                style={{ backgroundColor: s.color + "15", border: `1px solid ${s.color}30` }}>
                <div className="text-2xl font-black" style={{ color: s.color }}>{s.value}</div>
                <div className="text-xs" style={{ color: COLORS.muted }}>{s.label}</div>
              </div>
            ))}
          </div>

          {/* Controls list */}
          <div className="space-y-2">
            <div className="text-sm font-bold mb-3" style={{ color: COLORS.text }}>Control Assessment</div>
            {report.controls.map((c, i) => (
              <div key={i} className="flex items-center justify-between rounded-xl px-4 py-3"
                style={{ backgroundColor: COLORS.dark, border: `1px solid ${COLORS.border}` }}>
                <div className="flex items-center gap-3">
                  <div className="w-2 h-2 rounded-full" style={{
                    backgroundColor: c.status === "pass" ? COLORS.low : COLORS.critical
                  }} />
                  <div>
                    <div className="text-sm font-bold" style={{ color: COLORS.text }}>{c.title}</div>
                    <div className="text-xs" style={{ color: COLORS.muted }}>
                      {c.article || c.function || c.clause}
                    </div>
                  </div>
                </div>
                <div className="text-xs font-bold px-3 py-1 rounded-full" style={{
                  backgroundColor: c.status === "pass" ? COLORS.low + "20" : COLORS.critical + "20",
                  color: c.status === "pass" ? COLORS.low : COLORS.critical,
                }}>
                  {c.status.toUpperCase()}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function PricingPage({ currentPlan, onUpgrade, usageLoaded }) {
  const [currency, setCurrency] = useState({ code: 'GBP', symbol: '£' });

  const CURRENCY_PRICES = {
    GBP: { free: '0', professional: '49', enterprise: '499' },
    USD: { free: '0', professional: '59', enterprise: '599' },
    EUR: { free: '0', professional: '55', enterprise: '549' },
    JPY: { free: '0', professional: '8,900', enterprise: '89,000' },
  };

  useEffect(() => {
    fetch('http://localhost:5001/payments/detect-currency')
      .then(r => r.json())
      .then(d => setCurrency({ code: d.currency, symbol: d.symbol }))
      .catch(() => setCurrency({ code: 'GBP', symbol: '£' }));
  }, []);

  const plans = [
    {
      id:       "free",
      name:     "Free",
      price:    `${currency.symbol}${CURRENCY_PRICES[currency.code].free}`,
      period:   t('pricing.forever'),
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
      price:    `${currency.symbol}${CURRENCY_PRICES[currency.code].professional}`,
      period:   t('pricing.perMonth'),
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
      price:    `${currency.symbol}${CURRENCY_PRICES[currency.code].enterprise}`,
      period:   t('pricing.perMonth'),
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

      {/* Currency switcher */}
      <div className="flex items-center justify-center gap-2">
        {[
          { code: 'GBP', symbol: '£', label: 'GBP' },
          { code: 'USD', symbol: '$', label: 'USD' },
          { code: 'EUR', symbol: '€', label: 'EUR' },
          { code: 'JPY', symbol: '¥', label: 'JPY' },
        ].map(c => (
          <button key={c.code}
            onClick={() => setCurrency(c)}
            className="px-4 py-2 rounded-lg text-sm font-bold transition-all"
            style={{
              backgroundColor: currency.code === c.code ? COLORS.blue : COLORS.card,
              color: currency.code === c.code ? 'white' : COLORS.muted,
              border: `1px solid ${currency.code === c.code ? COLORS.blue : COLORS.border}`,
            }}>
            {c.symbol} {c.label}
          </button>
        ))}
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
                borderColor: isCurrentPlan ? plan.color : plan.color + "50",
                boxShadow: `0 0 20px ${plan.color}15`,
              }}>

              {/* Popular badge */}
              {plan.popular && (
                <div className="absolute top-0 right-0 px-3 py-1 text-xs font-bold rounded-bl-xl"
                  style={{ backgroundColor: plan.color, color: "white" }}>
                  {t("pricing.popular")}
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
  { id: "dashboard", label: "Overview",      icon: Activity,      group: "main"     },
  { id: "findings",  label: "Findings",      icon: AlertTriangle, group: "main"     },
  { id: "devices",   label: "Devices",       icon: Cpu,           group: "main"     },
  { id: "map",       label: "Network Map",   icon: Shield,        group: "intel"    },
  { id: "watch",     label: "Watch",         icon: Shield,        group: "intel"    },
  { id: "predict",   label: "CVE Intel",     icon: AlertTriangle, group: "intel"    },
  { id: "ask",       label: "Ask AIPET",     icon: Shield,        group: "intel"    },
  { id: "protocols", label: "Protocols",     icon: Cpu,           group: "intel"    },
  { id: "ai",        label: "AI Analysis",   icon: Shield,        group: "reports"  },
  { id: "reports",   label: "Reports",       icon: FileText,      group: "reports"  },
  { id: "compliance",label: "Compliance",     icon: Lock,          group: "reports"  },
  { id: "pricing",   label: "Pricing",       icon: Zap,           group: "account"  },
  { id: "billing",   label: "Billing",       icon: Lock,          group: "account"  },
  { id: "apikeys",   label: "API Keys",      icon: CreditCard,    group: "account"  },
];

const NAV_GROUPS = [
  { id: "main",    label: "Security"     },
  { id: "intel",   label: "Intelligence" },
  { id: "reports", label: "Reports"      },
  { id: "account", label: "Account"      },
];

export default function App() {
  const [data,       setData]       = useState({});
  const [activeTab,  setActiveTab]  = useState("dashboard");
  const [collapsedGroups, setCollapsedGroups] = useState({});
  const [showScan,   setShowScan]   = useState(false);
  const [loading,    setLoading]    = useState(true);
  const [scanning,   setScanning]   = useState(false);
  const [filter,     setFilter]     = useState("ALL");
  const [searchText, setSearchText] = useState("");
  const [usage,      setUsage]      = useState(null);
  const [token, setToken] = useState(localStorage.getItem("aipet_token") || "");
  const [showLanding, setShowLanding] = useState(!localStorage.getItem("aipet_token"));
  const [legalPage, setLegalPage] = useState(null);
  const [activePage, setActivePage] = useState(null);
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
    if (activePage === 'about') {
      return <AboutPage onBack={() => setActivePage(null)} onGetStarted={() => setShowLanding(false)} />;
    }
    if (activePage === 'contact') {
      return <ContactPage onBack={() => setActivePage(null)} />;
    }
    if (activePage === 'platform') {
      return <PlatformPage onBack={() => setActivePage(null)} onGetStarted={() => setShowLanding(false)} />;
    }
    if (activePage === 'solutions') {
      return <SolutionsPage onBack={() => setActivePage(null)} onGetStarted={() => setShowLanding(false)} />;
    }
    if (showLanding) {
      return (
        <LandingPage
          onGetStarted={() => setShowLanding(false)}
          onLogin={() => setShowLanding(false)}
          setLegalPage={setLegalPage}
          setActivePage={setActivePage}
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
    <div style={{
      display: "flex",
      minHeight: "100vh",
      backgroundColor: "#030712",
      color: "#e2e8f0",
      fontFamily: "'Inter', sans-serif",
      position: "relative",
      overflow: "hidden",
    }}>

      {/* Background atmospheric effect */}
      <div style={{
        position: "fixed",
        top: 0, left: 0, right: 0, bottom: 0,
        background: "radial-gradient(ellipse at 20% 50%, rgba(0,229,255,0.03) 0%, transparent 60%), radial-gradient(ellipse at 80% 20%, rgba(0,229,255,0.02) 0%, transparent 50%)",
        pointerEvents: "none",
        zIndex: 0,
      }} />

      {/* Sidebar */}
      <div style={{
        width: "240px",
        minWidth: "240px",
        backgroundColor: "#0a0f1a",
        borderRight: "1px solid #1e2d3d",
        display: "flex",
        flexDirection: "column",
        position: "relative",
        zIndex: 10,
      }}>

        {/* Logo */}
        <div style={{ padding: "20px 20px 16px", borderBottom: "1px solid #1e2d3d" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
            <div style={{
              width: "36px", height: "36px",
              borderRadius: "8px",
              backgroundColor: "rgba(0,229,255,0.1)",
              border: "1px solid rgba(0,229,255,0.3)",
              display: "flex", alignItems: "center", justifyContent: "center",
              boxShadow: "0 0 12px rgba(0,229,255,0.15)",
            }}>
              <Shield size={18} color="#00e5ff" />
            </div>
            <div>
              <div style={{
                fontFamily: "'JetBrains Mono', monospace",
                fontWeight: 900,
                fontSize: "15px",
                letterSpacing: "0.2em",
                color: "#e2e8f0",
              }}>AIPET</div>
              <div style={{
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: "9px",
                color: "#334155",
                letterSpacing: "0.05em",
              }}>IoT Security Platform</div>
            </div>
          </div>
        </div>

        {/* Scan status */}
        {scanning && (
          <div style={{
            margin: "12px 12px 0",
            padding: "10px 12px",
            backgroundColor: "rgba(0,229,255,0.08)",
            border: "1px solid rgba(0,229,255,0.2)",
            borderRadius: "8px",
            display: "flex", alignItems: "center", gap: "8px",
          }}>
            <div style={{
              width: "6px", height: "6px", borderRadius: "50%",
              backgroundColor: "#00e5ff",
              animation: "pulse 1.5s infinite",
            }} />
            <span style={{ fontSize: "11px", color: "#00e5ff", fontFamily: "'JetBrains Mono', monospace" }}>
              Scanning...
            </span>
          </div>
        )}

        {/* Navigation */}
        <nav style={{ flex: 1, padding: "16px 12px", overflowY: "auto" }}>
          {NAV_GROUPS.map(group => {
            const groupItems = NAV_ITEMS.filter(item => item.group === group.id);
            const isCollapsed = collapsedGroups[group.id] || false;
            return (
              <div key={group.id} style={{ marginBottom: "20px" }}>
                {/* Group header */}
                <button
                  onClick={() => setCollapsedGroups(prev => ({...prev, [group.id]: !prev[group.id]}))}
                  style={{
                    width: "100%",
                    display: "flex", alignItems: "center", justifyContent: "space-between",
                    padding: "4px 8px",
                    background: "none", border: "none", cursor: "pointer",
                    marginBottom: "4px",
                    borderRadius: "6px",
                    transition: "background 0.15s",
                  }}
                  onMouseEnter={e => e.currentTarget.style.background = "rgba(255,255,255,0.04)"}
                  onMouseLeave={e => e.currentTarget.style.background = "none"}
                >
                  <span style={{
                    fontFamily: "'JetBrains Mono', monospace",
                    fontSize: "9px",
                    fontWeight: 700,
                    letterSpacing: "0.15em",
                    color: "#00e5ff",
                    opacity: 0.6,
                    textTransform: "uppercase",
                  }}>{group.label}</span>
                  <ChevronDown size={16} color="#00e5ff" style={{
                    opacity: 0.5,
                    transform: isCollapsed ? "rotate(-90deg)" : "rotate(0deg)",
                    transition: "transform 0.2s ease",
                  }} />
                </button>

                {/* Nav items */}
                {!isCollapsed && groupItems.map(({ id, label, icon: Icon }) => {
                  const active = activeTab === id;
                  return (
                    <button key={id}
                      onClick={() => setActiveTab(id)}
                      style={{
                        width: "100%",
                        display: "flex", alignItems: "center", gap: "10px",
                        padding: "8px 10px",
                        borderRadius: "8px",
                        border: "none",
                        cursor: "pointer",
                        marginBottom: "2px",
                        backgroundColor: active ? "rgba(0,229,255,0.1)" : "transparent",
                        borderLeft: active ? "2px solid #00e5ff" : "2px solid transparent",
                        color: active ? "#00e5ff" : "#64748b",
                        fontSize: "13px",
                        fontWeight: active ? 600 : 400,
                        transition: "all 0.15s",
                        textAlign: "left",
                        boxShadow: active ? "0 0 12px rgba(0,229,255,0.08)" : "none",
                      }}
                      onMouseEnter={e => { if (!active) { e.currentTarget.style.backgroundColor = "rgba(255,255,255,0.04)"; e.currentTarget.style.color = "#94a3b8"; }}}
                      onMouseLeave={e => { if (!active) { e.currentTarget.style.backgroundColor = "transparent"; e.currentTarget.style.color = "#64748b"; }}}
                    >
                      <Icon size={15} />
                      <span style={{ flex: 1 }}>{label}</span>
                      {id === "findings" && findings.length > 0 && (
                        <span style={{
                          fontSize: "10px",
                          padding: "1px 6px",
                          borderRadius: "4px",
                          backgroundColor: "rgba(255,61,61,0.2)",
                          color: "#ff3d3d",
                          fontFamily: "'JetBrains Mono', monospace",
                          fontWeight: 700,
                        }}>
                          {findings.filter(f => f.severity === "Critical").length}
                        </span>
                      )}
                      {id === "predict" && (
                        <span style={{ width: "6px", height: "6px", borderRadius: "50%", backgroundColor: "#00e5ff" }} />
                      )}
                      {id === "watch" && (
                        <span style={{ width: "6px", height: "6px", borderRadius: "50%", backgroundColor: "#00ff94" }} />
                      )}
                    </button>
                  );
                })}
              </div>
            );
          })}
        </nav>

        {/* Sign out */}
        <div style={{ padding: "0 12px 8px" }}>
          <button onClick={handleLogout} style={{
            width: "100%",
            padding: "8px",
            borderRadius: "8px",
            border: "1px solid rgba(255,61,61,0.2)",
            backgroundColor: "rgba(255,61,61,0.08)",
            color: "#ff3d3d",
            fontSize: "12px",
            cursor: "pointer",
            display: "flex", alignItems: "center", justifyContent: "center", gap: "6px",
            transition: "all 0.15s",
          }}
          onMouseEnter={e => e.currentTarget.style.backgroundColor = "rgba(255,61,61,0.15)"}
          onMouseLeave={e => e.currentTarget.style.backgroundColor = "rgba(255,61,61,0.08)"}
          >
            <X size={12} /> Sign Out
          </button>
        </div>

        {/* New Scan button */}
        <div style={{ padding: "8px 12px 16px", borderTop: "1px solid #1e2d3d" }}>
          <button onClick={() => setShowScan(true)} disabled={scanning} style={{
            width: "100%",
            padding: "10px",
            borderRadius: "10px",
            border: "none",
            backgroundColor: scanning ? "#1e2d3d" : "#00e5ff",
            color: scanning ? "#64748b" : "#030712",
            fontSize: "13px",
            fontWeight: 700,
            cursor: scanning ? "not-allowed" : "pointer",
            display: "flex", alignItems: "center", justifyContent: "center", gap: "8px",
            transition: "all 0.2s",
            boxShadow: scanning ? "none" : "0 0 20px rgba(0,229,255,0.3)",
          }}
          onMouseEnter={e => { if (!scanning) e.currentTarget.style.boxShadow = "0 0 30px rgba(0,229,255,0.5)"; }}
          onMouseLeave={e => { if (!scanning) e.currentTarget.style.boxShadow = "0 0 20px rgba(0,229,255,0.3)"; }}
          >
            {scanning
              ? <><RefreshCw size={14} style={{ animation: "spin 1s linear infinite" }} /> Scanning...</>
              : <><Play size={14} /> New Scan</>
            }
          </button>
          <button onClick={fetchAll} style={{
            width: "100%",
            padding: "6px",
            marginTop: "6px",
            borderRadius: "8px",
            border: "none",
            backgroundColor: "transparent",
            color: "#334155",
            fontSize: "11px",
            cursor: "pointer",
            display: "flex", alignItems: "center", justifyContent: "center", gap: "6px",
            transition: "color 0.15s",
          }}
          onMouseEnter={e => e.currentTarget.style.color = "#64748b"}
          onMouseLeave={e => e.currentTarget.style.color = "#334155"}
          >
            <RefreshCw size={11} /> Refresh Data
          </button>
        </div>
      </div>

      {/* Main content */}
      <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden", position: "relative", zIndex: 10 }}>

        {/* Top header */}
        <div style={{
          padding: "0 32px",
          height: "60px",
          minHeight: "60px",
          borderBottom: "1px solid #1e2d3d",
          display: "flex", alignItems: "center", justifyContent: "space-between",
          backgroundColor: "rgba(10,15,26,0.95)",
          backdropFilter: "blur(20px)",
          position: "sticky", top: 0, zIndex: 20,
        }}>
          <div>
            <h1 style={{
              fontSize: "16px",
              fontWeight: 700,
              color: "#e2e8f0",
              margin: 0,
              letterSpacing: "-0.02em",
            }}>
              {NAV_ITEMS.find(n => n.id === activeTab)?.label || "Overview"}
            </h1>
            <p style={{ fontSize: "11px", color: "#334155", margin: 0, marginTop: "2px" }}>
              {summary?.last_scan ? `Last scan: ${summary.last_scan}` : "No scans yet — run a scan to begin"}
            </p>
          </div>

          {/* Header right — risk indicator + plan + user */}
          <div style={{ display: "flex", alignItems: "center", gap: "16px" }}>

            {/* Live risk score */}
            {summary && (
              <div style={{
                display: "flex", alignItems: "center", gap: "8px",
                padding: "6px 14px",
                borderRadius: "8px",
                backgroundColor: riskScore >= 70
                  ? "rgba(255,61,61,0.12)"
                  : riskScore >= 40
                  ? "rgba(255,183,0,0.12)"
                  : "rgba(0,255,148,0.12)",
                border: `1px solid ${riskScore >= 70
                  ? "rgba(255,61,61,0.3)"
                  : riskScore >= 40
                  ? "rgba(255,183,0,0.3)"
                  : "rgba(0,255,148,0.3)"}`,
              }}>
                <div style={{
                  width: "6px", height: "6px", borderRadius: "50%",
                  backgroundColor: riskScore >= 70 ? "#ff3d3d" : riskScore >= 40 ? "#ffb700" : "#00ff94",
                }} />
                <span style={{
                  fontFamily: "'JetBrains Mono', monospace",
                  fontSize: "12px",
                  fontWeight: 700,
                  color: riskScore >= 70 ? "#ff3d3d" : riskScore >= 40 ? "#ffb700" : "#00ff94",
                }}>
                  RISK {riskScore || 0}
                </span>
              </div>
            )}

            {/* Plan badge */}
            <div style={{
              padding: "4px 12px",
              borderRadius: "6px",
              backgroundColor: "rgba(139,92,246,0.1)",
              border: "1px solid rgba(139,92,246,0.3)",
              fontSize: "11px",
              fontWeight: 600,
              color: "#8b5cf6",
              fontFamily: "'JetBrains Mono', monospace",
              textTransform: "uppercase",
              letterSpacing: "0.05em",
            }}>
              {usage?.plan || "free"}
            </div>

            {/* User */}
            <div style={{
              fontSize: "13px",
              color: "#64748b",
              fontWeight: 500,
            }}>
              {usage?.name || "User"}
            </div>
          </div>
        </div>

        {/* Page content */}
        <div style={{
          flex: 1,
          overflowY: "auto",
          padding: "28px 32px",
          backgroundColor: "#030712",
        }}>

          {/* DASHBOARD / OVERVIEW */}
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
                    {[
                      "Module 1: Recon",
                      "Module 2: MQTT Scanner",
                      "Module 3: CoAP Scanner",
                      "Module 4: HTTP Scanner",
                      "Module 5: Firmware Analysis",
                      "Module 6: AI Engine",
                      "Module 7: Report",
                    ].map((m, i) => {
                      const ran = (summary.modules_run || []).some(r => r.includes(m.split(": ")[1]) || m.includes(r));
                      return (
                        <div key={i} className="flex items-center gap-3 p-3 rounded-xl"
                          style={{ backgroundColor: COLORS.darker }}>
                          <CheckCircle size={16} style={{ color: ran ? COLORS.low : COLORS.muted }} />
                          <span className="text-sm font-medium" style={{ color: ran ? COLORS.text : COLORS.muted }}>{m}</span>
                          <span className="ml-auto text-xs px-2 py-0.5 rounded-full"
                            style={{
                              backgroundColor: ran ? COLORS.low + "20" : COLORS.muted + "20",
                              color: ran ? COLORS.low : COLORS.muted
                            }}>
                            {ran ? "DONE" : "NOT DETECTED"}
                          </span>
                        </div>
                      );
                    })}
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
                        <div className="font-black text-xl" style={{ color: COLORS.text }}>{device.target}</div>
                        <div className="text-sm mt-0.5" style={{ color: COLORS.muted }}>{device.findings?.length || 0} finding{device.findings?.length !== 1 ? "s" : ""} detected</div>
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      {device.critical > 0 && <SeverityBadge severity="Critical" />}{device.critical === 0 && device.high > 0 && <SeverityBadge severity="High" />}
                      <div className="text-right">
                        <div className="text-2xl font-black" style={{ color: device.critical > 0 ? COLORS.critical : device.high > 0 ? COLORS.high : COLORS.medium }}>{device.critical > 0 ? "CRITICAL" : device.high > 0 ? "HIGH" : device.medium > 0 ? "MEDIUM" : "LOW"}</div>
                        <div className="text-xs" style={{ color: COLORS.muted }}>Risk Level</div>
                      </div>
                    </div>
                  </div>

                  <div className="grid grid-cols-3 gap-3 mb-4">
                    {[
                      { label: "Critical", value: device.critical || 0 },
                      { label: "High", value: device.high || 0 },
                      { label: "Medium", value: device.medium || 0 },
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

          {/* NETWORK MAP */}

          {/* NETWORK MAP */}
          {activeTab === "map" && (
            <NetworkMap token={token} scans={data?.scans || []} />
          )}

          {/* CVE INTELLIGENCE */}
          {activeTab === "predict" && (
            <PredictPanel token={token} scans={data?.scans || []} />
          )}

          {/* AIPET WATCH */}
          {activeTab === "watch" && (
            <WatchPanel token={token} />
          )}

          {/* AI ANALYSIS */}
          {activeTab === "ai" && (
            <div style={{ color: "#64748b", textAlign: "center", paddingTop: "80px" }}>
              <Shield size={48} style={{ opacity: 0.3, marginBottom: "16px" }} />
              <p>AI Analysis coming soon</p>
            </div>
          )}

          {/* ASK AIPET */}
          {activeTab === "ask" && (
            <AskPanel token={token} />
          )}

          {/* REPORTS */}
          {activeTab === "reports" && (
            <div style={{ color: "#64748b", textAlign: "center", paddingTop: "80px" }}>
              <FileText size={48} style={{ opacity: 0.3, marginBottom: "16px" }} />
              <p>Reports coming soon</p>
            </div>
          )}

          {/* PRICING */}
          {activeTab === "protocols" && (
            <ProtocolsPage token={token} showToast={showToast} currentPlan={usage?.plan} />
          )}
          {activeTab === "compliance" && (
            <CompliancePage token={token} showToast={showToast} currentPlan={usage?.plan} />
          )}
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
              showToast={showToast}
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

      <style>{`
        @keyframes pulse {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.4; }
        }
        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
        ::-webkit-scrollbar { width: 4px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: #1e2d3d; border-radius: 2px; }
        ::-webkit-scrollbar-thumb:hover { background: #334155; }
      `}</style>
    </div>
  );
}
