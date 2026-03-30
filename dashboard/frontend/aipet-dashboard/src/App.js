
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

const API = "http://localhost:5000/api";

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

function FindingRow({ finding }) {
  const [open, setOpen] = useState(false);
  const cfg = SEVERITY_CONFIG[finding.severity] || SEVERITY_CONFIG.INFO;
  return (
    <div className="rounded-xl border overflow-hidden transition-all duration-200"
      style={{ backgroundColor: COLORS.card, borderColor: open ? cfg.color + "40" : COLORS.border }}>
      <div className="flex items-center justify-between p-4 cursor-pointer hover:bg-white/5 transition-colors"
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
        <div className="flex items-center gap-3">
          <SeverityBadge severity={finding.severity} />
          {open ? <ChevronUp size={16} style={{ color: COLORS.muted }} /> : <ChevronDown size={16} style={{ color: COLORS.muted }} />}
        </div>
      </div>
      {open && (
        <div className="px-4 pb-4 pt-2 border-t" style={{ borderColor: COLORS.border }}>
          <p className="text-sm leading-relaxed" style={{ color: COLORS.muted }}>{finding.finding}</p>
        </div>
      )}
    </div>
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

function PricingPage({ currentPlan, onUpgrade }) {
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

function BillingPage({ usage, onUpgrade, onCancel, onPortal }) {
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

          <button onClick={onCancel}
            className="w-full py-3 rounded-xl font-semibold text-sm transition-all border"
            style={{
              backgroundColor: "transparent",
              borderColor: COLORS.critical + "40",
              color: COLORS.critical,
            }}>
            Cancel Subscription
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
  const [token,      setToken]      = useState(localStorage.getItem("aipet_token") || "");

  const fetchAll = useCallback(async () => {
    try {
      const [s, d, f, a, r, sc] = await Promise.all([
        axios.get(`${API}/summary`),
        axios.get(`${API}/devices`),
        axios.get(`${API}/findings`),
        axios.get(`${API}/ai`),
        axios.get(`${API}/reports`),
        axios.get(`${API}/scan/status`),
      ]);
      setData({
        summary:    s.data,
        devices:    Array.isArray(d.data) ? d.data : [],
        findings:   Array.isArray(f.data) ? f.data : [],
        aiResults:  Array.isArray(a.data) ? a.data : [],
        reports:    Array.isArray(r.data) ? r.data : [],
        scanStatus: sc.data,
      });
      setScanning(sc.data?.running || false);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAll();
    const interval = setInterval(fetchAll, 5000);
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
      alert("Payment error. Please try again.");
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
      alert("Could not open billing portal.");
    }
  };

  const handleCancel = async () => {
    if (!window.confirm("Are you sure you want to cancel your subscription?")) return;
    try {
      await axios.post(
        `http://localhost:5001/payments/cancel`,
        {},
        { headers: { Authorization: `Bearer ${token}` } }
      );
      alert("Subscription cancelled. You keep access until the end of your billing period.");
      fetchUsage();
    } catch (e) {
      alert("Could not cancel subscription.");
    }
  };

  const startScan = async (mode, target) => {
    setScanning(true);
    await axios.post(`${API}/scan/start`, { mode, target });
    setTimeout(fetchAll, 3000);
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
    const matchSev  = filter === "ALL" || f.severity === filter;
    const matchText = searchText === "" ||
      f.attack.toLowerCase().includes(searchText.toLowerCase()) ||
      f.finding.toLowerCase().includes(searchText.toLowerCase());
    return matchSev && matchText;
  });

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
            {summary && (
              <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg border"
                style={{ borderColor: riskColor + "40", backgroundColor: riskColor + "10" }}>
                <div className="w-2 h-2 rounded-full" style={{ backgroundColor: riskColor }} />
                <span className="text-xs font-bold" style={{ color: riskColor }}>
                  {summary.overall_risk}
                </span>
              </div>
            )}
          </div>
        </div>

        <div className="p-8">

          {/* DASHBOARD */}
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
              ) : filteredFindings.map((f, i) => <FindingRow key={i} finding={f} />)}
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

          {/* PRICING */}
          {activeTab === "pricing" && (
            <PricingPage
              currentPlan={usage?.plan || "free"}
              onUpgrade={handleUpgrade}
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

        </div>
      </div>
      {showScan && <ScanModal onClose={() => setShowScan(false)} onScan={startScan} scanning={scanning} />}
    </div>
  );
}
