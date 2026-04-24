import { useState, useEffect, useRef, useCallback } from "react";
import { useTranslation } from "react-i18next";

// ─── Inject global styles once ────────────────────────────────────────────────
const CSS = `
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700;800&family=Inter:wght@400;500;600;700;800;900&display=swap');
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  html { scroll-behavior: smooth; }
  body { background: #030712 !important; color: #e2e8f0; font-family: 'Inter', sans-serif; overflow-x: hidden; }
  ::selection { background: #00e5ff33; }
  ::-webkit-scrollbar { width: 6px; }
  ::-webkit-scrollbar-track { background: #060d1a; }
  ::-webkit-scrollbar-thumb { background: #00e5ff2a; border-radius: 3px; }

  @keyframes pulse2    { 0%,100%{opacity:.5;transform:scale(1)} 50%{opacity:1;transform:scale(1.1)} }
  @keyframes fadeUp    { from{opacity:0;transform:translateY(28px)} to{opacity:1;transform:none} }
  @keyframes gridScroll{ 0%{transform:translateY(0)} 100%{transform:translateY(60px)} }
  @keyframes float     { 0%,100%{transform:translateY(0px)} 50%{transform:translateY(-10px)} }
  @keyframes scanPulse { 0%{box-shadow:0 0 0 0 #00e5ff44} 70%{box-shadow:0 0 0 12px #00e5ff00} 100%{box-shadow:0 0 0 0 #00e5ff00} }
  @keyframes ticker    { 0%{transform:translateX(0)} 100%{transform:translateX(-50%)} }
  @keyframes blink     { 0%,100%{opacity:1} 50%{opacity:0} }

  .lp-btn-primary:hover  { background:#00ccee !important; transform:translateY(-2px); box-shadow:0 8px 32px #00e5ff44 !important; }
  .lp-btn-outline:hover  { background:#00e5ff12 !important; border-color:#00e5ff !important; color:#00e5ff !important; transform:translateY(-2px); }
  .lp-card-hover:hover   { border-color:#00e5ff44 !important; transform:translateY(-5px); box-shadow:0 24px 60px #00e5ff0a !important; }
  .lp-feat-card:hover    { border-color:#00e5ff55 !important; background:#0a1628 !important; }
  .lp-price-card:hover   { transform:translateY(-6px); }
  .lp-badge-hover:hover  { border-color:#00e5ff55 !important; background:#0a1628 !important; transform:scale(1.04); }
  .lp-footer-link:hover  { color:#00e5ff !important; }
  .lp-nav-link:hover     { color:#00e5ff !important; }
  .lp-lang-row:hover     { background:#00e5ff0d !important; }
  .lp-flag-cell:hover    { background:#0a1628 !important; transform:scale(1.06); }
  .lp-step-card:hover    { border-color:#00e5ff44 !important; }
  .lp-sol-card:hover     { border-color:#00e5ff44 !important; transform:translateY(-5px); box-shadow:0 24px 60px #00e5ff0a !important; }

  @media(max-width:900px) {
    .lp-hero-grid     { grid-template-columns:1fr !important; }
    .lp-hide-mob      { display:none !important; }
    .lp-feat-grid     { grid-template-columns:repeat(2,1fr) !important; }
    .lp-price-grid    { grid-template-columns:1fr 1fr !important; }
    .lp-footer-grid   { grid-template-columns:1fr 1fr !important; }
    .lp-problem-grid  { grid-template-columns:1fr !important; }
    .lp-sol-grid      { grid-template-columns:1fr !important; }
    .lp-steps-grid    { grid-template-columns:1fr !important; }
    .lp-flags-grid    { grid-template-columns:repeat(3,1fr) !important; }
    .lp-comp-grid     { grid-template-columns:repeat(2,1fr) !important; }
  }
  @media(max-width:600px) {
    .lp-price-grid  { grid-template-columns:1fr !important; }
    .lp-feat-grid   { grid-template-columns:1fr !important; }
  }
`;

// ─── Design tokens ────────────────────────────────────────────────────────────
const C = {
  bg: "#030712", dark: "#060d1a", card: "#0a1320", border: "#0f2040",
  cyan: "#00e5ff", text: "#e2e8f0", muted: "#64748b",
  green: "#00ff88", red: "#ff2d55", amber: "#ffd60a", purple: "#8b5cf6",
};

// ─── Static data ──────────────────────────────────────────────────────────────
const CURRENCY_PRICES = {
  GBP: { symbol: "£", pro: "49",    ent: "499",    x: "1,999" },
  USD: { symbol: "$", pro: "59",    ent: "599",    x: "2,499" },
  EUR: { symbol: "€", pro: "55",    ent: "549",    x: "2,199" },
  JPY: { symbol: "¥", pro: "8,900", ent: "89,000", x: "299,000" },
};

const LANGUAGES = [
  { code: "en", label: "EN", name: "English",    flag: "🇬🇧" },
  { code: "fr", label: "FR", name: "Français",   flag: "🇫🇷" },
  { code: "de", label: "DE", name: "Deutsch",    flag: "🇩🇪" },
  { code: "ja", label: "JA", name: "日本語",     flag: "🇯🇵" },
  { code: "ar", label: "AR", name: "العربية",    flag: "🇸🇦" },
  { code: "zh", label: "ZH", name: "中文",       flag: "🇨🇳" },
  { code: "ko", label: "KO", name: "한국어",     flag: "🇰🇷" },
  { code: "es", label: "ES", name: "Español",   flag: "🇪🇸" },
  { code: "pt", label: "PT", name: "Português",  flag: "🇧🇷" },
  { code: "it", label: "IT", name: "Italiano",   flag: "🇮🇹" },
  { code: "nl", label: "NL", name: "Nederlands", flag: "🇳🇱" },
];

const FEATURES_GRID = [
  { icon: "🔍", title: "Real Network Scanner",      desc: "Live Nmap-powered discovery across 65K+ ports. Detect every device in seconds." },
  { icon: "🧠", title: "AI Threat Analysis",         desc: "SHAP-explained ML scores every vulnerability. No black boxes, full transparency." },
  { icon: "☁️", title: "Cloud Runtime Protection",   desc: "AWS, Azure, GCP runtime scanning with Kubernetes deep inspection built in." },
  { icon: "🏭", title: "OT / ICS Security",          desc: "Modbus, DNP3, Zigbee, LoRaWAN — protocol-level analysis for operational tech." },
  { icon: "🛡️", title: "Zero Trust Engine",          desc: "Device trust scoring, policy automation, and micro-segmentation rules." },
  { icon: "📋", title: "Compliance Automation",      desc: "NIS2, ISO 27001, GDPR, SOC 2, NIST CSF mapped to every control automatically." },
  { icon: "📊", title: "Board-Ready Reports",        desc: "One-click Executive, CISO, Compliance PDFs generated in under 3 seconds." },
  { icon: "🔴", title: "Live CVE Intelligence",      desc: "NVD feed updated hourly. EPSS + CVSS scores on every finding." },
  { icon: "🎯", title: "Attack Path Mapping",        desc: "D3-powered kill-chain visualiser shows lateral movement before attackers do." },
  { icon: "🤖", title: "AI SOC Assistant",           desc: "Natural-language security queries answered with full context and citations." },
  { icon: "🔐", title: "Identity Threat Detection",  desc: "Credential abuse, privilege escalation, and anomalous logins caught instantly." },
  { icon: "📡", title: "SIEM & Log Analytics",       desc: "Correlate events across cloud, endpoint, and network in a single timeline." },
];

const COMPLIANCE_FW = [
  { label: "NIS2",      color: "#3b82f6", desc: "EU Critical Infrastructure" },
  { label: "ISO 27001", color: "#8b5cf6", desc: "Information Security Mgmt" },
  { label: "GDPR",      color: "#06b6d4", desc: "Data Protection Regulation" },
  { label: "SOC 2",     color: "#10b981", desc: "Service Organisation Control" },
  { label: "NIST CSF",  color: "#f59e0b", desc: "Cybersecurity Framework" },
  { label: "PCI DSS",   color: "#ef4444", desc: "Payment Card Security" },
];

const PROBLEMS = [
  { icon: "💸", title: "Enterprise tools cost £200K+/year",
    desc: "Traditional SIEM and vulnerability management platforms are priced for Fortune 500. SMEs and public sector are left unprotected." },
  { icon: "🧩", title: "No single platform covers IoT, OT & Cloud",
    desc: "You need 6 different tools to cover endpoints, operational technology, cloud workloads, and compliance. Until now." },
  { icon: "📜", title: "Compliance automation is out of reach",
    desc: "NIS2, ISO 27001, GDPR audits take months and cost tens of thousands. AIPET X automates evidence collection and gap analysis in minutes." },
];

const SOLUTION_CARDS = [
  { icon: "📡", color: C.cyan,   title: "Real Network Scanner",
    desc: "Nmap-powered live discovery scans your entire network in under 60 seconds. See every IoT device, open port, and running service. No agents required." },
  { icon: "🌐", color: C.green,  title: "Live Threat Intelligence",
    desc: "NVD CVE feed updated hourly with EPSS prioritisation. Attack path mapping shows lateral movement routes before adversaries exploit them." },
  { icon: "📑", color: C.purple, title: "One-Click Board Reports",
    desc: "Executive, CISO, Compliance, Incident, and Trend reports generated in under 3 seconds. Export to PDF, email to board — editable before download." },
];

const STEPS = [
  { num: "01", icon: "🔌", title: "Connect",  desc: "Enter your IP range or cloud credentials. No agents required. Works across cloud, on-premise, and hybrid environments." },
  { num: "02", icon: "🔍", title: "Discover", desc: "Real-time scanner maps every device, service, and vulnerability. AI scores each finding with financial impact and remediation priority." },
  { num: "03", icon: "🛡️", title: "Secure",   desc: "Get actionable playbooks, one-click compliance reports, and board-ready summaries. Close gaps in hours, not months." },
];

// ─── Severity colours for scanner ─────────────────────────────────────────────
const SEV = { critical: "#ff4444", high: "#f59e0b", medium: "#00e5ff", low: "#00ff88" };

// ─── Inline PublicScanner ─────────────────────────────────────────────────────
function PublicScanner() {
  const [target,   setTarget]   = useState("");
  const [scanning, setScanning] = useState(false);
  const [result,   setResult]   = useState(null);
  const [err,      setErr]      = useState(null);

  const run = async () => {
    if (!target.trim()) return;
    setScanning(true); setResult(null); setErr(null);
    try {
      const r = await fetch("http://localhost:5001/api/public/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: target.trim() }),
      });
      const d = await r.json();
      r.ok ? setResult(d) : setErr(d.error || "Scan failed");
    } catch { setErr("Connection failed — make sure AIPET backend is running."); }
    setScanning(false);
  };

  const iStyle = { flex: 1, padding: "16px 20px", borderRadius: 12, border: `1px solid ${C.border}`, background: C.dark, color: C.text, fontSize: 15, outline: "none", fontFamily: "Inter, sans-serif" };
  const btnSt  = { padding: "16px 32px", borderRadius: 12, background: C.cyan, color: "#000", border: "none", cursor: target ? "pointer" : "not-allowed", fontSize: 15, fontWeight: 800, opacity: !target ? 0.55 : 1, boxShadow: `0 0 24px ${C.cyan}44`, whiteSpace: "nowrap", transition: "all 0.2s", fontFamily: "'JetBrains Mono', monospace" };

  return (
    <div style={{ maxWidth: 700, margin: "0 auto" }}>
      <div style={{ display: "flex", gap: 12, marginBottom: 24 }}>
        <input value={target} onChange={e => setTarget(e.target.value)} onKeyDown={e => e.key === "Enter" && run()} placeholder="Enter IP address e.g. 192.168.1.1" style={iStyle} />
        <button onClick={run} disabled={scanning || !target} className="lp-btn-primary" style={btnSt}>
          {scanning ? "Scanning…" : "🔍 Scan Now"}
        </button>
      </div>

      {scanning && (
        <div style={{ textAlign: "center", padding: "32px", color: C.cyan }}>
          <div style={{ fontSize: 40, marginBottom: 12, animation: "float 1.5s ease-in-out infinite" }}>🔍</div>
          <div style={{ fontWeight: 700 }}>Scanning {target}…</div>
          <div style={{ color: C.muted, fontSize: 13, marginTop: 6 }}>Checking common IoT ports and CVE database</div>
        </div>
      )}

      {err && (
        <div style={{ padding: 16, borderRadius: 12, background: "#ff444418", border: "1px solid #ff444433", color: "#ff4444", fontSize: 14 }}>⚠ {err}</div>
      )}

      {result && (
        <div style={{ textAlign: "left" }}>
          <div style={{ padding: 24, borderRadius: 16, border: `1px solid ${C.cyan}25`, background: C.dark, marginBottom: 16, display: "flex", justifyContent: "space-between", alignItems: "center", gap: 16, flexWrap: "wrap" }}>
            <div style={{ display: "flex", gap: 16, alignItems: "center" }}>
              <div style={{ width: 52, height: 52, borderRadius: 12, background: `${C.cyan}18`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 26 }}>{result.device_icon}</div>
              <div>
                <div style={{ fontWeight: 800, fontSize: 17 }}>{result.target}</div>
                <div style={{ color: C.cyan, fontSize: 13, fontWeight: 600 }}>{result.device_type}</div>
                <div style={{ color: C.muted, fontSize: 12 }}>Open ports: {result.open_ports?.join(", ") || "None detected"}</div>
              </div>
            </div>
            <div style={{ textAlign: "center" }}>
              <div style={{ fontSize: 34, fontWeight: 900, color: SEV[result.risk_level?.toLowerCase()] || C.cyan }}>{result.risk_score}</div>
              <div style={{ fontSize: 12, color: C.muted }}>Risk Score</div>
              <div style={{ fontSize: 13, fontWeight: 700, color: SEV[result.risk_level?.toLowerCase()] || C.cyan }}>{result.risk_level}</div>
            </div>
          </div>

          {result.findings?.length > 0 ? (
            <>
              <div style={{ fontSize: 14, fontWeight: 700, marginBottom: 10 }}>Vulnerabilities Found ({result.total_findings} total)</div>
              {result.findings.map((f, i) => (
                <div key={i} style={{ padding: 14, borderRadius: 10, border: `1px solid ${SEV[f.severity]}30`, background: SEV[f.severity] + "0a", marginBottom: 8, display: "flex", justifyContent: "space-between", gap: 12, flexWrap: "wrap" }}>
                  <div>
                    <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 4 }}>
                      <span style={{ fontSize: 11, fontWeight: 700, color: SEV[f.severity], padding: "2px 8px", borderRadius: 6, background: SEV[f.severity] + "20" }}>{f.severity?.toUpperCase()}</span>
                      <span style={{ fontSize: 14, fontWeight: 600 }}>Port {f.port} — {f.name}</span>
                    </div>
                    <div style={{ color: C.muted, fontSize: 12 }}>MITRE: {f.mitre} · Fix: {f.fix}</div>
                  </div>
                </div>
              ))}
            </>
          ) : (
            <div style={{ padding: 20, borderRadius: 12, background: "#00ff8808", border: "1px solid #00ff8828", textAlign: "center", marginBottom: 16 }}>
              <div style={{ fontSize: 28, marginBottom: 6 }}>✅</div>
              <div style={{ color: C.green, fontWeight: 700 }}>No open vulnerable ports detected</div>
            </div>
          )}

          <div style={{ padding: 20, borderRadius: 14, background: `linear-gradient(135deg, ${C.cyan}12, ${C.purple}0a)`, border: `1px solid ${C.cyan}25`, textAlign: "center" }}>
            <div style={{ fontWeight: 700, fontSize: 15, marginBottom: 6 }}>
              {result.total_findings > 3 ? `+${result.total_findings - 3} more vulnerabilities hidden` : "Want the full report?"}
            </div>
            <div style={{ color: C.muted, fontSize: 13, marginBottom: 14 }}>Sign up free for all findings, SHAP AI explanations, financial risk, and compliance reports</div>
            <button className="lp-btn-primary" onClick={() => { window.location.href = "/app"; }}
              style={{ padding: "11px 28px", borderRadius: 10, background: C.cyan, color: "#000", border: "none", cursor: "pointer", fontWeight: 800, fontSize: 14, fontFamily: "'JetBrains Mono', monospace", transition: "all 0.2s" }}>
              Get Full Report Free →
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Main Landing Component ───────────────────────────────────────────────────
export default function Landing() {
  const { t, i18n } = useTranslation();
  const [scrolled,    setScrolled]    = useState(false);
  const [langOpen,    setLangOpen]    = useState(false);
  const [currency,    setCurrency]    = useState({ code: "GBP", ...CURRENCY_PRICES.GBP });
  const [activeDrop,  setActiveDrop]  = useState(null);

  // Inject CSS
  useEffect(() => {
    if (document.getElementById("lp-css")) return;
    const s = document.createElement("style");
    s.id = "lp-css";
    s.textContent = CSS;
    document.head.appendChild(s);
  }, []);

  // Detect currency from backend
  useEffect(() => {
    fetch("http://localhost:5001/payments/detect-currency")
      .then(r => r.json())
      .then(d => {
        if (CURRENCY_PRICES[d.currency]) setCurrency({ code: d.currency, ...CURRENCY_PRICES[d.currency] });
      })
      .catch(() => {});
  }, []);

  useEffect(() => {
    const h = () => setScrolled(window.scrollY > 40);
    window.addEventListener("scroll", h);
    return () => window.removeEventListener("scroll", h);
  }, []);

  const dismiss = useCallback(() => { setActiveDrop(null); setLangOpen(false); }, []);
  const goApp   = () => { window.location.href = "/app"; };

  const NAV_LINKS = [
    { label: "Platform",     id: "features" },
    { label: "How It Works", id: "how-it-works" },
    { label: "Pricing",      id: "pricing" },
  ];

  const PLANS = [
    { name: "Free",          color: C.muted,  price: `${currency.symbol}0`,              period: "forever",   popular: false, founder: false,
      cta: "Start Free", features: ["5 scans/month", "Real network scanner", "Basic AI analysis", "Community support", "3 compliance checks"] },
    { name: "Professional",  color: C.cyan,   price: `${currency.symbol}${currency.pro}`, period: "/ month",  popular: true,  founder: false,
      cta: "Start Free Trial", features: ["Unlimited scans", "All 93+ modules", "Full SHAP AI explanations", "Board-ready PDF reports", "API access", "All 6 compliance frameworks", "Email support"] },
    { name: "Enterprise",    color: C.purple, price: `${currency.symbol}${currency.ent}`, period: "/ month",  popular: false, founder: false,
      cta: "Get Enterprise", features: ["Everything in Pro", "10 parallel scans", "Multi-tenant management", "SSO / SAML integration", "SLA guarantee", "Dedicated support", "Custom integrations"] },
    { name: "AIPET X",       color: "#ff3b5c", price: `${currency.symbol}${currency.x}`, period: "/ month",  popular: false, founder: true,
      cta: "Get Founder Pricing", features: ["Everything in Enterprise", "SIEM & Event Management", "Threat Intelligence Feed", "Zero-Trust Engine", "Autonomous Defense", "AI SOC Analyst 24/7", "OT/ICS Security", "Multi-Cloud Security", "Digital Twin", "AI Red Team", "Source code licence"] },
  ];

  // ── Shared style helpers ───────────────────────────────────────────────────
  const S = (extra) => ({ maxWidth: 1200, margin: "0 auto", padding: "0 24px", ...extra });
  const sec = (bg, extra) => ({ background: bg || "transparent", padding: "90px 0", ...extra });
  const hdr = () => ({
    textAlign: "center", marginBottom: 56,
  });
  const mono = { fontFamily: "'JetBrains Mono', monospace" };

  return (
    <div style={{ background: C.bg, color: C.text, minHeight: "100vh" }} onClick={dismiss}>

      {/* ── Announcement Bar ─────────────────────────────────────────────────── */}
      <div style={{ background: `linear-gradient(90deg, ${C.cyan}cc, #0088bb, ${C.cyan}cc)`, padding: "10px 24px", textAlign: "center", fontSize: 13, fontWeight: 600, color: "#fff", letterSpacing: "0.01em" }}>
        ⚡&nbsp;&nbsp;AIPET X v7.0.0 — The World's First AI-Native IoT Security Platform&nbsp;&nbsp;·&nbsp;&nbsp;
        SIEM · Threat Intel · Zero-Trust · AI Red Team · Digital Twin&nbsp;&nbsp;·&nbsp;&nbsp;
        <span style={{ textDecoration: "underline", cursor: "pointer", fontWeight: 800 }} onClick={goApp}>Start Free Trial →</span>
      </div>

      {/* ── Navbar ───────────────────────────────────────────────────────────── */}
      <nav onClick={e => e.stopPropagation()} style={{
        position: "sticky", top: 0, zIndex: 100, height: 68,
        background: scrolled ? "rgba(3,7,18,0.97)" : C.bg,
        backdropFilter: scrolled ? "blur(20px)" : "none",
        borderBottom: `1px solid ${scrolled ? C.border : "transparent"}`,
        transition: "all 0.3s",
        display: "flex", alignItems: "center",
      }}>
        <div style={{ ...S(), display: "flex", alignItems: "center", justifyContent: "space-between", width: "100%" }}>
          {/* Logo + Mission Control badge */}
          <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
            <div style={{ ...mono, fontSize: 20, fontWeight: 800, color: C.cyan, cursor: "pointer", letterSpacing: "0.04em" }} onClick={() => window.scrollTo(0, 0)}>
              AIPET <span style={{ color: "#fff" }}>X</span>
            </div>
            <span className="lp-hide-mob" style={{ ...mono, fontSize: 10, fontWeight: 700, padding: "3px 10px", borderRadius: 20, background: `${C.cyan}18`, border: `1px solid ${C.cyan}44`, color: C.cyan, letterSpacing: "0.12em" }}>
              MISSION CONTROL
            </span>
          </div>

          {/* Nav links */}
          <div className="lp-hide-mob" style={{ display: "flex", alignItems: "center", gap: 4 }}>
            {NAV_LINKS.map(({ label, id }) => (
              <button key={id} className="lp-nav-link"
                onClick={() => document.getElementById(id)?.scrollIntoView({ behavior: "smooth" })}
                style={{ background: "none", border: "none", cursor: "pointer", color: C.muted, fontSize: 14, fontWeight: 500, padding: "8px 14px", borderRadius: 8, transition: "color 0.2s" }}>
                {label}
              </button>
            ))}
            <a href="https://github.com/Yallewbinyam/AIPET" target="_blank" rel="noreferrer" className="lp-nav-link"
              style={{ color: C.muted, fontSize: 14, fontWeight: 500, padding: "8px 14px", textDecoration: "none", transition: "color 0.2s" }}>
              GitHub
            </a>
          </div>

          {/* Right controls */}
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            {/* Language selector */}
            <div style={{ position: "relative" }} onClick={e => e.stopPropagation()}>
              <button onClick={() => { setLangOpen(o => !o); setActiveDrop(null); }}
                style={{ background: "none", border: `1px solid ${langOpen ? C.cyan : C.border}`, cursor: "pointer", color: C.muted, fontSize: 13, padding: "6px 12px", borderRadius: 8, display: "flex", alignItems: "center", gap: 6, transition: "border-color 0.2s" }}>
                🌍 {LANGUAGES.find(l => l.code === i18n.language)?.label || "EN"}
              </button>
              {langOpen && (
                <div style={{ position: "absolute", top: "calc(100% + 8px)", right: 0, background: C.card, border: `1px solid ${C.border}`, borderRadius: 12, padding: 6, minWidth: 170, zIndex: 200, boxShadow: "0 16px 48px #000a" }}>
                  {LANGUAGES.map(lang => (
                    <button key={lang.code} className="lp-lang-row"
                      onClick={() => { i18n.changeLanguage(lang.code); setLangOpen(false); }}
                      style={{ width: "100%", textAlign: "left", padding: "8px 12px", borderRadius: 8, background: i18n.language === lang.code ? `${C.cyan}18` : "none", color: i18n.language === lang.code ? C.cyan : C.text, border: "none", cursor: "pointer", display: "flex", justifyContent: "space-between", alignItems: "center", fontSize: 13, transition: "background 0.15s" }}>
                      <span>{lang.flag} <strong style={{ marginLeft: 4 }}>{lang.label}</strong></span>
                      <span style={{ color: C.muted, fontSize: 11 }}>{lang.name}</span>
                    </button>
                  ))}
                </div>
              )}
            </div>

            <button className="lp-btn-outline lp-hide-mob" onClick={goApp}
              style={{ padding: "8px 18px", borderRadius: 8, background: "transparent", border: `1px solid ${C.border}`, color: C.text, fontSize: 13, fontWeight: 600, cursor: "pointer", transition: "all 0.2s" }}>
              Sign In
            </button>
            <button className="lp-btn-primary" onClick={goApp}
              style={{ ...mono, padding: "9px 18px", borderRadius: 8, background: C.cyan, color: "#000", fontSize: 13, fontWeight: 800, border: "none", cursor: "pointer", transition: "all 0.2s" }}>
              Get Started
            </button>
          </div>
        </div>
      </nav>

      {/* ── Hero ─────────────────────────────────────────────────────────────── */}
      <div style={{ position: "relative", paddingTop: 32, paddingBottom: 0, overflow: "hidden" }}>
        {/* Grid bg */}
        <div style={{ position: "absolute", inset: 0, backgroundImage: `linear-gradient(${C.border}66 1px, transparent 1px), linear-gradient(90deg, ${C.border}66 1px, transparent 1px)`, backgroundSize: "60px 60px", animation: "gridScroll 10s linear infinite", opacity: 0.5 }} />
        <div style={{ position: "absolute", top: "30%", left: "50%", transform: "translateX(-50%)", width: 800, height: 400, background: `radial-gradient(ellipse, ${C.cyan}0a 0%, transparent 70%)`, pointerEvents: "none" }} />

        <div style={{ ...S(), position: "relative", zIndex: 1, textAlign: "center", padding: "60px 24px 0" }}>
          {/* Badge */}
          <div style={{ display: "inline-flex", alignItems: "center", gap: 8, padding: "6px 16px", borderRadius: 100, border: `1px solid ${C.cyan}44`, background: `${C.cyan}0e`, marginBottom: 28 }}>
            <span style={{ width: 7, height: 7, borderRadius: "50%", background: C.green, animation: "pulse2 2s infinite", display: "inline-block" }} />
            <span style={{ ...mono, color: C.cyan, fontSize: 12, fontWeight: 700, letterSpacing: "0.1em" }}>FREE PUBLIC SCANNER — NO LOGIN REQUIRED</span>
          </div>

          <h1 style={{ fontSize: "clamp(32px, 5.5vw, 62px)", fontWeight: 900, lineHeight: 1.08, marginBottom: 20, letterSpacing: "-0.025em" }}>
            Scan Any IoT Device<br />
            <span style={{ background: `linear-gradient(135deg, ${C.cyan}, ${C.green})`, WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent", backgroundClip: "text" }}>Right Now</span>
          </h1>
          <p style={{ fontSize: 18, color: C.muted, maxWidth: 620, margin: "0 auto 20px", lineHeight: 1.7 }}>
            93+ security modules. Real network scanning. Live CVE intelligence. Automated compliance for NIS2, ISO 27001 &amp; GDPR.
            Available in 11 languages. <strong style={{ color: C.text }}>From £49/month.</strong>
          </p>

          {/* Stats row */}
          <div style={{ display: "flex", gap: 32, justifyContent: "center", flexWrap: "wrap", marginBottom: 40 }}>
            {[["93+", "Modules"], ["11", "Languages"], ["6", "Frameworks"], ["£49", "From/mo"]].map(([v, l]) => (
              <div key={l} style={{ textAlign: "center" }}>
                <div style={{ ...mono, fontSize: 26, fontWeight: 900, color: C.cyan }}>{v}</div>
                <div style={{ fontSize: 11, color: C.muted, marginTop: 2 }}>{l}</div>
              </div>
            ))}
          </div>

          {/* CTA buttons */}
          <div style={{ display: "flex", gap: 12, justifyContent: "center", flexWrap: "wrap", marginBottom: 48 }}>
            <button className="lp-btn-primary" onClick={goApp}
              style={{ ...mono, padding: "14px 32px", borderRadius: 10, background: C.cyan, color: "#000", fontSize: 15, fontWeight: 800, border: "none", cursor: "pointer", transition: "all 0.2s" }}>
              Start Free Trial →
            </button>
            <button className="lp-btn-outline" onClick={() => document.getElementById("how-it-works")?.scrollIntoView({ behavior: "smooth" })}
              style={{ padding: "14px 32px", borderRadius: 10, background: "transparent", border: `1px solid ${C.border}`, color: C.text, fontSize: 15, fontWeight: 600, cursor: "pointer", transition: "all 0.2s" }}>
              ▶ Watch Demo
            </button>
          </div>

          {/* Trust badges */}
          <div style={{ display: "flex", gap: 24, justifyContent: "center", flexWrap: "wrap", marginBottom: 56, paddingBottom: 32, borderBottom: `1px solid ${C.border}` }}>
            {["NIS2 Compliant", "NIST CSF 2.0", "ISO 27001", "OWASP IoT Top 10"].map(b => (
              <div key={b} style={{ display: "flex", alignItems: "center", gap: 7 }}>
                <span style={{ width: 6, height: 6, borderRadius: "50%", background: C.green, display: "inline-block" }} />
                <span style={{ color: C.muted, fontSize: 13 }}>{b}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Scanner widget */}
        <div id="free-scan" style={{ ...S(), position: "relative", zIndex: 1, paddingBottom: 72 }}>
          <PublicScanner />
        </div>
      </div>

      {/* ── Problem ──────────────────────────────────────────────────────────── */}
      <div style={sec(C.dark, { borderTop: `1px solid ${C.border}`, borderBottom: `1px solid ${C.border}` })}>
        <div style={S()}>
          <div style={hdr()}>
            <div style={{ ...mono, color: C.cyan, fontSize: 11, fontWeight: 700, letterSpacing: "0.14em", textTransform: "uppercase", marginBottom: 10 }}>The Problem</div>
            <h2 style={{ fontSize: "clamp(26px, 4vw, 40px)", fontWeight: 900, color: "#fff", marginBottom: 14 }}>Security shouldn't cost a fortune</h2>
            <p style={{ color: C.muted, fontSize: 16, maxWidth: 560, margin: "0 auto" }}>The market has failed small teams, public sector, and growing companies. AIPET X was built to fix that.</p>
          </div>
          <div className="lp-problem-grid" style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 24 }}>
            {PROBLEMS.map((p, i) => (
              <div key={i} className="lp-card-hover" style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 16, padding: "32px 28px", transition: "all 0.3s" }}>
                <div style={{ fontSize: 36, marginBottom: 18 }}>{p.icon}</div>
                <h3 style={{ fontSize: 17, fontWeight: 800, color: "#fff", marginBottom: 10 }}>{p.title}</h3>
                <p style={{ color: C.muted, lineHeight: 1.7, fontSize: 14 }}>{p.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ── Solution ─────────────────────────────────────────────────────────── */}
      <div style={sec()}>
        <div style={S()}>
          <div style={hdr()}>
            <div style={{ ...mono, color: C.cyan, fontSize: 11, fontWeight: 700, letterSpacing: "0.14em", textTransform: "uppercase", marginBottom: 10 }}>The Solution</div>
            <h2 style={{ fontSize: "clamp(26px, 4vw, 40px)", fontWeight: 900, color: "#fff", marginBottom: 14 }}>One platform. Every attack surface.</h2>
            <p style={{ color: C.muted, fontSize: 16, maxWidth: 560, margin: "0 auto" }}>AIPET X unifies IoT, OT, cloud, identity, and compliance in a single AI-powered platform you can run in minutes.</p>
          </div>
          <div className="lp-sol-grid" style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 28 }}>
            {SOLUTION_CARDS.map((c, i) => (
              <div key={i} className="lp-sol-card" style={{ background: `linear-gradient(135deg, ${C.card}, ${C.dark})`, border: `1px solid ${C.border}`, borderRadius: 20, padding: "36px 28px", transition: "all 0.3s", position: "relative", overflow: "hidden" }}>
                <div style={{ position: "absolute", top: 0, left: 0, right: 0, height: 2, background: `linear-gradient(90deg, ${c.color}, transparent)` }} />
                <div style={{ width: 52, height: 52, borderRadius: 14, background: `${c.color}18`, border: `1px solid ${c.color}33`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 24, marginBottom: 20 }}>{c.icon}</div>
                <h3 style={{ fontSize: 19, fontWeight: 800, color: "#fff", marginBottom: 10 }}>{c.title}</h3>
                <p style={{ color: C.muted, lineHeight: 1.7, fontSize: 14 }}>{c.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ── Features Grid ────────────────────────────────────────────────────── */}
      <div id="features" style={sec(C.dark, { borderTop: `1px solid ${C.border}`, borderBottom: `1px solid ${C.border}` })}>
        <div style={S()}>
          <div style={hdr()}>
            <div style={{ ...mono, color: C.cyan, fontSize: 11, fontWeight: 700, letterSpacing: "0.14em", textTransform: "uppercase", marginBottom: 10 }}>93+ Modules</div>
            <h2 style={{ fontSize: "clamp(26px, 4vw, 40px)", fontWeight: 900, color: "#fff", marginBottom: 14 }}>Everything you need to secure anything</h2>
            <p style={{ color: C.muted, fontSize: 16, maxWidth: 560, margin: "0 auto" }}>From a Raspberry Pi to a Kubernetes cluster — AIPET X covers every asset class, protocol, and threat vector.</p>
          </div>
          <div className="lp-feat-grid" style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 14 }}>
            {FEATURES_GRID.map((f, i) => (
              <div key={i} className="lp-feat-card" style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 14, padding: "20px 18px", transition: "all 0.25s" }}>
                <div style={{ fontSize: 26, marginBottom: 10 }}>{f.icon}</div>
                <div style={{ fontSize: 13, fontWeight: 700, color: "#fff", marginBottom: 5 }}>{f.title}</div>
                <div style={{ fontSize: 12, color: C.muted, lineHeight: 1.6 }}>{f.desc}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ── Compliance ───────────────────────────────────────────────────────── */}
      <div style={sec()}>
        <div style={S()}>
          <div style={hdr()}>
            <div style={{ ...mono, color: C.cyan, fontSize: 11, fontWeight: 700, letterSpacing: "0.14em", textTransform: "uppercase", marginBottom: 10 }}>Compliance Automation</div>
            <h2 style={{ fontSize: "clamp(26px, 4vw, 40px)", fontWeight: 900, color: "#fff", marginBottom: 14 }}>Every major framework. Automated.</h2>
            <p style={{ color: C.muted, fontSize: 16, maxWidth: 560, margin: "0 auto" }}>Map your entire security posture to industry frameworks in minutes, not months. Evidence collection included.</p>
          </div>
          <div className="lp-comp-grid" style={{ display: "grid", gridTemplateColumns: "repeat(6,1fr)", gap: 16, marginBottom: 32 }}>
            {COMPLIANCE_FW.map((fw, i) => (
              <div key={i} className="lp-badge-hover" style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 16, padding: "22px 12px", textAlign: "center", transition: "all 0.2s" }}>
                <div style={{ width: 48, height: 48, borderRadius: 12, background: `${fw.color}18`, border: `1px solid ${fw.color}44`, display: "flex", alignItems: "center", justifyContent: "center", margin: "0 auto 12px", ...mono, fontSize: 10, fontWeight: 800, color: fw.color, letterSpacing: "0.04em" }}>
                  {fw.label.split(" ")[0]}
                </div>
                <div style={{ ...mono, fontSize: 12, fontWeight: 700, color: "#fff", marginBottom: 4 }}>{fw.label}</div>
                <div style={{ fontSize: 11, color: C.muted, lineHeight: 1.4 }}>{fw.desc}</div>
              </div>
            ))}
          </div>
          {/* Inline CTA */}
          <div style={{ background: `linear-gradient(135deg, ${C.cyan}0a, ${C.purple}0a)`, border: `1px solid ${C.border}`, borderRadius: 14, padding: "24px 28px", display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 16 }}>
            <div>
              <div style={{ fontWeight: 800, fontSize: 15, marginBottom: 4 }}>Need a compliance report for your auditor?</div>
              <div style={{ color: C.muted, fontSize: 13 }}>Generate a full gap analysis for any framework in under 60 seconds.</div>
            </div>
            <button className="lp-btn-primary" onClick={goApp}
              style={{ ...mono, padding: "11px 22px", borderRadius: 8, background: C.cyan, color: "#000", fontSize: 13, fontWeight: 800, border: "none", cursor: "pointer", transition: "all 0.2s", whiteSpace: "nowrap" }}>
              Try Free →
            </button>
          </div>
        </div>
      </div>

      {/* ── Global — 11 Languages ────────────────────────────────────────────── */}
      <div style={sec(C.dark, { borderTop: `1px solid ${C.border}`, borderBottom: `1px solid ${C.border}` })}>
        <div style={S()}>
          <div style={hdr()}>
            <div style={{ ...mono, color: C.cyan, fontSize: 11, fontWeight: 700, letterSpacing: "0.14em", textTransform: "uppercase", marginBottom: 10 }}>Global Platform</div>
            <h2 style={{ fontSize: "clamp(26px, 4vw, 40px)", fontWeight: 900, color: "#fff", marginBottom: 14 }}>Security in 11 languages</h2>
            <p style={{ color: C.muted, fontSize: 16, maxWidth: 560, margin: "0 auto" }}>The only security platform with full UI, reports, and AI responses in 11 languages — serving teams across 4 continents.</p>
          </div>
          <div className="lp-flags-grid" style={{ display: "grid", gridTemplateColumns: "repeat(6,1fr)", gap: 12 }}>
            {LANGUAGES.map(l => (
              <div key={l.code} className="lp-flag-cell lp-card-hover"
                style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 14, padding: "18px 10px", textAlign: "center", cursor: "pointer", transition: "all 0.2s" }}
                onClick={() => { i18n.changeLanguage(l.code); }}>
                <div style={{ fontSize: 28, marginBottom: 8 }}>{l.flag}</div>
                <div style={{ fontSize: 13, fontWeight: 700, color: i18n.language === l.code ? C.cyan : "#fff", marginBottom: 2, ...mono }}>{l.label}</div>
                <div style={{ fontSize: 11, color: C.muted }}>{l.name}</div>
                {i18n.language === l.code && <div style={{ marginTop: 6, width: 20, height: 2, background: C.cyan, borderRadius: 1, margin: "6px auto 0" }} />}
              </div>
            ))}
          </div>
          <p style={{ textAlign: "center", color: C.muted, fontSize: 12, marginTop: 20 }}>Click any flag to switch the interface language instantly</p>
        </div>
      </div>

      {/* ── How it Works ─────────────────────────────────────────────────────── */}
      <div id="how-it-works" style={sec()}>
        <div style={S()}>
          <div style={hdr()}>
            <div style={{ ...mono, color: C.cyan, fontSize: 11, fontWeight: 700, letterSpacing: "0.14em", textTransform: "uppercase", marginBottom: 10 }}>How It Works</div>
            <h2 style={{ fontSize: "clamp(26px, 4vw, 40px)", fontWeight: 900, color: "#fff", marginBottom: 14 }}>From zero to secure in 3 steps</h2>
            <p style={{ color: C.muted, fontSize: 16, maxWidth: 540, margin: "0 auto" }}>No 6-month deployment. No professional services fee. Start scanning in under 5 minutes.</p>
          </div>
          <div className="lp-steps-grid" style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 28, position: "relative" }}>
            <div className="lp-hide-mob" style={{ position: "absolute", top: 52, left: "16.5%", right: "16.5%", height: 2, background: `linear-gradient(90deg, ${C.cyan}33, ${C.cyan}, ${C.cyan}33)`, zIndex: 0 }} />
            {STEPS.map((s, i) => (
              <div key={i} className="lp-step-card lp-card-hover" style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 20, padding: "32px 24px", textAlign: "center", position: "relative", zIndex: 1, transition: "all 0.3s" }}>
                <div style={{ ...mono, width: 56, height: 56, borderRadius: "50%", background: `${C.cyan}18`, border: `2px solid ${C.cyan}55`, display: "flex", alignItems: "center", justifyContent: "center", margin: "0 auto 20px", fontSize: 16, fontWeight: 800, color: C.cyan }}>{s.num}</div>
                <div style={{ fontSize: 32, marginBottom: 14 }}>{s.icon}</div>
                <h3 style={{ fontSize: 19, fontWeight: 800, color: "#fff", marginBottom: 10 }}>{s.title}</h3>
                <p style={{ color: C.muted, lineHeight: 1.7, fontSize: 14 }}>{s.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ── Academic Credibility ─────────────────────────────────────────────── */}
      <div style={sec(C.dark, { borderTop: `1px solid ${C.border}`, borderBottom: `1px solid ${C.border}` })}>
        <div style={S()}>
          <div style={{ background: `linear-gradient(135deg, ${C.card}, ${C.dark})`, border: `1px solid ${C.border}`, borderRadius: 22, padding: "48px 44px", display: "flex", gap: 44, alignItems: "center", flexWrap: "wrap" }}>
            <div style={{ width: 76, height: 76, borderRadius: 20, background: "#3b82f618", border: "1px solid #3b82f633", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 38, flexShrink: 0 }}>🎓</div>
            <div style={{ flex: 1, minWidth: 260 }}>
              <div style={{ ...mono, color: C.cyan, fontSize: 10, fontWeight: 700, letterSpacing: "0.14em", textTransform: "uppercase", marginBottom: 8 }}>Academic Research Origin</div>
              <h3 style={{ fontSize: 24, fontWeight: 900, color: "#fff", marginBottom: 10, lineHeight: 1.2 }}>
                Rooted in MSc Cyber Security Research<br />
                <span style={{ color: C.muted, fontSize: 16, fontWeight: 400 }}>Coventry University, UK</span>
              </h3>
              <p style={{ color: C.muted, lineHeight: 1.7, fontSize: 14, maxWidth: 540 }}>
                AIPET X originated as a master's dissertation in Cyber Security at Coventry University, combining academic rigour in IoT threat modelling, machine learning explainability (SHAP), and regulatory compliance into a production-grade platform. The research underpins every algorithm, scoring model, and risk framework in the system.
              </p>
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              {["Peer-reviewed methodology", "SHAP-based AI explainability", "Published threat taxonomy", "Real-world validated dataset"].map((t, i) => (
                <div key={i} style={{ display: "flex", alignItems: "center", gap: 10, fontSize: 14, color: C.text }}>
                  <span style={{ color: C.green }}>✓</span>{t}
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* ── Pricing ──────────────────────────────────────────────────────────── */}
      <div id="pricing" style={sec()}>
        <div style={S()}>
          <div style={hdr()}>
            <div style={{ ...mono, color: C.cyan, fontSize: 11, fontWeight: 700, letterSpacing: "0.14em", textTransform: "uppercase", marginBottom: 10 }}>Transparent Pricing</div>
            <h2 style={{ fontSize: "clamp(26px, 4vw, 40px)", fontWeight: 900, color: "#fff", marginBottom: 14 }}>No hidden fees. No surprises.</h2>
            <p style={{ color: C.muted, fontSize: 16 }}>Start free. Scale when you're ready. Cancel anytime.</p>
          </div>

          {/* Currency switcher */}
          <div style={{ display: "flex", justifyContent: "center", gap: 8, marginBottom: 40, flexWrap: "wrap" }}>
            {Object.entries(CURRENCY_PRICES).map(([code, vals]) => (
              <button key={code} onClick={() => setCurrency({ code, ...vals })}
                style={{ ...mono, padding: "8px 18px", borderRadius: 8, fontSize: 13, fontWeight: 700, cursor: "pointer", background: currency.code === code ? C.cyan : C.card, color: currency.code === code ? "#000" : C.muted, border: `1px solid ${currency.code === code ? C.cyan : C.border}`, transition: "all 0.2s" }}>
                {vals.symbol} {code}
              </button>
            ))}
          </div>

          <div className="lp-price-grid" style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 18, alignItems: "stretch" }}>
            {PLANS.map((p, i) => (
              <div key={i} className="lp-price-card"
                style={{ background: p.popular ? `linear-gradient(135deg, #0a1628, #071328)` : C.card, border: `2px solid ${p.popular ? C.cyan : p.founder ? p.color : C.border}`, borderRadius: 20, padding: "28px 22px", position: "relative", display: "flex", flexDirection: "column", transition: "all 0.3s", boxShadow: p.popular ? `0 0 36px ${C.cyan}1a` : p.founder ? `0 0 24px ${p.color}18` : "none" }}>
                {p.popular && (
                  <div style={{ ...mono, position: "absolute", top: -13, left: "50%", transform: "translateX(-50%)", background: C.cyan, color: "#000", fontSize: 10, fontWeight: 800, padding: "4px 14px", borderRadius: 20, whiteSpace: "nowrap", letterSpacing: "0.08em" }}>
                    MOST POPULAR
                  </div>
                )}
                <div style={{ ...mono, color: p.color, fontSize: 12, fontWeight: 700, marginBottom: 6, letterSpacing: "0.1em" }}>{p.name.toUpperCase()}</div>
                <div style={{ display: "flex", alignItems: "baseline", gap: 4, marginBottom: 20 }}>
                  <span style={{ fontSize: 34, fontWeight: 900, color: "#fff" }}>{p.price}</span>
                  <span style={{ fontSize: 13, color: C.muted }}>{p.period}</span>
                </div>
                <div style={{ borderTop: `1px solid ${C.border}`, marginBottom: 18 }} />
                <ul style={{ listStyle: "none", marginBottom: 22, flex: 1 }}>
                  {p.features.map((f, j) => (
                    <li key={j} style={{ display: "flex", gap: 9, marginBottom: 9, fontSize: 13, color: C.text, alignItems: "flex-start" }}>
                      <span style={{ color: p.popular ? C.cyan : C.green, flexShrink: 0, marginTop: 1 }}>✓</span>{f}
                    </li>
                  ))}
                </ul>
                <button onClick={goApp} className={p.popular ? "lp-btn-primary" : "lp-btn-outline"}
                  style={{ width: "100%", padding: "12px", borderRadius: 10, border: p.popular ? "none" : `2px solid ${p.color}`, background: p.popular ? C.cyan : p.founder ? p.color : "transparent", color: (p.popular || p.founder) ? (p.founder ? "#fff" : "#000") : p.color, fontSize: 14, fontWeight: 700, cursor: "pointer", transition: "all 0.2s", position: "relative", overflow: "hidden" }}>
                  {p.founder && (
                    <span style={{ position: "absolute", top: 0, right: 0, background: C.amber, color: "#000", fontSize: 9, fontWeight: 800, padding: "2px 7px", borderRadius: "0 0 0 6px", letterSpacing: "0.06em" }}>FOUNDER</span>
                  )}
                  {p.cta}
                </button>
              </div>
            ))}
          </div>
          <p style={{ textAlign: "center", color: C.muted, fontSize: 12, marginTop: 20 }}>
            All plans include a 14-day free trial · No credit card required · Prices shown excluding VAT
          </p>
        </div>
      </div>

      {/* ── Final CTA ────────────────────────────────────────────────────────── */}
      <div style={{ ...sec(C.dark, { borderTop: `1px solid ${C.border}` }) }}>
        <div style={{ ...S(), textAlign: "center", maxWidth: 660, paddingTop: 0, paddingBottom: 0 }}>
          <div style={{ ...mono, color: C.cyan, fontSize: 11, fontWeight: 700, letterSpacing: "0.14em", textTransform: "uppercase", marginBottom: 16 }}>Get Started Today</div>
          <h2 style={{ fontSize: "clamp(28px, 4.5vw, 46px)", fontWeight: 900, lineHeight: 1.1, marginBottom: 18 }}>
            Secure your infrastructure<br />
            <span style={{ background: `linear-gradient(135deg, ${C.cyan}, ${C.green})`, WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent", backgroundClip: "text" }}>
              before attackers find it first
            </span>
          </h2>
          <p style={{ fontSize: 16, color: C.muted, marginBottom: 36, lineHeight: 1.7 }}>
            Join teams across healthcare, manufacturing, government, and finance using AIPET X to stay ahead of threats. Free plan available. No credit card required.
          </p>
          <div style={{ display: "flex", gap: 14, justifyContent: "center", flexWrap: "wrap", marginBottom: 28 }}>
            <button className="lp-btn-primary" onClick={goApp}
              style={{ ...mono, padding: "15px 34px", borderRadius: 12, background: C.cyan, color: "#000", fontSize: 16, fontWeight: 800, border: "none", cursor: "pointer", transition: "all 0.2s" }}>
              Start Free Trial →
            </button>
            <button className="lp-btn-outline" onClick={goApp}
              style={{ padding: "15px 34px", borderRadius: 12, background: "transparent", border: `1px solid ${C.border}`, color: C.text, fontSize: 16, fontWeight: 600, cursor: "pointer", transition: "all 0.2s" }}>
              Sign In
            </button>
          </div>
          <div style={{ display: "flex", gap: 24, justifyContent: "center", flexWrap: "wrap" }}>
            {["No credit card required", "14-day free trial", "Cancel anytime"].map(t => (
              <div key={t} style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 13, color: C.muted }}>
                <span style={{ color: C.green }}>✓</span>{t}
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ── Footer ───────────────────────────────────────────────────────────── */}
      <footer style={{ background: "#020609", borderTop: `1px solid ${C.border}`, padding: "56px 0 28px" }}>
        <div style={S()}>
          <div className="lp-footer-grid" style={{ display: "grid", gridTemplateColumns: "2fr 1fr 1fr 1fr", gap: 40, marginBottom: 44 }}>
            {/* Brand */}
            <div>
              <div style={{ ...mono, fontSize: 22, fontWeight: 800, color: C.cyan, marginBottom: 12 }}>AIPET <span style={{ color: "#fff" }}>X</span></div>
              <p style={{ color: C.muted, fontSize: 14, lineHeight: 1.7, maxWidth: 280, marginBottom: 16 }}>
                AI-powered cybersecurity platform for IoT, OT, Cloud, and Compliance. 93+ modules. 11 languages. From £49/month.
              </p>
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 16 }}>
                {["NIS2", "NIST", "ISO 27001"].map(b => (
                  <span key={b} style={{ ...mono, padding: "3px 10px", borderRadius: 6, fontSize: 10, fontWeight: 700, background: `${C.cyan}18`, color: C.cyan, border: `1px solid ${C.cyan}30` }}>{b}</span>
                ))}
              </div>
            </div>
            {/* Platform */}
            <div>
              <div style={{ fontSize: 12, fontWeight: 700, color: "#fff", letterSpacing: "0.1em", textTransform: "uppercase", marginBottom: 14 }}>Platform</div>
              {["Real Scanner", "AI Analysis", "Cloud Security", "OT/ICS Security", "Compliance", "Reports"].map(l => (
                <div key={l} className="lp-footer-link" onClick={() => document.getElementById("features")?.scrollIntoView({ behavior: "smooth" })}
                  style={{ color: C.muted, fontSize: 14, marginBottom: 9, cursor: "pointer", transition: "color 0.2s" }}>{l}</div>
              ))}
            </div>
            {/* Company */}
            <div>
              <div style={{ fontSize: 12, fontWeight: 700, color: "#fff", letterSpacing: "0.1em", textTransform: "uppercase", marginBottom: 14 }}>Company</div>
              {[
                { label: "GitHub", href: "https://github.com/Yallewbinyam/AIPET" },
                { label: "Pricing", id: "pricing" },
                { label: "How It Works", id: "how-it-works" },
              ].map(({ label, href, id }) => (
                <div key={label} className="lp-footer-link"
                  onClick={() => href ? window.open(href, "_blank") : document.getElementById(id)?.scrollIntoView({ behavior: "smooth" })}
                  style={{ color: C.muted, fontSize: 14, marginBottom: 9, cursor: "pointer", transition: "color 0.2s" }}>{label}</div>
              ))}
            </div>
            {/* Legal */}
            <div>
              <div style={{ fontSize: 12, fontWeight: 700, color: "#fff", letterSpacing: "0.1em", textTransform: "uppercase", marginBottom: 14 }}>Legal</div>
              {["Privacy Policy", "Terms of Service", "Security", "Cookie Policy"].map(l => (
                <div key={l} className="lp-footer-link" onClick={goApp}
                  style={{ color: C.muted, fontSize: 14, marginBottom: 9, cursor: "pointer", transition: "color 0.2s" }}>{l}</div>
              ))}
            </div>
          </div>

          <div style={{ borderTop: `1px solid ${C.border}`, paddingTop: 22, display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 12 }}>
            <div style={{ ...mono, fontSize: 12, color: "#2a3a4a" }}>
              © {new Date().getFullYear()} AIPET X · Built by Binyam Yallew, MSc Cyber Security — Coventry University · v7.0.0 · All rights reserved
            </div>
            <div style={{ display: "flex", gap: 20 }}>
              {["Privacy Policy", "Terms", "Security"].map(l => (
                <span key={l} className="lp-footer-link" onClick={goApp} style={{ ...mono, color: "#2a3a4a", fontSize: 12, cursor: "pointer", transition: "color 0.2s" }}>{l}</span>
              ))}
              <a href="https://github.com/Yallewbinyam/AIPET" target="_blank" rel="noreferrer" style={{ ...mono, color: C.cyan, fontSize: 12 }}>GitHub</a>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}
