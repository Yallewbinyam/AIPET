import { useState, useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";

// ─── Inject fonts + keyframes once ───────────────────────────────────────────
const STYLE = `
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700;800&family=Inter:wght@400;500;600;700;800;900&display=swap');
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  html { scroll-behavior: smooth; }
  body { background: #030712; color: #e2e8f0; font-family: 'Inter', sans-serif; overflow-x: hidden; }
  ::selection { background: #00e5ff33; }
  ::-webkit-scrollbar { width: 6px; } ::-webkit-scrollbar-track { background: #0a0f1a; } ::-webkit-scrollbar-thumb { background: #00e5ff33; border-radius: 3px; }

  @keyframes fadeUp   { from { opacity:0; transform:translateY(32px); } to { opacity:1; transform:none; } }
  @keyframes fadeIn   { from { opacity:0; } to { opacity:1; } }
  @keyframes scanLine { 0%{top:0} 100%{top:100%} }
  @keyframes pulse    { 0%,100%{opacity:.4;transform:scale(1)} 50%{opacity:.8;transform:scale(1.05)} }
  @keyframes blink    { 0%,100%{opacity:1} 50%{opacity:0} }
  @keyframes gridMove { 0%{transform:translateY(0)} 100%{transform:translateY(60px)} }
  @keyframes float    { 0%,100%{transform:translateY(0)} 50%{transform:translateY(-12px)} }
  @keyframes gradientShift { 0%{background-position:0% 50%} 50%{background-position:100% 50%} 100%{background-position:0% 50%} }
  @keyframes countUp  { from{opacity:0;transform:translateY(10px)} to{opacity:1;transform:none} }
  @keyframes shimmer  { 0%{background-position:-200% center} 100%{background-position:200% center} }
  @keyframes spin     { from{transform:rotate(0deg)} to{transform:rotate(360deg)} }
  @keyframes borderGlow { 0%,100%{border-color:#00e5ff33} 50%{border-color:#00e5ff99} }

  .fade-up  { animation: fadeUp  0.7s ease both; }
  .fade-in  { animation: fadeIn  0.5s ease both; }
  .float-el { animation: float  4s ease-in-out infinite; }

  .mono { font-family: 'JetBrains Mono', monospace; }
  .nav-link:hover { color: #00e5ff !important; }
  .btn-primary:hover { background: #00ccee !important; transform: translateY(-2px); box-shadow: 0 8px 30px #00e5ff44 !important; }
  .btn-outline:hover { background: #00e5ff15 !important; border-color: #00e5ff !important; color: #00e5ff !important; transform: translateY(-2px); }
  .card-hover:hover { border-color: #00e5ff44 !important; transform: translateY(-4px); box-shadow: 0 20px 60px #00e5ff0d !important; }
  .feature-card:hover { border-color: #00e5ff55 !important; background: #0a1628 !important; }
  .price-card:hover  { transform: translateY(-6px); box-shadow: 0 24px 60px #00000066 !important; }
  .compliance-badge:hover { border-color: #00e5ff66 !important; background: #0a1628 !important; transform: scale(1.05); }
  .step-card:hover { border-color: #00e5ff44 !important; }
  .footer-link:hover { color: #00e5ff !important; }
  .lang-flag:hover { transform: scale(1.1); background: #0a1628 !important; }
  .nav-dropdown { display:none; position:absolute; top:calc(100% + 8px); left:0; background:#0a1320; border:1px solid #00e5ff22; border-radius:12px; padding:8px; min-width:240px; z-index:200; box-shadow:0 20px 60px #000; }
  .nav-dropdown-wrap:hover .nav-dropdown { display:block; }
  .dropdown-item:hover { background:#00e5ff0d; border-radius:8px; }

  @media(max-width:768px) {
    .hide-mobile { display:none !important; }
    .hero-grid { grid-template-columns:1fr !important; }
    .features-grid { grid-template-columns:repeat(2,1fr) !important; }
    .pricing-grid { grid-template-columns:1fr !important; }
    .footer-grid { grid-template-columns:1fr 1fr !important; }
    .problem-grid { grid-template-columns:1fr !important; }
    .solution-grid { grid-template-columns:1fr !important; }
    .steps-grid { grid-template-columns:1fr !important; }
    .flags-grid { grid-template-columns:repeat(3,1fr) !important; }
    .compliance-grid { grid-template-columns:repeat(2,1fr) !important; }
  }
`;

// ─── Constants ────────────────────────────────────────────────────────────────
const C = { bg: "#030712", dark: "#060d1a", card: "#0a1320", border: "#0f2040", cyan: "#00e5ff", text: "#e2e8f0", muted: "#64748b", green: "#00ff88", red: "#ff2d55", amber: "#ffd60a" };

const FEATURES = [
  { icon: "🔍", title: "Real Network Scanner",       desc: "Live Nmap-powered discovery across 65K+ ports. See every device in seconds." },
  { icon: "🧠", title: "AI Threat Analysis",          desc: "SHAP-explained ML models score every vulnerability — no black boxes." },
  { icon: "☁️", title: "Cloud Runtime Protection",    desc: "AWS, Azure, GCP runtime scanning with K8s deep inspection built in." },
  { icon: "🏭", title: "OT/ICS Security",             desc: "Modbus, DNP3, Zigbee, LoRaWAN — protocol-level analysis for operational tech." },
  { icon: "🛡️", title: "Zero Trust Engine",           desc: "Device trust scoring, policy automation, micro-segmentation rules." },
  { icon: "📋", title: "Compliance Automation",       desc: "NIS2, ISO 27001, GDPR, SOC 2, NIST CSF mapped to every control automatically." },
  { icon: "📊", title: "Board-Ready Reports",         desc: "One-click Executive, CISO, and Compliance PDFs in under 3 seconds." },
  { icon: "🔴", title: "Live CVE Intelligence",       desc: "NVD feed updated hourly. EPSS + CVSS scores on every finding." },
  { icon: "🎯", title: "Attack Path Mapping",         desc: "D3-powered kill-chain visualiser shows lateral movement before attackers do." },
  { icon: "🤖", title: "AI SOC Assistant",            desc: "Natural-language security queries answered with full context and citations." },
  { icon: "🔐", title: "Identity Threat Detection",   desc: "Credential abuse, privilege escalation, and anomalous logins caught instantly." },
  { icon: "📡", title: "SIEM & Log Analytics",        desc: "Correlate events across cloud, endpoint, and network in a single timeline." },
];

const COMPLIANCE = [
  { label: "NIS2",      color: "#3b82f6", desc: "EU Critical Infrastructure" },
  { label: "ISO 27001", color: "#8b5cf6", desc: "Information Security Mgmt" },
  { label: "GDPR",      color: "#06b6d4", desc: "Data Protection Regulation" },
  { label: "SOC 2",     color: "#10b981", desc: "Service Organisation Control" },
  { label: "NIST CSF",  color: "#f59e0b", desc: "Cybersecurity Framework" },
  { label: "PCI DSS",   color: "#ef4444", desc: "Payment Card Security" },
];

const LANGUAGES = [
  { flag: "🇬🇧", name: "English",    country: "UK" },
  { flag: "🇫🇷", name: "Français",   country: "France" },
  { flag: "🇩🇪", name: "Deutsch",    country: "Germany" },
  { flag: "🇯🇵", name: "日本語",     country: "Japan" },
  { flag: "🇸🇦", name: "العربية",   country: "Middle East" },
  { flag: "🇨🇳", name: "中文",       country: "China" },
  { flag: "🇰🇷", name: "한국어",     country: "Korea" },
  { flag: "🇪🇸", name: "Español",   country: "Spain" },
  { flag: "🇧🇷", name: "Português",  country: "Brazil" },
  { flag: "🇮🇳", name: "हिन्दी",    country: "India" },
  { flag: "🇷🇺", name: "Русский",   country: "Russia" },
];

const PRICING = [
  { tier: "Free",          price: "£0",     period: "/forever", color: C.muted,  popular: false, cta: "Start Free",
    features: ["5 scans/month", "Real network scanner", "Basic AI analysis", "Community support", "3 compliance checks"] },
  { tier: "Professional",  price: "£49",    period: "/month",   color: C.cyan,   popular: true,  cta: "Start Free Trial",
    features: ["Unlimited scans", "All 93+ modules", "Full SHAP AI explanations", "Board-ready PDF reports", "Email support", "API access", "All compliance frameworks"] },
  { tier: "Enterprise",    price: "£499",   period: "/month",   color: "#a78bfa", popular: false, cta: "Get Enterprise",
    features: ["Everything in Professional", "10 parallel scans", "Multi-tenant management", "SSO / SAML integration", "SLA guarantee", "Dedicated support", "Custom integrations"] },
  { tier: "AIPET X",       price: "£1,999", period: "/month",   color: C.amber,  popular: false, cta: "Contact Sales",
    features: ["Everything in Enterprise", "Unlimited parallel scans", "On-premise deployment", "Source code licence", "Custom AI model training", "24/7 dedicated SOC support", "White-label option"] },
];

const PROBLEMS = [
  { icon: "💸", title: "Enterprise tools cost £200K+/year",        desc: "Traditional SIEM and vulnerability management platforms are priced for Fortune 500. SMEs and public sector are left unprotected." },
  { icon: "🧩", title: "No single platform covers IoT, OT and Cloud", desc: "You need 6 different tools to cover endpoints, operational technology, cloud workloads, and compliance. Until now." },
  { icon: "📜", title: "Compliance automation is out of reach",      desc: "NIS2, ISO 27001, GDPR audits take months and cost tens of thousands. AIPET X automates evidence collection and gap analysis in minutes." },
];

const SOLUTION_CARDS = [
  { icon: "📡", color: C.cyan,   title: "Real Network Scanner",        desc: "Nmap-powered live discovery scans your entire network in under 60 seconds. See every IoT device, open port, and running service. No agents, no credentials required." },
  { icon: "🌐", color: C.green,  title: "Live Threat Intelligence",    desc: "NVD CVE feed updated hourly with EPSS prioritisation. Attack path mapping shows lateral movement routes before adversaries exploit them." },
  { icon: "📑", color: "#a78bfa", title: "One-Click Board Reports",    desc: "Executive, CISO, Compliance, Incident, and Trend reports generated in under 3 seconds. Export to PDF, email to board, done. Editable before download." },
];

const STEPS = [
  { num: "01", title: "Connect",  desc: "Enter your IP range or cloud credentials. No agents required. AIPET X works across cloud, on-premise, and hybrid environments.", icon: "🔌" },
  { num: "02", title: "Discover", desc: "Our real-time scanner maps every device, service, and vulnerability. AI scores each finding with financial impact and remediation priority.", icon: "🔍" },
  { num: "03", title: "Secure",   desc: "Get actionable playbooks, one-click compliance reports, and board-ready summaries. Close gaps with guided remediation in hours, not months.", icon: "🛡️" },
];

// ─── Terminal animation lines ─────────────────────────────────────────────────
const TERMINAL_LINES = [
  { t: 0,    text: "$ aipet scan --target 192.168.1.0/24 --mode full", color: C.cyan },
  { t: 800,  text: "▸ Initialising AIPET X scanner v2.0.0...", color: C.muted },
  { t: 1600, text: "▸ Discovering hosts on subnet... found 47 devices", color: C.text },
  { t: 2400, text: "▸ Running CVE correlation [NVD 2024]...", color: C.text },
  { t: 3200, text: "⚠ [CRITICAL] CVE-2024-3400 PAN-OS RCE — Host: 192.168.1.45", color: C.red },
  { t: 4000, text: "⚠ [HIGH]     Telnet enabled — 3 IoT cameras exposed", color: "#ff6b00" },
  { t: 4800, text: "▸ Running MITRE ATT&CK mapping...", color: C.text },
  { t: 5600, text: "▸ Generating compliance gap report [NIS2, ISO27001]...", color: C.text },
  { t: 6400, text: "✓ Scan complete — 23 findings, 4 critical, report ready", color: C.green },
  { t: 7200, text: "▸ Board PDF exported to /reports/executive_2026-04.pdf", color: C.muted },
];

// ─── Subcomponents ────────────────────────────────────────────────────────────

function TerminalWidget() {
  const [lines, setLines] = useState([]);
  const [cursor, setCursor] = useState(true);
  const ref = useRef(null);

  useEffect(() => {
    const timers = TERMINAL_LINES.map(({ t, text, color }) =>
      setTimeout(() => setLines(prev => [...prev, { text, color }]), t)
    );
    const blinkInterval = setInterval(() => setCursor(c => !c), 530);
    return () => { timers.forEach(clearTimeout); clearInterval(blinkInterval); };
  }, []);

  useEffect(() => {
    if (ref.current) ref.current.scrollTop = ref.current.scrollHeight;
  }, [lines]);

  return (
    <div style={{ background: "#060d1a", border: `1px solid #00e5ff22`, borderRadius: 12, overflow: "hidden", boxShadow: "0 0 60px #00e5ff0a, 0 40px 80px #00000066", fontFamily: "'JetBrains Mono', monospace" }}>
      {/* Traffic lights */}
      <div style={{ background: "#0a1320", padding: "10px 16px", display: "flex", alignItems: "center", gap: 8, borderBottom: "1px solid #0f2040" }}>
        <div style={{ width: 12, height: 12, borderRadius: "50%", background: "#ff5f57" }} />
        <div style={{ width: 12, height: 12, borderRadius: "50%", background: "#febc2e" }} />
        <div style={{ width: 12, height: 12, borderRadius: "50%", background: "#28c840" }} />
        <span style={{ marginLeft: 8, fontSize: 11, color: C.muted }}>aipet-scanner — bash</span>
      </div>
      <div ref={ref} style={{ padding: "16px 20px", minHeight: 260, maxHeight: 320, overflowY: "auto", fontSize: 12, lineHeight: 1.8 }}>
        {lines.map((l, i) => (
          <div key={i} style={{ color: l.color }}>{l.text}</div>
        ))}
        {lines.length < TERMINAL_LINES.length && (
          <span style={{ color: C.cyan }}>{cursor ? "▋" : " "}</span>
        )}
      </div>
    </div>
  );
}

function StatsBadge({ value, label }) {
  return (
    <div style={{ textAlign: "center" }}>
      <div style={{ fontSize: 28, fontWeight: 900, color: C.cyan, fontFamily: "'JetBrains Mono', monospace" }}>{value}</div>
      <div style={{ fontSize: 12, color: C.muted, marginTop: 2 }}>{label}</div>
    </div>
  );
}

function Section({ id, children, style }) {
  return (
    <section id={id} style={{ padding: "100px 0", ...style }}>
      <div style={{ maxWidth: 1200, margin: "0 auto", padding: "0 24px" }}>{children}</div>
    </section>
  );
}

function SectionHeader({ eyebrow, title, subtitle }) {
  return (
    <div style={{ textAlign: "center", marginBottom: 64 }}>
      {eyebrow && (
        <div className="mono" style={{ color: C.cyan, fontSize: 12, fontWeight: 700, letterSpacing: "0.15em", textTransform: "uppercase", marginBottom: 12 }}>
          {eyebrow}
        </div>
      )}
      <h2 style={{ fontSize: "clamp(28px, 4vw, 42px)", fontWeight: 900, color: "#fff", lineHeight: 1.15, marginBottom: 16 }}>{title}</h2>
      {subtitle && <p style={{ fontSize: 17, color: C.muted, maxWidth: 600, margin: "0 auto", lineHeight: 1.7 }}>{subtitle}</p>}
    </div>
  );
}

// ─── Main Component ───────────────────────────────────────────────────────────
export default function Landing() {
  const navigate = useNavigate();
  const [scrolled, setScrolled] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  useEffect(() => {
    const style = document.createElement("style");
    style.textContent = STYLE;
    document.head.appendChild(style);
    const onScroll = () => setScrolled(window.scrollY > 40);
    window.addEventListener("scroll", onScroll);
    return () => { window.removeEventListener("scroll", onScroll); };
  }, []);

  const goApp   = () => { window.location.href = "/app"; };
  const goLogin = () => { window.location.href = "/app"; };

  const inputSt = { width: "100%", padding: "12px 16px", borderRadius: 10, background: C.card, border: `1px solid ${C.border}`, color: C.text, fontSize: 14, outline: "none" };
  const navH = 72;

  return (
    <div style={{ background: C.bg, color: C.text, minHeight: "100vh" }}>

      {/* ── Navbar ── */}
      <nav style={{
        position: "fixed", top: 0, left: 0, right: 0, zIndex: 100, height: navH,
        background: scrolled ? "rgba(3,7,18,0.95)" : "transparent",
        backdropFilter: scrolled ? "blur(20px)" : "none",
        borderBottom: scrolled ? `1px solid ${C.border}` : "1px solid transparent",
        transition: "all 0.3s ease",
      }}>
        <div style={{ maxWidth: 1200, margin: "0 auto", padding: "0 24px", height: "100%", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
          {/* Logo */}
          <div className="mono" style={{ fontSize: 20, fontWeight: 800, color: C.cyan, letterSpacing: "0.05em", cursor: "pointer" }} onClick={() => window.scrollTo(0, 0)}>
            AIPET<span style={{ color: "#fff" }}> X</span>
          </div>

          {/* Nav links */}
          <div className="hide-mobile" style={{ display: "flex", alignItems: "center", gap: 8 }}>
            {[
              { label: "Platform",  href: "#features" },
              { label: "Solutions", href: "#compliance" },
              { label: "How it Works", href: "#how-it-works" },
              { label: "Pricing",   href: "#pricing" },
            ].map(({ label, href }) => (
              <a key={label} href={href} className="nav-link"
                style={{ padding: "8px 14px", color: C.muted, fontSize: 14, fontWeight: 500, textDecoration: "none", borderRadius: 8, transition: "color 0.2s" }}>
                {label}
              </a>
            ))}
          </div>

          {/* CTA buttons */}
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <button className="btn-outline hide-mobile" onClick={goLogin}
              style={{ padding: "9px 20px", borderRadius: 8, background: "transparent", border: `1px solid ${C.border}`, color: C.text, fontSize: 14, fontWeight: 600, cursor: "pointer", transition: "all 0.2s" }}>
              Login
            </button>
            <button className="btn-primary" onClick={goApp}
              style={{ padding: "9px 20px", borderRadius: 8, background: C.cyan, color: "#000", fontSize: 14, fontWeight: 700, border: "none", cursor: "pointer", transition: "all 0.2s", fontFamily: "'JetBrains Mono', monospace" }}>
              Start Free Trial
            </button>
          </div>
        </div>
      </nav>

      {/* ── Hero ── */}
      <div style={{ position: "relative", minHeight: "100vh", display: "flex", alignItems: "center", paddingTop: navH, overflow: "hidden" }}>
        {/* Grid bg */}
        <div style={{ position: "absolute", inset: 0, backgroundImage: `linear-gradient(${C.border}55 1px, transparent 1px), linear-gradient(90deg, ${C.border}55 1px, transparent 1px)`, backgroundSize: "60px 60px", opacity: 0.4, animation: "gridMove 8s linear infinite" }} />
        {/* Glow */}
        <div style={{ position: "absolute", top: "20%", left: "50%", transform: "translateX(-50%)", width: 800, height: 400, background: `radial-gradient(ellipse, #00e5ff0a 0%, transparent 70%)`, pointerEvents: "none" }} />

        <div style={{ maxWidth: 1200, margin: "0 auto", padding: "80px 24px", width: "100%", position: "relative", zIndex: 1 }}>
          <div className="hero-grid" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 60, alignItems: "center" }}>

            {/* Left */}
            <div>
              <div className="mono fade-up" style={{ color: C.cyan, fontSize: 12, fontWeight: 700, letterSpacing: "0.15em", textTransform: "uppercase", marginBottom: 20, display: "flex", alignItems: "center", gap: 8 }}>
                <span style={{ display: "inline-block", width: 6, height: 6, borderRadius: "50%", background: C.green, animation: "pulse 2s infinite" }} />
                Live Security Platform
              </div>
              <h1 className="fade-up" style={{ fontSize: "clamp(32px, 5vw, 56px)", fontWeight: 900, lineHeight: 1.1, marginBottom: 24, animationDelay: "0.1s" }}>
                The AI Security Platform<br />
                <span style={{ background: `linear-gradient(135deg, ${C.cyan}, #00ff88)`, WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent", backgroundClip: "text" }}>
                  Built for Everyone
                </span>
              </h1>
              <p className="fade-up" style={{ fontSize: 18, color: C.muted, lineHeight: 1.7, marginBottom: 36, animationDelay: "0.2s" }}>
                93+ security modules. Real network scanning. Live CVE intelligence. Automated compliance for NIS2, ISO 27001 & GDPR. Available in 11 languages. <strong style={{ color: C.text }}>From £49/month.</strong>
              </p>

              <div className="fade-up" style={{ display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 48, animationDelay: "0.3s" }}>
                <button className="btn-primary" onClick={goApp}
                  style={{ padding: "14px 28px", borderRadius: 10, background: C.cyan, color: "#000", fontSize: 16, fontWeight: 800, border: "none", cursor: "pointer", transition: "all 0.2s", fontFamily: "'JetBrains Mono', monospace" }}>
                  Start Free Trial →
                </button>
                <button className="btn-outline" onClick={() => document.getElementById("how-it-works")?.scrollIntoView({ behavior: "smooth" })}
                  style={{ padding: "14px 28px", borderRadius: 10, background: "transparent", border: `1px solid ${C.border}`, color: C.text, fontSize: 16, fontWeight: 600, cursor: "pointer", transition: "all 0.2s", display: "flex", alignItems: "center", gap: 8 }}>
                  <span style={{ display: "inline-block", width: 0, height: 0, borderTop: "6px solid transparent", borderBottom: "6px solid transparent", borderLeft: `10px solid ${C.cyan}` }} />
                  Watch Demo
                </button>
              </div>

              {/* Stats row */}
              <div className="fade-up" style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 16, padding: "20px 0", borderTop: `1px solid ${C.border}`, animationDelay: "0.4s" }}>
                <StatsBadge value="93+" label="Modules" />
                <StatsBadge value="11"  label="Languages" />
                <StatsBadge value="6"   label="Frameworks" />
                <StatsBadge value="£49" label="From/mo" />
              </div>
            </div>

            {/* Right — Terminal */}
            <div className="float-el hide-mobile" style={{ animationDelay: "0.5s" }}>
              <TerminalWidget />
            </div>
          </div>
        </div>
      </div>

      {/* ── Problem ── */}
      <Section id="problem" style={{ background: C.dark, borderTop: `1px solid ${C.border}` }}>
        <SectionHeader
          eyebrow="The Problem"
          title="Security shouldn't cost a fortune"
          subtitle="The market has failed small teams, public sector, and growing companies. AIPET X was built to fix that."
        />
        <div className="problem-grid" style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 24 }}>
          {PROBLEMS.map((p, i) => (
            <div key={i} className="card-hover"
              style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 16, padding: 32, transition: "all 0.3s" }}>
              <div style={{ fontSize: 36, marginBottom: 20 }}>{p.icon}</div>
              <h3 style={{ fontSize: 18, fontWeight: 800, color: "#fff", marginBottom: 12 }}>{p.title}</h3>
              <p style={{ color: C.muted, lineHeight: 1.7, fontSize: 15 }}>{p.desc}</p>
            </div>
          ))}
        </div>
      </Section>

      {/* ── Solution ── */}
      <Section id="solution">
        <SectionHeader
          eyebrow="The Solution"
          title="One platform. Every attack surface."
          subtitle="AIPET X unifies IoT, OT, cloud, identity, and compliance in a single AI-powered platform you can run in minutes."
        />
        <div className="solution-grid" style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 28 }}>
          {SOLUTION_CARDS.map((c, i) => (
            <div key={i} className="card-hover"
              style={{ background: `linear-gradient(135deg, ${C.card}, ${C.dark})`, border: `1px solid ${C.border}`, borderRadius: 20, padding: 36, transition: "all 0.3s", position: "relative", overflow: "hidden" }}>
              <div style={{ position: "absolute", top: 0, left: 0, right: 0, height: 2, background: `linear-gradient(90deg, ${c.color}, transparent)` }} />
              <div style={{ width: 52, height: 52, borderRadius: 14, background: `${c.color}15`, border: `1px solid ${c.color}33`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 24, marginBottom: 20 }}>{c.icon}</div>
              <h3 style={{ fontSize: 20, fontWeight: 800, color: "#fff", marginBottom: 12 }}>{c.title}</h3>
              <p style={{ color: C.muted, lineHeight: 1.7, fontSize: 15 }}>{c.desc}</p>
            </div>
          ))}
        </div>
      </Section>

      {/* ── Features Grid ── */}
      <Section id="features" style={{ background: C.dark }}>
        <SectionHeader
          eyebrow="93+ Modules"
          title="Everything you need to secure anything"
          subtitle="From a Raspberry Pi to a Kubernetes cluster — AIPET X covers every asset class, protocol, and threat vector."
        />
        <div className="features-grid" style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 16 }}>
          {FEATURES.map((f, i) => (
            <div key={i} className="feature-card"
              style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 14, padding: "20px 20px", transition: "all 0.25s", cursor: "default" }}>
              <div style={{ fontSize: 28, marginBottom: 12 }}>{f.icon}</div>
              <div style={{ fontSize: 14, fontWeight: 700, color: "#fff", marginBottom: 6 }}>{f.title}</div>
              <div style={{ fontSize: 12, color: C.muted, lineHeight: 1.6 }}>{f.desc}</div>
            </div>
          ))}
        </div>
      </Section>

      {/* ── Compliance ── */}
      <Section id="compliance">
        <SectionHeader
          eyebrow="Compliance Automation"
          title="Every major framework. Automated."
          subtitle="Map your entire security posture to industry frameworks in minutes, not months. Evidence collection included."
        />
        <div className="compliance-grid" style={{ display: "grid", gridTemplateColumns: "repeat(6, 1fr)", gap: 16, marginBottom: 40 }}>
          {COMPLIANCE.map((c, i) => (
            <div key={i} className="compliance-badge"
              style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 16, padding: "24px 16px", textAlign: "center", cursor: "default", transition: "all 0.2s" }}>
              <div style={{ width: 48, height: 48, borderRadius: 12, background: `${c.color}18`, border: `1px solid ${c.color}44`, display: "flex", alignItems: "center", justifyContent: "center", margin: "0 auto 12px", fontSize: 10, fontWeight: 800, color: c.color, fontFamily: "'JetBrains Mono', monospace", letterSpacing: "0.05em" }}>
                {c.label.split(" ")[0]}
              </div>
              <div className="mono" style={{ fontSize: 13, fontWeight: 700, color: "#fff", marginBottom: 4 }}>{c.label}</div>
              <div style={{ fontSize: 11, color: C.muted, lineHeight: 1.4 }}>{c.desc}</div>
            </div>
          ))}
        </div>
        <div style={{ background: `linear-gradient(135deg, #00e5ff0a, #8b5cf610)`, border: `1px solid ${C.border}`, borderRadius: 16, padding: "28px 32px", display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 16 }}>
          <div>
            <div style={{ fontSize: 16, fontWeight: 800, color: "#fff", marginBottom: 4 }}>Need a compliance report for your auditor?</div>
            <div style={{ fontSize: 14, color: C.muted }}>Generate a full gap analysis for any framework in under 60 seconds.</div>
          </div>
          <button className="btn-primary" onClick={goApp}
            style={{ padding: "12px 24px", borderRadius: 8, background: C.cyan, color: "#000", fontSize: 14, fontWeight: 700, border: "none", cursor: "pointer", transition: "all 0.2s", whiteSpace: "nowrap" }}>
            Try Free →
          </button>
        </div>
      </Section>

      {/* ── Global ── */}
      <Section id="global" style={{ background: C.dark }}>
        <SectionHeader
          eyebrow="Global Platform"
          title="Security in 11 languages"
          subtitle="AIPET X is the only security platform with full UI, reports, and AI responses in 11 languages — serving teams across 4 continents."
        />
        <div className="flags-grid" style={{ display: "grid", gridTemplateColumns: "repeat(6, 1fr)", gap: 12 }}>
          {LANGUAGES.map((l, i) => (
            <div key={i} className="lang-flag card-hover"
              style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 14, padding: "18px 12px", textAlign: "center", transition: "all 0.2s", cursor: "default" }}>
              <div style={{ fontSize: 28, marginBottom: 8 }}>{l.flag}</div>
              <div style={{ fontSize: 13, fontWeight: 700, color: "#fff", marginBottom: 2 }}>{l.name}</div>
              <div style={{ fontSize: 11, color: C.muted }}>{l.country}</div>
            </div>
          ))}
          {/* "More coming" card */}
          <div style={{ background: `${C.cyan}0a`, border: `1px dashed ${C.cyan}33`, borderRadius: 14, padding: "18px 12px", textAlign: "center" }}>
            <div style={{ fontSize: 28, marginBottom: 8 }}>🌍</div>
            <div style={{ fontSize: 11, color: C.cyan }}>More coming</div>
          </div>
        </div>
      </Section>

      {/* ── How it works ── */}
      <Section id="how-it-works">
        <SectionHeader
          eyebrow="How it Works"
          title="From zero to secure in 3 steps"
          subtitle="No 6-month deployment. No professional services fee. Start scanning in under 5 minutes."
        />
        <div className="steps-grid" style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 28, position: "relative" }}>
          {/* Connector line */}
          <div className="hide-mobile" style={{ position: "absolute", top: 52, left: "16.6%", right: "16.6%", height: 2, background: `linear-gradient(90deg, ${C.cyan}33, ${C.cyan}, ${C.cyan}33)`, zIndex: 0 }} />

          {STEPS.map((s, i) => (
            <div key={i} className="step-card card-hover"
              style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 20, padding: "36px 28px", transition: "all 0.3s", position: "relative", zIndex: 1, textAlign: "center" }}>
              <div className="mono" style={{ width: 56, height: 56, borderRadius: "50%", background: `${C.cyan}18`, border: `2px solid ${C.cyan}55`, display: "flex", alignItems: "center", justifyContent: "center", margin: "0 auto 24px", fontSize: 18, fontWeight: 800, color: C.cyan }}>{s.num}</div>
              <div style={{ fontSize: 32, marginBottom: 16 }}>{s.icon}</div>
              <h3 style={{ fontSize: 20, fontWeight: 800, color: "#fff", marginBottom: 12 }}>{s.title}</h3>
              <p style={{ color: C.muted, lineHeight: 1.7, fontSize: 15 }}>{s.desc}</p>
            </div>
          ))}
        </div>
      </Section>

      {/* ── Pricing ── */}
      <Section id="pricing" style={{ background: C.dark }}>
        <SectionHeader
          eyebrow="Transparent Pricing"
          title="No hidden fees. No surprises."
          subtitle="Start free. Scale when you're ready. Cancel anytime."
        />
        <div className="pricing-grid" style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 20, alignItems: "stretch" }}>
          {PRICING.map((p, i) => (
            <div key={i} className="price-card"
              style={{
                background: p.popular ? `linear-gradient(135deg, #0a1628, #071328)` : C.card,
                border: `1.5px solid ${p.popular ? C.cyan : C.border}`,
                borderRadius: 20, padding: "32px 24px", transition: "all 0.3s", position: "relative", display: "flex", flexDirection: "column",
                boxShadow: p.popular ? `0 0 40px ${C.cyan}1a` : "none",
              }}>
              {p.popular && (
                <div className="mono" style={{ position: "absolute", top: -13, left: "50%", transform: "translateX(-50%)", background: C.cyan, color: "#000", fontSize: 11, fontWeight: 800, padding: "4px 16px", borderRadius: 20, whiteSpace: "nowrap", letterSpacing: "0.08em" }}>
                  MOST POPULAR
                </div>
              )}
              <div style={{ color: p.color, fontSize: 13, fontWeight: 700, marginBottom: 8, fontFamily: "'JetBrains Mono', monospace", letterSpacing: "0.1em" }}>{p.tier.toUpperCase()}</div>
              <div style={{ display: "flex", alignItems: "baseline", gap: 4, marginBottom: 6 }}>
                <span style={{ fontSize: 36, fontWeight: 900, color: "#fff" }}>{p.price}</span>
                <span style={{ fontSize: 13, color: C.muted }}>{p.period}</span>
              </div>
              <div style={{ borderTop: `1px solid ${C.border}`, margin: "20px 0", flex: "0 0 1px" }} />
              <ul style={{ listStyle: "none", marginBottom: 28, flex: 1 }}>
                {p.features.map((f, j) => (
                  <li key={j} style={{ display: "flex", alignItems: "flex-start", gap: 10, marginBottom: 10, fontSize: 13, color: C.text }}>
                    <span style={{ color: p.popular ? C.cyan : C.green, flex: "0 0 16px", marginTop: 1 }}>✓</span>
                    {f}
                  </li>
                ))}
              </ul>
              <button onClick={goApp} className={p.popular ? "btn-primary" : "btn-outline"}
                style={{
                  width: "100%", padding: "12px", borderRadius: 10, border: p.popular ? "none" : `1px solid ${C.border}`,
                  background: p.popular ? C.cyan : "transparent", color: p.popular ? "#000" : C.text,
                  fontSize: 14, fontWeight: 700, cursor: "pointer", transition: "all 0.2s",
                }}>
                {p.cta}
              </button>
            </div>
          ))}
        </div>
        <p style={{ textAlign: "center", color: C.muted, fontSize: 13, marginTop: 24 }}>
          All plans include a 14-day free trial. No credit card required. &nbsp;·&nbsp; Prices shown in GBP excluding VAT.
        </p>
      </Section>

      {/* ── Academic Credibility ── */}
      <Section id="academic">
        <div style={{ background: `linear-gradient(135deg, ${C.card}, ${C.dark})`, border: `1px solid ${C.border}`, borderRadius: 24, padding: "52px 48px", display: "flex", gap: 48, alignItems: "center", flexWrap: "wrap" }}>
          <div style={{ flex: "0 0 auto" }}>
            <div style={{ width: 80, height: 80, borderRadius: 20, background: `#3b82f618`, border: `1px solid #3b82f633`, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 40 }}>🎓</div>
          </div>
          <div style={{ flex: 1, minWidth: 280 }}>
            <div className="mono" style={{ color: C.cyan, fontSize: 11, fontWeight: 700, letterSpacing: "0.12em", textTransform: "uppercase", marginBottom: 8 }}>Academic Research Origin</div>
            <h3 style={{ fontSize: 26, fontWeight: 900, color: "#fff", marginBottom: 12, lineHeight: 1.2 }}>
              Rooted in MSc Cyber Security Research<br />
              <span style={{ color: C.muted, fontSize: 18, fontWeight: 400 }}>Coventry University, UK</span>
            </h3>
            <p style={{ color: C.muted, lineHeight: 1.7, fontSize: 15, maxWidth: 600 }}>
              AIPET X originated as a master's dissertation in Cyber Security at Coventry University, combining academic rigour in IoT threat modelling, machine learning explainability (SHAP), and regulatory compliance into a production-grade platform. The research underpins every algorithm, scoring model, and risk framework in the system.
            </p>
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 12, flex: "0 0 auto" }}>
            {["Peer-reviewed methodology", "SHAP-based AI explainability", "Published threat taxonomy", "Real-world validated dataset"].map((t, i) => (
              <div key={i} style={{ display: "flex", alignItems: "center", gap: 10, fontSize: 14, color: C.text }}>
                <span style={{ color: C.green, fontSize: 16 }}>✓</span>{t}
              </div>
            ))}
          </div>
        </div>
      </Section>

      {/* ── Final CTA ── */}
      <Section id="cta" style={{ background: C.dark, borderTop: `1px solid ${C.border}` }}>
        <div style={{ textAlign: "center", maxWidth: 680, margin: "0 auto" }}>
          <div className="mono" style={{ color: C.cyan, fontSize: 11, fontWeight: 700, letterSpacing: "0.15em", textTransform: "uppercase", marginBottom: 16 }}>Get Started Today</div>
          <h2 style={{ fontSize: "clamp(30px, 5vw, 48px)", fontWeight: 900, color: "#fff", lineHeight: 1.1, marginBottom: 20 }}>
            Secure your infrastructure<br />
            <span style={{ background: `linear-gradient(135deg, ${C.cyan}, ${C.green})`, WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent", backgroundClip: "text" }}>
              before attackers find it first
            </span>
          </h2>
          <p style={{ fontSize: 17, color: C.muted, marginBottom: 40, lineHeight: 1.7 }}>
            Join teams across healthcare, manufacturing, government, and finance using AIPET X to stay ahead of threats. Free plan available. No credit card required.
          </p>
          <div style={{ display: "flex", gap: 16, justifyContent: "center", flexWrap: "wrap" }}>
            <button className="btn-primary" onClick={goApp}
              style={{ padding: "16px 36px", borderRadius: 12, background: C.cyan, color: "#000", fontSize: 17, fontWeight: 800, border: "none", cursor: "pointer", transition: "all 0.2s", fontFamily: "'JetBrains Mono', monospace" }}>
              Start Free Trial →
            </button>
            <button className="btn-outline" onClick={goLogin}
              style={{ padding: "16px 36px", borderRadius: 12, background: "transparent", border: `1px solid ${C.border}`, color: C.text, fontSize: 17, fontWeight: 600, cursor: "pointer", transition: "all 0.2s" }}>
              Sign In
            </button>
          </div>
          <div style={{ display: "flex", gap: 24, justifyContent: "center", marginTop: 32, flexWrap: "wrap" }}>
            {["No credit card required", "14-day free trial", "Cancel anytime"].map((t, i) => (
              <div key={i} style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 13, color: C.muted }}>
                <span style={{ color: C.green }}>✓</span>{t}
              </div>
            ))}
          </div>
        </div>
      </Section>

      {/* ── Footer ── */}
      <footer style={{ background: "#020609", borderTop: `1px solid ${C.border}`, padding: "60px 0 32px" }}>
        <div style={{ maxWidth: 1200, margin: "0 auto", padding: "0 24px" }}>
          <div className="footer-grid" style={{ display: "grid", gridTemplateColumns: "2fr 1fr 1fr 1fr", gap: 40, marginBottom: 48 }}>
            {/* Brand */}
            <div>
              <div className="mono" style={{ fontSize: 22, fontWeight: 800, color: C.cyan, marginBottom: 12 }}>AIPET <span style={{ color: "#fff" }}>X</span></div>
              <p style={{ color: C.muted, fontSize: 14, lineHeight: 1.7, maxWidth: 300, marginBottom: 20 }}>
                The AI-powered cybersecurity platform built for IoT, OT, Cloud, and Compliance. From MSc research to production security.
              </p>
              <div className="mono" style={{ fontSize: 11, color: "#2a3a4a", letterSpacing: "0.06em" }}>
                © {new Date().getFullYear()} AIPET X. All rights reserved.
              </div>
            </div>

            {/* Platform */}
            <div>
              <div style={{ fontSize: 12, fontWeight: 700, color: "#fff", letterSpacing: "0.1em", textTransform: "uppercase", marginBottom: 16 }}>Platform</div>
              {["Real Scanner", "AI Analysis", "Cloud Security", "OT/ICS Security", "Compliance", "Reports"].map(l => (
                <a key={l} href="#features" className="footer-link" style={{ display: "block", color: C.muted, fontSize: 14, marginBottom: 10, textDecoration: "none", transition: "color 0.2s" }}>{l}</a>
              ))}
            </div>

            {/* Company */}
            <div>
              <div style={{ fontSize: 12, fontWeight: 700, color: "#fff", letterSpacing: "0.1em", textTransform: "uppercase", marginBottom: 16 }}>Company</div>
              {[
                { label: "GitHub", href: "https://github.com/Yallewbinyam/AIPET" },
                { label: "Pricing", href: "#pricing" },
                { label: "How it Works", href: "#how-it-works" },
              ].map(({ label, href }) => (
                <a key={label} href={href} className="footer-link" style={{ display: "block", color: C.muted, fontSize: 14, marginBottom: 10, textDecoration: "none", transition: "color 0.2s" }}>{label}</a>
              ))}
            </div>

            {/* Legal */}
            <div>
              <div style={{ fontSize: 12, fontWeight: 700, color: "#fff", letterSpacing: "0.1em", textTransform: "uppercase", marginBottom: 16 }}>Legal</div>
              {[
                { label: "Privacy Policy", key: "privacy" },
                { label: "Terms of Service", key: "terms" },
                { label: "Security", key: "security" },
              ].map(({ label, key }) => (
                <a key={key} href={`/app`} className="footer-link" style={{ display: "block", color: C.muted, fontSize: 14, marginBottom: 10, textDecoration: "none", transition: "color 0.2s" }}>{label}</a>
              ))}
            </div>
          </div>

          {/* Bottom bar */}
          <div style={{ borderTop: `1px solid ${C.border}`, paddingTop: 24, display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 12 }}>
            <div className="mono" style={{ fontSize: 11, color: "#2a3a4a" }}>
              Built with ♥ at Coventry University · MSc Cyber Security
            </div>
            <div style={{ display: "flex", gap: 16 }}>
              {["Privacy Policy", "Terms", "Security"].map(l => (
                <a key={l} href="/app" className="footer-link" style={{ color: "#2a3a4a", fontSize: 12, textDecoration: "none", transition: "color 0.2s" }}>{l}</a>
              ))}
            </div>
          </div>
        </div>
      </footer>

    </div>
  );
}
