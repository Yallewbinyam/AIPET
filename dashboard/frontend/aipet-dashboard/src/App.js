
import { useState, useEffect } from "react";
import axios from "axios";
import {
  PieChart, Pie, Cell,
  Tooltip, ResponsiveContainer
} from "recharts";
import {
  Shield, Server, AlertTriangle,
  CheckCircle, Activity, Download, Play,
  RefreshCw, ChevronRight, Cpu
} from "lucide-react";

const API = "http://localhost:5000/api";

const SEVERITY_COLORS = {
  CRITICAL: "#ef4444",
  HIGH:     "#f97316",
  MEDIUM:   "#eab308",
  LOW:      "#22c55e",
  INFO:     "#6b7280"
};

const SEVERITY_BG = {
  CRITICAL: "bg-red-100 text-red-800 border-red-200",
  HIGH:     "bg-orange-100 text-orange-800 border-orange-200",
  MEDIUM:   "bg-yellow-100 text-yellow-800 border-yellow-200",
  LOW:      "bg-green-100 text-green-800 border-green-200",
  INFO:     "bg-gray-100 text-gray-800 border-gray-200"
};

function SeverityBadge({ severity }) {
  return (
    <span className={`px-2 py-1 rounded-full text-xs font-bold border ${SEVERITY_BG[severity] || SEVERITY_BG.INFO}`}>
      {severity}
    </span>
  );
}

function StatCard({ title, value, icon: Icon, color }) {
  return (
    <div className="bg-white rounded-2xl p-6 shadow-sm border border-gray-100">
      <div className="flex items-center justify-between mb-4">
        <div className="p-3 rounded-xl" style={{ backgroundColor: color + "20" }}>
          <Icon size={24} style={{ color }} />
        </div>
      </div>
      <div className="text-3xl font-bold text-gray-900 mb-1">{value}</div>
      <div className="text-sm font-medium text-gray-500">{title}</div>
    </div>
  );
}

function RiskGauge({ risk, color }) {
  const scores = { CRITICAL: 95, HIGH: 75, MEDIUM: 45, LOW: 15 };
  const score  = scores[risk] || 0;
  return (
    <div className="bg-white rounded-2xl p-6 shadow-sm border border-gray-100 flex flex-col items-center">
      <div className="relative w-40 h-40 mb-4">
        <svg viewBox="0 0 120 120" className="w-full h-full">
          <circle cx="60" cy="60" r="50" fill="none" stroke="#f3f4f6" strokeWidth="12"/>
          <circle cx="60" cy="60" r="50" fill="none" stroke={color} strokeWidth="12"
            strokeDasharray={`${score * 3.14} 314`} strokeLinecap="round"
            transform="rotate(-90 60 60)" />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-2xl font-bold" style={{ color }}>{score}</span>
          <span className="text-xs text-gray-400">Risk Score</span>
        </div>
      </div>
      <div className="text-xl font-bold" style={{ color }}>{risk}</div>
      <div className="text-sm text-gray-500">Overall Risk Level</div>
    </div>
  );
}

function FindingCard({ finding }) {
  const [expanded, setExpanded] = useState(false);
  return (
    <div className="bg-white rounded-xl border border-gray-100 shadow-sm overflow-hidden">
      <div className="flex items-center justify-between p-4 cursor-pointer hover:bg-gray-50"
        onClick={() => setExpanded(!expanded)}>
        <div className="flex items-center gap-3">
          <SeverityBadge severity={finding.severity} />
          <div>
            <div className="font-semibold text-gray-900 text-sm">{finding.attack}</div>
            <div className="text-xs text-gray-500">{finding.module} — {finding.target}</div>
          </div>
        </div>
        <ChevronRight size={16} className={`text-gray-400 transition-transform ${expanded ? "rotate-90" : ""}`} />
      </div>
      {expanded && (
        <div className="px-4 pb-4 border-t border-gray-50 pt-3">
          <p className="text-sm text-gray-700">{finding.finding}</p>
        </div>
      )}
    </div>
  );
}

function ScanModal({ onClose, onScan }) {
  const [target, setTarget] = useState("");
  const [mode, setMode]     = useState("demo");
  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-2xl p-6 w-96 shadow-2xl">
        <h3 className="text-lg font-bold text-gray-900 mb-4">Start New Scan</h3>
        <div className="mb-4">
          <label className="block text-sm font-medium text-gray-700 mb-2">Scan Mode</label>
          <div className="flex gap-2">
            <button onClick={() => setMode("demo")}
              className={`flex-1 py-2 rounded-xl text-sm font-medium transition-colors ${mode === "demo" ? "bg-blue-600 text-white" : "bg-gray-100 text-gray-700"}`}>
              Demo Mode
            </button>
            <button onClick={() => setMode("live")}
              className={`flex-1 py-2 rounded-xl text-sm font-medium transition-colors ${mode === "live" ? "bg-blue-600 text-white" : "bg-gray-100 text-gray-700"}`}>
              Live Scan
            </button>
          </div>
        </div>
        {mode === "live" && (
          <div className="mb-4">
            <label className="block text-sm font-medium text-gray-700 mb-2">Target IP / Range</label>
            <input type="text" value={target} onChange={e => setTarget(e.target.value)}
              placeholder="e.g. 192.168.1.0/24"
              className="w-full px-3 py-2 border border-gray-200 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-blue-500" />
          </div>
        )}
        <div className="flex gap-2 mt-6">
          <button onClick={onClose} className="flex-1 py-2 rounded-xl bg-gray-100 text-gray-700 text-sm font-medium">Cancel</button>
          <button onClick={() => { onScan(mode, target); onClose(); }}
            className="flex-1 py-2 rounded-xl bg-blue-600 text-white text-sm font-medium">
            Start Scan
          </button>
        </div>
      </div>
    </div>
  );
}

export default function App() {
  const [summary,    setSummary]    = useState(null);
  const [devices,    setDevices]    = useState([]);
  const [findings,   setFindings]   = useState([]);
  const [aiResults,  setAiResults]  = useState([]);
  const [reports,    setReports]    = useState([]);
  const [scanStatus, setScanStatus] = useState(null);
  const [activeTab,  setActiveTab]  = useState("dashboard");
  const [showScan,   setShowScan]   = useState(false);
  const [loading,    setLoading]    = useState(true);

  const fetchAll = async () => {
    try {
      const [s, d, f, a, r, sc] = await Promise.all([
        axios.get(`${API}/summary`),
        axios.get(`${API}/devices`),
        axios.get(`${API}/findings`),
        axios.get(`${API}/ai`),
        axios.get(`${API}/reports`),
        axios.get(`${API}/scan/status`),
      ]);
      setSummary(s.data);
      setDevices(d.data);
      setFindings(f.data);
      setAiResults(a.data);
      setReports(r.data);
      setScanStatus(sc.data);
    } catch (e) {
      console.error("API error:", e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAll();
    const interval = setInterval(fetchAll, 5000);
    return () => clearInterval(interval);
  }, []);

  const startScan = async (mode, target) => {
    await axios.post(`${API}/scan/start`, { mode, target });
    setTimeout(fetchAll, 2000);
  };

  const pieData = summary ? [
    { name: "Critical", value: summary.findings.critical, color: "#ef4444" },
    { name: "High",     value: summary.findings.high,     color: "#f97316" },
    { name: "Medium",   value: summary.findings.medium,   color: "#eab308" },
    { name: "Low",      value: summary.findings.low,      color: "#22c55e" },
  ].filter(d => d.value > 0) : [];

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <Shield size={48} className="text-blue-600 mx-auto mb-4 animate-pulse" />
          <p className="text-gray-600 font-medium">Loading AIPET Dashboard...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 flex">
      <div className="w-64 bg-gray-900 text-white flex flex-col">
        <div className="p-6 border-b border-gray-800">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-blue-600 rounded-xl flex items-center justify-center">
              <Shield size={20} className="text-white" />
            </div>
            <div>
              <div className="font-bold text-white">AIPET</div>
              <div className="text-xs text-gray-400">v1.0.0</div>
            </div>
          </div>
        </div>

        <nav className="flex-1 p-4 space-y-1">
          {[
            { id: "dashboard", label: "Dashboard",   icon: Activity      },
            { id: "devices",   label: "Devices",     icon: Cpu           },
            { id: "findings",  label: "Findings",    icon: AlertTriangle },
            { id: "ai",        label: "AI Analysis", icon: Shield        },
            { id: "reports",   label: "Reports",     icon: Download      },
          ].map(({ id, label, icon: Icon }) => (
            <button key={id} onClick={() => setActiveTab(id)}
              className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl text-sm font-medium transition-colors ${activeTab === id ? "bg-blue-600 text-white" : "text-gray-400 hover:bg-gray-800 hover:text-white"}`}>
              <Icon size={18} />
              {label}
            </button>
          ))}
        </nav>

        <div className="px-4 pb-2">
          <a href="https://github.com/YOUR_USERNAME/AIPET/blob/main/USER_MANUAL.md"
            target="_blank" rel="noreferrer"
            className="w-full flex items-center gap-3 px-4 py-3 rounded-xl text-sm font-medium text-gray-400 hover:bg-gray-800 hover:text-white transition-colors">
            <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><path d="M12 17h.01"/></svg>
            User Manual
          </a>
        </div>
        <div className="p-4 border-t border-gray-800">
          <button onClick={() => setShowScan(true)} disabled={scanStatus?.running}
            className="w-full flex items-center justify-center gap-2 py-3 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-700 text-white rounded-xl text-sm font-medium transition-colors">
            {scanStatus?.running
              ? <><RefreshCw size={16} className="animate-spin" /> Scanning...</>
              : <><Play size={16} /> New Scan</>}
          </button>
        </div>
      </div>

      <div className="flex-1 overflow-auto">
        <div className="bg-white border-b border-gray-100 px-8 py-4 flex items-center justify-between">
          <div>
            <h1 className="text-xl font-bold text-gray-900 capitalize">{activeTab}</h1>
            <p className="text-sm text-gray-500">
              {summary?.last_scan ? `Last scan: ${summary.last_scan}` : "No scans yet"}
            </p>
          </div>
          <button onClick={fetchAll}
            className="flex items-center gap-2 px-4 py-2 bg-gray-100 hover:bg-gray-200 text-gray-700 rounded-xl text-sm font-medium transition-colors">
            <RefreshCw size={14} /> Refresh
          </button>
        </div>

        <div className="p-8">

          {activeTab === "dashboard" && summary && (
            <div className="space-y-6">
              <div className="grid grid-cols-4 gap-4">
                <RiskGauge risk={summary.overall_risk} color={summary.risk_color} />
                <StatCard title="Devices Found"     value={summary.devices}           icon={Cpu}           color="#6366f1" />
                <StatCard title="Critical Findings" value={summary.findings.critical} icon={AlertTriangle} color="#ef4444" />
                <StatCard title="Total Findings"    value={summary.findings.total}    icon={Shield}        color="#f97316" />
              </div>

              <div className="grid grid-cols-2 gap-6">
                <div className="bg-white rounded-2xl p-6 shadow-sm border border-gray-100">
                  <h3 className="font-bold text-gray-900 mb-4">Findings by Severity</h3>
                  {pieData.length > 0 ? (
                    <ResponsiveContainer width="100%" height={200}>
                      <PieChart>
                        <Pie data={pieData} cx="50%" cy="50%" outerRadius={80} dataKey="value"
                          label={({ name, value }) => `${name}: ${value}`}>
                          {pieData.map((entry, i) => <Cell key={i} fill={entry.color} />)}
                        </Pie>
                        <Tooltip />
                      </PieChart>
                    </ResponsiveContainer>
                  ) : (
                    <div className="flex items-center justify-center h-48 text-gray-400">No findings yet</div>
                  )}
                </div>

                <div className="bg-white rounded-2xl p-6 shadow-sm border border-gray-100">
                  <h3 className="font-bold text-gray-900 mb-4">Modules Executed</h3>
                  <div className="space-y-2">
                    {summary.modules_run.map((m, i) => (
                      <div key={i} className="flex items-center gap-3">
                        <CheckCircle size={16} className="text-green-500 flex-shrink-0" />
                        <span className="text-sm text-gray-700">{m}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === "devices" && (
            <div className="space-y-4">
              {devices.length === 0 ? (
                <div className="bg-white rounded-2xl p-12 text-center border border-gray-100">
                  <Cpu size={48} className="text-gray-300 mx-auto mb-4" />
                  <p className="text-gray-500">No devices found. Run a scan first.</p>
                </div>
              ) : devices.map((device, i) => (
                <div key={i} className="bg-white rounded-2xl p-6 shadow-sm border border-gray-100">
                  <div className="flex items-start justify-between mb-4">
                    <div className="flex items-center gap-4">
                      <div className="w-12 h-12 bg-blue-100 rounded-xl flex items-center justify-center">
                        <Server size={24} className="text-blue-600" />
                      </div>
                      <div>
                        <div className="font-bold text-gray-900 text-lg">{device.ip}</div>
                        <div className="text-sm text-gray-500">{device.device_type}</div>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      {device.ai_severity && <SeverityBadge severity={device.ai_severity} />}
                      <span className="text-sm text-gray-500">Risk: {device.risk_score}/100</span>
                    </div>
                  </div>
                  <div className="grid grid-cols-3 gap-4 mb-4">
                    <div className="bg-gray-50 rounded-xl p-3">
                      <div className="text-xs text-gray-500 mb-1">Open Ports</div>
                      <div className="font-semibold text-gray-900 text-sm">{device.ports?.join(", ") || "None"}</div>
                    </div>
                    <div className="bg-gray-50 rounded-xl p-3">
                      <div className="text-xs text-gray-500 mb-1">Risk Label</div>
                      <div className="font-semibold text-gray-900">{device.risk_label}</div>
                    </div>
                    <div className="bg-gray-50 rounded-xl p-3">
                      <div className="text-xs text-gray-500 mb-1">AI Confidence</div>
                      <div className="font-semibold text-gray-900">
                        {device.ai_confidence ? `${(device.ai_confidence * 100).toFixed(1)}%` : "N/A"}
                      </div>
                    </div>
                  </div>
                  {device.ai_explanation && (
                    <div className="bg-blue-50 rounded-xl p-4">
                      <div className="text-xs font-bold text-blue-800 mb-2">AI Explanation</div>
                      <pre className="text-xs text-blue-700 whitespace-pre-wrap font-mono">{device.ai_explanation}</pre>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}

          {activeTab === "findings" && (
            <div className="space-y-3">
              <div className="flex gap-4 mb-4">
                {["CRITICAL","HIGH","MEDIUM","LOW"].map(sev => (
                  <span key={sev} className="flex items-center gap-1 text-xs">
                    <span className="w-2 h-2 rounded-full" style={{ backgroundColor: SEVERITY_COLORS[sev] }}></span>
                    {sev}: {findings.filter(f => f.severity === sev).length}
                  </span>
                ))}
              </div>
              {findings.length === 0 ? (
                <div className="bg-white rounded-2xl p-12 text-center border border-gray-100">
                  <CheckCircle size={48} className="text-gray-300 mx-auto mb-4" />
                  <p className="text-gray-500">No findings yet. Run a scan first.</p>
                </div>
              ) : findings.map((f, i) => <FindingCard key={i} finding={f} />)}
            </div>
          )}

          {activeTab === "ai" && (
            <div className="space-y-4">
              {aiResults.length === 0 ? (
                <div className="bg-white rounded-2xl p-12 text-center border border-gray-100">
                  <Shield size={48} className="text-gray-300 mx-auto mb-4" />
                  <p className="text-gray-500">No AI results yet. Run a scan first.</p>
                </div>
              ) : aiResults.map((result, i) => {
                const pred     = result.prediction || {};
                const contribs = pred.shap_contributions || {};
                const top5     = Object.entries(contribs)
                  .sort((a, b) => Math.abs(b[1]) - Math.abs(a[1]))
                  .slice(0, 5);
                return (
                  <div key={i} className="bg-white rounded-2xl p-6 shadow-sm border border-gray-100">
                    <div className="flex items-center justify-between mb-6">
                      <div>
                        <div className="font-bold text-gray-900 text-lg">{result.ip}</div>
                        <div className="text-sm text-gray-500">{result.device_type}</div>
                      </div>
                      <div className="text-right">
                        <SeverityBadge severity={pred.predicted_severity} />
                        <div className="text-sm text-gray-500 mt-1">
                          {((pred.confidence || 0) * 100).toFixed(1)}% confidence
                        </div>
                      </div>
                    </div>
                    {top5.length > 0 && (
                      <div>
                        <div className="text-sm font-bold text-gray-700 mb-3">Key Factors (SHAP Values)</div>
                        <div className="space-y-2">
                          {top5.map(([feature, value], j) => (
                            <div key={j} className="flex items-center gap-3">
                              <div className="w-48 text-xs text-gray-600 truncate">{feature.replace(/_/g, " ")}</div>
                              <div className="flex-1 bg-gray-100 rounded-full h-2">
                                <div className="h-2 rounded-full" style={{
                                  width: `${Math.min(Math.abs(value) * 200, 100)}%`,
                                  backgroundColor: value > 0 ? "#ef4444" : "#22c55e"
                                }} />
                              </div>
                              <div className="text-xs text-gray-500 w-16 text-right">
                                {value > 0 ? "+" : ""}{(value * 100).toFixed(1)}%
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                    <div className="mt-4 grid grid-cols-4 gap-2">
                      {Object.entries(pred.probabilities || {}).map(([sev, prob]) => (
                        <div key={sev} className="bg-gray-50 rounded-xl p-3 text-center">
                          <div className="text-xs text-gray-500 mb-1">{sev}</div>
                          <div className="font-bold text-sm" style={{ color: SEVERITY_COLORS[sev] || "#6b7280" }}>
                            {(prob * 100).toFixed(1)}%
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                );
              })}
            </div>
          )}

          {activeTab === "reports" && (
            <div className="space-y-3">
              {reports.length === 0 ? (
                <div className="bg-white rounded-2xl p-12 text-center border border-gray-100">
                  <Download size={48} className="text-gray-300 mx-auto mb-4" />
                  <p className="text-gray-500">No reports yet. Run a scan first.</p>
                </div>
              ) : reports.map((report, i) => (
                <div key={i} className="bg-white rounded-xl p-4 shadow-sm border border-gray-100 flex items-center justify-between">
                  <div>
                    <div className="font-medium text-gray-900 text-sm">{report.filename}</div>
                    <div className="text-xs text-gray-500">{report.created} · {(report.size / 1024).toFixed(1)} KB</div>
                  </div>
                  <a href={`${API}/reports/${report.filename}`} download
                    className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-xl text-sm font-medium hover:bg-blue-700 transition-colors">
                    <Download size={14} /> Download
                  </a>
                </div>
              ))}
            </div>
          )}

        </div>
      </div>

      {showScan && <ScanModal onClose={() => setShowScan(false)} onScan={startScan} />}
    </div>
  );
}
