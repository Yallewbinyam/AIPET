# ============================================================
# AIPET X — Runtime Workload Protection
# Process Injection | Fileless Malware | Memory Protection
# ============================================================

import json, uuid, datetime
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.models import db
from sqlalchemy import Column, String, Integer, Text, DateTime, ForeignKey, Float
from sqlalchemy.orm import relationship

runtime_protection_bp = Blueprint("runtime_protection", __name__)

class RuntimeProtectionScan(db.Model):
    __tablename__ = "runtime_protection_scans"
    id             = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id        = Column(Integer, nullable=False)
    workload_type  = Column(String(64), default="container")
    workload_name  = Column(String(256), default="unknown")
    risk_score     = Column(Float, default=0.0)
    severity       = Column(String(16), default="LOW")
    total_findings = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    summary        = Column(Text, nullable=True)
    created_at     = Column(DateTime, default=datetime.datetime.utcnow)
    node_meta      = Column(Text, default="{}")
    findings       = relationship("RuntimeProtectionFinding", backref="scan", lazy=True, cascade="all, delete-orphan")

class RuntimeProtectionFinding(db.Model):
    __tablename__ = "runtime_protection_findings"
    id             = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id        = Column(String(64), ForeignKey("runtime_protection_scans.id"), nullable=False)
    category       = Column(String(64))
    title          = Column(String(256))
    severity       = Column(String(16))
    technique      = Column(String(128), nullable=True)
    description    = Column(Text)
    remediation    = Column(Text)
    confidence     = Column(String(16), default="HIGH")
    node_meta      = Column(Text, default="{}")
    created_at     = Column(DateTime, default=datetime.datetime.utcnow)

RUNTIME_RULES = [
    {"category":"Process Injection","title":"Reflective DLL Injection Detected","keywords":["reflective dll","dll injection","reflective injection","loadlibrary injection","dll hollowing"],"severity":"CRITICAL","technique":"T1055.001 — Reflective DLL Injection","confidence":"HIGH","remediation":"Enable kernel-level protection. Deploy memory integrity checks. Block unsigned DLL loading."},
    {"category":"Process Injection","title":"Process Hollowing Detected","keywords":["process hollowing","process replacement","hollow process","runpe","process doppelganging"],"severity":"CRITICAL","technique":"T1055.012 — Process Hollowing","confidence":"HIGH","remediation":"Enable Endpoint Detection with behavioural memory scanning. Deploy Windows Defender Credential Guard."},
    {"category":"Process Injection","title":"Thread Injection via CreateRemoteThread","keywords":["createremotethread","remote thread","thread injection","writeprocessmemory","virtualalloc remote"],"severity":"CRITICAL","technique":"T1055.003 — Thread Execution Hijacking","confidence":"HIGH","remediation":"Monitor CreateRemoteThread API calls. Restrict cross-process memory access via AppLocker."},
    {"category":"Fileless Malware","title":"PowerShell Download Cradle Detected","keywords":["powershell download","iex download","invoke-expression","downloadstring","webclient download","fileless powershell"],"severity":"CRITICAL","technique":"T1059.001 — PowerShell","confidence":"HIGH","remediation":"Enable PowerShell Constrained Language Mode. Enable Script Block Logging. Block encoded commands."},
    {"category":"Fileless Malware","title":"WMI Persistence for Fileless Execution","keywords":["wmi persistence","wmi subscription","__eventfilter","wmi fileless","wmi execute","permanent subscription"],"severity":"HIGH","technique":"T1546.003 — WMI Event Subscription","confidence":"HIGH","remediation":"Monitor WMI event subscriptions. Disable WMI if not required. Deploy WMI activity monitoring."},
    {"category":"Fileless Malware","title":"Living-off-the-Land Binary Abuse","keywords":["lolbas","certutil","regsvr32","mshta","rundll32 abuse","msiexec abuse","bitsadmin abuse"],"severity":"HIGH","technique":"T1218 — Signed Binary Proxy Execution","confidence":"MEDIUM","remediation":"Allowlist legitimate uses of LOLBins. Monitor execution of certutil, mshta, regsvr32 with unusual parameters."},
    {"category":"Memory Protection","title":"Heap Spray Attack Detected","keywords":["heap spray","heap overflow","heap corruption","memory spray","nop sled","shellcode heap"],"severity":"CRITICAL","technique":"T1203 — Exploitation for Client Execution","confidence":"HIGH","remediation":"Enable Data Execution Prevention (DEP). Deploy ASLR. Use memory-safe programming languages."},
    {"category":"Memory Protection","title":"Return-Oriented Programming (ROP) Chain","keywords":["rop chain","return oriented","rop gadget","stack pivot","control flow hijack","rop attack"],"severity":"CRITICAL","technique":"T1203","confidence":"HIGH","remediation":"Enable Control Flow Integrity (CFI). Deploy hardware-enforced stack protection (Intel CET)."},
    {"category":"Memory Protection","title":"Kernel Exploit Attempt","keywords":["kernel exploit","privilege escalation kernel","ring0","kernel vulnerability","driver exploit","sysret exploit"],"severity":"CRITICAL","technique":"T1068 — Exploitation for Privilege Escalation","confidence":"HIGH","remediation":"Keep kernel patched. Enable Secure Boot. Deploy kernel integrity monitoring. Restrict driver loading."},
    {"category":"Container Escape","title":"Container Escape via Kernel Exploit","keywords":["container escape","docker escape","namespace escape","cgroup escape","kernel escape container","privileged escape"],"severity":"CRITICAL","technique":"T1611 — Escape to Host","confidence":"HIGH","remediation":"Run containers as non-root. Disable privileged mode. Apply seccomp and AppArmor profiles. Keep kernel patched."},
    {"category":"Container Escape","title":"Docker Socket Mount Exploitation","keywords":["docker socket","docker.sock","socket mount","docker escape socket","/var/run/docker"],"severity":"CRITICAL","technique":"T1611","confidence":"HIGH","remediation":"Never mount Docker socket into containers. Use rootless Docker. Implement container runtime security."},
    {"category":"Supply Chain","title":"Malicious Package Execution at Runtime","keywords":["malicious package","supply chain runtime","backdoor package","npm malicious","pypi malicious","package backdoor"],"severity":"CRITICAL","technique":"T1195.002 — Compromise Software Supply Chain","confidence":"MEDIUM","remediation":"Implement runtime application self-protection (RASP). Scan packages at build time. Use private registries."},
    {"category":"Supply Chain","title":"Typosquatting Package Detected","keywords":["typosquatting","typo package","similar package name","confusable package","npm typo","pip typo"],"severity":"HIGH","technique":"T1195","confidence":"MEDIUM","remediation":"Audit all package names carefully. Use dependency pinning. Enable package integrity verification."},
    {"category":"Cryptomining","title":"Cryptomining Process Detected","keywords":["cryptominer","xmrig","monero mining","cpu spike","cryptojacking","mining pool","stratum protocol"],"severity":"HIGH","technique":"T1496 — Resource Hijacking","confidence":"HIGH","remediation":"Monitor CPU usage anomalies. Block mining pool domains at DNS. Deploy process allowlisting."},
    {"category":"Cryptomining","title":"GPU Cryptomining Detected","keywords":["gpu mining","gpu cryptominer","cuda mining","opencl mining","gpu spike","graphics mining"],"severity":"HIGH","technique":"T1496","confidence":"MEDIUM","remediation":"Monitor GPU utilisation. Block cryptocurrency mining domains. Enable cloud spend anomaly detection."},
]

SEV_W = {"CRITICAL":15,"HIGH":8,"MEDIUM":4,"LOW":1}

def run_runtime_protection(description, workload_type):
    desc_lower = description.lower()
    findings = []
    for rule in RUNTIME_RULES:
        if any(kw.lower() in desc_lower for kw in rule["keywords"]):
            findings.append({
                "category":    rule["category"],
                "title":       rule["title"],
                "severity":    rule["severity"],
                "technique":   rule["technique"],
                "description": f"Runtime workload threat detected in {workload_type}: {rule['title']}.",
                "remediation": rule["remediation"],
                "confidence":  rule["confidence"],
            })
    return findings

def calc_risk(findings):
    if not findings: return 0.0
    return round(min(sum(SEV_W.get(f["severity"],0) for f in findings)*1.5, 100.0), 1)

def overall_sev(score):
    if score >= 70: return "CRITICAL"
    if score >= 45: return "HIGH"
    if score >= 20: return "MEDIUM"
    return "LOW"

@runtime_protection_bp.route("/api/runtime-protection/scan", methods=["POST"])
@jwt_required()
def scan():
    data          = request.get_json(silent=True) or {}
    workload_type = data.get("workload_type", "container")
    workload_name = data.get("workload_name", "unknown")
    desc          = data.get("description", "")
    if not desc.strip(): return jsonify({"error":"No description provided"}), 400
    findings  = run_runtime_protection(desc, workload_type)
    score     = calc_risk(findings)
    sev       = overall_sev(score)
    critical  = sum(1 for f in findings if f["severity"]=="CRITICAL")
    cats      = len(set(f["category"] for f in findings))
    summary   = f"Runtime Protection scan complete for {workload_name} ({workload_type}). Risk: {score}/100. {len(findings)} threat(s) — {critical} critical across {cats} categories."
    s = RuntimeProtectionScan(user_id=get_jwt_identity(), workload_type=workload_type, workload_name=workload_name, risk_score=score, severity=sev, total_findings=len(findings), critical_count=critical, summary=summary, node_meta="{}")
    db.session.add(s); db.session.flush()
    for f in findings:
        db.session.add(RuntimeProtectionFinding(scan_id=s.id, category=f["category"], title=f["title"], severity=f["severity"], technique=f["technique"], description=f["description"], remediation=f["remediation"], confidence=f["confidence"], node_meta="{}"))
    db.session.commit()
    return jsonify({"scan_id":s.id,"workload_name":workload_name,"workload_type":workload_type,"risk_score":score,"severity":sev,"total_findings":len(findings),"critical_count":critical,"summary":summary}), 200

@runtime_protection_bp.route("/api/runtime-protection/scans/<scan_id>", methods=["GET"])
@jwt_required()
def get_scan(scan_id):
    s = RuntimeProtectionScan.query.filter_by(id=scan_id, user_id=get_jwt_identity()).first()
    if not s: return jsonify({"error":"Not found"}), 404
    findings = RuntimeProtectionFinding.query.filter_by(scan_id=scan_id).all()
    cats = list(dict.fromkeys(f.category for f in findings))
    return jsonify({"scan_id":s.id,"workload_type":s.workload_type,"workload_name":s.workload_name,"risk_score":s.risk_score,"severity":s.severity,"total_findings":s.total_findings,"critical_count":s.critical_count,"summary":s.summary,"created_at":s.created_at.isoformat(),"categories":cats,"findings":[{"category":f.category,"title":f.title,"severity":f.severity,"technique":f.technique,"description":f.description,"remediation":f.remediation,"confidence":f.confidence} for f in findings]}), 200

@runtime_protection_bp.route("/api/runtime-protection/history", methods=["GET"])
@jwt_required()
def history():
    scans = RuntimeProtectionScan.query.filter_by(user_id=get_jwt_identity()).order_by(RuntimeProtectionScan.created_at.desc()).limit(50).all()
    return jsonify({"scans":[{"scan_id":s.id,"workload_type":s.workload_type,"workload_name":s.workload_name,"risk_score":s.risk_score,"severity":s.severity,"total_findings":s.total_findings,"critical_count":s.critical_count,"created_at":s.created_at.isoformat()} for s in scans]}), 200

@runtime_protection_bp.route("/api/runtime-protection/health", methods=["GET"])
def health():
    return jsonify({"module":"Runtime Workload Protection","version":"1.0.0","rules":len(RUNTIME_RULES),"status":"operational"}), 200
