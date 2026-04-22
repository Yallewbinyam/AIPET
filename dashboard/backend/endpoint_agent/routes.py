# ============================================================
# AIPET X — Endpoint Agent (CrowdStrike Gap — Phase 2)
# Device Health | EDR Simulation | Behavioural Analysis
# ============================================================

import json, uuid, datetime
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.models import db
from sqlalchemy import Column, String, Integer, Text, DateTime, ForeignKey, Float
from sqlalchemy.orm import relationship

endpoint_agent_bp = Blueprint("endpoint_agent", __name__)

class EndpointScan(db.Model):
    __tablename__ = "endpoint_scans"
    id              = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id         = Column(Integer, nullable=False)
    hostname        = Column(String(256), default="unknown-host")
    os_type         = Column(String(64), default="unknown")
    os_version      = Column(String(64), default="unknown")
    risk_score      = Column(Float, default=0.0)
    severity        = Column(String(16), default="LOW")
    total_findings  = Column(Integer, default=0)
    critical_count  = Column(Integer, default=0)
    health_score    = Column(Float, default=100.0)
    summary         = Column(Text, nullable=True)
    created_at      = Column(DateTime, default=datetime.datetime.utcnow)
    node_meta       = Column(Text, default="{}")
    findings        = relationship("EndpointFinding", backref="scan", lazy=True, cascade="all, delete-orphan")

class EndpointFinding(db.Model):
    __tablename__ = "endpoint_findings"
    id              = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id         = Column(String(64), ForeignKey("endpoint_scans.id"), nullable=False)
    category        = Column(String(64))
    title           = Column(String(256))
    severity        = Column(String(16))
    tactic          = Column(String(128), nullable=True)
    technique       = Column(String(128), nullable=True)
    description     = Column(Text)
    remediation     = Column(Text)
    ioc             = Column(String(256), nullable=True)
    node_meta       = Column(Text, default="{}")
    created_at      = Column(DateTime, default=datetime.datetime.utcnow)

ENDPOINT_RULES = [
    # Patch & Vulnerability
    {"id":"EP-PATCH-001","category":"Patch Management","title":"Critical OS Patches Missing","keywords":["unpatched","missing patch","patch not applied","os update pending","critical update missing","outdated os"],"severity":"CRITICAL","tactic":"Initial Access","technique":"T1190 — Exploit Public-Facing Application","ioc":"OS patch gap > 30 days","remediation":"Apply all critical OS patches immediately. Enable automatic security updates. Patch within 48 hours of release."},
    {"id":"EP-PATCH-002","category":"Patch Management","title":"End-of-Life OS Detected","keywords":["end of life","eol os","windows 7","windows xp","ubuntu 18","eol operating system","unsupported os"],"severity":"CRITICAL","tactic":"Initial Access","technique":"T1190","ioc":"EOL OS version detected","remediation":"Upgrade to supported OS immediately. EOL systems receive no security patches and are trivially exploitable."},
    {"id":"EP-PATCH-003","category":"Patch Management","title":"Third-Party Software Unpatched","keywords":["unpatched software","adobe unpatched","java unpatched","browser unpatched","office unpatched","third party patch"],"severity":"HIGH","tactic":"Initial Access","technique":"T1203 — Exploitation for Client Execution","ioc":"Third-party software CVEs detected","remediation":"Implement automated third-party patch management. Prioritise browser, Office, and PDF reader updates."},
    # Malware & Threats
    {"id":"EP-MAL-001","category":"Malware Detection","title":"Suspicious Process Execution","keywords":["suspicious process","unknown process","malicious process","powershell encoded","cmd encoded","wscript","cscript suspicious"],"severity":"CRITICAL","tactic":"Execution","technique":"T1059 — Command and Scripting Interpreter","ioc":"Suspicious process hash detected","remediation":"Terminate process immediately. Isolate endpoint. Perform full forensic investigation. Check for persistence."},
    {"id":"EP-MAL-002","category":"Malware Detection","title":"Ransomware Behaviour Detected","keywords":["ransomware","file encryption","ransom note","vssadmin delete","shadow copy delete","mass file rename","encrypt files"],"severity":"CRITICAL","tactic":"Impact","technique":"T1486 — Data Encrypted for Impact","ioc":"Mass file encryption activity","remediation":"Isolate endpoint from network immediately. Do not restart. Preserve memory for forensics. Restore from backup."},
    {"id":"EP-MAL-003","category":"Malware Detection","title":"Fileless Malware Indicators","keywords":["fileless","in memory","powershell download","reflective dll","process hollowing","living off the land","lolbas"],"severity":"CRITICAL","tactic":"Defense Evasion","technique":"T1055 — Process Injection","ioc":"In-memory execution detected","remediation":"Enable PowerShell Constrained Language Mode. Deploy memory protection. Enable script block logging."},
    {"id":"EP-MAL-004","category":"Malware Detection","title":"Rootkit Activity Detected","keywords":["rootkit","kernel modification","boot sector","mbr modification","hypervisor attack","uefi rootkit","bootkit"],"severity":"CRITICAL","tactic":"Persistence","technique":"T1542 — Pre-OS Boot","ioc":"Kernel-level modification detected","remediation":"Boot from trusted media. Reimage endpoint from clean baseline. Enable Secure Boot and UEFI protection."},
    # Persistence
    {"id":"EP-PERS-001","category":"Persistence","title":"Suspicious Registry Autorun","keywords":["registry autorun","run key","runonce","registry startup","autostart registry","hkcu run","hklm run"],"severity":"HIGH","tactic":"Persistence","technique":"T1547.001 — Registry Run Keys","ioc":"Unexpected registry autorun entry","remediation":"Remove malicious registry entries. Audit all Run/RunOnce keys. Enable registry monitoring."},
    {"id":"EP-PERS-002","category":"Persistence","title":"Scheduled Task Created by Malware","keywords":["scheduled task","schtasks","cron malware","task scheduler","malicious task","persistence task","crontab modified"],"severity":"HIGH","tactic":"Persistence","technique":"T1053 — Scheduled Task/Job","ioc":"Unexpected scheduled task detected","remediation":"Remove malicious scheduled tasks. Audit all scheduled tasks. Restrict schtasks creation to admins."},
    {"id":"EP-PERS-003","category":"Persistence","title":"New Admin Account Created","keywords":["new admin","admin account created","backdoor account","net user add","useradd admin","rogue account","ghost account"],"severity":"CRITICAL","tactic":"Persistence","technique":"T1136 — Create Account","ioc":"Unexpected admin account creation","remediation":"Disable and investigate the account immediately. Audit all account creation events. Enable alerting on privileged account creation."},
    # Credential Theft
    {"id":"EP-CRED-001","category":"Credential Theft","title":"LSASS Memory Access Detected","keywords":["lsass","credential dump","mimikatz","sekurlsa","wce","lsass dump","process dump lsass"],"severity":"CRITICAL","tactic":"Credential Access","technique":"T1003.001 — LSASS Memory","ioc":"LSASS process access detected","remediation":"Enable Credential Guard. Deploy EDR with LSASS protection. Enable Protected Users security group."},
    {"id":"EP-CRED-002","category":"Credential Theft","title":"Keylogger Activity Detected","keywords":["keylogger","keystroke","input capture","hook keyboard","setwindowshook","keyboard monitor"],"severity":"CRITICAL","tactic":"Credential Access","technique":"T1056.001 — Keylogging","ioc":"Keyboard hook API calls detected","remediation":"Terminate process. Rotate all credentials entered on affected system. Deploy behavioural EDR."},
    # Lateral Movement
    {"id":"EP-LAT-001","category":"Lateral Movement","title":"Pass-the-Hash Attempt","keywords":["pass the hash","pth","lateral movement hash","ntlm hash","pass hash","credential relay"],"severity":"CRITICAL","tactic":"Lateral Movement","technique":"T1550.002 — Pass the Hash","ioc":"NTLM hash used for lateral movement","remediation":"Enable Protected Users group. Disable NTLM where possible. Deploy PAM and privileged access workstations."},
    {"id":"EP-LAT-002","category":"Lateral Movement","title":"Remote Service Exploitation","keywords":["psexec","wmiexec","lateral wmi","remote execution","smb lateral","remote service exploit","winrm lateral"],"severity":"HIGH","tactic":"Lateral Movement","technique":"T1021 — Remote Services","ioc":"Remote admin tool execution detected","remediation":"Block lateral movement tools at network layer. Enforce application allowlisting. Monitor SMB and WMI usage."},
    # Defence Evasion
    {"id":"EP-DEF-001","category":"Defence Evasion","title":"Antivirus Disabled or Tampered","keywords":["av disabled","antivirus disabled","defender disabled","tamper protection","security disabled","edr disabled","av tamper"],"severity":"CRITICAL","tactic":"Defense Evasion","technique":"T1562.001 — Disable or Modify Tools","ioc":"Security tool termination detected","remediation":"Re-enable security tools immediately. Isolate endpoint. Investigate how AV was disabled — likely active compromise."},
    {"id":"EP-DEF-002","category":"Defence Evasion","title":"Log Tampering Detected","keywords":["log cleared","event log cleared","wevtutil","audit log deleted","log tamper","clear log","log deletion"],"severity":"HIGH","tactic":"Defense Evasion","technique":"T1070.001 — Clear Windows Event Logs","ioc":"Windows event log cleared","remediation":"Forward logs to SIEM in real time. Isolate endpoint. Treat log clearing as active incident indicator."},
    # Security Posture
    {"id":"EP-SEC-001","category":"Security Posture","title":"No EDR Agent Installed","keywords":["no edr","edr missing","no endpoint protection","no crowdstrike","no sentinelone","no carbon black","edr not installed"],"severity":"CRITICAL","tactic":"Defense Evasion","technique":"T1562 — Impair Defenses","ioc":"No EDR telemetry from endpoint","remediation":"Deploy EDR agent immediately. Prioritise servers and privileged workstations. Ensure 100% EDR coverage."},
    {"id":"EP-SEC-002","category":"Security Posture","title":"Disk Encryption Not Enabled","keywords":["no bitlocker","no filevault","disk not encrypted","no disk encryption","unencrypted disk","bitlocker disabled"],"severity":"HIGH","tactic":"Collection","technique":"T1005 — Data from Local System","ioc":"Unencrypted disk detected","remediation":"Enable BitLocker (Windows) or FileVault (macOS) on all endpoints. Escrow recovery keys to IT."},
    {"id":"EP-SEC-003","category":"Security Posture","title":"USB/Removable Media Unrestricted","keywords":["usb unrestricted","removable media","usb allowed","no usb control","device control disabled","usb policy"],"severity":"MEDIUM","tactic":"Exfiltration","technique":"T1052 — Exfiltration Over Physical Medium","ioc":"Unrestricted USB access","remediation":"Implement device control policy. Block unauthorised USB devices. Allow only approved encrypted drives."},
]

SEV_W = {"CRITICAL":15,"HIGH":8,"MEDIUM":4,"LOW":1}

def run_endpoint_scan(description, hostname, os_type):
    desc_lower = description.lower()
    findings = []
    for rule in ENDPOINT_RULES:
        if any(kw.lower() in desc_lower for kw in rule["keywords"]):
            findings.append({
                "category":    rule["category"],
                "title":       rule["title"],
                "severity":    rule["severity"],
                "tactic":      rule["tactic"],
                "technique":   rule["technique"],
                "description": f"Endpoint threat detected on {hostname} ({os_type}): {rule['title']}. MITRE ATT&CK: {rule['tactic']}.",
                "remediation": rule["remediation"],
                "ioc":         rule["ioc"],
            })
    return findings

def calc_risk(findings):
    if not findings: return 0.0
    return round(min(sum(SEV_W.get(f["severity"],0) for f in findings) * 1.5, 100.0), 1)

def calc_health(risk_score):
    return round(max(0, 100 - risk_score), 1)

def overall_sev(score):
    if score >= 70: return "CRITICAL"
    if score >= 45: return "HIGH"
    if score >= 20: return "MEDIUM"
    return "LOW"

@endpoint_agent_bp.route("/api/endpoint-agent/scan", methods=["POST"])
@jwt_required()
def scan():
    data        = request.get_json(silent=True) or {}
    hostname    = data.get("hostname", "unknown-host")
    os_type     = data.get("os_type", "Windows")
    os_version  = data.get("os_version", "Unknown")
    description = data.get("description", "")
    if not description.strip(): return jsonify({"error":"No description provided"}), 400

    findings = run_endpoint_scan(description, hostname, os_type)
    score    = calc_risk(findings)
    health   = calc_health(score)
    sev      = overall_sev(score)
    critical = sum(1 for f in findings if f["severity"] == "CRITICAL")
    summary  = (f"Endpoint Agent scan complete for {hostname} ({os_type} {os_version}). "
                f"Risk: {score}/100. Health: {health}/100. "
                f"{len(findings)} finding(s) — {critical} critical. "
                f"Threat categories: {len(set(f['category'] for f in findings))}.")

    s = EndpointScan(user_id=get_jwt_identity(), hostname=hostname, os_type=os_type, os_version=os_version, risk_score=score, severity=sev, total_findings=len(findings), critical_count=critical, health_score=health, summary=summary, node_meta="{}")
    db.session.add(s); db.session.flush()
    for f in findings:
        db.session.add(EndpointFinding(scan_id=s.id, category=f["category"], title=f["title"], severity=f["severity"], tactic=f["tactic"], technique=f["technique"], description=f["description"], remediation=f["remediation"], ioc=f["ioc"], node_meta="{}"))
    db.session.commit()
    return jsonify({"scan_id":s.id,"hostname":hostname,"os_type":os_type,"risk_score":score,"health_score":health,"severity":sev,"total_findings":len(findings),"critical_count":critical,"summary":summary}), 200

@endpoint_agent_bp.route("/api/endpoint-agent/scans/<scan_id>", methods=["GET"])
@jwt_required()
def get_scan(scan_id):
    s = EndpointScan.query.filter_by(id=scan_id, user_id=get_jwt_identity()).first()
    if not s: return jsonify({"error":"Not found"}), 404
    findings = EndpointFinding.query.filter_by(scan_id=scan_id).all()
    cats = list(dict.fromkeys(f.category for f in findings))
    return jsonify({"scan_id":s.id,"hostname":s.hostname,"os_type":s.os_type,"os_version":s.os_version,"risk_score":s.risk_score,"health_score":s.health_score,"severity":s.severity,"total_findings":s.total_findings,"critical_count":s.critical_count,"summary":s.summary,"created_at":s.created_at.isoformat(),"categories":cats,"findings":[{"category":f.category,"title":f.title,"severity":f.severity,"tactic":f.tactic,"technique":f.technique,"description":f.description,"remediation":f.remediation,"ioc":f.ioc} for f in findings]}), 200

@endpoint_agent_bp.route("/api/endpoint-agent/history", methods=["GET"])
@jwt_required()
def history():
    scans = EndpointScan.query.filter_by(user_id=get_jwt_identity()).order_by(EndpointScan.created_at.desc()).limit(50).all()
    return jsonify({"scans":[{"scan_id":s.id,"hostname":s.hostname,"os_type":s.os_type,"risk_score":s.risk_score,"health_score":s.health_score,"severity":s.severity,"total_findings":s.total_findings,"critical_count":s.critical_count,"created_at":s.created_at.isoformat()} for s in scans]}), 200

@endpoint_agent_bp.route("/api/endpoint-agent/health", methods=["GET"])
def health_check():
    return jsonify({"module":"Endpoint Agent","phase":"CrowdStrike Gap — Phase 2","version":"1.0.0","rules":len(ENDPOINT_RULES),"status":"operational"}), 200
