# ============================================================
# AIPET X — Module #47: Code Security Engine
# SAST | SCA | Secrets Detection | IaC Scanning | SBOM
# Phase 5C | v6.1.0
# ============================================================

import os, re, json, uuid, datetime
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.models import db
from sqlalchemy import Column, String, Integer, Text, DateTime, ForeignKey, Float
from sqlalchemy.orm import relationship

code_security_bp = Blueprint("code_security", __name__)

class CodeScan(db.Model):
    __tablename__ = "code_scans"
    id            = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id       = Column(Integer, ForeignKey("users.id"), nullable=False)
    target_type   = Column(String(32))
    target_name   = Column(String(256))
    status        = Column(String(32), default="pending")
    risk_score    = Column(Float, default=0.0)
    total_findings= Column(Integer, default=0)
    created_at    = Column(DateTime, default=datetime.datetime.utcnow)
    completed_at  = Column(DateTime, nullable=True)
    node_meta     = Column(Text, default="{}")
    findings      = relationship("CodeFinding", backref="scan", lazy=True, cascade="all, delete-orphan")
    sbom_entries  = relationship("CodeSBOM", backref="scan", lazy=True, cascade="all, delete-orphan")

class CodeFinding(db.Model):
    __tablename__ = "code_findings"
    id            = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id       = Column(String(64), ForeignKey("code_scans.id"), nullable=False)
    engine        = Column(String(32))
    severity      = Column(String(16))
    category      = Column(String(64))
    title         = Column(String(256))
    description   = Column(Text)
    file_path     = Column(String(512), nullable=True)
    line_number   = Column(Integer, nullable=True)
    recommendation= Column(Text, nullable=True)
    cwe_id        = Column(String(32), nullable=True)
    node_meta     = Column(Text, default="{}")
    created_at    = Column(DateTime, default=datetime.datetime.utcnow)

class CodeSBOM(db.Model):
    __tablename__ = "code_sbom"
    id            = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id       = Column(String(64), ForeignKey("code_scans.id"), nullable=False)
    component     = Column(String(256))
    version       = Column(String(64))
    ecosystem     = Column(String(32))
    license       = Column(String(128), nullable=True)
    is_vulnerable = Column(Integer, default=0)
    vuln_summary  = Column(Text, nullable=True)
    node_meta     = Column(Text, default="{}")
    created_at    = Column(DateTime, default=datetime.datetime.utcnow)

SAST_RULES = [
    {"id":"SAST-001","title":"SQL Injection Risk","pattern":r'(execute|cursor\.execute)\s*\(\s*["\'].*%[s|d].*["\']',"severity":"CRITICAL","category":"Injection","cwe":"CWE-89","recommendation":"Use parameterised queries or an ORM."},
    {"id":"SAST-002","title":"Hardcoded Password","pattern":r'(?i)(password|passwd|pwd)\s*=\s*["\'][^"\']{4,}["\']',"severity":"CRITICAL","category":"Hardcoded Secrets","cwe":"CWE-798","recommendation":"Move credentials to environment variables."},
    {"id":"SAST-003","title":"Dangerous eval()","pattern":r'\beval\s*\(',"severity":"HIGH","category":"Code Injection","cwe":"CWE-95","recommendation":"Use ast.literal_eval() instead."},
    {"id":"SAST-004","title":"Shell Injection via os.system","pattern":r'\bos\.system\s*\(',"severity":"HIGH","category":"Command Injection","cwe":"CWE-78","recommendation":"Use subprocess.run() with shell=False."},
    {"id":"SAST-005","title":"Insecure Deserialization","pattern":r'\bpickle\.loads?\s*\(',"severity":"HIGH","category":"Deserialization","cwe":"CWE-502","recommendation":"Avoid pickle for untrusted data."},
    {"id":"SAST-006","title":"Debug Mode Enabled","pattern":r'(?i)(app\.run|debug)\s*=\s*True',"severity":"MEDIUM","category":"Configuration","cwe":"CWE-215","recommendation":"Disable debug in production."},
    {"id":"SAST-007","title":"Weak Hash Algorithm","pattern":r'hashlib\.(md5|sha1)\s*\(',"severity":"MEDIUM","category":"Cryptography","cwe":"CWE-327","recommendation":"Use SHA-256 or SHA-3."},
    {"id":"SAST-008","title":"Path Traversal Risk","pattern":r'open\s*\(\s*.*\+.*["\']',"severity":"HIGH","category":"Path Traversal","cwe":"CWE-22","recommendation":"Validate all file paths."},
]

SECRETS_RULES = [
    {"title":"AWS Access Key","pattern":r'AKIA[0-9A-Z]{16}',"severity":"CRITICAL","category":"Cloud Credentials","cwe":"CWE-312","recommendation":"Rotate immediately. Use AWS Secrets Manager."},
    {"title":"Generic API Key","pattern":r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']?[A-Za-z0-9_\-]{20,}["\']?',"severity":"HIGH","category":"API Credentials","cwe":"CWE-312","recommendation":"Inject via environment variables."},
    {"title":"JWT Token Hardcoded","pattern":r'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}',"severity":"HIGH","category":"Token Exposure","cwe":"CWE-312","recommendation":"Never hardcode JWTs."},
    {"title":"Private Key Detected","pattern":r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----',"severity":"CRITICAL","category":"Private Key","cwe":"CWE-321","recommendation":"Remove and revoke immediately."},
    {"title":"Database Connection String","pattern":r'(?i)(postgres|mysql|mongodb|redis):\/\/[^\s"\'][^\s"\']{8,}',"severity":"CRITICAL","category":"DB Credentials","cwe":"CWE-312","recommendation":"Use environment variables."},
    {"title":"GitHub Token","pattern":r'ghp_[A-Za-z0-9]{36}',"severity":"CRITICAL","category":"VCS Token","cwe":"CWE-312","recommendation":"Revoke on GitHub immediately."},
]

IAC_RULES = [
    {"title":"S3 Bucket Public","pattern":r'(?i)acl\s*=\s*["\']public-read["\']',"severity":"CRITICAL","category":"Cloud Misconfiguration","cwe":"CWE-732","recommendation":"Set ACL to private."},
    {"title":"Open Security Group 0.0.0.0/0","pattern":r'0\.0\.0\.0/0',"severity":"HIGH","category":"Network Exposure","cwe":"CWE-284","recommendation":"Restrict CIDR to known IPs."},
    {"title":"Encryption Disabled","pattern":r'(?i)encrypted\s*=\s*(false|0)',"severity":"HIGH","category":"Data Protection","cwe":"CWE-311","recommendation":"Enable encryption at rest."},
    {"title":"Root Account Usage","pattern":r'(?i)(arn:aws:iam::\d+:root)',"severity":"CRITICAL","category":"Identity Risk","cwe":"CWE-250","recommendation":"Avoid root account. Use IAM roles."},
    {"title":"Logging Disabled","pattern":r'(?i)logging\s*=\s*(false|disabled)',"severity":"MEDIUM","category":"Audit","cwe":"CWE-778","recommendation":"Enable logging on all resources."},
]

KNOWN_VULNERABLE = {
    "pip": {
        "django":       {"4.2.0": {"severity":"HIGH",    "vuln":"CVE-2023-36053 ReDoS in EmailValidator"}},
        "flask":        {"2.3.0": {"severity":"MEDIUM",  "vuln":"CVE-2023-30861 Cookie security issue"}},
        "requests":     {"2.31.0":{"severity":"MEDIUM",  "vuln":"CVE-2023-32681 Proxy auth leak"}},
        "pyyaml":       {"6.0.0": {"severity":"CRITICAL","vuln":"CVE-2020-14343 Arbitrary code execution"}},
        "cryptography": {"41.0.0":{"severity":"HIGH",    "vuln":"CVE-2023-49083 NULL pointer dereference"}},
    },
    "npm": {
        "lodash":       {"4.17.21":{"severity":"HIGH",    "vuln":"CVE-2021-23337 Command injection"}},
        "axios":        {"1.6.0":  {"severity":"MEDIUM",  "vuln":"CVE-2023-45857 CSRF token leak"}},
        "jsonwebtoken": {"9.0.0":  {"severity":"CRITICAL","vuln":"CVE-2022-23539 Weak key acceptance"}},
    }
}

def version_less_than(v1, v2):
    try:
        norm = lambda v: [int(x) for x in re.sub(r"[^0-9.]","",v).split(".") if x]
        return norm(v1) < norm(v2)
    except:
        return False

def run_sast(code, filename):
    out = []
    lines = code.splitlines()
    for rule in SAST_RULES:
        for i, line in enumerate(lines, 1):
            if re.search(rule["pattern"], line):
                out.append({"engine":"SAST","severity":rule["severity"],"category":rule["category"],"title":rule["title"],"description":f"Line {i}: {line.strip()[:100]}","file_path":filename,"line_number":i,"recommendation":rule["recommendation"],"cwe_id":rule["cwe"]})
    return out

def run_secrets(code, filename):
    out = []
    lines = code.splitlines()
    for rule in SECRETS_RULES:
        for i, line in enumerate(lines, 1):
            if re.search(rule["pattern"], line):
                safe = re.sub(rule["pattern"],"[REDACTED]",line).strip()[:100]
                out.append({"engine":"SECRETS","severity":rule["severity"],"category":rule["category"],"title":rule["title"],"description":f"Line {i}: {safe}","file_path":filename,"line_number":i,"recommendation":rule["recommendation"],"cwe_id":rule["cwe"]})
    return out

def run_iac(code, filename):
    out = []
    lines = code.splitlines()
    for rule in IAC_RULES:
        for i, line in enumerate(lines, 1):
            if re.search(rule["pattern"], line):
                out.append({"engine":"IAC","severity":rule["severity"],"category":rule["category"],"title":rule["title"],"description":f"Line {i}: {line.strip()[:100]}","file_path":filename,"line_number":i,"recommendation":rule["recommendation"],"cwe_id":rule["cwe"]})
    return out

def run_sca(text, target_type):
    findings, sbom = [], []
    ecosystem = "pip" if target_type == "requirements" else "npm"
    packages = []
    if target_type == "requirements":
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"): continue
            m = re.match(r"^([A-Za-z0-9_\-\.]+)\s*[><=!~]+\s*([\d\.]+)", line)
            if m: packages.append((m.group(1).lower(), m.group(2)))
            else: packages.append((line.lower(), "unknown"))
    else:
        try:
            data = json.loads(text)
            deps = {**data.get("dependencies",{}), **data.get("devDependencies",{})}
            for pkg, ver in deps.items(): packages.append((pkg.lower(), ver.lstrip("^~>=<")))
        except: pass
    db2 = KNOWN_VULNERABLE.get(ecosystem, {})
    for pkg, ver in packages:
        is_vuln, vuln_text, vuln_sev = False, None, "INFO"
        if pkg in db2:
            for threshold, meta in db2[pkg].items():
                if ver == "unknown" or version_less_than(ver, threshold):
                    is_vuln, vuln_text, vuln_sev = True, meta["vuln"], meta["severity"]
                    findings.append({"engine":"SCA","severity":vuln_sev,"category":"Vulnerable Dependency","title":f"Vulnerable: {pkg}@{ver}","description":vuln_text,"file_path":"requirements.txt" if ecosystem=="pip" else "package.json","line_number":None,"recommendation":f"Upgrade {pkg} to {threshold}+","cwe_id":"CWE-1035"})
        sbom.append({"component":pkg,"version":ver,"ecosystem":ecosystem,"license":"Unknown","is_vulnerable":1 if is_vuln else 0,"vuln_summary":vuln_text})
    return findings, sbom

def risk_score(findings):
    weights = {"CRITICAL":10,"HIGH":6,"MEDIUM":3,"LOW":1,"INFO":0}
    return round(min(sum(weights.get(f.get("severity","INFO"),0) for f in findings)*2, 100.0), 1)

@code_security_bp.route("/api/code-security/scan", methods=["POST"])
@jwt_required()
def submit_scan():
    data = request.get_json(silent=True) or {}
    target_type = data.get("target_type","snippet")
    target_name = data.get("target_name","unnamed")
    content     = data.get("content","")
    if not content.strip(): return jsonify({"error":"No content provided"}), 400
    if target_type not in {"snippet","requirements","iac","package_json"}: return jsonify({"error":"Invalid target_type"}), 400
    scan = CodeScan(user_id=get_jwt_identity(), target_type=target_type, target_name=target_name, status="running", node_meta=json.dumps({}))
    db.session.add(scan); db.session.flush()
    all_findings, sbom_data = [], []
    if target_type == "snippet":
        all_findings += run_sast(content, target_name)
        all_findings += run_secrets(content, target_name)
    elif target_type == "iac":
        all_findings += run_iac(content, target_name)
        all_findings += run_secrets(content, target_name)
    elif target_type in ("requirements","package_json"):
        sca_f, sbom_data = run_sca(content, target_type)
        all_findings += sca_f
    for f in all_findings:
        db.session.add(CodeFinding(scan_id=scan.id, engine=f["engine"], severity=f["severity"], category=f["category"], title=f["title"], description=f["description"], file_path=f.get("file_path"), line_number=f.get("line_number"), recommendation=f.get("recommendation"), cwe_id=f.get("cwe_id"), node_meta="{}"))
    for s in sbom_data:
        db.session.add(CodeSBOM(scan_id=scan.id, component=s["component"], version=s["version"], ecosystem=s["ecosystem"], license=s.get("license","Unknown"), is_vulnerable=s["is_vulnerable"], vuln_summary=s.get("vuln_summary"), node_meta="{}"))
    scan.risk_score=risk_score(all_findings); scan.total_findings=len(all_findings); scan.status="complete"; scan.completed_at=datetime.datetime.utcnow()
    db.session.commit()
    return jsonify({"scan_id":scan.id,"status":"complete","total_findings":len(all_findings),"risk_score":scan.risk_score}), 200

@code_security_bp.route("/api/code-security/results/<scan_id>", methods=["GET"])
@jwt_required()
def get_results(scan_id):
    scan = CodeScan.query.filter_by(id=scan_id, user_id=get_jwt_identity()).first()
    if not scan: return jsonify({"error":"Not found"}), 404
    findings = CodeFinding.query.filter_by(scan_id=scan_id).all()
    return jsonify({"scan_id":scan.id,"target_name":scan.target_name,"risk_score":scan.risk_score,"total_findings":scan.total_findings,"summary":{"CRITICAL":sum(1 for f in findings if f.severity=="CRITICAL"),"HIGH":sum(1 for f in findings if f.severity=="HIGH"),"MEDIUM":sum(1 for f in findings if f.severity=="MEDIUM"),"LOW":sum(1 for f in findings if f.severity=="LOW")},"findings":[{"id":f.id,"engine":f.engine,"severity":f.severity,"category":f.category,"title":f.title,"description":f.description,"file_path":f.file_path,"line_number":f.line_number,"recommendation":f.recommendation,"cwe_id":f.cwe_id} for f in findings]}), 200

@code_security_bp.route("/api/code-security/sbom/<scan_id>", methods=["GET"])
@jwt_required()
def get_sbom(scan_id):
    scan = CodeScan.query.filter_by(id=scan_id, user_id=get_jwt_identity()).first()
    if not scan: return jsonify({"error":"Not found"}), 404
    entries = CodeSBOM.query.filter_by(scan_id=scan_id).all()
    return jsonify({"scan_id":scan_id,"components":[{"component":e.component,"version":e.version,"ecosystem":e.ecosystem,"license":e.license,"is_vulnerable":bool(e.is_vulnerable),"vuln_summary":e.vuln_summary} for e in entries],"total":len(entries),"vulnerable":sum(1 for e in entries if e.is_vulnerable)}), 200

@code_security_bp.route("/api/code-security/history", methods=["GET"])
@jwt_required()
def scan_history():
    scans = CodeScan.query.filter_by(user_id=get_jwt_identity()).order_by(CodeScan.created_at.desc()).limit(50).all()
    return jsonify({"scans":[{"scan_id":s.id,"target_name":s.target_name,"target_type":s.target_type,"status":s.status,"risk_score":s.risk_score,"total_findings":s.total_findings,"created_at":s.created_at.isoformat()} for s in scans]}), 200

@code_security_bp.route("/api/code-security/health", methods=["GET"])
def health():
    return jsonify({"module":"AIPET Code Security Engine","version":"1.0.0","status":"operational"}), 200
