# ============================================================
# AIPET X — Log Ingestion + Analytics
# Log Parsing | Anomaly Detection | Pattern Analysis
# ============================================================

import json, uuid, datetime, re
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.models import db
from sqlalchemy import Column, String, Integer, Text, DateTime, Float

log_analytics_bp = Blueprint("log_analytics", __name__)

class LogAnalysisReport(db.Model):
    __tablename__ = "log_analysis_reports"
    id             = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id        = Column(Integer, nullable=False)
    log_source     = Column(String(128))
    total_lines    = Column(Integer, default=0)
    error_count    = Column(Integer, default=0)
    warning_count  = Column(Integer, default=0)
    anomaly_count  = Column(Integer, default=0)
    security_events= Column(Integer, default=0)
    risk_score     = Column(Float, default=0.0)
    summary        = Column(Text, nullable=True)
    findings       = Column(Text, default="[]")
    patterns       = Column(Text, default="[]")
    created_at     = Column(DateTime, default=datetime.datetime.utcnow)
    node_meta      = Column(Text, default="{}")

LOG_RULES = [
    {"title":"Authentication Failures Detected","keywords":["failed login","authentication failed","invalid password","login failure","auth failed","bad credentials","401 unauthorized"],"severity":"HIGH","category":"Security","pattern":"Multiple auth failures — possible brute force","remediation":"Enable account lockout. Review source IPs. Check for credential stuffing."},
    {"title":"SQL Injection Attempt in Logs","keywords":["sql injection","select * from","union select","drop table","insert into","xp_cmdshell","sqlmap"],"severity":"CRITICAL","category":"Security","pattern":"SQL injection pattern in request logs","remediation":"Sanitise all inputs. Deploy WAF. Review and patch vulnerable endpoints immediately."},
    {"title":"XSS Attack Pattern Detected","keywords":["<script>","javascript:","onerror=","onload=","xss","cross site scripting","alert("],"severity":"HIGH","category":"Security","pattern":"XSS payload in request logs","remediation":"Implement Content Security Policy. Encode all outputs. Deploy WAF XSS rules."},
    {"title":"Directory Traversal Attempt","keywords":["../","..\\","directory traversal","path traversal","etc/passwd","etc/shadow","file inclusion"],"severity":"HIGH","category":"Security","pattern":"Path traversal in request logs","remediation":"Validate and sanitise file paths. Restrict file access. Chroot application."},
    {"title":"High Error Rate Detected","keywords":["error rate","5xx","500 internal","503 service","502 bad gateway","exception","stack trace","unhandled error"],"severity":"HIGH","category":"Performance","pattern":"Elevated application error rate","remediation":"Review recent deployments. Check application logs. Implement circuit breaker."},
    {"title":"Slow Query Log Detected","keywords":["slow query","query time","long running","timeout query","index missing","full table scan","slow_query_log"],"severity":"MEDIUM","category":"Performance","pattern":"Database slow queries impacting performance","remediation":"Add missing indexes. Optimise queries. Enable query caching. Review execution plans."},
    {"title":"Out of Memory Errors","keywords":["out of memory","oom killer","java.lang.outofmemory","heap space","gc overhead","memory error","kill process"],"severity":"CRITICAL","category":"Infrastructure","pattern":"Memory exhaustion in application logs","remediation":"Increase heap size. Fix memory leaks. Add memory alerting. Review GC settings."},
    {"title":"Disk Space Warning","keywords":["disk full","no space left","disk usage","inode","disk warning","storage full","quota exceeded"],"severity":"HIGH","category":"Infrastructure","pattern":"Disk space critical in system logs","remediation":"Clean logs and temp files. Add disk space alerting. Expand storage. Archive old data."},
    {"title":"Certificate Expiry Warning","keywords":["certificate expired","ssl expired","tls expired","cert expiry","certificate warning","ssl error","handshake failed"],"severity":"HIGH","category":"Security","pattern":"TLS certificate expiring or expired","remediation":"Renew certificate immediately. Implement auto-renewal with Let's Encrypt or ACM."},
    {"title":"Suspicious IP Access Pattern","keywords":["tor exit","proxy detected","vpn ip","suspicious ip","blocked ip","threat intelligence ip","malicious ip","ip reputation"],"severity":"HIGH","category":"Security","pattern":"Access from known malicious IP ranges","remediation":"Block suspicious IPs at WAF. Enable IP reputation filtering. Review access logs."},
    {"title":"Data Exfiltration Pattern","keywords":["large response","data dump","bulk export","unusual download","mass data","exfil","large payload","bulk request"],"severity":"CRITICAL","category":"Security","pattern":"Possible data exfiltration in access logs","remediation":"Implement DLP. Alert on large outbound transfers. Review user activity immediately."},
    {"title":"Privilege Escalation in Audit Log","keywords":["sudo","su -","privilege escalation","root access","admin access granted","role changed","permission elevated"],"severity":"HIGH","category":"Security","pattern":"Privilege escalation in audit logs","remediation":"Review who escalated privileges. Enforce principle of least privilege. Audit sudo usage."},
]

def analyse_logs(raw_logs, log_source):
    lines = raw_logs.split("\n")
    total = len([l for l in lines if l.strip()])
    logs_lower = raw_logs.lower()

    findings, patterns = [], []
    errors   = len(re.findall(r"error|exception|failed|critical", logs_lower))
    warnings = len(re.findall(r"warn|warning|deprecated", logs_lower))

    for rule in LOG_RULES:
        if any(kw.lower() in logs_lower for kw in rule["keywords"]):
            findings.append({"title":rule["title"],"severity":rule["severity"],"category":rule["category"],"pattern":rule["pattern"],"remediation":rule["remediation"],"count":logs_lower.count(rule["keywords"][0])})
            patterns.append(rule["pattern"])

    security = sum(1 for f in findings if f["category"]=="Security")
    anomalies= sum(1 for f in findings if f["severity"] in ["CRITICAL","HIGH"])
    risk     = round(min(len(findings)*12 + (errors/max(total,1))*100*0.3, 100.0), 1)

    summary = (f"Log analysis complete for {log_source}. "
               f"{total} log line(s) processed. {errors} error(s), {warnings} warning(s). "
               f"{len(findings)} finding(s) — {security} security event(s), {anomalies} anomaly(s). "
               f"Risk score: {risk}/100.")

    return findings, patterns, total, errors, warnings, anomalies, security, risk, summary

@log_analytics_bp.route("/api/log-analytics/analyse", methods=["POST"])
@jwt_required()
def analyse():
    data       = request.get_json(silent=True) or {}
    log_source = data.get("log_source", "application")
    raw_logs   = data.get("raw_logs", "")
    if not raw_logs.strip(): return jsonify({"error":"No logs provided"}), 400

    findings, patterns, total, errors, warnings, anomalies, security, risk, summary = analyse_logs(raw_logs, log_source)

    r = LogAnalysisReport(user_id=get_jwt_identity(), log_source=log_source, total_lines=total, error_count=errors, warning_count=warnings, anomaly_count=anomalies, security_events=security, risk_score=risk, summary=summary, findings=json.dumps(findings), patterns=json.dumps(patterns), node_meta="{}")
    db.session.add(r); db.session.commit()

    return jsonify({"report_id":r.id,"log_source":log_source,"total_lines":total,"error_count":errors,"warning_count":warnings,"anomaly_count":anomalies,"security_events":security,"risk_score":risk,"findings":findings,"summary":summary}), 200

@log_analytics_bp.route("/api/log-analytics/history", methods=["GET"])
@jwt_required()
def history():
    reports = LogAnalysisReport.query.filter_by(user_id=get_jwt_identity()).order_by(LogAnalysisReport.created_at.desc()).limit(50).all()
    return jsonify({"reports":[{"report_id":r.id,"log_source":r.log_source,"total_lines":r.total_lines,"error_count":r.error_count,"risk_score":r.risk_score,"security_events":r.security_events,"created_at":r.created_at.isoformat()} for r in reports]}), 200

@log_analytics_bp.route("/api/log-analytics/health", methods=["GET"])
def health():
    return jsonify({"module":"Log Ingestion + Analytics","version":"1.0.0","rules":len(LOG_RULES),"status":"operational"}), 200
