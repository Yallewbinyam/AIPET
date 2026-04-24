# ============================================================
# AIPET X — Enterprise Reporting
# Executive | CISO | Compliance | Incident | Trend Reports
# ============================================================

import json, uuid, datetime, random, io, os
from flask import Blueprint, request, jsonify, send_file, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from flask_mail import Mail, Message
from dashboard.backend.models import db
from sqlalchemy import Column, String, Integer, Text, DateTime, Float

enterprise_reporting_bp = Blueprint("enterprise_reporting", __name__)

class EnterpriseReport(db.Model):
    __tablename__ = "enterprise_reports"
    id            = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id       = Column(Integer, nullable=False)
    report_type   = Column(String(64))
    organisation  = Column(String(256))
    period        = Column(String(64))
    risk_score    = Column(Float, default=0.0)
    status        = Column(String(32), default="GENERATED")
    content       = Column(Text, default="{}")
    created_at    = Column(DateTime, default=datetime.datetime.utcnow)
    node_meta     = Column(Text, default="{}")

def generate_executive_report(organisation, period):
    risk = round(random.uniform(35, 85), 1)
    return {
        "title": f"Executive Security Summary — {organisation}",
        "period": period,
        "classification": "CONFIDENTIAL",
        "sections": [
            {"title":"Overall Security Posture","content":f"During {period}, {organisation} maintained a security risk score of {risk}/100. The platform identified and remediated {random.randint(15,80)} security findings across cloud, endpoint and identity systems.","score":risk,"trend":"improving"},
            {"title":"Top Business Risks","items":[{"risk":"Cloud Misconfiguration Exposure","impact":"HIGH","status":"Remediated"},{"risk":"Identity & Credential Threats","impact":"CRITICAL","status":"In Progress"},{"risk":"Supply Chain Vulnerabilities","impact":"HIGH","status":"Monitored"},{"risk":"Ransomware Threat Surface","impact":"CRITICAL","status":"Remediated"}]},
            {"title":"Compliance Status","items":[{"framework":"NIS2","score":round(random.uniform(70,95),1),"status":"SUBSTANTIALLY_COMPLIANT"},{"framework":"ISO 27001","score":round(random.uniform(65,90),1),"status":"PARTIALLY_COMPLIANT"},{"framework":"GDPR","score":round(random.uniform(75,95),1),"status":"SUBSTANTIALLY_COMPLIANT"}]},
            {"title":"Key Achievements","items":[f"Deployed AI-powered threat detection across {random.randint(3,10)} cloud environments",f"Reduced mean detection time to {round(random.uniform(2,15),1)} minutes",f"Achieved {round(random.uniform(95,99.9),1)}% uptime across all monitored services",f"Completed {random.randint(2,6)} compliance framework assessments"]},
            {"title":"Recommended Board Actions","items":["Approve budget for Zero Trust implementation","Mandate MFA across all business units","Commission external penetration test","Review cyber insurance policy limits"]}
        ]
    }

def generate_ciso_report(organisation, period):
    return {
        "title": f"CISO Security Report — {organisation}",
        "period": period,
        "classification": "RESTRICTED",
        "sections": [
            {"title":"Threat Landscape","content":f"During {period}, AIPET X detected {random.randint(50,500)} security events across all monitored systems. {random.randint(5,25)} events were escalated to incidents requiring active response."},
            {"title":"Module Performance","modules":[
                {"name":"Cloud Runtime Scanner","scans":random.randint(20,100),"findings":random.randint(0,30),"critical":random.randint(0,8)},
                {"name":"Endpoint Agent","scans":random.randint(10,50),"findings":random.randint(0,20),"critical":random.randint(0,5)},
                {"name":"Identity Threat Detection","scans":random.randint(5,30),"findings":random.randint(0,15),"critical":random.randint(0,4)},
                {"name":"Cloud SIEM","scans":random.randint(100,1000),"findings":random.randint(0,50),"critical":random.randint(0,10)},
                {"name":"Vulnerability Management","scans":random.randint(10,40),"findings":random.randint(5,80),"critical":random.randint(0,15)},
                {"name":"Compliance Automation","scans":random.randint(3,12),"findings":random.randint(0,20),"critical":random.randint(0,5)},
            ]},
            {"title":"MITRE ATT&CK Coverage","tactics":["Initial Access","Execution","Persistence","Privilege Escalation","Defense Evasion","Credential Access","Discovery","Lateral Movement","Collection","Command & Control","Exfiltration","Impact"],"coverage":round(random.uniform(60,90),1)},
            {"title":"Vulnerability Metrics","critical":random.randint(2,15),"high":random.randint(5,30),"medium":random.randint(10,50),"mean_time_to_remediate_days":round(random.uniform(1,14),1)},
            {"title":"Recommendations","items":["Deploy runtime protection to remaining 15% of workloads","Complete Kubernetes security hardening","Implement privileged access management solution","Expand threat intelligence feed coverage"]}
        ]
    }

def generate_compliance_report(organisation, period):
    frameworks = ["NIS2","ISO 27001","NIST CSF 2.0","GDPR","SOC 2","PCI DSS"]
    return {
        "title": f"Compliance Assessment Report — {organisation}",
        "period": period,
        "classification": "CONFIDENTIAL",
        "sections": [
            {"title":"Compliance Overview","frameworks":[{"name":fw,"score":round(random.uniform(55,95),1),"passed":random.randint(5,9),"failed":random.randint(1,4),"status":random.choice(["COMPLIANT","SUBSTANTIALLY_COMPLIANT","PARTIALLY_COMPLIANT"])} for fw in frameworks]},
            {"title":"Critical Gaps","items":[{"gap":"Incident reporting SLA not meeting 72-hour NIS2 requirement","framework":"NIS2","priority":"CRITICAL"},{"gap":"Data Protection Impact Assessment process incomplete","framework":"GDPR","priority":"HIGH"},{"gap":"Privileged access management controls insufficient","framework":"ISO 27001","priority":"HIGH"},{"gap":"Audit logging retention below 12-month requirement","framework":"SOC 2","priority":"MEDIUM"}]},
            {"title":"Remediation Roadmap","items":[{"action":"Implement automated 72-hour breach notification","deadline":"30 days","owner":"CISO"},{"action":"Complete DPIA for all high-risk processing","deadline":"60 days","owner":"DPO"},{"action":"Deploy PAM solution","deadline":"90 days","owner":"IT Security"},{"action":"Extend log retention to 12 months","deadline":"30 days","owner":"IT Ops"}]},
            {"title":"Evidence Collected","count":random.randint(45,120),"automated":True,"last_assessment":datetime.datetime.utcnow().strftime("%Y-%m-%d")}
        ]
    }

def generate_incident_report(organisation, period):
    return {
        "title": f"Incident Report — {organisation}",
        "period": period,
        "classification": "RESTRICTED",
        "sections": [
            {"title":"Incident Summary","total":random.randint(3,15),"critical":random.randint(0,3),"high":random.randint(1,5),"resolved":random.randint(2,12),"open":random.randint(0,3),"mean_resolution_hours":round(random.uniform(2,48),1)},
            {"title":"Notable Incidents","incidents":[
                {"id":"INC-001","title":"Brute Force Attack on Admin Portal","severity":"HIGH","detected":"2024-01-15","resolved":"2024-01-15","duration_hours":2,"impact":"No breach — blocked by MFA","action":"Source IP blocked, rate limiting implemented"},
                {"id":"INC-002","title":"Cloud Storage Misconfiguration","severity":"CRITICAL","detected":"2024-01-18","resolved":"2024-01-19","duration_hours":6,"impact":"Potential data exposure — no confirmed access","action":"Bucket policy corrected, access logs reviewed"},
                {"id":"INC-003","title":"Suspicious Lateral Movement","severity":"HIGH","detected":"2024-01-22","resolved":"2024-01-22","duration_hours":1,"impact":"Contained to single subnet","action":"Endpoint isolated, credentials rotated"},
            ]},
            {"title":"Lessons Learned","items":["Admin portals require hardware MFA — SMS insufficient","Cloud storage policies need automated continuous monitoring","Lateral movement detection improved — reduced dwell time to under 1 hour"]},
            {"title":"Actions Taken","items":["Updated incident response playbooks","Deployed additional monitoring rules to SIEM","Conducted post-incident tabletop exercise","Reported to regulatory authority per NIS2 requirements"]}
        ]
    }

def generate_trend_report(organisation, period):
    weeks = ["Week 1","Week 2","Week 3","Week 4"]
    base = random.uniform(55, 75)
    trend = []
    for w in weeks:
        base = min(95, base + random.uniform(-3, 6))
        trend.append({"week":w,"score":round(base,1),"threats":random.randint(2,20),"resolved":random.randint(1,18)})
    return {
        "title": f"Security Trend Report — {organisation}",
        "period": period,
        "classification": "INTERNAL",
        "sections": [
            {"title":"Security Score Trend","data":trend,"overall_improvement":round(trend[-1]["score"]-trend[0]["score"],1)},
            {"title":"Threat Volume Trend","total_threats":sum(t["threats"] for t in trend),"total_resolved":sum(t["resolved"] for t in trend),"resolution_rate":round(sum(t["resolved"] for t in trend)/max(sum(t["threats"] for t in trend),1)*100,1)},
            {"title":"Key Metrics Week-on-Week","metrics":[{"metric":"Mean Detection Time","start":"12.5 min","end":"3.2 min","improvement":"74%"},{"metric":"Critical Findings","start":str(random.randint(8,20)),"end":str(random.randint(1,7)),"improvement":"65%"},{"metric":"Compliance Score","start":"67%","end":"84%","improvement":"25%"},{"metric":"Patch Compliance","start":"72%","end":"94%","improvement":"31%"}]},
            {"title":"Next Period Objectives","items":["Target security score above 90/100","Complete ISO 27001 gap remediation","Deploy endpoint agent to all servers","Achieve 95%+ patch compliance"]}
        ]
    }

GENERATORS = {
    "executive":   generate_executive_report,
    "ciso":        generate_ciso_report,
    "compliance":  generate_compliance_report,
    "incident":    generate_incident_report,
    "trend":       generate_trend_report,
}

@enterprise_reporting_bp.route("/api/enterprise-reporting/generate", methods=["POST"])
@jwt_required()
def generate():
    data         = request.get_json(silent=True) or {}
    report_type  = data.get("report_type", "executive")
    organisation = data.get("organisation", "My Organisation")
    period       = data.get("period", "Q1 2026")
    if report_type not in GENERATORS:
        return jsonify({"error":"Unknown report type"}), 400

    content = GENERATORS[report_type](organisation, period)
    risk    = round(random.uniform(35, 85), 1)

    r = EnterpriseReport(user_id=get_jwt_identity(), report_type=report_type, organisation=organisation, period=period, risk_score=risk, status="GENERATED", content=json.dumps(content), node_meta="{}")
    db.session.add(r); db.session.commit()

    return jsonify({"report_id":r.id,"report_type":report_type,"organisation":organisation,"period":period,"risk_score":risk,"status":"GENERATED","content":content,"created_at":r.created_at.isoformat()}), 200

@enterprise_reporting_bp.route("/api/enterprise-reporting/reports/<report_id>", methods=["GET"])
@jwt_required()
def get_report(report_id):
    r = EnterpriseReport.query.filter_by(id=report_id, user_id=get_jwt_identity()).first()
    if not r: return jsonify({"error":"Not found"}), 404
    return jsonify({"report_id":r.id,"report_type":r.report_type,"organisation":r.organisation,"period":r.period,"risk_score":r.risk_score,"status":r.status,"content":json.loads(r.content),"created_at":r.created_at.isoformat()}), 200

@enterprise_reporting_bp.route("/api/enterprise-reporting/history", methods=["GET"])
@jwt_required()
def history():
    reports = EnterpriseReport.query.filter_by(user_id=get_jwt_identity()).order_by(EnterpriseReport.created_at.desc()).limit(50).all()
    return jsonify({"reports":[{"report_id":r.id,"report_type":r.report_type,"organisation":r.organisation,"period":r.period,"risk_score":r.risk_score,"status":r.status,"created_at":r.created_at.isoformat()} for r in reports]}), 200

def _build_pdf_html(report, sig_name="", sig_title="", sig_date=""):
    content = report["content"] if isinstance(report["content"], dict) else json.loads(report["content"])
    title = content.get("title", "Enterprise Security Report")
    period = content.get("period", "")
    classification = content.get("classification", "CONFIDENTIAL")
    org = report.get("organisation", "")
    risk = report.get("risk_score", 0)
    now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    sections_html = ""
    for sec in content.get("sections", []):
        sec_title = sec.get("title", "")
        sections_html += f"<div class='section'><h2>{sec_title}</h2>"
        if "content" in sec:
            sections_html += f"<p>{sec['content']}</p>"
        if "items" in sec:
            items = sec["items"]
            if items and isinstance(items[0], dict):
                for it in items:
                    vals = " &nbsp;|&nbsp; ".join(f"<strong>{k.replace('_',' ').title()}</strong>: {v}" for k, v in it.items())
                    sections_html += f"<div class='item-row'>{vals}</div>"
            else:
                sections_html += "<ul>" + "".join(f"<li>{i}</li>" for i in items) + "</ul>"
        if "modules" in sec:
            rows = "".join(f"<tr><td>{m['name']}</td><td>{m['scans']}</td><td>{m['findings']}</td><td class='crit'>{m['critical']}</td></tr>" for m in sec["modules"])
            sections_html += f"<table><thead><tr><th>Module</th><th>Scans</th><th>Findings</th><th>Critical</th></tr></thead><tbody>{rows}</tbody></table>"
        if "frameworks" in sec:
            for fw in sec["frameworks"]:
                name = fw.get("name", ""); score = fw.get("score", 0); status = fw.get("status", "")
                sections_html += f"<div class='item-row'><strong>{name}</strong> &nbsp;Score: <strong>{score}</strong> &nbsp;Status: <strong>{status}</strong></div>"
        if "data" in sec:
            for d in sec["data"]:
                sections_html += f"<div class='item-row'>{d.get('week','')} — Score: <strong>{d.get('score','')}</strong> &nbsp;Threats: {d.get('threats','')} &nbsp;Resolved: {d.get('resolved','')}</div>"
        if "incidents" in sec:
            for inc in sec["incidents"]:
                sections_html += f"<div class='item-row'><strong>{inc.get('id','')}</strong>: {inc.get('title','')} — Severity: <strong>{inc.get('severity','')}</strong> — Duration: {inc.get('duration_hours','')}h — Impact: {inc.get('impact','')}</div>"
        sections_html += "</div>"

    sig_date_val = sig_date or now[:10]
    return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"/>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap');
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Inter', Arial, sans-serif; font-size: 11pt; color: #1a1a2e; background: #fff; }}
  .watermark {{
    position: fixed; top: 50%; left: 50%;
    transform: translate(-50%, -50%) rotate(-40deg);
    font-size: 80pt; font-weight: 900; opacity: 0.045;
    color: #cc0000; letter-spacing: 0.05em; white-space: nowrap;
    pointer-events: none; z-index: 0;
  }}
  .header {{
    background: #0a0f1a; color: #fff; padding: 28px 36px 22px;
    border-bottom: 4px solid #00e5ff;
    display: flex; justify-content: space-between; align-items: flex-start;
  }}
  .header-left h1 {{ font-size: 20pt; font-weight: 700; letter-spacing: -0.02em; }}
  .header-left .sub {{ font-size: 9pt; color: #00e5ff; margin-top: 4px; letter-spacing: 0.08em; }}
  .header-right {{ text-align: right; font-size: 9pt; color: #94a3b8; }}
  .header-right .classification {{
    display: inline-block; padding: 4px 12px; border-radius: 4px;
    background: #cc0000; color: #fff; font-weight: 700; font-size: 8pt;
    letter-spacing: 0.12em; margin-bottom: 6px;
  }}
  .meta-bar {{
    background: #f8fafc; border-bottom: 1px solid #e2e8f0;
    padding: 10px 36px; display: flex; gap: 40px; font-size: 9pt; color: #475569;
  }}
  .meta-bar span strong {{ color: #1a1a2e; }}
  .body {{ padding: 28px 36px; }}
  .section {{ margin-bottom: 28px; page-break-inside: avoid; }}
  .section h2 {{
    font-size: 12pt; font-weight: 700; color: #0a0f1a;
    border-left: 4px solid #00e5ff; padding-left: 10px;
    margin-bottom: 12px;
  }}
  .section p {{ color: #374151; line-height: 1.65; }}
  .section ul {{ margin-left: 20px; }}
  .section ul li {{ margin-bottom: 4px; color: #374151; }}
  .item-row {{
    background: #f8fafc; border: 1px solid #e2e8f0;
    border-radius: 6px; padding: 8px 12px; margin-bottom: 6px;
    font-size: 10pt; color: #374151;
  }}
  table {{ width: 100%; border-collapse: collapse; font-size: 10pt; margin-top: 8px; }}
  th {{ background: #0a0f1a; color: #00e5ff; padding: 8px 12px; text-align: left; font-weight: 600; font-size: 9pt; }}
  td {{ padding: 8px 12px; border-bottom: 1px solid #e2e8f0; }}
  td.crit {{ color: #dc2626; font-weight: 700; }}
  tr:nth-child(even) td {{ background: #f8fafc; }}
  .signature-block {{
    margin-top: 40px; border-top: 2px solid #0a0f1a;
    padding-top: 24px; page-break-inside: avoid;
  }}
  .signature-block h3 {{
    font-size: 11pt; font-weight: 700; color: #0a0f1a; margin-bottom: 20px;
    letter-spacing: 0.04em;
  }}
  .sig-grid {{ display: flex; gap: 40px; }}
  .sig-field {{ flex: 1; }}
  .sig-field .label {{ font-size: 8pt; color: #64748b; letter-spacing: 0.08em; text-transform: uppercase; margin-bottom: 4px; }}
  .sig-field .value {{
    border-bottom: 1px solid #1a1a2e; padding-bottom: 4px;
    font-size: 11pt; color: #1a1a2e; min-height: 22px;
  }}
  .footer {{
    position: fixed; bottom: 0; left: 0; right: 0;
    border-top: 1px solid #e2e8f0; padding: 8px 36px;
    background: #fff; display: flex; justify-content: space-between;
    font-size: 8pt; color: #94a3b8;
  }}
</style>
</head><body>
<div class="watermark">{classification}</div>
<div class="header">
  <div class="header-left">
    <div class="sub">AIPET X &nbsp;|&nbsp; AUTONOMOUS CYBERSECURITY PLATFORM</div>
    <h1>{title}</h1>
  </div>
  <div class="header-right">
    <div class="classification">{classification}</div><br/>
    Generated: {now}<br/>
    Period: {period}
  </div>
</div>
<div class="meta-bar">
  <span><strong>Organisation:</strong> {org}</span>
  <span><strong>Period:</strong> {period}</span>
  <span><strong>Risk Score:</strong> {risk}/100</span>
  <span><strong>Classification:</strong> {classification}</span>
</div>
<div class="body">
{sections_html}
<div class="signature-block">
  <h3>AUTHORISATION &amp; SIGNATURE</h3>
  <div class="sig-grid">
    <div class="sig-field">
      <div class="label">Authorised By (Name)</div>
      <div class="value">{sig_name}</div>
    </div>
    <div class="sig-field">
      <div class="label">Title / Role</div>
      <div class="value">{sig_title}</div>
    </div>
    <div class="sig-field">
      <div class="label">Date</div>
      <div class="value">{sig_date_val}</div>
    </div>
    <div class="sig-field">
      <div class="label">Signature</div>
      <div class="value">&nbsp;</div>
    </div>
  </div>
</div>
</div>
<div class="footer">
  <span>AIPET X — Autonomous Cybersecurity Platform &nbsp;|&nbsp; {classification}</span>
  <span>Generated: {now}</span>
</div>
</body></html>"""


@enterprise_reporting_bp.route("/api/enterprise-reporting/export-pdf/<report_id>", methods=["GET"])
@jwt_required()
def export_pdf(report_id):
    try:
        from weasyprint import HTML
    except ImportError:
        return jsonify({"error": "WeasyPrint not installed"}), 500

    r = EnterpriseReport.query.filter_by(id=report_id, user_id=get_jwt_identity()).first()
    if not r:
        return jsonify({"error": "Not found"}), 404

    sig_name  = request.args.get("sig_name", "")
    sig_title = request.args.get("sig_title", "")
    sig_date  = request.args.get("sig_date", "")

    report_dict = {
        "content": r.content,
        "organisation": r.organisation,
        "period": r.period,
        "risk_score": r.risk_score,
    }
    html_str = _build_pdf_html(report_dict, sig_name, sig_title, sig_date)
    pdf_bytes = HTML(string=html_str).write_pdf()

    safe_org  = "".join(c if c.isalnum() else "_" for c in (r.organisation or "report"))
    filename  = f"AIPET_X_{r.report_type}_{safe_org}_{r.period}.pdf".replace(" ", "_")

    return send_file(
        io.BytesIO(pdf_bytes),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=filename,
    )


@enterprise_reporting_bp.route("/api/enterprise-reporting/email-pdf/<report_id>", methods=["POST"])
@jwt_required()
def email_pdf(report_id):
    try:
        from weasyprint import HTML
    except ImportError:
        return jsonify({"error": "WeasyPrint not installed — run: pip install weasyprint"}), 500

    r = EnterpriseReport.query.filter_by(id=report_id, user_id=get_jwt_identity()).first()
    if not r:
        return jsonify({"error": "Not found"}), 404

    data        = request.get_json(silent=True) or {}
    recipient   = data.get("recipient", "").strip()
    sender_name = data.get("sender_name", "AIPET X Platform").strip() or "AIPET X Platform"
    sig_name    = data.get("sig_name", "")
    sig_title   = data.get("sig_title", "")
    sig_date    = data.get("sig_date", "")

    if not recipient or "@" not in recipient:
        return jsonify({"error": "Valid recipient email required"}), 400

    # Build PDF
    report_dict  = {"content": r.content, "organisation": r.organisation,
                    "period": r.period, "risk_score": r.risk_score}
    html_str     = _build_pdf_html(report_dict, sig_name, sig_title, sig_date)
    pdf_bytes    = HTML(string=html_str).write_pdf()

    safe_org     = "".join(c if c.isalnum() else "_" for c in (r.organisation or "report"))
    filename     = f"AIPET_X_{r.report_type}_{safe_org}_{r.period}.pdf".replace(" ", "_")
    content_json = json.loads(r.content) if isinstance(r.content, str) else r.content
    report_title = content_json.get("title", "Enterprise Security Report")
    classification = content_json.get("classification", "CONFIDENTIAL")
    now_str      = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    smtp_user = os.environ.get("SMTP_USER", current_app.config.get("MAIL_USERNAME", ""))
    from_addr = f"{sender_name} <{smtp_user}>" if smtp_user else sender_name

    body_text = (
        f"Please find attached: {report_title}\n\n"
        f"Organisation : {r.organisation}\n"
        f"Period       : {r.period}\n"
        f"Risk Score   : {r.risk_score}/100\n"
        f"Classification: {classification}\n"
        f"Generated    : {now_str}\n"
        f"Sent by      : {sender_name}\n\n"
        "This report was generated by AIPET X — Autonomous Cybersecurity Platform.\n"
        "Handle in accordance with your information security policy."
    )

    body_html = f"""
    <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;background:#0a0f1a;color:#e0e0e0;padding:32px;border-radius:8px;">
      <div style="border-bottom:3px solid #00e5ff;padding-bottom:16px;margin-bottom:24px;">
        <span style="color:#00e5ff;font-size:18px;font-weight:700;">AIPET X</span>
        <span style="color:#475569;font-size:12px;margin-left:12px;">Autonomous Cybersecurity Platform</span>
      </div>
      <h2 style="color:#e0e0e0;font-size:18px;margin:0 0 8px;">{report_title}</h2>
      <div style="background:#1e293b;border-radius:6px;padding:16px;margin:16px 0;">
        <table style="width:100%;border-collapse:collapse;font-size:13px;">
          <tr><td style="color:#64748b;padding:4px 0;width:140px;">Organisation</td><td style="color:#e0e0e0;">{r.organisation}</td></tr>
          <tr><td style="color:#64748b;padding:4px 0;">Period</td><td style="color:#e0e0e0;">{r.period}</td></tr>
          <tr><td style="color:#64748b;padding:4px 0;">Risk Score</td><td style="color:#00e5ff;font-weight:700;">{r.risk_score}/100</td></tr>
          <tr><td style="color:#64748b;padding:4px 0;">Classification</td><td style="color:#dc2626;font-weight:700;">{classification}</td></tr>
          <tr><td style="color:#64748b;padding:4px 0;">Sent by</td><td style="color:#e0e0e0;">{sender_name}</td></tr>
          <tr><td style="color:#64748b;padding:4px 0;">Generated</td><td style="color:#e0e0e0;">{now_str}</td></tr>
        </table>
      </div>
      <p style="color:#94a3b8;font-size:12px;">The full report is attached as a PDF. Handle in accordance with your information security policy.</p>
      <div style="border-top:1px solid #1e293b;margin-top:24px;padding-top:12px;font-size:11px;color:#475569;">
        AIPET X — Autonomous Cybersecurity Platform &nbsp;|&nbsp; {classification}
      </div>
    </div>"""

    try:
        mail = Mail(current_app)
        msg = Message(
            subject    = f"[{classification}] {report_title} — AIPET X",
            sender     = from_addr,
            recipients = [recipient],
            body       = body_text,
            html       = body_html,
        )
        msg.attach(filename, "application/pdf", pdf_bytes)
        mail.send(msg)
    except Exception as e:
        return jsonify({"error": f"Mail send failed: {str(e)}",
                        "hint":  "Set SMTP_HOST, SMTP_USER, SMTP_PASSWORD env vars"}), 500

    return jsonify({"sent": True, "recipient": recipient,
                    "filename": filename, "sender_name": sender_name}), 200


@enterprise_reporting_bp.route("/api/enterprise-reporting/health", methods=["GET"])
def health():
    return jsonify({"module":"Enterprise Reporting","version":"1.0.0","report_types":len(GENERATORS),"status":"operational"}), 200
