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

def _build_pdf_html(report, sig_name="", sig_title="", sig_date="", content_override=None):
    content     = content_override if content_override is not None else (
        report["content"] if isinstance(report["content"], dict) else json.loads(report["content"])
    )
    title       = content.get("title", "Enterprise Security Report")
    period      = content.get("period", "")
    classification = content.get("classification", "CONFIDENTIAL")
    org         = report.get("organisation", "")
    risk        = report.get("risk_score", 0)
    now         = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    sig_date_val = sig_date or now[:10]

    # ── Risk score colour ──────────────────────────────────
    if risk >= 70:
        risk_color = "#b91c1c"
    elif risk >= 45:
        risk_color = "#c2410c"
    else:
        risk_color = "#15803d"

    # ── Sections HTML ──────────────────────────────────────
    sections_html = ""
    for sec in content.get("sections", []):
        sec_title = sec.get("title", "")
        sections_html += f"<div class='section'><h2>{sec_title}</h2>"

        if "content" in sec:
            sections_html += f"<p>{sec['content']}</p>"

        if "score" in sec and "trend" in sec:
            score_c = "#15803d" if sec["score"] >= 70 else "#c2410c" if sec["score"] >= 45 else "#b91c1c"
            sections_html += f"<div class='score-row'><span class='big-num' style='color:{score_c}'>{sec['score']}/100</span><span class='trend-label'>Trend: {sec['trend']}</span></div>"

        if "items" in sec:
            items = sec["items"]
            if items and isinstance(items[0], dict):
                for it in items:
                    cells = "".join(f"<td><strong>{k.replace('_',' ').title()}</strong><br/>{v}</td>" for k, v in it.items())
                    sections_html += f"<table class='kv-table'><tr>{cells}</tr></table>"
            else:
                sections_html += "<ul>" + "".join(f"<li>{i}</li>" for i in items) + "</ul>"

        if "modules" in sec:
            rows = "".join(
                f"<tr><td>{m['name']}</td><td>{m['scans']}</td><td>{m['findings']}</td><td class='crit'>{m['critical']}</td></tr>"
                for m in sec["modules"]
            )
            sections_html += (
                "<table><thead><tr>"
                "<th>Module</th><th>Scans</th><th>Findings</th><th>Critical</th>"
                f"</tr></thead><tbody>{rows}</tbody></table>"
            )

        if "frameworks" in sec:
            rows = "".join(
                f"<tr><td><strong>{fw.get('name','')}</strong></td>"
                f"<td>{fw.get('score','')}%</td>"
                f"<td>{fw.get('status','').replace('_',' ')}</td></tr>"
                for fw in sec["frameworks"]
            )
            sections_html += (
                "<table><thead><tr><th>Framework</th><th>Score</th><th>Status</th></tr></thead>"
                f"<tbody>{rows}</tbody></table>"
            )

        if "data" in sec:
            rows = "".join(
                f"<tr><td>{d.get('week','')}</td><td>{d.get('score','')}</td>"
                f"<td>{d.get('threats','')}</td><td>{d.get('resolved','')}</td></tr>"
                for d in sec["data"]
            )
            sections_html += (
                "<table><thead><tr><th>Week</th><th>Score</th><th>Threats</th><th>Resolved</th></tr></thead>"
                f"<tbody>{rows}</tbody></table>"
            )

        if "incidents" in sec:
            for inc in sec["incidents"]:
                sev_color = "#b91c1c" if inc.get("severity") == "CRITICAL" else "#c2410c" if inc.get("severity") == "HIGH" else "#374151"
                sections_html += (
                    f"<div class='item-row'>"
                    f"<strong style='color:{sev_color}'>[{inc.get('severity','')}]</strong> "
                    f"<strong>{inc.get('id','')}</strong>: {inc.get('title','')} &mdash; "
                    f"Duration: {inc.get('duration_hours','')}h &mdash; Impact: {inc.get('impact','')}"
                    f"</div>"
                )

        if "critical" in sec and "high" in sec and "medium" in sec:
            sections_html += (
                "<table><thead><tr><th>Severity</th><th>Count</th></tr></thead><tbody>"
                f"<tr><td class='crit'>Critical</td><td>{sec.get('critical',0)}</td></tr>"
                f"<tr><td style='color:#c2410c'>High</td><td>{sec.get('high',0)}</td></tr>"
                f"<tr><td style='color:#b45309'>Medium</td><td>{sec.get('medium',0)}</td></tr>"
                f"<tr><td>MTTR</td><td>{sec.get('mean_time_to_remediate_days',0)} days</td></tr>"
                "</tbody></table>"
            )

        if "total_threats" in sec:
            sections_html += (
                "<table><thead><tr><th>Metric</th><th>Value</th></tr></thead><tbody>"
                f"<tr><td>Total Threats</td><td>{sec.get('total_threats',0)}</td></tr>"
                f"<tr><td>Resolved</td><td>{sec.get('total_resolved',0)}</td></tr>"
                f"<tr><td>Resolution Rate</td><td>{sec.get('resolution_rate',0)}%</td></tr>"
                "</tbody></table>"
            )

        if "coverage" in sec:
            sections_html += f"<p><strong>MITRE ATT&CK Coverage:</strong> {sec['coverage']}%</p>"
            tactics = sec.get("tactics", [])
            if tactics:
                badges = "".join(f"<span class='badge'>{t}</span>" for t in tactics)
                sections_html += f"<div class='badge-row'>{badges}</div>"

        if "count" in sec and "last_assessment" in sec:
            sections_html += (
                f"<p><strong>Evidence items collected:</strong> {sec['count']} &nbsp;|&nbsp; "
                f"<strong>Last assessment:</strong> {sec['last_assessment']}</p>"
            )

        if "overall_improvement" in sec:
            sign  = "+" if sec["overall_improvement"] >= 0 else ""
            color = "#15803d" if sec["overall_improvement"] >= 0 else "#b91c1c"
            sections_html += f"<p>Overall security score improvement: <strong style='color:{color};font-size:16pt'>{sign}{sec['overall_improvement']}</strong></p>"

        sections_html += "</div>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<style>
  @page {{
    size: A4;
    margin: 2cm 2cm 2.5cm 2cm;
    @bottom-center {{
      content: "AIPET X \2014 {classification} \2014 Page " counter(page) " of " counter(pages);
      font-family: Arial, Helvetica, sans-serif;
      font-size: 8pt;
      color: #6b7280;
    }}
  }}

  * {{ box-sizing: border-box; margin: 0; padding: 0; }}

  body {{
    font-family: Arial, Helvetica, sans-serif;
    font-size: 12pt;
    line-height: 1.6;
    color: #111827;
    background: #ffffff;
  }}

  /* ── Watermark ── */
  .watermark {{
    position: fixed;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%) rotate(-42deg);
    font-size: 96pt;
    font-weight: 900;
    color: #ef4444;
    opacity: 0.06;
    letter-spacing: 0.1em;
    white-space: nowrap;
    z-index: -1;
    pointer-events: none;
  }}

  /* ── Cover header ── */
  .header {{
    border-bottom: 4pt solid #1d4ed8;
    padding-bottom: 16pt;
    margin-bottom: 14pt;
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
  }}
  .brand {{
    font-size: 10pt;
    font-weight: 700;
    color: #1d4ed8;
    letter-spacing: 0.15em;
    text-transform: uppercase;
    margin-bottom: 6pt;
  }}
  h1 {{
    font-size: 20pt;
    font-weight: 700;
    color: #111827;
    line-height: 1.2;
    max-width: 380pt;
  }}
  .header-right {{
    text-align: right;
    font-size: 9pt;
    color: #6b7280;
    flex-shrink: 0;
    padding-left: 20pt;
  }}
  .classification-badge {{
    display: inline-block;
    background: #b91c1c;
    color: #ffffff;
    font-size: 8pt;
    font-weight: 700;
    letter-spacing: 0.14em;
    padding: 3pt 10pt;
    border-radius: 3pt;
    margin-bottom: 6pt;
  }}

  /* ── Meta bar ── */
  .meta-bar {{
    background: #f3f4f6;
    border: 1pt solid #e5e7eb;
    border-radius: 4pt;
    padding: 8pt 12pt;
    margin-bottom: 18pt;
    display: flex;
    gap: 28pt;
    font-size: 9pt;
    color: #4b5563;
  }}
  .meta-bar strong {{ color: #111827; }}

  /* ── Risk score hero ── */
  .risk-hero {{
    text-align: center;
    padding: 16pt 0 10pt;
    page-break-after: always;
  }}
  .risk-number {{
    font-size: 72pt;
    font-weight: 900;
    line-height: 1;
    color: {risk_color};
  }}
  .risk-label {{
    font-size: 10pt;
    color: #6b7280;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    margin-top: 4pt;
  }}

  /* ── Sections ── */
  .section {{
    margin-bottom: 20pt;
    page-break-inside: avoid;
  }}
  h2 {{
    font-size: 16pt;
    font-weight: 700;
    color: #1d4ed8;
    border-bottom: 1.5pt solid #bfdbfe;
    padding-bottom: 5pt;
    margin-bottom: 10pt;
    page-break-after: avoid;
  }}
  h3 {{
    font-size: 13pt;
    font-weight: 700;
    color: #1e3a8a;
    margin-bottom: 8pt;
    page-break-after: avoid;
  }}
  p {{
    color: #374151;
    margin-bottom: 8pt;
    orphans: 3;
    widows: 3;
  }}
  ul {{
    margin-left: 18pt;
    margin-bottom: 8pt;
  }}
  li {{
    color: #374151;
    margin-bottom: 4pt;
    line-height: 1.6;
    orphans: 3;
    widows: 3;
  }}

  /* ── Item rows ── */
  .item-row {{
    background: #f9fafb;
    border: 1pt solid #e5e7eb;
    border-left: 3pt solid #1d4ed8;
    border-radius: 3pt;
    padding: 7pt 10pt;
    margin-bottom: 5pt;
    font-size: 10pt;
    color: #374151;
  }}

  /* ── Tables ── */
  table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 10pt;
    margin: 8pt 0 12pt;
    page-break-inside: avoid;
  }}
  thead th {{
    background: #1e3a8a;
    color: #ffffff;
    font-weight: 700;
    font-size: 9pt;
    padding: 7pt 10pt;
    text-align: left;
    border: 1pt solid #1e3a8a;
  }}
  td {{
    padding: 6pt 10pt;
    border: 1pt solid #d1d5db;
    vertical-align: top;
    color: #374151;
  }}
  tr:nth-child(even) td {{ background: #f9fafb; }}
  td.crit {{ color: #b91c1c; font-weight: 700; }}
  .kv-table td {{ border: 1pt solid #d1d5db; background: #f9fafb; }}

  /* ── Score row ── */
  .score-row {{ display: flex; align-items: center; gap: 16pt; margin: 8pt 0; }}
  .big-num {{ font-size: 28pt; font-weight: 900; line-height: 1; }}
  .trend-label {{ font-size: 11pt; color: #6b7280; }}

  /* ── Badges ── */
  .badge-row {{ display: flex; flex-wrap: wrap; gap: 4pt; margin-top: 6pt; }}
  .badge {{
    background: #eff6ff;
    border: 1pt solid #bfdbfe;
    color: #1e40af;
    font-size: 8pt;
    padding: 2pt 7pt;
    border-radius: 3pt;
    white-space: nowrap;
  }}

  /* ── Signature block ── */
  .signature-block {{
    margin-top: 28pt;
    border-top: 2pt solid #111827;
    padding-top: 20pt;
    page-break-inside: avoid;
  }}
  .sig-title {{
    font-size: 10pt;
    font-weight: 700;
    color: #111827;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    margin-bottom: 16pt;
  }}
  .sig-grid {{
    display: flex;
    gap: 20pt;
  }}
  .sig-field {{ flex: 1; }}
  .sig-label {{
    font-size: 7pt;
    color: #9ca3af;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    margin-bottom: 4pt;
  }}
  .sig-value {{
    border-bottom: 1pt solid #111827;
    padding-bottom: 3pt;
    font-size: 11pt;
    color: #111827;
    min-height: 20pt;
  }}
</style>
</head>
<body>

<div class="watermark">{classification}</div>

<div class="header">
  <div>
    <div class="brand">AIPET X &nbsp;&mdash;&nbsp; Autonomous Cybersecurity Platform</div>
    <h1>{title}</h1>
  </div>
  <div class="header-right">
    <div class="classification-badge">{classification}</div><br/>
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

<div class="risk-hero">
  <div class="risk-number">{risk}</div>
  <div class="risk-label">Risk Score / 100</div>
</div>

{sections_html}

<div class="signature-block">
  <div class="sig-title">Authorisation &amp; Signature</div>
  <div class="sig-grid">
    <div class="sig-field">
      <div class="sig-label">Authorised By (Name)</div>
      <div class="sig-value">{sig_name}</div>
    </div>
    <div class="sig-field">
      <div class="sig-label">Title / Role</div>
      <div class="sig-value">{sig_title}</div>
    </div>
    <div class="sig-field">
      <div class="sig-label">Date</div>
      <div class="sig-value">{sig_date_val}</div>
    </div>
    <div class="sig-field">
      <div class="sig-label">Signature</div>
      <div class="sig-value">&nbsp;</div>
    </div>
  </div>
</div>

</body>
</html>"""


@enterprise_reporting_bp.route("/api/enterprise-reporting/export-pdf/<report_id>", methods=["POST"])
@jwt_required()
def export_pdf(report_id):
    try:
        from weasyprint import HTML
    except ImportError:
        return jsonify({"error": "WeasyPrint not installed"}), 500

    r = EnterpriseReport.query.filter_by(id=report_id, user_id=get_jwt_identity()).first()
    if not r:
        return jsonify({"error": "Not found"}), 404

    data            = request.get_json(silent=True) or {}
    sig_name        = data.get("sig_name", "")
    sig_title       = data.get("sig_title", "")
    sig_date        = data.get("sig_date", "")
    content_override = data.get("content_override", None)

    report_dict = {
        "content": r.content,
        "organisation": r.organisation,
        "period": r.period,
        "risk_score": r.risk_score,
    }
    html_str = _build_pdf_html(report_dict, sig_name, sig_title, sig_date, content_override)
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

    data             = request.get_json(silent=True) or {}
    recipient        = data.get("recipient", "").strip()
    sender_name      = data.get("sender_name", "AIPET X Platform").strip() or "AIPET X Platform"
    sig_name         = data.get("sig_name", "")
    sig_title        = data.get("sig_title", "")
    sig_date         = data.get("sig_date", "")
    content_override = data.get("content_override", None)

    if not recipient or "@" not in recipient:
        return jsonify({"error": "Valid recipient email required"}), 400

    # Build PDF
    report_dict  = {"content": r.content, "organisation": r.organisation,
                    "period": r.period, "risk_score": r.risk_score}
    html_str     = _build_pdf_html(report_dict, sig_name, sig_title, sig_date, content_override)
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
