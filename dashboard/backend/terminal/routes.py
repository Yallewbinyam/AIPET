"""
AIPET X Terminal — Command Engine

Endpoints:
  POST /api/terminal/command   — execute a command
  POST /api/terminal/nl        — natural language → command via Claude
  GET  /api/terminal/history   — command history for this user
  GET  /api/terminal/suggest   — autocomplete suggestions
  POST /api/terminal/session   — create/update session context

Command Language:
  help                          — show all commands
  status                        — overall platform health
  scan [--target IP]            — run a scan
  identity [list|risks|graph]   — identity graph
  behavioral [anomalies|baselines] — behavioral AI
  compliance [status|framework] — compliance scores
  dspm [datastores|findings]    — data security
  cost [resources|recs]         — cost optimizer
  api [endpoints|findings]      — API security
  supply [components|vulns]     — supply chain
  network [nodes|issues]        — network visualizer
  timeline [events]             — security timeline
  incidents [list|create]       — incident response
  narrative [generate]          — AI risk narrative
  attackpath [analyse]          — attack path modelling
  siem [events|rules]           — SIEM
  ask <question>                — AI knowledge assistant
  clear                         — clear terminal
  whoami                        — current user + session
  audit                         — show audit log
"""
import json, os, time, urllib.request
from datetime import datetime, timezone, timedelta
from flask import Blueprint, request, jsonify, g
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.models import db, User
from dashboard.backend.terminal.models import TerminalSession, TerminalAuditLog

terminal_bp = Blueprint("terminal", __name__)

# ── Helpers ───────────────────────────────────────────────────

def _audit(user_id, raw_input, parsed_cmd, module,
           success=True, error=None, duration_ms=0):
    """Log every command to the audit trail."""
    try:
        log = TerminalAuditLog(
            user_id    = user_id,
            raw_input  = raw_input[:500],
            parsed_cmd = parsed_cmd,
            module     = module,
            success    = success,
            error      = error,
            duration_ms= duration_ms,
            ip_address = request.remote_addr,
        )
        db.session.add(log)
        db.session.commit()
    except Exception:
        pass


def _ok(lines, module="terminal", data=None, render="text"):
    """
    Standard success response.
    render: text | table | cards | gauge | json
    """
    return {
        "success": True,
        "module":  module,
        "render":  render,
        "lines":   lines,
        "data":    data or {},
    }


def _err(message):
    return {
        "success": False,
        "module":  "terminal",
        "render":  "error",
        "lines":   [message],
        "data":    {},
    }


def _risk_bar(score, width=20):
    """ASCII risk bar — e.g. [████████░░░░] 82"""
    filled = int((score / 100) * width)
    bar    = "█" * filled + "░" * (width - filled)
    color  = "critical" if score >= 80 else "high" if score >= 60              else "medium" if score >= 40 else "safe"
    return f"[{bar}] {score}", color


# ── Command handlers ──────────────────────────────────────────

def cmd_help(args, user_id):
    return _ok([
        "╔══════════════════════════════════════════════════════════╗",
        "║           AIPET X Terminal — Command Reference           ║",
        "╠══════════════════════════════════════════════════════════╣",
        "║  GENERAL                                                  ║",
        "║  help                    Show this help                   ║",
        "║  status                  Platform health overview         ║",
        "║  whoami                  Current user + session           ║",
        "║  clear                   Clear terminal                   ║",
        "║  audit                   Show command audit log           ║",
        "╠══════════════════════════════════════════════════════════╣",
        "║  SECURITY OPERATIONS                                      ║",
        "║  scan                    Run network scan                 ║",
        "║  incidents list          Active incidents                 ║",
        "║  incidents create        Create new incident              ║",
        "║  timeline                Unified security timeline        ║",
        "║  siem events             Recent SIEM events               ║",
        "╠══════════════════════════════════════════════════════════╣",
        "║  IDENTITY & ACCESS                                        ║",
        "║  identity list           All identities                   ║",
        "║  identity risks          Identity risk findings           ║",
        "║  behavioral anomalies    Detected anomalies               ║",
        "║  behavioral baselines    Entity baselines                 ║",
        "╠══════════════════════════════════════════════════════════╣",
        "║  CLOUD & INFRASTRUCTURE                                   ║",
        "║  network nodes           Network topology nodes           ║",
        "║  network issues          Network security issues          ║",
        "║  cost resources          Cloud resources + savings        ║",
        "║  cost recs               Cost+security recommendations    ║",
        "║  dspm datastores         Data store inventory             ║",
        "║  dspm findings           Data security findings           ║",
        "╠══════════════════════════════════════════════════════════╣",
        "║  COMPLIANCE & RISK                                        ║",
        "║  compliance status       All framework scores             ║",
        "║  compliance nis2         NIS2 controls                    ║",
        "║  compliance iso          ISO 27001 controls               ║",
        "║  attackpath analyse      Run attack path analysis         ║",
        "║  narrative executive     Generate executive narrative     ║",
        "╠══════════════════════════════════════════════════════════╣",
        "║  SOFTWARE & APIs                                          ║",
        "║  supply components       SBOM component list              ║",
        "║  supply vulns            Known CVEs in your stack         ║",
        "║  api endpoints           API endpoint inventory           ║",
        "║  api findings            API security findings            ║",
        "╠══════════════════════════════════════════════════════════╣",
        "║  AI ASSISTANT                                             ║",
        "║  ask <question>          Natural language security query  ║",
        "║  <any sentence>          Auto-detected as natural language ║",
        "╚══════════════════════════════════════════════════════════╝",
        "",
        "  Tip: Type any question in plain English — the AI will answer it.",
        "  Example: ask what are my biggest security risks right now",
    ], render="text")


def cmd_status(args, user_id):
    """Platform-wide health overview."""
    try:
        from dashboard.backend.behavioral.models import BaAnomaly
        from dashboard.backend.complianceauto.models import CaFramework
        from dashboard.backend.apisecurity.models import AsFinding
        from dashboard.backend.supplychain.models import ScVuln
        from dashboard.backend.incidents.models import IrIncident
        from dashboard.backend.dspm.models import DspmFinding
        from dashboard.backend.identitygraph.models import IgRisk
        from dashboard.backend.netvisualizer.models import NvIssue

        anomalies   = BaAnomaly.query.filter_by(status="new").count()
        frameworks  = CaFramework.query.all()
        avg_score   = round(sum(f.score for f in frameworks) /
                            max(len(frameworks), 1), 0)
        api_crit    = AsFinding.query.filter_by(
            severity="Critical", status="open").count()
        supply_crit = ScVuln.query.filter_by(
            severity="Critical", status="open").count()
        incidents   = IrIncident.query.filter(
            IrIncident.status.notin_(["resolved","closed"])).count()
        dspm_crit   = DspmFinding.query.filter_by(
            severity="Critical", status="open").count()
        id_risks    = IgRisk.query.filter_by(
            severity="Critical", resolved=False).count()
        net_issues  = NvIssue.query.filter_by(
            severity="Critical", status="open").count()

        total_critical = (api_crit + supply_crit + dspm_crit +
                          id_risks + net_issues)

        status_icon = "🔴 CRITICAL" if total_critical > 5             else "🟡 WARNING" if total_critical > 0             else "🟢 HEALTHY"

        lines = [
            f"",
            f"  AIPET X Platform Status — {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
            f"  Overall: {status_icon}",
            f"",
            f"  ┌─────────────────────────────────────────┐",
            f"  │ MODULE                    STATUS         │",
            f"  ├─────────────────────────────────────────┤",
            f"  │ Compliance (avg)          {int(avg_score)}/100            │",
            f"  │ Behavioral Anomalies      {anomalies} new            │",
            f"  │ API Security (critical)   {api_crit} findings       │",
            f"  │ Supply Chain (critical)   {supply_crit} CVEs           │",
            f"  │ Data Security (critical)  {dspm_crit} findings       │",
            f"  │ Identity Risks (critical) {id_risks} risks          │",
            f"  │ Network Issues (critical) {net_issues} issues         │",
            f"  │ Active Incidents          {incidents} open           │",
            f"  └─────────────────────────────────────────┘",
            f"",
            f"  Total critical issues: {total_critical}",
            f"  Run 'ask what should I fix first' for AI prioritization.",
            f"",
        ]
        return _ok(lines, module="status", render="text")
    except Exception as e:
        return _err(f"Status check failed: {str(e)}")


def cmd_whoami(args, user_id):
    user = User.query.get(user_id)
    return _ok([
        f"",
        f"  User:     {user.email if user else 'Unknown'}",
        f"  Plan:     {user.plan if user else 'Unknown'}",
        f"  Session:  Zero-Trust verified · JWT authenticated",
        f"  Terminal: AIPET X Terminal v2.0",
        f"  Time:     {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"",
    ], render="text")


def cmd_identity(args, user_id):
    from dashboard.backend.identitygraph.models import IgIdentity, IgRisk
    sub = args[0] if args else "list"

    if sub == "list":
        identities = IgIdentity.query.order_by(
            IgIdentity.risk_score.desc()).all()
        rows = []
        for i in identities:
            bar, color = _risk_bar(i.risk_score, 12)
            tags = json.loads(i.tags) if i.tags else []
            tag_str = " ".join(f"[{t}]" for t in tags[:3])
            rows.append({
                "name":  i.name,
                "type":  i.identity_type,
                "risk":  i.risk_score,
                "bar":   bar,
                "color": color,
                "tags":  tag_str,
            })
        lines = [
            f"",
            f"  IDENTITY GRAPH — {len(identities)} identities",
            f"  {'NAME':<30} {'TYPE':<12} {'RISK':<6} {'SCORE BAR':<20} TAGS",
            f"  {'─'*80}",
        ]
        for r in rows:
            lines.append(
                f"  {r['name']:<30} {r['type']:<12} "
                f"{r['risk']:<6} {r['bar']:<20} {r['tags']}")
        lines.append(f"")
        return _ok(lines, module="identity",
                   data={"rows": rows}, render="table")

    elif sub == "risks":
        risks = IgRisk.query.filter_by(resolved=False).order_by(
            IgRisk.severity.desc()).all()
        lines = [f"", f"  IDENTITY RISKS — {len(risks)} open risks", f""]
        for r in risks:
            icon = "🔴" if r.severity=="Critical" else "🟡"
            identity = IgIdentity.query.get(r.identity_id)
            lines.append(f"  {icon} [{r.severity.upper()}] {r.risk_type}")
            lines.append(f"     Entity: {identity.name if identity else 'Unknown'}")
            lines.append(f"     {r.description[:80]}...")
            lines.append(f"     Fix: {r.remediation[:70]}...")
            lines.append(f"")
        return _ok(lines, module="identity", render="text")

    return _err(f"Unknown identity subcommand: {sub}. Try: list, risks")


def cmd_behavioral(args, user_id):
    from dashboard.backend.behavioral.models import BaAnomaly, BaBaseline
    sub = args[0] if args else "anomalies"

    if sub == "anomalies":
        anomalies = BaAnomaly.query.filter_by(status="new").order_by(
            BaAnomaly.deviation.desc()).limit(10).all()
        lines = [f"", f"  BEHAVIORAL ANOMALIES — {len(anomalies)} new", f""]
        for a in anomalies:
            icon = "🔴" if a.severity=="Critical" else                    "🟡" if a.severity=="High" else "🔵"
            lines.append(f"  {icon} [{a.severity}] {a.title}")
            lines.append(f"     Deviation: {a.deviation:.1f}σ · MITRE: {a.mitre_id or 'N/A'}")
            lines.append(f"     {a.description[:80]}...")
            lines.append(f"")
        if not anomalies:
            lines.append("  ✓ No new behavioral anomalies detected.")
        return _ok(lines, module="behavioral", render="text")

    elif sub == "baselines":
        baselines = BaBaseline.query.order_by(
            BaBaseline.risk_score.desc()).all()
        lines = [
            f"", f"  BEHAVIORAL BASELINES — {len(baselines)} entities",
            f"  {'ENTITY':<35} {'TYPE':<10} {'RISK':<6} {'CONF':<6} ANOMALIES",
            f"  {'─'*70}",
        ]
        for b in baselines:
            lines.append(
                f"  {b.entity_name:<35} {b.entity_type:<10} "
                f"{b.risk_score:<6} {b.confidence}%   {b.anomaly_count}")
        lines.append(f"")
        return _ok(lines, module="behavioral", render="text")

    return _err(f"Unknown subcommand: {sub}. Try: anomalies, baselines")


def cmd_compliance(args, user_id):
    from dashboard.backend.complianceauto.models import CaFramework, CaControl
    sub = args[0] if args else "status"

    if sub == "status":
        frameworks = CaFramework.query.all()
        lines = [f"", f"  COMPLIANCE STATUS — {len(frameworks)} frameworks", f""]
        for fw in frameworks:
            bar, color = _risk_bar(fw.score, 16)
            status = "✓ COMPLIANT" if fw.score >= 80                 else "⚠ PARTIAL" if fw.score >= 60 else "✗ AT RISK"
            lines.append(f"  {fw.name:<20} {bar}  {status}")
            lines.append(f"  {'':20} Passed: {fw.passed} · "
                         f"Partial: {fw.partial} · Failed: {fw.failed}")
            lines.append(f"")
        return _ok(lines, module="compliance", render="text")

    # Framework-specific
    fw_map = {
        "nis2": "NIS2 Directive", "iso": "ISO 27001",
        "soc2": "SOC 2 Type II", "nist": "NIST CSF",
    }
    fw_name = fw_map.get(sub.lower())
    if fw_name:
        fw = CaFramework.query.filter_by(name=fw_name).first()
        if not fw:
            return _err(f"Framework {fw_name} not found")
        failed = CaControl.query.filter_by(
            framework_id=fw.id, status="fail").all()
        partial= CaControl.query.filter_by(
            framework_id=fw.id, status="partial").all()
        lines  = [
            f"", f"  {fw.name} — Score: {fw.score}/100",
            f"  {'─'*60}",
            f"  FAILED CONTROLS ({len(failed)}):", f"",
        ]
        for c in failed:
            lines.append(f"  ✗ [{c.control_id}] {c.title}")
            if c.gap:
                lines.append(f"    Gap: {c.gap}")
            lines.append(f"")
        lines.append(f"  PARTIAL CONTROLS ({len(partial)}):")
        lines.append(f"")
        for c in partial[:5]:
            lines.append(f"  ◑ [{c.control_id}] {c.title}")
        lines.append(f"")
        return _ok(lines, module="compliance", render="text")

    return _err(f"Unknown subcommand: {sub}. Try: status, nis2, iso, soc2, nist")


def cmd_dspm(args, user_id):
    from dashboard.backend.dspm.models import DspmDatastore, DspmFinding
    sub = args[0] if args else "datastores"

    if sub == "datastores":
        stores = DspmDatastore.query.order_by(
            DspmDatastore.risk_score.desc()).all()
        lines = [
            f"", f"  DATA STORES — {len(stores)} discovered",
            f"  {'NAME':<28} {'SENSITIVITY':<14} {'RISK':<6} {'ENCRYPTED':<10} FINDINGS",
            f"  {'─'*75}",
        ]
        for s in stores:
            enc = "✓ Yes" if s.encrypted_at_rest else "✗ No"
            pub = " 🌐PUBLIC" if s.publicly_accessible else ""
            lines.append(
                f"  {s.name:<28} {s.sensitivity:<14} "
                f"{s.risk_score:<6} {enc:<10} {s.finding_count}{pub}")
        lines.append(f"")
        return _ok(lines, module="dspm", render="text")

    elif sub == "findings":
        findings = DspmFinding.query.filter_by(
            status="open").order_by(DspmFinding.severity).all()
        lines = [f"", f"  DSPM FINDINGS — {len(findings)} open", f""]
        for f_ in findings:
            icon = "🔴" if f_.severity=="Critical" else "🟡"
            lines.append(f"  {icon} [{f_.severity}] {f_.title}")
            lines.append(f"     Regulation: {f_.regulation or 'N/A'}")
            lines.append(f"     Fix: {(f_.remediation or '')[:70]}...")
            lines.append(f"")
        return _ok(lines, module="dspm", render="text")

    return _err(f"Unknown subcommand: {sub}. Try: datastores, findings")


def cmd_cost(args, user_id):
    from dashboard.backend.costsecurity.models import CsResource, CsRecommendation
    sub = args[0] if args else "resources"

    if sub == "resources":
        resources = CsResource.query.all()
        total_saving = sum(r.monthly_cost - r.optimised_cost for r in resources)
        lines = [
            f"", f"  CLOUD RESOURCES — {len(resources)} resources",
            f"  Total monthly saving potential: £{total_saving:,.2f}",
            f"  Annual saving potential: £{total_saving*12:,.2f}",
            f"",
            f"  {'NAME':<25} {'CLOUD':<8} {'CURRENT':<10} {'SAVING':<10} SECURITY",
            f"  {'─'*70}",
        ]
        for r in resources:
            saving = r.monthly_cost - r.optimised_cost
            sec    = "🔴" if r.security_score < 40 else                      "🟡" if r.security_score < 70 else "🟢"
            lines.append(
                f"  {r.name:<25} {r.cloud_provider:<8} "
                f"£{r.monthly_cost:<9.0f} £{saving:<9.0f} "
                f"{sec} {r.security_score}/100")
        lines.append(f"")
        return _ok(lines, module="cost", render="text")

    elif sub == "recs":
        recs = CsRecommendation.query.filter_by(
            status="open").order_by(
            CsRecommendation.monthly_saving.desc()).all()
        lines = [
            f"", f"  RECOMMENDATIONS — {len(recs)} open",
            f"  {'PRIORITY':<10} {'SAVING/MO':<12} TITLE",
            f"  {'─'*70}",
        ]
        for r in recs:
            icon = "🔴" if r.priority=="critical" else                    "🟡" if r.priority=="high" else "🔵"
            lines.append(
                f"  {icon} {r.priority:<9} £{r.monthly_saving:<11.0f} "
                f"{r.title[:45]}...")
        lines.append(f"")
        total = sum(r.monthly_saving for r in recs)
        lines.append(f"  Total: £{total:,.2f}/month · £{total*12:,.2f}/year")
        lines.append(f"")
        return _ok(lines, module="cost", render="text")

    return _err(f"Unknown subcommand: {sub}. Try: resources, recs")


def cmd_api(args, user_id):
    from dashboard.backend.apisecurity.models import AsEndpoint, AsFinding
    sub = args[0] if args else "endpoints"

    if sub == "endpoints":
        endpoints = AsEndpoint.query.order_by(
            AsEndpoint.risk_score.desc()).all()
        lines = [
            f"", f"  API ENDPOINTS — {len(endpoints)} discovered",
            f"  {'METHOD':<8} {'PATH':<35} {'AUTH':<10} {'RISK':<6} ISSUES",
            f"  {'─'*72}",
        ]
        for ep in endpoints:
            auth = "✓" if ep.authenticated else "✗ NONE"
            rl   = "✓" if ep.rate_limited  else "✗"
            icon = "🔴" if ep.risk_score>=70 else                    "🟡" if ep.risk_score>=40 else "🟢"
            lines.append(
                f"  {ep.method:<8} {ep.path:<35} {auth:<10} "
                f"{icon}{ep.risk_score:<5} {ep.finding_count} findings")
        lines.append(f"")
        return _ok(lines, module="api", render="text")

    elif sub == "findings":
        findings = AsFinding.query.filter_by(
            status="open").order_by(AsFinding.severity).all()
        lines = [f"", f"  API FINDINGS — {len(findings)} open", f""]
        for f_ in findings:
            icon = "🔴" if f_.severity=="Critical" else "🟡"
            ep   = AsEndpoint.query.get(f_.endpoint_id)
            lines.append(
                f"  {icon} [{f_.severity}] {f_.owasp_id or ''} {f_.title}")
            if ep:
                lines.append(f"     Endpoint: {ep.method} {ep.path}")
            lines.append(f"     Fix: {(f_.remediation or '')[:70]}...")
            lines.append(f"")
        return _ok(lines, module="api", render="text")

    return _err(f"Unknown subcommand: {sub}. Try: endpoints, findings")


def cmd_supply(args, user_id):
    from dashboard.backend.supplychain.models import ScComponent, ScVuln
    sub = args[0] if args else "components"

    if sub == "components":
        components = ScComponent.query.order_by(
            ScComponent.critical_vulns.desc()).all()
        lines = [
            f"", f"  SUPPLY CHAIN — {len(components)} components",
            f"  {'NAME':<25} {'VERSION':<10} {'ECOSYSTEM':<10} {'RISK':<10} CVEs",
            f"  {'─'*68}",
        ]
        for c in components:
            icon = "🔴" if c.risk_level=="critical" else                    "🟡" if c.risk_level=="high" else                    "🔵" if c.risk_level=="medium" else "🟢"
            lines.append(
                f"  {icon} {c.name:<24} {(c.version or ''):<10} "
                f"{(c.ecosystem or ''):<10} {c.risk_level:<10} "
                f"{c.vuln_count} ({c.critical_vulns} crit)")
        lines.append(f"")
        return _ok(lines, module="supply", render="text")

    elif sub == "vulns":
        vulns = ScVuln.query.filter_by(
            status="open").order_by(
            ScVuln.cvss_score.desc()).all()
        lines = [f"", f"  VULNERABILITIES — {len(vulns)} open", f""]
        for v in vulns:
            comp = ScComponent.query.get(v.component_id)
            kev  = " 🇺🇸KEV" if v.cisa_kev else ""
            exp  = " 💥EXPLOIT" if v.exploit_public else ""
            lines.append(
                f"  🔴 {v.cve_id} (CVSS {v.cvss_score}){kev}{exp}")
            lines.append(
                f"     Component: {comp.name} v{comp.version}"
                if comp else "     Component: Unknown")
            lines.append(f"     {v.title}")
            if v.fixed_version:
                lines.append(f"     Fix: Upgrade to v{v.fixed_version}")
            lines.append(f"")
        return _ok(lines, module="supply", render="text")

    return _err(f"Unknown subcommand: {sub}. Try: components, vulns")


def cmd_network(args, user_id):
    from dashboard.backend.netvisualizer.models import NvNode, NvIssue
    sub = args[0] if args else "nodes"

    if sub == "nodes":
        nodes = NvNode.query.order_by(NvNode.risk_score.desc()).all()
        lines = [
            f"", f"  NETWORK NODES — {len(nodes)} discovered",
            f"  {'NAME':<28} {'ZONE':<16} {'RISK':<6} {'INTERNET':<10} ISSUES",
            f"  {'─'*74}",
        ]
        for n in nodes:
            internet = "🌐 YES" if n.internet_facing else "No"
            enc      = "" if n.encrypted else " 🔓"
            icon     = "🔴" if n.risk_score>=70 else                        "🟡" if n.risk_score>=40 else "🟢"
            lines.append(
                f"  {icon} {n.name:<27} {n.zone:<16} "
                f"{n.risk_score:<6} {internet:<10} "
                f"{n.issue_count}{enc}")
        lines.append(f"")
        return _ok(lines, module="network", render="text")

    elif sub == "issues":
        issues = NvIssue.query.filter_by(
            status="open").order_by(NvIssue.severity).all()
        lines = [f"", f"  NETWORK ISSUES — {len(issues)} open", f""]
        for i in issues:
            icon = "🔴" if i.severity=="Critical" else "🟡"
            node = NvNode.query.get(i.node_id) if i.node_id else None
            lines.append(f"  {icon} [{i.severity}] {i.title}")
            if node:
                lines.append(f"     Node: {node.name} ({node.zone})")
            lines.append(f"     Fix: {(i.remediation or '')[:70]}...")
            lines.append(f"")
        return _ok(lines, module="network", render="text")

    return _err(f"Unknown subcommand: {sub}. Try: nodes, issues")


def cmd_timeline(args, user_id):
    from dashboard.backend.timeline.models import TimelineEvent
    events = TimelineEvent.query.filter_by(
        resolved=False).order_by(
        TimelineEvent.created_at.desc()).limit(15).all()
    lines = [f"", f"  SECURITY TIMELINE — Latest {len(events)} events", f""]
    for e in events:
        icon = "🔴" if e.severity=="Critical" else                "🟡" if e.severity=="High" else "🔵"
        age  = datetime.now(timezone.utc) - e.created_at.replace(
            tzinfo=timezone.utc)
        age_str = f"{int(age.total_seconds()/3600)}h ago"             if age.total_seconds() < 86400             else f"{int(age.days)}d ago"
        lines.append(
            f"  {icon} [{e.severity:<8}] [{e.source:<12}] {e.title[:45]}...")
        lines.append(
            f"     {age_str} · {e.entity or ''}")
        lines.append(f"")
    return _ok(lines, module="timeline", render="text")


def cmd_incidents(args, user_id):
    from dashboard.backend.incidents.models import IrIncident
    sub = args[0] if args else "list"

    if sub == "list":
        incidents = IrIncident.query.filter(
            IrIncident.status.notin_(["resolved","closed"])
        ).order_by(IrIncident.priority).all()
        lines = [
            f"", f"  INCIDENTS — {len(incidents)} active",
            f"  {'PRIORITY':<6} {'STATUS':<14} {'SLA':<12} TITLE",
            f"  {'─'*72}",
        ]
        for inc in incidents:
            d     = inc.to_dict()
            sla   = "🔴 BREACHED" if d.get("sla_breached")                 else f"{d.get('age_hours',0)}h/{inc.sla_hours}h"
            icon  = "🔴" if inc.priority=="P1" else                     "🟡" if inc.priority=="P2" else "🔵"
            lines.append(
                f"  {icon} {inc.priority:<5} {inc.status:<14} "
                f"{sla:<12} {inc.title[:35]}...")
        if not incidents:
            lines.append("  ✓ No active incidents.")
        lines.append(f"")
        return _ok(lines, module="incidents", render="text")

    return _err(f"Unknown subcommand: {sub}. Try: list")


def cmd_attackpath(args, user_id):
    from dashboard.backend.attackpath.models import ApAnalysis, ApPath
    analyses = ApAnalysis.query.order_by(
        ApAnalysis.created_at.desc()).limit(3).all()
    if not analyses:
        return _ok([
            f"",
            f"  No attack path analyses found.",
            f"  Run: attackpath analyse",
            f"",
        ], module="attackpath", render="text")

    latest = analyses[0]
    paths  = ApPath.query.filter_by(
        analysis_id=latest.id).order_by(
        ApPath.likelihood.desc()).all()

    lines = [
        f"",
        f"  ATTACK PATHS — Latest analysis: {latest.name}",
        f"  {latest.total_paths} paths found · "
        f"{latest.critical_paths} critical · "
        f"Max depth: {latest.max_depth}",
        f"",
        f"  {'ENTRY':<22} {'TARGET':<22} {'SEVERITY':<10} {'LIKELIHOOD':<12} HOPS",
        f"  {'─'*75}",
    ]
    for p in paths:
        icon = "🔴" if p.severity=="Critical" else "🟡"
        blocked = " [BLOCKED]" if p.blocked else ""
        lines.append(
            f"  {icon} {p.entry_point:<21} → {p.target:<21} "
            f"{p.severity:<10} {p.likelihood}%{'':<8} "
            f"{p.hops}{blocked}")
    lines.append(f"")
    return _ok(lines, module="attackpath", render="text")


def cmd_ask(args, user_id):
    """
    AI Knowledge Assistant — Claude answers security questions
    using context from all AIPET modules.
    """
    if not args:
        return _err("Usage: ask <your question>")

    question = " ".join(args)

    # Build security context for Claude
    try:
        from dashboard.backend.behavioral.models import BaAnomaly
        from dashboard.backend.complianceauto.models import CaFramework
        from dashboard.backend.apisecurity.models import AsFinding
        from dashboard.backend.supplychain.models import ScVuln
        from dashboard.backend.incidents.models import IrIncident
        from dashboard.backend.dspm.models import DspmFinding
        from dashboard.backend.identitygraph.models import IgRisk

        anomaly_count = BaAnomaly.query.filter_by(status="new").count()
        frameworks    = CaFramework.query.all()
        avg_score     = round(sum(f.score for f in frameworks) /
                              max(len(frameworks), 1), 0)
        api_crit      = AsFinding.query.filter_by(
            severity="Critical", status="open").count()
        supply_kev    = ScVuln.query.filter_by(
            cisa_kev=True, status="open").count()
        open_incidents= IrIncident.query.filter(
            IrIncident.status.notin_(["resolved","closed"])).count()
        dspm_public   = DspmFinding.query.filter_by(
            finding_type="public_exposure", status="open").count()
        id_critical   = IgRisk.query.filter_by(
            severity="Critical", resolved=False).count()

        context = f"""You are AIPET X — an AI-powered enterprise IoT security platform.

Current security posture:
- Behavioral anomalies (new): {anomaly_count}
- Compliance average score: {avg_score}/100
- API security critical findings: {api_crit}
- CISA KEV vulnerabilities in supply chain: {supply_kev}
- Active security incidents: {open_incidents}
- Public data exposure findings: {dspm_public}
- Critical identity risks: {id_critical}

The user is a security professional asking:
{question}

Answer in 3-5 concise lines. Be specific and actionable.
Reference the actual numbers above when relevant.
Do not use markdown headers or bullet points — use plain text.
Start directly with the answer."""

        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not api_key:
            return _err("ANTHROPIC_API_KEY not configured")

        payload = json.dumps({
            "model":      "claude-opus-4-5",
            "max_tokens": 400,
            "messages":   [{"role": "user", "content": context}],
        }).encode("utf-8")

        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=payload,
            headers={
                "x-api-key":         api_key,
                "anthropic-version": "2023-06-01",
                "content-type":      "application/json",
            }, method="POST"
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read().decode("utf-8"))
            answer = result["content"][0]["text"]

        lines = [f"", f"  [AI] {question}", f"  {'─'*60}", f""]
        for line in answer.split("\n"):
            if line.strip():
                lines.append(f"  {line}")
        lines.append(f"")
        return _ok(lines, module="ask", render="text")

    except Exception as e:
        return _err(f"AI assistant error: {str(e)}")


def cmd_audit(args, user_id):
    logs = TerminalAuditLog.query.filter_by(
        user_id=user_id).order_by(
        TerminalAuditLog.created_at.desc()).limit(20).all()
    lines = [
        f"", f"  AUDIT LOG — Last {len(logs)} commands",
        f"  {'TIME':<20} {'MODULE':<14} {'COMMAND':<30} STATUS",
        f"  {'─'*72}",
    ]
    for log in logs:
        t      = log.created_at.strftime("%Y-%m-%d %H:%M")
        status = "✓" if log.success else "✗"
        lines.append(
            f"  {t:<20} {(log.module or ''):<14} "
            f"{(log.raw_input or '')[:29]:<30} {status}")
    lines.append(f"")
    return _ok(lines, module="audit", render="text")


def cmd_narrative(args, user_id):
    from dashboard.backend.narrative.models import RiskNarrative
    sub      = args[0] if args else "executive"
    audience = sub if sub in ("executive","board","technical","compliance")                else "executive"
    narratives = RiskNarrative.query.filter_by(
        audience=audience).order_by(
        RiskNarrative.created_at.desc()).first()
    if narratives:
        lines = [
            f"", f"  RISK NARRATIVE — {audience.upper()}",
            f"  Risk Score: {narratives.risk_score}/100",
            f"  Generated: {narratives.created_at.strftime('%Y-%m-%d %H:%M')}",
            f"  {'─'*60}", f"",
        ]
        for para in narratives.narrative[:800].split("\n"):
            if para.strip():
                lines.append(f"  {para[:75]}")
        lines.append(f"")
        lines.append(f"  ... Run 'narrative {audience}' in the UI for full report")
        lines.append(f"")
    else:
        lines = [
            f"",
            f"  No {audience} narrative generated yet.",
            f"  Go to Risk Narrative → Generate to create one.",
            f"",
        ]
    return _ok(lines, module="narrative", render="text")


def cmd_siem(args, user_id):
    from dashboard.backend.siem.models import SiemEvent
    sub    = args[0] if args else "events"
    events = SiemEvent.query.order_by(
        SiemEvent.created_at.desc()).limit(10).all()
    lines  = [f"", f"  SIEM — Latest {len(events)} events", f""]
    for e in events:
        icon = "🔴" if e.severity=="Critical" else                "🟡" if e.severity=="High" else "🔵"
        t    = e.created_at.strftime("%H:%M")
        lines.append(f"  {icon} [{t}] [{e.severity:<8}] {e.title[:50]}...")
    lines.append(f"")
    return _ok(lines, module="siem", render="text")


# ── Natural language processor ────────────────────────────────

def _nl_to_command(text):
    """
    Use Claude to translate natural language to a terminal command.
    Returns: (command_string, explanation)
    """
    nl_prompt = f"""You are an AIPET X terminal assistant.
Convert this natural language query to an AIPET terminal command.

Available commands:
help, status, whoami, identity list, identity risks,
behavioral anomalies, behavioral baselines,
compliance status, compliance nis2, compliance iso, compliance soc2, compliance nist,
dspm datastores, dspm findings,
cost resources, cost recs,
api endpoints, api findings,
supply components, supply vulns,
network nodes, network issues,
timeline, incidents list,
attackpath, narrative executive, narrative board, narrative technical,
audit, ask <question>

Query: {text}

Reply with ONLY the command on line 1, nothing else.
If it cannot be mapped to a command, write: ask {text}
Examples:
"show me all risks" → status
"what CVEs do I have" → supply vulns
"list my APIs" → api endpoints
"how compliant am I" → compliance status"""

    try:
        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        payload = json.dumps({
            "model":      "claude-opus-4-5",
            "max_tokens": 50,
            "messages":   [{"role":"user","content":nl_prompt}],
        }).encode("utf-8")
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=payload,
            headers={
                "x-api-key":         api_key,
                "anthropic-version": "2023-06-01",
                "content-type":      "application/json",
            }, method="POST"
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            result = json.loads(resp.read().decode("utf-8"))
            cmd    = result["content"][0]["text"].strip().split("\n")[0]
            return cmd
    except Exception:
        return f"ask {text}"


# ── Command dispatcher ────────────────────────────────────────

COMMANDS = {
    "help":       cmd_help,
    "status":     cmd_status,
    "whoami":     cmd_whoami,
    "identity":   cmd_identity,
    "behavioral": cmd_behavioral,
    "compliance": cmd_compliance,
    "dspm":       cmd_dspm,
    "cost":       cmd_cost,
    "api":        cmd_api,
    "supply":     cmd_supply,
    "network":    cmd_network,
    "timeline":   cmd_timeline,
    "incidents":  cmd_incidents,
    "attackpath": cmd_attackpath,
    "ask":        cmd_ask,
    "audit":      cmd_audit,
    "narrative":  cmd_narrative,
    "siem":       cmd_siem,
}


# ── API Endpoints ─────────────────────────────────────────────

@terminal_bp.route("/api/terminal/command", methods=["POST"])
@jwt_required()
def execute_command():
    """
    Execute a terminal command.
    Zero-Trust: every command is JWT-verified and audit-logged.
    """
    start   = time.time()
    user_id = int(get_jwt_identity())
    data    = request.get_json(silent=True) or {}
    raw     = data.get("command", "").strip()

    if not raw:
        return jsonify(_err("Empty command"))

    # Parse command
    parts  = raw.split()
    cmd    = parts[0].lower() if parts else ""
    args   = parts[1:] if len(parts) > 1 else []

    # Handle clear — client-side
    if cmd == "clear":
        return jsonify({
            "success": True,
            "module":  "terminal",
            "render":  "clear",
            "lines":   [],
            "data":    {},
        })

    # Dispatch to handler
    handler = COMMANDS.get(cmd)
    if handler:
        try:
            result      = handler(args, user_id)
            duration_ms = int((time.time() - start) * 1000)
            _audit(user_id, raw, cmd, result.get("module","terminal"),
                   success=True, duration_ms=duration_ms)
            return jsonify(result)
        except Exception as e:
            duration_ms = int((time.time() - start) * 1000)
            _audit(user_id, raw, cmd, "terminal",
                   success=False, error=str(e), duration_ms=duration_ms)
            return jsonify(_err(f"Command failed: {str(e)}"))
    else:
        # Unknown command — try natural language
        _audit(user_id, raw, "nl_detect", "terminal")
        return jsonify({
            "success": True,
            "module":  "terminal",
            "render":  "nl_detect",
            "lines":   [raw],
            "data":    {"original": raw},
        })


@terminal_bp.route("/api/terminal/nl", methods=["POST"])
@jwt_required()
def natural_language():
    """
    Translate natural language to command and execute it.
    Called after user confirms NL detection.
    """
    user_id = int(get_jwt_identity())
    data    = request.get_json(silent=True) or {}
    text    = data.get("text", "").strip()

    if not text:
        return jsonify(_err("Empty input"))

    # Translate to command
    cmd_str = _nl_to_command(text)

    # Execute the translated command
    parts   = cmd_str.split()
    cmd     = parts[0].lower() if parts else ""
    args    = parts[1:] if len(parts) > 1 else []

    handler = COMMANDS.get(cmd)
    if handler:
        try:
            result = handler(args, user_id)
            result["nl_translated"] = cmd_str
            _audit(user_id, text, cmd_str, result.get("module","terminal"),
                   success=True)
            return jsonify(result)
        except Exception as e:
            return jsonify(_err(f"Command failed: {str(e)}"))

    return jsonify(_err(f"Could not process: {text}"))


@terminal_bp.route("/api/terminal/history", methods=["GET"])
@jwt_required()
def command_history():
    user_id = int(get_jwt_identity())
    logs    = TerminalAuditLog.query.filter_by(
        user_id=user_id).order_by(
        TerminalAuditLog.created_at.desc()).limit(50).all()
    return jsonify({
        "history": [log.raw_input for log in reversed(logs)
                    if log.success]
    })


@terminal_bp.route("/api/terminal/suggest", methods=["POST"])
@jwt_required()
def suggest():
    """Autocomplete suggestions based on partial input."""
    data    = request.get_json(silent=True) or {}
    partial = data.get("partial", "").lower()
    all_cmds= [
        "help", "status", "whoami", "clear", "audit",
        "identity list", "identity risks",
        "behavioral anomalies", "behavioral baselines",
        "compliance status", "compliance nis2",
        "compliance iso", "compliance soc2", "compliance nist",
        "dspm datastores", "dspm findings",
        "cost resources", "cost recs",
        "api endpoints", "api findings",
        "supply components", "supply vulns",
        "network nodes", "network issues",
        "timeline", "incidents list",
        "attackpath", "narrative executive",
        "narrative board", "narrative technical",
        "siem events", "ask ",
    ]
    matches = [c for c in all_cmds if c.startswith(partial)][:6]
    return jsonify({"suggestions": matches})
