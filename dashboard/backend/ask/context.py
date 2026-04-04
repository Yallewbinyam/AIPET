"""
AIPET Ask — Security Context Builder
Gathers all relevant security data for a user and builds
a structured context document for Claude.

The quality of Claude's answers depends entirely on the
quality of this context. We gather everything AIPET knows
about the user's specific network situation.

Usage:
    from dashboard.backend.ask.context import build_context
    context = build_context(user_id, db)
"""

from datetime import datetime, timezone


def build_context(user_id, db_session):
    """
    Builds a complete security context document for a user.

    Queries all relevant tables and assembles the data into
    a structured text document that Claude can reason about.

    Args:
        user_id (int): The current user's ID
        db_session: SQLAlchemy database session

    Returns:
        str: A structured context document
    """
    from dashboard.backend.models import (
        User, Scan, Finding, DeviceTag,
        ScoreResult, PredictAlert, WatchBaseline, WatchAlert,
        ExplainResult
    )

    # Load user
    user = User.query.get(user_id)
    if not user:
        return "No user data available."

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    sections = []

    # ── Header ────────────────────────────────────────────────────────────
    sections.append(f"""AIPET SECURITY CONTEXT REPORT
Generated: {now}
User: {user.name} | Plan: {user.plan.upper()}
""")

    # ── Scan Summary ──────────────────────────────────────────────────────
    latest_scan = Scan.query.filter(
        Scan.user_id == user_id,
        Scan.status.in_(["completed", "complete"])
    ).order_by(Scan.id.desc()).first()

    if latest_scan:
        findings = Finding.query.filter_by(scan_id=latest_scan.id).all()
        critical = sum(1 for f in findings if f.severity == "Critical")
        high     = sum(1 for f in findings if f.severity == "High")
        medium   = sum(1 for f in findings if f.severity == "Medium")
        low      = sum(1 for f in findings if f.severity == "Low")
        fixed    = sum(1 for f in findings if f.fix_status == "fixed")
        open_cnt = sum(1 for f in findings if f.fix_status == "open")

        risk_level = "CRITICAL" if critical >= 1 else "HIGH" if high >= 1 else "MEDIUM" if medium >= 1 else "LOW"

        sections.append(f"""SCAN SUMMARY
Last scan: {str(latest_scan.created_at)[:10]}
Total findings: {len(findings)} | Critical: {critical} | High: {high} | Medium: {medium} | Low: {low}
Fixed: {fixed} | Open: {open_cnt}
Overall risk level: {risk_level}
Scan target: {latest_scan.target}
""")
    else:
        findings = []
        sections.append("SCAN SUMMARY\nNo completed scans found.\n")

    # ── Device Inventory ──────────────────────────────────────────────────
    tags     = DeviceTag.query.filter_by(user_id=user_id).all()
    tag_map  = {t.device_ip: t.business_function for t in tags}
    industry = tags[0].industry if tags else "General Business"

    if findings:
        # Group findings by device
        devices = {}
        for f in findings:
            if f.target not in devices:
                devices[f.target] = []
            devices[f.target].append(f)

        device_lines = ["DEVICE INVENTORY"]
        for ip, device_findings in devices.items():
            function    = tag_map.get(ip, "Unknown")
            worst_sev   = "Low"
            sev_rank    = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
            for f in device_findings:
                if sev_rank.get(f.severity, 0) > sev_rank.get(worst_sev, 0):
                    worst_sev = f.severity
            risk_score  = min(sum({"Critical": 25, "High": 15, "Medium": 8, "Low": 3}.get(f.severity, 1)
                                  for f in device_findings), 100)
            device_lines.append(f"{ip} — {function} — Risk: {risk_score} — Worst: {worst_sev}")
            for f in device_findings:
                status_note = "✓ FIXED" if f.fix_status == "fixed" else f.fix_status.upper()
                device_lines.append(f"  • {f.attack} ({f.severity}) [{status_note}]")

        sections.append("\n".join(device_lines) + "\n")
    else:
        sections.append("DEVICE INVENTORY\nNo device data available.\n")

    # ── Financial Risk ────────────────────────────────────────────────────
    score = ScoreResult.query.filter_by(user_id=user_id).order_by(
        ScoreResult.id.desc()
    ).first()

    if score:
        breakdown  = score.findings_breakdown or []
        top_risks  = sorted(breakdown, key=lambda x: x.get("exposure_gbp", 0), reverse=True)[:3]
        risk_lines = [f"FINANCIAL RISK EXPOSURE",
                      f"Industry: {score.industry}",
                      f"Total exposure: £{score.total_exposure_gbp:,}",
                      "Top financial risks:"]
        for r in top_risks:
            risk_lines.append(f"  • {r.get('attack')} on {r.get('target')}: £{r.get('exposure_gbp', 0):,} ({r.get('severity')})")
        sections.append("\n".join(risk_lines) + "\n")
    else:
        sections.append(f"FINANCIAL RISK EXPOSURE\nIndustry: {industry}\nNo financial score calculated yet.\n")

    # ── CVE Intelligence ──────────────────────────────────────────────────
    cve_alerts = PredictAlert.query.filter_by(
        user_id=user_id, is_reviewed=False
    ).order_by(PredictAlert.cvss_score.desc()).limit(5).all()

    if cve_alerts:
        cve_lines = [f"CVE INTELLIGENCE", f"Active CVE alerts: {len(cve_alerts)} (unreviewed)"]
        for alert in cve_alerts:
            affected = [d.get("ip") for d in (alert.affected_devices or [])]
            affected_str = ", ".join(affected) if affected else "unknown devices"
            cve_lines.append(
                f"  • {alert.cve_id} (CVSS {alert.cvss_score}, {alert.severity}) — "
                f"Weaponisation: {alert.weaponisation_pct}% — Affects: {affected_str}"
            )
        sections.append("\n".join(cve_lines) + "\n")
    else:
        sections.append("CVE INTELLIGENCE\nNo active CVE alerts.\n")

    # ── Watch Status ──────────────────────────────────────────────────────
    baselines    = WatchBaseline.query.filter_by(user_id=user_id, is_active=True).all()
    watch_alerts = WatchAlert.query.filter_by(
        user_id=user_id, is_acknowledged=False
    ).order_by(WatchAlert.created_at.desc()).limit(5).all()

    watch_lines = [f"WATCH STATUS", f"Devices monitored: {len(baselines)}"]
    if watch_alerts:
        watch_lines.append(f"Unacknowledged alerts: {len(watch_alerts)}")
        for wa in watch_alerts:
            watch_lines.append(f"  • [{wa.severity}] {wa.description}")
    else:
        watch_lines.append("Network status: All Clear — no anomalies detected")
    sections.append("\n".join(watch_lines) + "\n")

    # ── Attack Paths ──────────────────────────────────────────────────────
    if findings and tags:
        from dashboard.backend.map.graph import build_graph
        findings_data = [f.to_dict() for f in findings]
        graph         = build_graph(findings_data, tag_map)
        attack_paths  = graph.get("attack_paths", [])
        recommendations = graph.get("recommendations", [])

        if attack_paths:
            path_lines = [f"ATTACK PATHS", f"{len(attack_paths)} attack paths detected:"]
            for p in attack_paths[:3]:
                path_lines.append(f"  • {' → '.join(p['path'])} (target: {p['target_function']})")
            if recommendations:
                path_lines.append("Priority fixes to break attack paths:")
                for r in recommendations[:3]:
                    path_lines.append(f"  • Fix {r['finding']} on {r['device']} — breaks {r['paths_broken']} path(s)")
            sections.append("\n".join(path_lines) + "\n")
        else:
            sections.append("ATTACK PATHS\nNo attack paths detected with current device tags.\n")
    else:
        sections.append("ATTACK PATHS\nInsufficient data for attack path analysis.\n")

    # ── Remediation Progress ──────────────────────────────────────────────
    if findings:
        total    = len(findings)
        fixed    = sum(1 for f in findings if f.fix_status == "fixed")
        in_prog  = sum(1 for f in findings if f.fix_status == "in_progress")
        accepted = sum(1 for f in findings if f.fix_status == "accepted_risk")
        open_f   = sum(1 for f in findings if f.fix_status == "open")

        sev_weights  = {"Critical": 20, "High": 10, "Medium": 5, "Low": 2}
        total_risk   = sum(sev_weights.get(f.severity, 5) for f in findings)
        reduced_risk = sum(sev_weights.get(f.severity, 5) for f in findings
                          if f.fix_status in ["fixed", "accepted_risk"])
        pct = round((reduced_risk / total_risk * 100), 1) if total_risk > 0 else 0

        sections.append(f"""REMEDIATION PROGRESS
Total findings: {total} | Fixed: {fixed} | In Progress: {in_prog} | Accepted Risk: {accepted} | Open: {open_f}
Risk reduction: {pct}% achieved
""")

    # ── Combine all sections ──────────────────────────────────────────────
    return "\n".join(sections)