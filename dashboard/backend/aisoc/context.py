"""
AIPET X — AI SOC Context Builder

Aggregates live data from all AIPET X modules into a single
structured context string that Claude uses to answer SOC questions.

Data sources:
  • SIEM:             recent events + open incidents
  • Threat Intel:     recent matches + IOC count
  • Zero-Trust:       device trust scores + quarantined devices
  • Autonomous Defense: recent actions + active playbooks
  • Core AIPET:       latest scan findings + risk scores
"""
from datetime import datetime, timezone, timedelta
from dashboard.backend.models import db, Scan, Finding


def build_soc_context():
    """
    Build a comprehensive security context snapshot.
    Called before every Claude API request in the AI SOC.

    Returns a structured string summarising the current
    security posture across all AIPET X modules.
    """
    now   = datetime.now(timezone.utc)
    today = now.replace(hour=0, minute=0, second=0, microsecond=0)
    lines = []

    lines.append("=== AIPET X SECURITY OPERATIONS CONTEXT ===")
    lines.append(f"Generated: {now.strftime('%Y-%m-%d %H:%M UTC')}")
    lines.append("")

    # ── SIEM summary ─────────────────────────────────────────
    try:
        from dashboard.backend.siem.models import SiemEvent, SiemIncident
        total_events   = SiemEvent.query.filter(
            SiemEvent.created_at >= today).count()
        critical_events= SiemEvent.query.filter(
            SiemEvent.created_at >= today,
            SiemEvent.severity == "Critical").count()
        unacked        = SiemEvent.query.filter_by(
            acknowledged=False).count()
        open_incidents = SiemIncident.query.filter_by(status="open").count()
        inv_incidents  = SiemIncident.query.filter_by(
            status="investigating").count()

        lines.append("--- SIEM STATUS ---")
        lines.append(f"Events today: {total_events} ({critical_events} Critical)")
        lines.append(f"Unacknowledged events: {unacked}")
        lines.append(f"Open incidents: {open_incidents} | Investigating: {inv_incidents}")

        # Most recent critical events
        recent_critical = SiemEvent.query.filter(
            SiemEvent.severity.in_(["Critical", "High"])
        ).order_by(SiemEvent.created_at.desc()).limit(5).all()
        if recent_critical:
            lines.append("Recent Critical/High events:")
            for e in recent_critical:
                lines.append(
                    f"  [{e.severity}] {e.title}"
                    f" | MITRE:{e.mitre_id or 'N/A'}"
                    f" | {e.created_at.strftime('%H:%M') if e.created_at else 'unknown'}"
                )

        # Open incidents detail
        incidents = SiemIncident.query.filter(
            SiemIncident.status.in_(["open", "investigating"])
        ).order_by(SiemIncident.created_at.desc()).limit(3).all()
        if incidents:
            lines.append("Active incidents:")
            for i in incidents:
                lines.append(
                    f"  [{i.severity}] {i.title} | Status:{i.status}"
                )
        lines.append("")
    except Exception as ex:
        lines.append(f"SIEM: unavailable ({ex})")
        lines.append("")

    # ── Threat Intel summary ──────────────────────────────────
    try:
        from dashboard.backend.threatintel.models import IocEntry, ThreatMatch
        total_iocs     = IocEntry.query.filter_by(active=True).count()
        matches_today  = ThreatMatch.query.filter(
            ThreatMatch.created_at >= today).count()
        critical_matches= ThreatMatch.query.filter(
            ThreatMatch.created_at >= today,
            ThreatMatch.severity == "Critical").count()

        lines.append("--- THREAT INTELLIGENCE ---")
        lines.append(f"IOC database: {total_iocs} active indicators")
        lines.append(
            f"Threat matches today: {matches_today}"
            f" ({critical_matches} Critical)")

        recent_matches = ThreatMatch.query.order_by(
            ThreatMatch.created_at.desc()).limit(3).all()
        if recent_matches:
            lines.append("Recent threat matches:")
            for m in recent_matches:
                lines.append(
                    f"  [{m.severity}] {m.matched_value}"
                    f" | {m.threat_type} | confidence:{m.confidence}%"
                )
        lines.append("")
    except Exception as ex:
        lines.append(f"Threat Intel: unavailable ({ex})")
        lines.append("")

    # ── Zero-Trust summary ────────────────────────────────────
    try:
        from dashboard.backend.zerotrust.models import ZtDeviceTrust
        quarantined = ZtDeviceTrust.query.filter_by(
            status="quarantined").all()
        restricted  = ZtDeviceTrust.query.filter_by(
            status="restricted").all()
        monitored   = ZtDeviceTrust.query.filter_by(
            status="monitored").count()
        trusted     = ZtDeviceTrust.query.filter_by(
            status="trusted").count()

        lines.append("--- ZERO-TRUST DEVICE STATUS ---")
        lines.append(
            f"Trusted:{trusted} | Monitored:{monitored}"
            f" | Restricted:{len(restricted)}"
            f" | Quarantined:{len(quarantined)}"
        )

        if quarantined:
            lines.append("QUARANTINED devices (no network access):")
            for d in quarantined:
                lines.append(
                    f"  {d.device_ip} ({d.device_name or 'unknown'})"
                    f" trust_score:{d.trust_score}"
                )

        if restricted:
            lines.append("Restricted devices (limited access):")
            for d in restricted[:3]:
                lines.append(
                    f"  {d.device_ip} ({d.device_name or 'unknown'})"
                    f" trust_score:{d.trust_score}"
                )
        lines.append("")
    except Exception as ex:
        lines.append(f"Zero-Trust: unavailable ({ex})")
        lines.append("")

    # ── Autonomous Defense summary ────────────────────────────
    try:
        from dashboard.backend.defense.models import DefensePlaybook, DefenseAction
        active_pbs     = DefensePlaybook.query.filter_by(enabled=True).count()
        actions_today  = DefenseAction.query.filter(
            DefenseAction.created_at >= today).count()
        quarantines    = DefenseAction.query.filter(
            DefenseAction.created_at >= today,
            DefenseAction.action_type == "quarantine_device").count()

        lines.append("--- AUTONOMOUS DEFENSE ---")
        lines.append(
            f"Active playbooks: {active_pbs}"
            f" | Actions today: {actions_today}"
            f" | Auto-quarantines: {quarantines}"
        )

        recent_actions = DefenseAction.query.order_by(
            DefenseAction.created_at.desc()).limit(3).all()
        if recent_actions:
            lines.append("Recent autonomous actions:")
            for a in recent_actions:
                lines.append(
                    f"  [{a.status.upper()}] {a.action_type}"
                    f" on {a.target} | {a.outcome}"
                )
        lines.append("")
    except Exception as ex:
        lines.append(f"Autonomous Defense: unavailable ({ex})")
        lines.append("")

    # ── Core AIPET scan summary ───────────────────────────────
    try:
        latest_scan = Scan.query.order_by(
            Scan.created_at.desc()).first()
        if latest_scan:
            findings = Finding.query.filter_by(
                scan_id=latest_scan.id).all()
            sev_counts = {}
            for f in findings:
                sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1

            lines.append("--- LATEST SCAN RESULTS ---")
            lines.append(
                f"Scan ID:{latest_scan.id}"
                f" | Target:{latest_scan.target}"
                f" | Risk:{latest_scan.risk_level}"
                f" | Devices:{latest_scan.device_count}"
            )
            lines.append(
                f"Findings: "
                + " | ".join(
                    f"{s}:{c}" for s, c in sev_counts.items()
                )
            )

            # Top findings
            top_findings = Finding.query.filter_by(
                scan_id=latest_scan.id
            ).filter(
                Finding.severity.in_(["Critical", "High"])
            ).limit(5).all()
            if top_findings:
                lines.append("Top Critical/High findings:")
                for f in top_findings:
                    lines.append(
                        f"  [{f.severity}] {f.attack}"
                        f" on {f.target}"
                    )
        lines.append("")
    except Exception as ex:
        lines.append(f"Scan data: unavailable ({ex})")
        lines.append("")

    lines.append("=== END CONTEXT ===")
    return "\n".join(lines)
