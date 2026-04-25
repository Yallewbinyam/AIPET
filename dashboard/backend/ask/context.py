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
    Each section is wrapped in try/except so a missing table
    never crashes the whole build.

    Args:
        user_id (int): The current user's ID
        db_session: SQLAlchemy database session (unused — kept for compat)

    Returns:
        str: A structured context document
    """
    from dashboard.backend.models import (
        User, Scan, Finding, DeviceTag,
        ScoreResult, PredictAlert, WatchBaseline, WatchAlert,
        ExplainResult
    )

    user = User.query.get(user_id)
    if not user:
        return "No user data available."

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    sections = []

    # ── Header ────────────────────────────────────────────────────────────────
    sections.append(f"""AIPET SECURITY CONTEXT REPORT
Generated: {now}
User: {user.name} | Plan: {user.plan.upper()}
""")

    # ── Phase 1 Scan Summary (legacy scanner) ─────────────────────────────────
    try:
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
            risk_level = ("CRITICAL" if critical else "HIGH" if high
                          else "MEDIUM" if medium else "LOW")
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
    except Exception:
        findings = []
        sections.append("SCAN SUMMARY\nUnavailable.\n")

    # ── Phase 2 Real Scanner Summary (nmap-based) ─────────────────────────────
    try:
        from dashboard.backend.real_scanner.routes import RealScanResult
        import json as _json

        real_scans = (RealScanResult.query
                      .filter_by(user_id=user_id, status="complete")
                      .order_by(RealScanResult.finished_at.desc())
                      .limit(3).all())

        if real_scans:
            lines = ["NMAP SCAN RESULTS (most recent 3)"]
            for rs in real_scans:
                hosts = _json.loads(rs.results_json or "[]")
                lines.append(
                    f"Target: {rs.target} | Hosts found: {rs.hosts_found} "
                    f"| CVEs matched: {rs.cve_count} "
                    f"| Scanned: {str(rs.finished_at)[:16] if rs.finished_at else 'unknown'}"
                )
                for h in hosts[:5]:
                    ip = h.get("ip", "?")
                    ports = h.get("port_count", 0)
                    cves  = h.get("cve_count", 0)
                    risk  = h.get("risk_score", 0)
                    lines.append(f"  {ip} — {ports} open ports, {cves} CVEs, risk score {risk}")
            sections.append("\n".join(lines) + "\n")
        else:
            sections.append("NMAP SCAN RESULTS\nNo completed nmap scans found.\n")
    except Exception:
        sections.append("NMAP SCAN RESULTS\nUnavailable.\n")

    # ── Device Inventory (Phase 1 findings) ───────────────────────────────────
    try:
        tags    = DeviceTag.query.filter_by(user_id=user_id).all()
        tag_map = {t.device_ip: t.business_function for t in tags}
        industry = tags[0].industry if tags else "General Business"

        if findings:
            devices = {}
            for f in findings:
                devices.setdefault(f.target, []).append(f)

            lines = ["DEVICE INVENTORY"]
            for ip, dev_findings in devices.items():
                function  = tag_map.get(ip, "Unknown")
                sev_rank  = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
                worst_sev = max(dev_findings, key=lambda f: sev_rank.get(f.severity, 0)).severity
                risk_score = min(sum(
                    {"Critical": 25, "High": 15, "Medium": 8, "Low": 3}.get(f.severity, 1)
                    for f in dev_findings), 100)
                lines.append(f"{ip} — {function} — Risk: {risk_score} — Worst: {worst_sev}")
                for f in dev_findings:
                    status_note = "✓ FIXED" if f.fix_status == "fixed" else f.fix_status.upper()
                    lines.append(f"  • {f.attack} ({f.severity}) [{status_note}]")
            sections.append("\n".join(lines) + "\n")
        else:
            sections.append("DEVICE INVENTORY\nNo device data available.\n")
    except Exception:
        sections.append("DEVICE INVENTORY\nUnavailable.\n")

    # ── Financial Risk ────────────────────────────────────────────────────────
    try:
        score = ScoreResult.query.filter_by(user_id=user_id).order_by(
            ScoreResult.id.desc()).first()
        if score:
            breakdown = score.findings_breakdown or []
            top_risks = sorted(breakdown, key=lambda x: x.get("exposure_gbp", 0), reverse=True)[:3]
            lines = [
                "FINANCIAL RISK EXPOSURE",
                f"Industry: {score.industry}",
                f"Total exposure: £{score.total_exposure_gbp:,}",
                "Top financial risks:",
            ]
            for r in top_risks:
                lines.append(
                    f"  • {r.get('attack')} on {r.get('target')}: "
                    f"£{r.get('exposure_gbp', 0):,} ({r.get('severity')})"
                )
            sections.append("\n".join(lines) + "\n")
        else:
            sections.append("FINANCIAL RISK EXPOSURE\nNo financial score calculated yet.\n")
    except Exception:
        sections.append("FINANCIAL RISK EXPOSURE\nUnavailable.\n")

    # ── CVE Intelligence ──────────────────────────────────────────────────────
    try:
        cve_alerts = (PredictAlert.query
                      .filter_by(user_id=user_id, is_reviewed=False)
                      .order_by(PredictAlert.cvss_score.desc())
                      .limit(5).all())
        if cve_alerts:
            lines = [f"CVE INTELLIGENCE",
                     f"Active CVE alerts: {len(cve_alerts)} (unreviewed)"]
            for alert in cve_alerts:
                affected = [d.get("ip") for d in (alert.affected_devices or [])]
                lines.append(
                    f"  • {alert.cve_id} (CVSS {alert.cvss_score}, {alert.severity}) — "
                    f"Weaponisation: {alert.weaponisation_pct}% — Affects: {', '.join(affected) or 'unknown'}"
                )
            sections.append("\n".join(lines) + "\n")
        else:
            sections.append("CVE INTELLIGENCE\nNo active CVE alerts.\n")
    except Exception:
        sections.append("CVE INTELLIGENCE\nUnavailable.\n")

    # ── Watch Status ──────────────────────────────────────────────────────────
    try:
        baselines    = WatchBaseline.query.filter_by(user_id=user_id, is_active=True).all()
        watch_alerts = (WatchAlert.query
                        .filter_by(user_id=user_id, is_acknowledged=False)
                        .order_by(WatchAlert.created_at.desc())
                        .limit(5).all())
        lines = [f"WATCH STATUS", f"Devices monitored: {len(baselines)}"]
        if watch_alerts:
            lines.append(f"Unacknowledged alerts: {len(watch_alerts)}")
            for wa in watch_alerts:
                lines.append(f"  • [{wa.severity}] {wa.description}")
        else:
            lines.append("Network status: All Clear — no anomalies detected")
        sections.append("\n".join(lines) + "\n")
    except Exception:
        sections.append("WATCH STATUS\nUnavailable.\n")

    # ── Attack Paths ──────────────────────────────────────────────────────────
    try:
        if findings and tags:
            from dashboard.backend.map.graph import build_graph
            graph        = build_graph([f.to_dict() for f in findings], tag_map)
            attack_paths = graph.get("attack_paths", [])
            recs         = graph.get("recommendations", [])
            if attack_paths:
                lines = [f"ATTACK PATHS", f"{len(attack_paths)} attack paths detected:"]
                for p in attack_paths[:3]:
                    lines.append(f"  • {' → '.join(p['path'])} (target: {p['target_function']})")
                if recs:
                    lines.append("Priority fixes to break attack paths:")
                    for r in recs[:3]:
                        lines.append(f"  • Fix {r['finding']} on {r['device']} — breaks {r['paths_broken']} path(s)")
                sections.append("\n".join(lines) + "\n")
            else:
                sections.append("ATTACK PATHS\nNo attack paths detected with current device tags.\n")
        else:
            sections.append("ATTACK PATHS\nInsufficient data for attack path analysis.\n")
    except Exception:
        sections.append("ATTACK PATHS\nUnavailable.\n")

    # ── Remediation Progress ──────────────────────────────────────────────────
    try:
        if findings:
            total    = len(findings)
            fixed    = sum(1 for f in findings if f.fix_status == "fixed")
            in_prog  = sum(1 for f in findings if f.fix_status == "in_progress")
            accepted = sum(1 for f in findings if f.fix_status == "accepted_risk")
            open_f   = sum(1 for f in findings if f.fix_status == "open")
            sev_w    = {"Critical": 20, "High": 10, "Medium": 5, "Low": 2}
            total_risk   = sum(sev_w.get(f.severity, 5) for f in findings)
            reduced_risk = sum(sev_w.get(f.severity, 5) for f in findings
                               if f.fix_status in ["fixed", "accepted_risk"])
            pct = round((reduced_risk / total_risk * 100), 1) if total_risk > 0 else 0
            sections.append(
                f"REMEDIATION PROGRESS\n"
                f"Total findings: {total} | Fixed: {fixed} | In Progress: {in_prog} "
                f"| Accepted Risk: {accepted} | Open: {open_f}\n"
                f"Risk reduction: {pct}% achieved\n"
            )
    except Exception:
        sections.append("REMEDIATION PROGRESS\nUnavailable.\n")

    # ── NEW: ML Anomaly Detections (Capability 1) ─────────────────────────────
    try:
        from dashboard.backend.ml_anomaly.models import AnomalyDetection
        anomalies = (AnomalyDetection.query
                     .filter_by(user_id=user_id, is_anomaly=True)
                     .order_by(AnomalyDetection.detected_at.desc())
                     .limit(5).all())
        if anomalies:
            lines = [f"ML ANOMALY DETECTIONS (Isolation Forest, last {len(anomalies)})"]
            for a in anomalies:
                lines.append(
                    f"  • {a.target_ip or 'unknown'} — severity: {a.severity} "
                    f"— score: {round(a.anomaly_score, 3)} "
                    f"— detected: {str(a.detected_at)[:16] if a.detected_at else '?'}"
                )
            sections.append("\n".join(lines) + "\n")
        else:
            sections.append("ML ANOMALY DETECTIONS\nNo anomalies flagged by Isolation Forest.\n")
    except Exception:
        sections.append("ML ANOMALY DETECTIONS\nUnavailable.\n")

    # ── NEW: Behavioral Baseline Anomalies (Capability 2) ─────────────────────
    try:
        from dashboard.backend.behavioral.models import BaAnomaly
        ba_anomalies = (BaAnomaly.query
                        .filter(BaAnomaly.status != "resolved")
                        .order_by(BaAnomaly.created_at.desc())
                        .limit(5).all())
        if ba_anomalies:
            lines = [f"BEHAVIORAL ANOMALIES (Z-score deviations, last {len(ba_anomalies)})"]
            for a in ba_anomalies:
                lines.append(
                    f"  • {a.entity_name} — {a.anomaly_type} — severity: {a.severity} "
                    f"— deviation: {round(a.deviation, 1) if a.deviation else '?'}σ "
                    f"— MITRE: {a.mitre_id or 'N/A'}"
                )
            sections.append("\n".join(lines) + "\n")
        else:
            sections.append("BEHAVIORAL ANOMALIES\nNo open behavioral anomalies.\n")
    except Exception:
        sections.append("BEHAVIORAL ANOMALIES\nUnavailable.\n")

    # ── NEW: KEV Active Exploitation (Capability 5) ───────────────────────────
    try:
        from dashboard.backend.live_cves.models import KevCatalogEntry
        kev_total      = KevCatalogEntry.query.count()
        kev_ransomware = KevCatalogEntry.query.filter_by(
            known_ransomware_use="Known").count()
        sections.append(
            f"KEV ACTIVE EXPLOITATION CATALOG\n"
            f"Total actively-exploited CVEs in CISA KEV: {kev_total}\n"
            f"Ransomware-associated: {kev_ransomware}\n"
            f"(Use these to prioritise patching — KEV CVEs are being exploited in the wild today)\n"
        )
    except Exception:
        sections.append("KEV CATALOG\nUnavailable.\n")

    # ── NEW: OTX Threat Intelligence IOCs (Capability 4) ─────────────────────
    try:
        from dashboard.backend.threatintel.models import OTXIndicator
        ioc_count = OTXIndicator.query.count()
        sections.append(
            f"THREAT INTELLIGENCE (AlienVault OTX)\n"
            f"IOCs in local database: {ioc_count:,}\n"
            f"(All network communications from monitored devices are checked against these IOCs)\n"
        )
    except Exception:
        try:
            from dashboard.backend.models import db as _db
            ioc_count = _db.session.execute(
                _db.text("SELECT count(*) FROM ioc_entries")
            ).scalar() or 0
            sections.append(
                f"THREAT INTELLIGENCE (AlienVault OTX)\n"
                f"IOCs in local database: {ioc_count:,}\n"
            )
        except Exception:
            sections.append("THREAT INTELLIGENCE\nUnavailable.\n")

    # ── NEW: MITRE ATT&CK Mapping (Capability 6) ──────────────────────────────
    try:
        from dashboard.backend.models import db as _db
        technique_count = _db.session.execute(
            _db.text("SELECT count(*) FROM mitre_techniques")
        ).scalar() or 0
        sections.append(
            f"MITRE ATT&CK MAPPING\n"
            f"Techniques in local catalog: {technique_count}\n"
            f"(All anomaly detections are mapped to ATT&CK techniques automatically)\n"
        )
    except Exception:
        sections.append("MITRE ATT&CK\nUnavailable.\n")

    # ── NEW: Device Risk Scores (Capability 9) ────────────────────────────────
    try:
        from dashboard.backend.risk_engine.models import DeviceRiskScore
        high_risk = (DeviceRiskScore.query
                     .filter(DeviceRiskScore.user_id == user_id,
                             DeviceRiskScore.score >= 50)
                     .order_by(DeviceRiskScore.score.desc())
                     .limit(10).all())
        all_scores = DeviceRiskScore.query.filter_by(user_id=user_id).all()

        if all_scores:
            avg_score = round(sum(r.score for r in all_scores) / len(all_scores), 1)
            lines = [
                f"UNIFIED DEVICE RISK SCORES (0-100 scale, 8h decay-weighted)",
                f"Devices tracked: {len(all_scores)} | Average score: {avg_score}",
            ]
            if high_risk:
                lines.append("High-risk devices (score ≥ 50):")
                for r in high_risk:
                    lines.append(
                        f"  • {r.entity} (type: {r.entity_type or '?'}) — "
                        f"score: {r.score} — from: {', '.join(r.contributing_modules or [])}"
                    )
            else:
                lines.append("No devices currently above risk threshold 50.")
            sections.append("\n".join(lines) + "\n")
        else:
            sections.append("DEVICE RISK SCORES\nNo risk scores computed yet. Run a recompute.\n")
    except Exception:
        sections.append("DEVICE RISK SCORES\nUnavailable.\n")

    # ── NEW: Central Event Feed (Capability 7) ────────────────────────────────
    try:
        from dashboard.backend.central_events.models import CentralEvent
        recent_events = (CentralEvent.query
                         .filter_by(user_id=user_id)
                         .order_by(CentralEvent.created_at.desc())
                         .limit(10).all())
        if recent_events:
            from collections import Counter
            by_module   = Counter(e.source_module for e in recent_events)
            by_severity = Counter(e.severity for e in recent_events)
            lines = [
                f"RECENT SECURITY EVENTS (last {len(recent_events)} events)",
                f"By module: " + ", ".join(f"{m}={c}" for m, c in by_module.most_common()),
                f"By severity: " + ", ".join(f"{s}={c}" for s, c in by_severity.most_common()),
            ]
            critical_or_high = [e for e in recent_events
                                 if e.severity in ("critical", "high")][:5]
            if critical_or_high:
                lines.append("Critical/High events:")
                for e in critical_or_high:
                    lines.append(
                        f"  • [{e.severity.upper()}] {e.source_module}: {e.title or e.event_type} "
                        f"— entity: {e.entity or 'N/A'}"
                    )
            sections.append("\n".join(lines) + "\n")
        else:
            sections.append("RECENT SECURITY EVENTS\nNo events in unified feed yet.\n")
    except Exception:
        sections.append("RECENT SECURITY EVENTS\nUnavailable.\n")

    # ── NEW: Automated Response History (Capability 8) ───────────────────────
    try:
        from dashboard.backend.automated_response.models import ResponseHistory
        from datetime import timedelta
        cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=24)
        responses = (ResponseHistory.query
                     .filter(ResponseHistory.user_id == user_id,
                             ResponseHistory.fired_at >= cutoff)
                     .order_by(ResponseHistory.fired_at.desc())
                     .limit(5).all())
        if responses:
            lines = [f"AUTOMATED RESPONSES (last 24h, {len(responses)} fired)"]
            for r in responses:
                lines.append(
                    f"  • [{r.threshold_name}] {r.entity} — score: {r.triggering_score} "
                    f"— status: {r.status} — slack: {'✓' if r.slack_sent else '—'}"
                )
            sections.append("\n".join(lines) + "\n")
        else:
            sections.append("AUTOMATED RESPONSES\nNo automated responses fired in last 24h.\n")
    except Exception:
        sections.append("AUTOMATED RESPONSES\nUnavailable.\n")

    return "\n".join(sections)
