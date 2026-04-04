"""
AIPET Watch — Baseline Calculator
Builds baseline profiles for devices from scan findings.

A baseline represents the "normal" state of a device —
its typical finding count, severity profile, protocols,
and risk score. Anomalies are detected by comparing
current state against the baseline.

Usage:
    from dashboard.backend.watch.baseline import build_baselines
    baselines = build_baselines(findings, device_tags)
"""

from datetime import datetime, timezone


# ── Severity Risk Weights ──────────────────────────────────────────────────
SEVERITY_WEIGHTS = {
    "Critical": 25,
    "High":     15,
    "Medium":   8,
    "Low":      3,
    "Info":     1,
}


def calculate_risk_score(findings_for_device):
    """Calculates a 0-100 risk score for a device."""
    if not findings_for_device:
        return 0
    total = sum(SEVERITY_WEIGHTS.get(f.get("severity", "Info"), 1)
                for f in findings_for_device)
    return min(total, 100)


def get_severity_profile(findings_for_device):
    """
    Returns a dict counting findings by severity.
    e.g. {"Critical": 2, "High": 1, "Medium": 0, "Low": 0}
    """
    profile = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in findings_for_device:
        sev = f.get("severity", "Info")
        if sev in profile:
            profile[sev] += 1
    return profile


def get_worst_severity(findings_for_device):
    """Returns the worst severity found on a device."""
    rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
    worst = "None"
    worst_rank = -1
    for f in findings_for_device:
        sev = f.get("severity", "Info")
        if rank.get(sev, 0) > worst_rank:
            worst_rank = rank.get(sev, 0)
            worst = sev
    return worst


def build_baselines(findings, device_tags, scan_timestamp=None):
    """
    Builds baseline profiles for all devices found in scan findings.

    Args:
        findings (list): List of finding dicts from the database
        device_tags (dict): Mapping of device IP to business function
        scan_timestamp (datetime): When the scan was performed

    Returns:
        dict: Mapping of device IP to baseline profile
        {
            "192.168.1.1": {
                "device_ip":        "192.168.1.1",
                "device_function":  "Infrastructure / Network",
                "finding_count":    1,
                "severity_profile": {"Critical": 1, "High": 0, ...},
                "worst_severity":   "Critical",
                "protocols":        ["network"],
                "attack_types":     ["open_telnet"],
                "risk_score":       25,
                "open_findings":    1,
                "fixed_findings":   0,
                "first_seen":       "2026-04-04T...",
                "last_seen":        "2026-04-04T...",
                "status":           "monitored",
            }
        }
    """
    if not findings:
        return {}

    now = scan_timestamp or datetime.now(timezone.utc)

    # Group findings by device
    devices = {}
    for f in findings:
        target = f.get("target", "").strip()
        if not target:
            continue
        if target not in devices:
            devices[target] = []
        devices[target].append(f)

    baselines = {}
    for ip, device_findings in devices.items():
        # Extract unique protocols and attack types
        protocols   = list(set(f.get("module", "unknown") for f in device_findings))
        attack_types = list(set(f.get("attack", "unknown") for f in device_findings))

        # Count open vs fixed findings
        open_findings  = sum(1 for f in device_findings if f.get("fix_status") == "open")
        fixed_findings = sum(1 for f in device_findings if f.get("fix_status") == "fixed")

        baselines[ip] = {
            "device_ip":        ip,
            "device_function":  device_tags.get(ip, "Unknown"),
            "finding_count":    len(device_findings),
            "severity_profile": get_severity_profile(device_findings),
            "worst_severity":   get_worst_severity(device_findings),
            "protocols":        protocols,
            "attack_types":     attack_types,
            "risk_score":       calculate_risk_score(device_findings),
            "open_findings":    open_findings,
            "fixed_findings":   fixed_findings,
            "first_seen":       now.isoformat(),
            "last_seen":        now.isoformat(),
            "status":           "monitored",
        }

    return baselines


def compare_baselines(old_baseline, new_baseline):
    """
    Compares a new baseline against an existing stored baseline
    and returns a list of detected changes.

    Args:
        old_baseline (dict): The stored baseline data
        new_baseline (dict): The newly calculated baseline data

    Returns:
        list: List of change dicts describing what changed
        [
            {
                "type":        "finding_spike",
                "severity":    "High",
                "description": "Finding count increased from 1 to 4",
                "details":     {"old": 1, "new": 4}
            }
        ]
    """
    changes = []
    ip = new_baseline.get("device_ip", "Unknown")

    # Check finding count change
    old_count = old_baseline.get("finding_count", 0)
    new_count = new_baseline.get("finding_count", 0)
    if new_count > old_count:
        increase = new_count - old_count
        changes.append({
            "type":        "finding_spike",
            "severity":    "High" if increase >= 3 else "Medium",
            "description": f"Finding count increased from {old_count} to {new_count} on {ip}",
            "details":     {"old_count": old_count, "new_count": new_count, "increase": increase}
        })

    # Check severity escalation
    severity_rank = {"None": 0, "Info": 1, "Low": 2, "Medium": 3, "High": 4, "Critical": 5}
    old_severity  = old_baseline.get("worst_severity", "None")
    new_severity  = new_baseline.get("worst_severity", "None")
    if severity_rank.get(new_severity, 0) > severity_rank.get(old_severity, 0):
        changes.append({
            "type":        "severity_increase",
            "severity":    "Critical" if new_severity == "Critical" else "High",
            "description": f"Severity escalated from {old_severity} to {new_severity} on {ip}",
            "details":     {"old_severity": old_severity, "new_severity": new_severity}
        })

    # Check risk score change
    old_risk = old_baseline.get("risk_score", 0)
    new_risk = new_baseline.get("risk_score", 0)
    if new_risk - old_risk >= 20:
        changes.append({
            "type":        "risk_score_jump",
            "severity":    "High",
            "description": f"Risk score jumped from {old_risk} to {new_risk} on {ip}",
            "details":     {"old_risk": old_risk, "new_risk": new_risk}
        })

    # Check new protocols
    old_protocols = set(old_baseline.get("protocols", []))
    new_protocols = set(new_baseline.get("protocols", []))
    new_proto     = new_protocols - old_protocols
    if new_proto:
        changes.append({
            "type":        "new_protocol",
            "severity":    "Medium",
            "description": f"New protocol detected on {ip}: {', '.join(new_proto)}",
            "details":     {"new_protocols": list(new_proto)}
        })

    # Check new attack types
    old_attacks = set(old_baseline.get("attack_types", []))
    new_attacks = set(new_baseline.get("attack_types", []))
    new_atk     = new_attacks - old_attacks
    if new_atk:
        changes.append({
            "type":        "new_attack_type",
            "severity":    "High",
            "description": f"New vulnerability type detected on {ip}: {', '.join(new_atk)}",
            "details":     {"new_attacks": list(new_atk)}
        })

    return changes