"""
AIPET Score — Financial Risk Calculator
Translates technical vulnerabilities into financial business impact.

Uses UK breach cost data from IBM Cost of a Data Breach Report 2024
and NCSC UK Cyber Security Breaches Survey 2024.

Usage:
    from dashboard.backend.score.calculator import calculate_score
    result = calculate_score(findings, device_tags, industry)
"""


# ── Industry Base Breach Costs (UK averages, GBP) ─────────────────────────
# Source: IBM Cost of a Data Breach Report 2024, NCSC UK 2024
INDUSTRY_BASE_COSTS = {
    "Healthcare":           8_200_000,
    "Financial Services":   5_900_000,
    "Retail / E-commerce":  3_800_000,
    "Manufacturing":        3_200_000,
    "Education":            2_100_000,
    "Legal Services":       4_100_000,
    "Energy / Utilities":   4_600_000,
    "Government":           3_900_000,
    "Technology":           4_300_000,
    "General Business":     3_400_000,
}

# ── Severity Multipliers ───────────────────────────────────────────────────
SEVERITY_MULTIPLIERS = {
    "Critical": 1.00,
    "High":     0.60,
    "Medium":   0.30,
    "Low":      0.10,
    "Info":     0.02,
}

# ── Device Criticality Multipliers ────────────────────────────────────────
# How much of the base breach cost this device type represents
DEVICE_CRITICALITY = {
    "Patient Records / Medical":  1.00,
    "Financial / Payment":        0.90,
    "Customer Data":              0.80,
    "Operations / Manufacturing": 0.70,
    "Research / IP":              0.75,
    "HR / Employee Data":         0.65,
    "General IT":                 0.50,
    "Infrastructure / Network":   0.40,
    "IoT / Sensor":               0.30,
    "Unknown":                    0.35,
}

# ── Breach Probability by Attack Type ─────────────────────────────────────
# Probability that this vulnerability leads to a breach if exploited
BREACH_PROBABILITY = {
    "default_credentials":      0.85,
    "open_telnet":              0.75,
    "mqtt_no_auth":             0.80,
    "unencrypted_mqtt":         0.60,
    "open_ftp":                 0.65,
    "open_ssh_root":            0.70,
    "http_no_https":            0.55,
    "open_vnc":                 0.80,
    "open_snmp":                0.50,
    "outdated_firmware":        0.55,
    "weak_password_policy":     0.60,
    "no_account_lockout":       0.55,
    "open_redis":               0.85,
    "coap_no_dtls":             0.50,
    "open_database_port":       0.80,
    "ssl_expired_certificate":  0.45,
    "unnecessary_services":     0.35,
    "no_firewall":              0.65,
    "insecure_api":             0.70,
    "hardcoded_credentials":    0.90,
    "open_rsync":               0.55,
    "cleartext_storage":        0.70,
    "no_update_mechanism":      0.40,
    "open_upnp":                0.55,
    "open_nfs":                 0.65,
    "debug_interface_exposed":  0.75,
    "no_logging":               0.30,
    "insecure_deserialization": 0.70,
    "open_memcached":           0.60,
    "privilege_escalation_risk":0.65,
}

DEFAULT_BREACH_PROBABILITY = 0.40

# ── Business Function Options ──────────────────────────────────────────────
# These are shown to users in the device tagging UI
BUSINESS_FUNCTIONS = [
    "Patient Records / Medical",
    "Financial / Payment",
    "Customer Data",
    "Operations / Manufacturing",
    "Research / IP",
    "HR / Employee Data",
    "General IT",
    "Infrastructure / Network",
    "IoT / Sensor",
    "Unknown",
]

INDUSTRIES = list(INDUSTRY_BASE_COSTS.keys())


def normalize_attack_type(attack_string):
    """
    Converts a raw attack string from a finding into a breach
    probability key. Uses partial matching as a fallback.
    """
    attack_lower = attack_string.lower().strip().replace(" ", "_")

    # Direct match
    if attack_lower in BREACH_PROBABILITY:
        return attack_lower

    # Partial match
    for key in BREACH_PROBABILITY:
        if key in attack_lower or attack_lower in key:
            return key

    return None


def calculate_score(findings, device_tags, industry):
    """
    Calculates the financial risk exposure for a set of findings.

    Args:
        findings (list): List of finding dicts from the database
            Each finding has: id, attack, severity, target, fix_status
        device_tags (dict): Mapping of device IP to business function
            e.g. {"192.168.1.1": "Infrastructure / Network"}
        industry (str): The industry the organisation operates in
            e.g. "Healthcare"

    Returns:
        dict: {
            "industry":            "Healthcare",
            "base_cost":           8200000,
            "total_exposure_gbp":  1247000,
            "total_exposure_fmt":  "£1,247,000",
            "findings_breakdown":  [...],
            "summary": {
                "critical_exposure": 800000,
                "high_exposure":     300000,
                "medium_exposure":   120000,
                "low_exposure":      27000,
                "fixed_savings":     450000,
            }
        }
    """
    # Get base cost for industry
    base_cost = INDUSTRY_BASE_COSTS.get(industry, INDUSTRY_BASE_COSTS["General Business"])

    total_findings  = len(findings)
    if total_findings == 0:
        return {
            "industry":           industry,
            "base_cost":          base_cost,
            "total_exposure_gbp": 0,
            "total_exposure_fmt": "£0",
            "findings_breakdown": [],
            "summary": {
                "critical_exposure": 0,
                "high_exposure":     0,
                "medium_exposure":   0,
                "low_exposure":      0,
                "fixed_savings":     0,
            }
        }

    findings_breakdown = []
    total_exposure     = 0
    summary = {
        "critical_exposure": 0,
        "high_exposure":     0,
        "medium_exposure":   0,
        "low_exposure":      0,
        "fixed_savings":     0,
    }

    for finding in findings:
        attack      = finding.get("attack",     "unknown")
        severity    = finding.get("severity",   "Low")
        target      = finding.get("target",     "Unknown")
        fix_status  = finding.get("fix_status", "open")
        finding_id  = finding.get("id",         0)

        # Get multipliers
        severity_mult  = SEVERITY_MULTIPLIERS.get(severity, 0.10)
        device_fn      = device_tags.get(target, "Unknown")
        device_mult    = DEVICE_CRITICALITY.get(device_fn, 0.35)
        attack_key     = normalize_attack_type(attack)
        breach_prob    = BREACH_PROBABILITY.get(attack_key, DEFAULT_BREACH_PROBABILITY) if attack_key else DEFAULT_BREACH_PROBABILITY

        # Calculate exposure for this finding
        # Divide by total findings to distribute the base cost across all findings
        exposure = int(
            base_cost
            * severity_mult
            * device_mult
            * breach_prob
            / total_findings
        )

        findings_breakdown.append({
            "finding_id":        finding_id,
            "attack":            attack,
            "severity":          severity,
            "target":            target,
            "device_function":   device_fn,
            "exposure_gbp":      exposure,
            "exposure_fmt":      f"£{exposure:,}",
            "breach_probability": int(breach_prob * 100),
            "fix_status":        fix_status,
        })

        total_exposure += exposure

        # Add to summary by severity
        severity_lower = severity.lower()
        if severity_lower == "critical":
            summary["critical_exposure"] += exposure
        elif severity_lower == "high":
            summary["high_exposure"] += exposure
        elif severity_lower == "medium":
            summary["medium_exposure"] += exposure
        else:
            summary["low_exposure"] += exposure

        # Track savings from fixed findings
        if fix_status in ["fixed", "accepted_risk"]:
            summary["fixed_savings"] += exposure

    # Sort breakdown by exposure descending
    findings_breakdown.sort(key=lambda x: x["exposure_gbp"], reverse=True)

    return {
        "industry":           industry,
        "base_cost":          base_cost,
        "total_exposure_gbp": total_exposure,
        "total_exposure_fmt": f"£{total_exposure:,}",
        "findings_breakdown": findings_breakdown,
        "summary":            summary,
    }