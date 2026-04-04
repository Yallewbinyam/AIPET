"""
AIPET Predict — CVE Matching Engine
Matches NVD CVEs against a user's device inventory and findings.

Takes a list of CVEs and a user's device profile and returns
only the CVEs that are relevant to that specific user's network.

Usage:
    from dashboard.backend.predict.matcher import match_cves
    alerts = match_cves(cves, findings, device_tags)
"""

from datetime import datetime, timezone


# ── Keyword Mapping ────────────────────────────────────────────────────────
# Maps attack types from AIPET findings to CVE keywords that indicate
# a CVE is relevant to that attack type

ATTACK_TO_KEYWORDS = {
    "open_telnet":              ["telnet"],
    "default_credentials":      ["default credential", "default password", "hardcoded", "hard-coded"],
    "unencrypted_mqtt":         ["mqtt"],
    "mqtt_no_auth":             ["mqtt", "authentication"],
    "open_ftp":                 ["ftp"],
    "open_ssh_root":            ["ssh", "openssh"],
    "http_no_https":            ["http", "tls", "ssl", "cleartext", "plaintext"],
    "open_vnc":                 ["vnc", "remote desktop"],
    "open_snmp":                ["snmp"],
    "outdated_firmware":        ["firmware", "embedded"],
    "open_redis":               ["redis"],
    "coap_no_dtls":             ["coap", "dtls"],
    "open_database_port":       ["database", "mysql", "postgresql", "mongodb"],
    "no_firewall":              ["firewall", "network"],
    "insecure_api":             ["api", "authentication bypass", "authorization"],
    "hardcoded_credentials":    ["hardcoded", "hard-coded", "default credential"],
    "open_memcached":           ["memcached"],
    "debug_interface_exposed":  ["debug", "diagnostic"],
    "privilege_escalation_risk":["privilege escalation"],
    "insecure_deserialization": ["deserialization", "serialization"],
}

# ── Device Function to Keyword Mapping ────────────────────────────────────
FUNCTION_TO_KEYWORDS = {
    "Patient Records / Medical":  ["medical", "healthcare", "hospital", "patient", "dicom", "hl7"],
    "Financial / Payment":        ["payment", "pos", "atm", "financial", "banking"],
    "Operations / Manufacturing": ["scada", "ics", "plc", "modbus", "bacnet", "industrial"],
    "Infrastructure / Network":   ["router", "switch", "firewall", "network", "dns", "dhcp"],
    "IoT / Sensor":               ["iot", "sensor", "embedded", "firmware", "zigbee", "lorawan"],
}

# ── Weaponisation Probability Model ──────────────────────────────────────
def calculate_weaponisation_probability(cve):
    """
    Calculates the probability (0-100) that a CVE will be actively
    exploited within the next 30 days.

    Based on:
    - CVSS score (higher = more likely to be exploited)
    - Attack complexity (low = more accessible to attackers)
    - Days since published (probability increases over time)
    - CVE type (RCE, auth bypass = very high probability)
    """
    score     = cve.get("cvss_score", 0.0)
    keywords  = cve.get("keywords", [])
    published = cve.get("published_date")

    probability = 0

    # Base probability from CVSS score
    if score >= 9.0:
        probability += 50
    elif score >= 7.0:
        probability += 35
    elif score >= 4.0:
        probability += 20
    else:
        probability += 5

    # High-value attack types add probability
    high_value = ["rce", "remote code execution", "authentication bypass",
                  "default credential", "default password", "hardcoded"]
    for kw in keywords:
        if any(hv in kw.lower() for hv in high_value):
            probability += 20
            break

    # Days since published — probability increases over time
    if published:
        try:
            if published.tzinfo is None:
                published = published.replace(tzinfo=timezone.utc)
            days_old = (datetime.now(timezone.utc) - published).days
            if days_old >= 14:
                probability += 15
            elif days_old >= 7:
                probability += 10
            elif days_old >= 3:
                probability += 5
        except Exception:
            pass

    return min(probability, 95)


def build_user_profile(findings, device_tags):
    """
    Builds a keyword profile of the user's network based on their
    findings and device tags.

    Returns a set of keywords that describe what the user's network
    looks like — used to match against CVE keywords.
    """
    profile_keywords = set()

    # Add keywords from attack types found in findings
    for finding in findings:
        attack = finding.get("attack", "").lower().strip()
        if attack in ATTACK_TO_KEYWORDS:
            for kw in ATTACK_TO_KEYWORDS[attack]:
                profile_keywords.add(kw.lower())

        # Also add the raw attack type as a keyword
        profile_keywords.add(attack.replace("_", " "))

    # Add keywords from device function tags
    for ip, function in device_tags.items():
        if function in FUNCTION_TO_KEYWORDS:
            for kw in FUNCTION_TO_KEYWORDS[function]:
                profile_keywords.add(kw.lower())

    return profile_keywords


def match_cves(cves, findings, device_tags):
    """
    Matches a list of CVEs against a user's device inventory.

    Args:
        cves (list): List of CVE dicts from nvd_client.fetch_recent_cves()
        findings (list): List of finding dicts from the database
        device_tags (dict): Mapping of device IP to business function

    Returns:
        list: List of matched CVE alert dicts, sorted by severity then score
    """
    if not cves or not findings:
        return []

    # Build user's network profile
    user_profile = build_user_profile(findings, device_tags)

    if not user_profile:
        return []

    matched_alerts = []

    for cve in cves:
        cve_keywords = set(kw.lower() for kw in cve.get("keywords", []))

        if not cve_keywords:
            continue

        # Find intersection between CVE keywords and user profile
        matches = cve_keywords.intersection(user_profile)

        if not matches:
            continue

        # Find which devices are most likely affected
        affected_devices = find_affected_devices(cve, findings, device_tags)

        # Calculate weaponisation probability
        weaponisation_pct = calculate_weaponisation_probability(cve)

        # Build title from CVE ID and top keyword
        top_keyword = list(matches)[0].title()
        title       = f"{cve['cve_id']} — {top_keyword} vulnerability affecting your IoT devices"

        matched_alerts.append({
            "cve_id":            cve["cve_id"],
            "title":             title,
            "description":       cve["description"],
            "severity":          cve["severity"],
            "cvss_score":        cve["cvss_score"],
            "affected_devices":  affected_devices,
            "weaponisation_pct": weaponisation_pct,
            "published_date":    cve["published_date"],
            "nvd_url":           cve["nvd_url"],
            "matched_keywords":  list(matches),
        })

    # Sort by severity then CVSS score
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Unknown": 4}
    matched_alerts.sort(
        key=lambda x: (severity_order.get(x["severity"], 4), -x["cvss_score"])
    )

    return matched_alerts


def find_affected_devices(cve, findings, device_tags):
    """
    Identifies which specific devices in the user's inventory
    are most likely affected by a CVE.

    Returns a list of affected device IPs with context.
    """
    affected = []
    cve_keywords = set(kw.lower() for kw in cve.get("keywords", []))

    # Group findings by device
    devices = {}
    for f in findings:
        target = f.get("target", "")
        if target not in devices:
            devices[target] = []
        devices[target].append(f)

    for ip, device_findings in devices.items():
        device_keywords = set()

        # Add keywords from this device's attack types
        for f in device_findings:
            attack = f.get("attack", "").lower()
            if attack in ATTACK_TO_KEYWORDS:
                for kw in ATTACK_TO_KEYWORDS[attack]:
                    device_keywords.add(kw.lower())

        # Add keywords from device function
        function = device_tags.get(ip, "Unknown")
        if function in FUNCTION_TO_KEYWORDS:
            for kw in FUNCTION_TO_KEYWORDS[function]:
                device_keywords.add(kw.lower())

        # Check if this device matches the CVE
        device_matches = cve_keywords.intersection(device_keywords)
        if device_matches:
            affected.append({
                "ip":       ip,
                "function": function,
                "matches":  list(device_matches),
            })

    return affected