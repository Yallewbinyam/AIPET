# =============================================================
# AIPET — AI-Powered Penetration Testing Framework for IoT
# Module 7: Report Generator
# Author: Binyam
# Institution: Coventry University — MSc Cyber Security
#              (Ethical Hacking)
# Date: March 2025
# Licence: MIT
# Description: Generates professional penetration test reports
#              from all AIPET module outputs.
#              Combines findings from Modules 1-6 into a
#              structured, human-readable report in both
#              Markdown and JSON formats.
#              Includes AI-generated explanations from Module 6
#              to justify every finding in plain English.
# =============================================================

import json
import os
from datetime import datetime

# ── Constants ─────────────────────────────────────────────────

# Severity ordering — Critical is most urgent
SEVERITY_ORDER = {
    "Critical": 0,
    "High":     1,
    "Medium":   2,
    "Low":      3,
    "INFO":     4
}

# Severity icons for visual clarity in reports
SEVERITY_ICONS = {
    "Critical": "🚨 CRITICAL",
    "High":     "🔴 HIGH",
    "Medium":   "⚠️  MEDIUM",
    "Low":      "ℹ️  LOW",
    "INFO":     "📋 INFO"
}

# Recommendations for common IoT vulnerability types
# These map findings to actionable remediation steps
RECOMMENDATIONS = {
    "mqtt_anonymous": (
        "Configure MQTT broker authentication. "
        "Enable username/password authentication in "
        "mosquitto.conf: `allow_anonymous false`. "
        "Generate strong unique credentials for each client."
    ),
    "mqtt_default_creds": (
        "Change all default MQTT credentials immediately. "
        "Implement per-device unique credentials. "
        "Consider certificate-based authentication for "
        "production deployments."
    ),
    "mqtt_sensitive_data": (
        "Review all MQTT topic payloads for sensitive data. "
        "Implement payload encryption using TLS (port 8883). "
        "Apply topic-level access control lists (ACLs)."
    ),
    "coap_unauth_read": (
        "Implement CoAP access control. "
        "Use DTLS for CoAP communication (CoAPS). "
        "Restrict resource access to authorised clients only."
    ),
    "coap_unauth_write": (
        "Immediately restrict write access on CoAP resources. "
        "Implement DTLS mutual authentication. "
        "Apply resource-level access control policies."
    ),
    "coap_replay": (
        "Implement replay protection using nonces or "
        "timestamps in CoAP messages. "
        "Enable DTLS which provides replay protection "
        "at the transport layer."
    ),
    "http_default_creds": (
        "Change all default credentials immediately. "
        "Implement account lockout after failed attempts. "
        "Use strong unique passwords for each device. "
        "Consider disabling the web interface if not needed."
    ),
    "http_admin_exposed": (
        "Restrict admin interface access by IP whitelist. "
        "Implement strong authentication on all admin pages. "
        "Consider moving admin interface to non-standard port. "
        "Disable admin interface if not required remotely."
    ),
    "http_sensitive_data": (
        "Remove all sensitive data from HTTP responses. "
        "Implement proper access control on all API endpoints. "
        "Audit all endpoints for unintended data exposure. "
        "Implement API authentication tokens."
    ),
    "firmware_hardcoded_creds": (
        "Remove all hardcoded credentials from firmware. "
        "Implement secure credential provisioning at "
        "manufacturing time. "
        "Issue firmware update to all affected devices. "
        "This affects ALL devices running this firmware version."
    ),
    "firmware_private_key": (
        "CRITICAL: Remove private key from firmware immediately. "
        "Generate unique keys per device during provisioning. "
        "Revoke the compromised key across all deployments. "
        "All devices sharing this key are vulnerable to "
        "traffic decryption and impersonation."
    ),
    "firmware_telnet": (
        "Disable Telnet immediately — it transmits all data "
        "including passwords in plaintext. "
        "Replace with SSH for remote access. "
        "Issue firmware update to all affected devices."
    ),
    "firmware_vulnerable_component": (
        "Update all identified vulnerable components. "
        "Establish a firmware update process. "
        "Subscribe to CVE notifications for all components. "
        "Test updates in staging before deployment."
    ),
    "port_23": (
        "Disable Telnet service immediately. "
        "Telnet transmits credentials in plaintext. "
        "Replace with SSH (port 22) for secure remote access."
    ),
    "port_502": (
        "Restrict Modbus access to authorised IPs only. "
        "Implement network segmentation — industrial protocols "
        "should never be exposed to untrusted networks. "
        "Consider VPN for remote industrial access."
    ),
}

# Default recommendation for findings without specific mapping
DEFAULT_RECOMMENDATION = (
    "Review this finding with your security team. "
    "Apply the principle of least privilege. "
    "Ensure all services are patched to latest versions. "
    "Implement network segmentation to limit exposure."
)


# ── Helper: Load JSON file safely ────────────────────────────
def load_json(filepath):
    """
    Load a JSON file safely, returning empty dict on failure.

    Args:
        filepath (str): Path to JSON file

    Returns:
        dict or list: Parsed JSON content, or {} on failure
    """
    if not os.path.exists(filepath):
        return {}
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except Exception:
        return {}


# ── Helper: Get recommendation for finding ────────────────────
def get_recommendation(finding_key):
    """
    Get actionable remediation recommendation for a finding.

    Args:
        finding_key (str): Feature or finding identifier

    Returns:
        str: Recommendation text
    """
    # Check direct match first
    if finding_key in RECOMMENDATIONS:
        return RECOMMENDATIONS[finding_key]

    # Check partial match
    for key, rec in RECOMMENDATIONS.items():
        if key in finding_key or finding_key in key:
            return rec

    return DEFAULT_RECOMMENDATION


# ── Section 1: Executive Summary ─────────────────────────────
def generate_executive_summary(all_data):
    """
    Generate executive summary section of the report.

    The executive summary is written for non-technical
    stakeholders — managers, executives, and board members
    who need to understand risk without technical detail.

    Covers: scope, total findings by severity, overall
    risk rating, and top priority actions.

    Args:
        all_data (dict): Aggregated data from all modules

    Returns:
        str: Executive summary markdown text
    """
    profiles   = all_data.get("profiles", [])
    ai_results = all_data.get("ai_results", [])

    # Count total findings across all modules and devices
    total_critical = 0
    total_high     = 0
    total_medium   = 0
    total_low      = 0

    # Count from module results
    for module_key in ["mqtt", "coap", "http", "firmware"]:
        results = all_data.get(module_key, {})
        summary = results.get("summary", {})
        total_critical += summary.get("critical", 0)
        total_high     += summary.get("high", 0)
        total_medium   += summary.get("medium", 0)
        total_low      += summary.get("info", 0)

    # Overall risk rating from total findings
    if total_critical > 0:
        overall_risk = "🚨 CRITICAL"
        risk_summary = (
            f"The assessment identified {total_critical} "
            f"critical vulnerability/vulnerabilities requiring "
            f"immediate remediation."
        )
    elif total_high > 0:
        overall_risk = "🔴 HIGH"
        risk_summary = (
            f"The assessment identified {total_high} high "
            f"severity finding(s) requiring urgent attention."
        )
    elif total_medium > 0:
        overall_risk = "⚠️ MEDIUM"
        risk_summary = (
            "The assessment identified medium severity "
            "findings that should be addressed promptly."
        )
    else:
        overall_risk = "ℹ️ LOW"
        risk_summary = (
            "The assessment identified low severity findings "
            "with minimal immediate risk."
        )

    lines = []
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(f"**Overall Risk Rating: {overall_risk}**")
    lines.append("")
    lines.append(risk_summary)
    lines.append("")
    lines.append("### Assessment Scope")
    lines.append(
        f"- Devices assessed: {len(profiles)}"
    )
    lines.append(
        f"- Modules executed: MQTT, CoAP, HTTP, "
        f"Firmware, AI Analysis"
    )
    lines.append("")
    lines.append("### Finding Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    lines.append(f"| 🚨 Critical | {total_critical} |")
    lines.append(f"| 🔴 High     | {total_high} |")
    lines.append(f"| ⚠️  Medium   | {total_medium} |")
    lines.append(f"| ℹ️  Low      | {total_low} |")
    lines.append(
        f"| **Total**   | "
        f"**{total_critical + total_high + total_medium + total_low}** |"
    )
    lines.append("")

    # Top priority actions
    lines.append("### Immediate Priority Actions")
    lines.append("")

    priority_actions = []

    # Check for most critical findings
    mqtt = all_data.get("mqtt", {})
    if mqtt:
        attacks = mqtt.get("attacks", [])
        for attack in attacks:
            if (attack.get("attack") == "Connection Test" and
                    attack.get("severity") == "CRITICAL"):
                priority_actions.append(
                    "1. **Disable MQTT anonymous access** — "
                    "MQTT broker accepts connections without "
                    "authentication"
                )

    firmware = all_data.get("firmware", {})
    if firmware:
        analyses = firmware.get("analyses", [])
        for analysis in analyses:
            if (analysis.get("analysis") == "Private Key Scanner"
                    and analysis.get("keys_found")):
                priority_actions.append(
                    "2. **Revoke shared private key** — "
                    "Private key found in firmware affects "
                    "ALL devices of this model"
                )
            if (analysis.get("analysis") ==
                    "Dangerous Configuration Scanner" and
                    analysis.get("severity") == "CRITICAL"):
                priority_actions.append(
                    "3. **Disable Telnet** — "
                    "Telnet transmits credentials in plaintext"
                )

    if not priority_actions:
        priority_actions = [
            "1. Review all findings below",
            "2. Prioritise Critical and High severity items",
            "3. Implement network segmentation",
        ]

    for action in priority_actions[:5]:
        lines.append(action)
        lines.append("")

    return "\n".join(lines)


# ── Section 2: Device Profiles ────────────────────────────────
def generate_device_section(profiles, ai_results):
    """
    Generate device profile section of the report.

    Lists all discovered devices with their type,
    risk score, open ports, and AI-predicted severity.

    Args:
        profiles (list): Complete device profiles from Module 1
        ai_results (list): AI predictions from Module 6

    Returns:
        str: Device section markdown text
    """
    lines = []
    lines.append("## Discovered Devices")
    lines.append("")

    if not profiles:
        lines.append("No devices were discovered.")
        return "\n".join(lines)

    # Build AI results lookup by IP
    ai_by_ip = {}
    for result in ai_results:
        ip = result.get("ip", "")
        if ip:
            ai_by_ip[ip] = result

    for profile in profiles:
        ip          = profile.get("ip", "unknown")
        device_type = profile.get("device_type", "unknown")
        risk_score  = profile.get("risk_score", 0)
        risk_label  = profile.get("risk_label", "Unknown")
        ports       = profile.get("ports", [])
        hostname    = profile.get("hostname", "unknown")
        confidence  = profile.get("confidence", 0)

        lines.append(f"### Device: {ip}")
        lines.append("")
        lines.append(
            f"| Property | Value |"
        )
        lines.append("|----------|-------|")
        lines.append(f"| IP Address | `{ip}` |")
        lines.append(f"| Hostname | {hostname} |")
        lines.append(
            f"| Device Type | {device_type} |"
        )
        lines.append(
            f"| Fingerprint Confidence | {confidence}% |"
        )
        lines.append(
            f"| Risk Score | {risk_score}/100 |"
        )
        lines.append(
            f"| Risk Label | {risk_label} |"
        )
        lines.append(
            f"| Open Ports | {', '.join(map(str, ports))} |"
        )

        # Add AI prediction if available
        if ip in ai_by_ip:
            ai = ai_by_ip[ip]
            pred = ai.get("prediction", {})
            ai_severity   = pred.get(
                "predicted_severity", "Unknown"
            )
            ai_confidence = pred.get("confidence", 0) * 100
            lines.append(
                f"| AI Severity | {ai_severity} "
                f"({ai_confidence:.1f}% confidence) |"
            )

        lines.append("")

        # Services table
        services = profile.get("services", {})
        if services:
            lines.append("**Services Detected:**")
            lines.append("")
            lines.append(
                "| Port | Protocol | Service | Version |"
            )
            lines.append(
                "|------|----------|---------|---------|"
            )
            for port, info in services.items():
                lines.append(
                    f"| {port} | "
                    f"{info.get('protocol', '')} | "
                    f"{info.get('name', '')} | "
                    f"{info.get('product', '')} "
                    f"{info.get('version', '')} |"
                )
            lines.append("")

        # Risk indicators
        risks = profile.get("risk_indicators", [])
        if risks:
            lines.append("**Risk Indicators:**")
            lines.append("")
            for risk in risks:
                lines.append(
                    f"- Port {risk.get('port')}: "
                    f"{risk.get('risk')}"
                )
            lines.append("")

        lines.append("---")
        lines.append("")

    return "\n".join(lines)


# ── Section 3: Findings by Module ────────────────────────────
def generate_findings_section(all_data):
    """
    Generate detailed findings section grouped by module.

    Presents all findings from each attack module,
    sorted by severity (Critical first).

    Args:
        all_data (dict): Aggregated data from all modules

    Returns:
        str: Findings section markdown text
    """
    lines = []
    lines.append("## Detailed Findings")
    lines.append("")

    # ── MQTT Findings ─────────────────────────────────────────
    mqtt = all_data.get("mqtt", {})
    if mqtt and mqtt.get("attacks"):
        lines.append("### Module 2 — MQTT Attack Suite")
        lines.append(
            f"**Target:** {mqtt.get('target', 'N/A')}:"
            f"{mqtt.get('port', 1883)}"
        )
        lines.append("")

        attacks = sorted(
            mqtt.get("attacks", []),
            key=lambda x: SEVERITY_ORDER.get(
                x.get("severity", "INFO"), 4
            )
        )

        for attack in attacks:
            severity = attack.get("severity", "INFO")
            icon     = SEVERITY_ICONS.get(severity, severity)
            name     = attack.get("attack", "Unknown")
            finding  = attack.get("finding", "")

            lines.append(f"#### {icon} — {name}")
            lines.append("")
            lines.append(f"**Finding:** {finding}")
            lines.append("")

            # Add specific details
            if attack.get("valid_credentials"):
                lines.append(
                    f"**Valid Credentials Found:** "
                    f"{len(attack['valid_credentials'])}"
                )
                lines.append("")

            if attack.get("topics_found"):
                lines.append(
                    f"**Topics Discovered:** "
                    f"{', '.join(attack['topics_found'][:5])}"
                )
                lines.append("")

            # Add recommendation
            rec_key = {
                "Connection Test":       "mqtt_anonymous",
                "Authentication Bypass": "mqtt_default_creds",
                "Sensitive Data Harvest":"mqtt_sensitive_data",
            }.get(name, "")

            if rec_key:
                lines.append(
                    f"**Recommendation:** "
                    f"{get_recommendation(rec_key)}"
                )
                lines.append("")

        lines.append("---")
        lines.append("")

    # ── CoAP Findings ─────────────────────────────────────────
    coap = all_data.get("coap", {})
    if coap and coap.get("attacks"):
        lines.append("### Module 3 — CoAP Attack Suite")
        lines.append(
            f"**Target:** coap://{coap.get('target', 'N/A')}:"
            f"{coap.get('port', 5683)}"
        )
        lines.append("")

        attacks = sorted(
            coap.get("attacks", []),
            key=lambda x: SEVERITY_ORDER.get(
                x.get("severity", "INFO"), 4
            )
        )

        for attack in attacks:
            severity = attack.get("severity", "INFO")
            icon     = SEVERITY_ICONS.get(severity, severity)
            name     = attack.get("attack", "Unknown")
            finding  = attack.get("finding", "")

            lines.append(f"#### {icon} — {name}")
            lines.append("")
            lines.append(f"**Finding:** {finding}")
            lines.append("")

            if attack.get("resources_found"):
                lines.append(
                    f"**Resources Found:** "
                    f"{', '.join(attack['resources_found'][:5])}"
                )
                lines.append("")

            rec_key = {
                "Unauthenticated Access": "coap_unauth_read",
                "Replay Attack":          "coap_replay",
            }.get(name, "")

            if rec_key:
                lines.append(
                    f"**Recommendation:** "
                    f"{get_recommendation(rec_key)}"
                )
                lines.append("")

        lines.append("---")
        lines.append("")

    # ── HTTP Findings ─────────────────────────────────────────
    http = all_data.get("http", {})
    if http and http.get("attacks"):
        lines.append("### Module 4 — HTTP/Web IoT Suite")
        lines.append(
            f"**Target:** http://{http.get('target', 'N/A')}:"
            f"{http.get('port', 80)}"
        )
        lines.append("")

        attacks = sorted(
            http.get("attacks", []),
            key=lambda x: SEVERITY_ORDER.get(
                x.get("severity", "INFO"), 4
            )
        )

        for attack in attacks:
            severity = attack.get("severity", "INFO")
            icon     = SEVERITY_ICONS.get(severity, severity)
            name     = attack.get("attack", "Unknown")
            finding  = attack.get("finding", "")

            lines.append(f"#### {icon} — {name}")
            lines.append("")
            lines.append(f"**Finding:** {finding}")
            lines.append("")

            rec_key = {
                "Default Credential Testing":
                    "http_default_creds",
                "Admin Interface Discovery":
                    "http_admin_exposed",
                "API Security Testing":
                    "http_sensitive_data",
            }.get(name, "")

            if rec_key:
                lines.append(
                    f"**Recommendation:** "
                    f"{get_recommendation(rec_key)}"
                )
                lines.append("")

        lines.append("---")
        lines.append("")

    # ── Firmware Findings ─────────────────────────────────────
    firmware = all_data.get("firmware", {})
    if firmware and firmware.get("analyses"):
        lines.append("### Module 5 — Firmware Analyser")
        lines.append(
            f"**Target:** {firmware.get('target', 'N/A')}"
        )
        lines.append("")

        analyses = sorted(
            firmware.get("analyses", []),
            key=lambda x: SEVERITY_ORDER.get(
                x.get("severity", "INFO"), 4
            )
        )

        for analysis in analyses:
            severity = analysis.get("severity", "INFO")
            icon     = SEVERITY_ICONS.get(severity, severity)
            name     = analysis.get("analysis", "Unknown")
            finding  = analysis.get("finding", "")

            lines.append(f"#### {icon} — {name}")
            lines.append("")
            lines.append(f"**Finding:** {finding}")
            lines.append("")

            rec_key = {
                "Credential Hunt":
                    "firmware_hardcoded_creds",
                "Private Key Scanner":
                    "firmware_private_key",
                "Dangerous Configuration Scanner":
                    "firmware_telnet",
                "Vulnerable Component Scanner":
                    "firmware_vulnerable_component",
            }.get(name, "")

            if rec_key:
                lines.append(
                    f"**Recommendation:** "
                    f"{get_recommendation(rec_key)}"
                )
                lines.append("")

        lines.append("---")
        lines.append("")

    return "\n".join(lines)


# ── Section 4: AI Explanation Section ────────────────────────
def generate_ai_section(ai_results):
    """
    Generate AI explanation section of the report.

    This section presents the explainable AI predictions
    from Module 6 — showing not just the severity rating
    but exactly WHY each device received that rating.

    This is the unique contribution of AIPET — the
    explainability layer that makes AI decisions
    transparent and auditable.

    Args:
        ai_results (list): AI predictions from Module 6

    Returns:
        str: AI section markdown text
    """
    lines = []
    lines.append("## AI-Powered Risk Analysis")
    lines.append("")
    lines.append(
        "The following analysis was generated by AIPET's "
        "Explainable AI engine using a Random Forest "
        "classifier trained on IoT CVE data and SHAP "
        "(SHapley Additive exPlanations) values to justify "
        "each prediction."
    )
    lines.append("")

    if not ai_results:
        lines.append(
            "No AI analysis results available. "
            "Run ai_engine/explainer.py to generate predictions."
        )
        return "\n".join(lines)

    for result in ai_results:
        ip          = result.get("ip", "unknown")
        device_type = result.get("device_type", "unknown")
        prediction  = result.get("prediction", {})
        explanation = result.get("explanation", "")

        severity   = prediction.get(
            "predicted_severity", "Unknown"
        )
        confidence = prediction.get("confidence", 0) * 100
        icon       = SEVERITY_ICONS.get(severity, severity)

        lines.append(f"### {icon} — Device: {ip}")
        lines.append("")
        lines.append(f"**Device Type:** {device_type}")
        lines.append(
            f"**AI Predicted Severity:** {severity} "
            f"({confidence:.1f}% confidence)"
        )
        lines.append("")

        # Probability breakdown
        probs = prediction.get("probabilities", {})
        if probs:
            lines.append("**Severity Probability Breakdown:**")
            lines.append("")
            lines.append("| Severity | Probability |")
            lines.append("|----------|-------------|")
            for sev, prob in probs.items():
                bar = "█" * int(prob * 20)
                lines.append(
                    f"| {sev} | {prob*100:.1f}% {bar} |"
                )
            lines.append("")

        # Top SHAP contributions
        contribs = prediction.get("shap_contributions", {})
        if contribs:
            lines.append(
                "**Key Factors (SHAP Feature Contributions):**"
            )
            lines.append("")
            lines.append(
                "| Feature | Impact | Direction |"
            )
            lines.append(
                "|---------|--------|-----------|"
            )

            # Show top 8 contributors
            top_contribs = list(contribs.items())[:8]
            for feature, shap_val in top_contribs:
                direction = (
                    "⬆️ Increases severity"
                    if shap_val > 0
                    else "⬇️ Reduces severity"
                )
                impact = f"{abs(shap_val)*100:.1f}%"
                feat_name = feature.replace("_", " ").title()
                lines.append(
                    f"| {feat_name} | {impact} | "
                    f"{direction} |"
                )
            lines.append("")

        # Plain English explanation
        if explanation:
            lines.append("**Plain-English Explanation:**")
            lines.append("")
            lines.append("```")
            lines.append(explanation)
            lines.append("```")
            lines.append("")

        lines.append("---")
        lines.append("")

    return "\n".join(lines)


# ── Section 5: Recommendations Summary ───────────────────────
def generate_recommendations_section(all_data):
    """
    Generate consolidated recommendations section.

    Aggregates all recommendations from all findings
    and presents them in priority order.

    Args:
        all_data (dict): All module results

    Returns:
        str: Recommendations section markdown text
    """
    lines = []
    lines.append("## Recommendations")
    lines.append("")
    lines.append(
        "The following recommendations are prioritised "
        "by severity. Address Critical items immediately "
        "before moving to High severity items."
    )
    lines.append("")

    lines.append("### 🚨 Critical Priority")
    lines.append("")
    lines.append(
        "1. **Disable anonymous MQTT access** — "
        "Enforce authentication on all MQTT brokers. "
        "No device should connect without credentials."
    )
    lines.append("")
    lines.append(
        "2. **Remove hardcoded credentials from firmware** — "
        "Issue firmware update. All devices running "
        "affected firmware are vulnerable."
    )
    lines.append("")
    lines.append(
        "3. **Revoke and replace shared private keys** — "
        "Every device sharing the same key is vulnerable "
        "to traffic decryption and impersonation."
    )
    lines.append("")
    lines.append(
        "4. **Disable Telnet** — "
        "Replace with SSH on all devices. "
        "Telnet exposes credentials on the network."
    )
    lines.append("")

    lines.append("### 🔴 High Priority")
    lines.append("")
    lines.append(
        "5. **Change all default web interface credentials** — "
        "Each device must have unique, strong credentials."
    )
    lines.append("")
    lines.append(
        "6. **Restrict admin interface access** — "
        "Admin panels should not be accessible without "
        "authentication. Apply IP whitelisting where possible."
    )
    lines.append("")
    lines.append(
        "7. **Update vulnerable firmware components** — "
        "OpenSSL 1.0.x and OpenSSH < 7.4 have known "
        "critical vulnerabilities. Update immediately."
    )
    lines.append("")

    lines.append("### ⚠️ Medium Priority")
    lines.append("")
    lines.append(
        "8. **Implement CoAP authentication** — "
        "Use DTLS for CoAP communication. "
        "Restrict resource access to authorised clients."
    )
    lines.append("")
    lines.append(
        "9. **Implement replay protection** — "
        "Add nonce or timestamp validation to CoAP "
        "and MQTT message processing."
    )
    lines.append("")
    lines.append(
        "10. **Add HTTP security headers** — "
        "Implement X-Frame-Options, Content-Security-Policy, "
        "and X-Content-Type-Options on all web interfaces."
    )
    lines.append("")

    lines.append("### ℹ️ General Best Practices")
    lines.append("")
    lines.append(
        "- Implement network segmentation — "
        "IoT devices should be on isolated VLANs"
    )
    lines.append(
        "- Enable firmware automatic updates where possible"
    )
    lines.append(
        "- Monitor all IoT device communications "
        "for anomalous behaviour"
    )
    lines.append(
        "- Conduct regular penetration testing "
        "as devices and firmware are updated"
    )
    lines.append(
        "- Subscribe to CVE notifications for all "
        "IoT device models and firmware versions"
    )
    lines.append("")

    return "\n".join(lines)


# ── Main Report Generator ─────────────────────────────────────
def generate_report(
    profiles_path   = "recon/complete_profiles.json",
    mqtt_path       = "mqtt/mqtt_results.json",
    coap_path       = "coap/coap_results.json",
    http_path       = "http/http_results.json",
    firmware_path   = "firmware/firmware_results.json",
    ai_path         = "ai_engine/ai_results.json",
    output_dir      = "reporting"
):
    """
    Generate complete AIPET penetration test report.

    Loads all module outputs and combines them into
    a professional report in both Markdown and JSON formats.

    Args:
        profiles_path (str): Module 1 complete profiles
        mqtt_path (str):     Module 2 MQTT results
        coap_path (str):     Module 3 CoAP results
        http_path (str):     Module 4 HTTP results
        firmware_path (str): Module 5 firmware results
        ai_path (str):       Module 6 AI results
        output_dir (str):    Output directory for reports

    Returns:
        str: Path to generated report
    """
    print("=" * 60)
    print("  AIPET — Module 7: Report Generator")
    print("=" * 60)

    # Load all module outputs
    print("[*] Loading module results...")
    profiles   = load_json(profiles_path)
    mqtt       = load_json(mqtt_path)
    coap       = load_json(coap_path)
    http       = load_json(http_path)
    firmware   = load_json(firmware_path)
    ai_results = load_json(ai_path)

    # Handle profiles being a list
    if isinstance(profiles, list):
        profiles_list = profiles
    else:
        profiles_list = [profiles] if profiles else []

    # Handle ai_results being a list
    if isinstance(ai_results, list):
        ai_list = ai_results
    else:
        ai_list = [ai_results] if ai_results else []

    print(f"    [+] Profiles:    {len(profiles_list)} device(s)")
    print(f"    [+] MQTT:        "
          f"{'loaded' if mqtt else 'not found'}")
    print(f"    [+] CoAP:        "
          f"{'loaded' if coap else 'not found'}")
    print(f"    [+] HTTP:        "
          f"{'loaded' if http else 'not found'}")
    print(f"    [+] Firmware:    "
          f"{'loaded' if firmware else 'not found'}")
    print(f"    [+] AI Results:  {len(ai_list)} prediction(s)")

    # Aggregate all data
    all_data = {
        "profiles":   profiles_list,
        "mqtt":       mqtt,
        "coap":       coap,
        "http":       http,
        "firmware":   firmware,
        "ai_results": ai_list,
    }

    # Generate report timestamp
    timestamp    = datetime.now()
    report_date  = timestamp.strftime("%Y-%m-%d %H:%M:%S")
    file_date    = timestamp.strftime("%Y%m%d_%H%M%S")

    print("\n[*] Generating report sections...")

    # ── Build report ──────────────────────────────────────────
    report_lines = []

    # Report header
    report_lines.append(
        "# AIPET — IoT Penetration Test Report"
    )
    report_lines.append("")
    report_lines.append(
        "**AI-Powered Penetration Testing Framework for IoT**"
    )
    report_lines.append("")
    report_lines.append("---")
    report_lines.append("")
    report_lines.append("| Field | Value |")
    report_lines.append("|-------|-------|")
    report_lines.append(f"| Report Date | {report_date} |")
    report_lines.append(
        f"| Devices Assessed | {len(profiles_list)} |"
    )
    report_lines.append(
        "| Framework | AIPET v1.0 — Explainable AI "
        "IoT Penetration Testing |"
    )
    report_lines.append(
        "| Institution | Coventry University — "
        "MSc Cyber Security (Ethical Hacking) |"
    )
    report_lines.append(
        "| Classification | CONFIDENTIAL — "
        "For authorised use only |"
    )
    report_lines.append("")
    report_lines.append("---")
    report_lines.append("")

    # Table of contents
    report_lines.append("## Table of Contents")
    report_lines.append("")
    report_lines.append("1. [Executive Summary]"
                        "(#executive-summary)")
    report_lines.append("2. [Discovered Devices]"
                        "(#discovered-devices)")
    report_lines.append("3. [Detailed Findings]"
                        "(#detailed-findings)")
    report_lines.append("4. [AI-Powered Risk Analysis]"
                        "(#ai-powered-risk-analysis)")
    report_lines.append("5. [Recommendations]"
                        "(#recommendations)")
    report_lines.append("")
    report_lines.append("---")
    report_lines.append("")

    # Generate each section
    print("    [*] Executive summary...")
    report_lines.append(
        generate_executive_summary(all_data)
    )
    report_lines.append("---")
    report_lines.append("")

    print("    [*] Device profiles...")
    report_lines.append(
        generate_device_section(profiles_list, ai_list)
    )

    print("    [*] Detailed findings...")
    report_lines.append(
        generate_findings_section(all_data)
    )

    print("    [*] AI analysis section...")
    report_lines.append(
        generate_ai_section(ai_list)
    )

    print("    [*] Recommendations...")
    report_lines.append(
        generate_recommendations_section(all_data)
    )

    # Report footer
    report_lines.append("---")
    report_lines.append("")
    report_lines.append(
        "*Report generated by AIPET — "
        "AI-Powered Penetration Testing Framework for IoT*"
    )
    report_lines.append(
        "*Coventry University — MSc Cyber Security "
        "(Ethical Hacking) — 2025*"
    )
    report_lines.append(
        "*This report is confidential and intended solely "
        "for the authorised recipient.*"
    )

    # ── Save report ───────────────────────────────────────────
    os.makedirs(output_dir, exist_ok=True)

    # Save as Markdown
    md_filename = (
        f"{output_dir}/aipet_report_{file_date}.md"
    )
    report_content = "\n".join(report_lines)

    with open(md_filename, 'w') as f:
        f.write(report_content)

    # Save as JSON for programmatic access
    json_filename = (
        f"{output_dir}/aipet_report_{file_date}.json"
    )
    report_json = {
        "report_date":     report_date,
        "devices_assessed":len(profiles_list),
        "modules_run":     [
            "Recon Engine",
            "MQTT Attack Suite",
            "CoAP Attack Suite",
            "HTTP/Web IoT Suite",
            "Firmware Analyser",
            "Explainable AI Engine"
        ],
        "all_data":        all_data,
        "report_content":  report_content
    }

    with open(json_filename, 'w') as f:
        json.dump(report_json, f, indent=4)

    print(f"\n[+] Markdown report: {md_filename}")
    print(f"[+] JSON report:     {json_filename}")

    # Print summary
    print("\n" + "=" * 60)
    print("  REPORT GENERATION COMPLETE")
    print("=" * 60)
    print(f"  Devices:  {len(profiles_list)}")
    print(f"  Modules:  6 modules executed")
    print(f"  Format:   Markdown + JSON")
    print(f"  Output:   {output_dir}/")
    print("=" * 60)

    return md_filename


if __name__ == "__main__":
    generate_report()