# =============================================================
# AIPET — AI-Powered Penetration Testing Framework for IoT
# Module 1: Recon Engine — Profile Builder
# Author: Binyam
# Institution: Coventry University — MSc Cyber Security
#              (Ethical Hacking)
# Date: March 2025
# Licence: MIT
# Description: Builds complete device profiles by combining
#              scanner and fingerprint results. Calculates
#              risk scores and recommends attack modules.
# =============================================================

import json
from datetime import datetime

# Risk points assigned to dangerous open ports
# Higher = more dangerous
PORT_RISK_SCORES = {
    23:    40,   # Telnet — plaintext credentials, critical
    1883:  35,   # MQTT — often no authentication
    502:   40,   # Modbus — no authentication by design
    102:   40,   # S7comm — Siemens PLC, critical infrastructure
    47808: 35,   # BACnet — building automation, often exposed
    5683:  25,   # CoAP — lightweight, often unauthenticated
    8080:  15,   # Alternative HTTP — often admin interfaces
    8443:  10,   # Alternative HTTPS — check certificates
    21:    30,   # FTP — plaintext credentials
    25:    20,   # SMTP — mail relay abuse
    9100:  20,   # Printer — direct print access
    5060:  20,   # SIP — VoIP eavesdropping
}

# Risk points assigned to device types
DEVICE_TYPE_RISK = {
    "industrial_controller":  40,
    "mqtt_broker":            35,
    "ip_camera":              30,
    "coap_device":            25,
    "iot_gateway":            25,
    "smart_home_hub":         20,
    "voip_device":            20,
    "embedded_linux_device":  15,
    "network_printer":        15,
    "generic_iot_device":     10,
    "unknown_device":         20,
}


# Maps open ports to recommended AIPET attack modules
MODULE_RECOMMENDATIONS = {
    1883:  {
        "module":      "Module 2 — MQTT Attack Suite",
        "reason":      "MQTT broker detected on port 1883",
        "priority":    "HIGH"
    },
    8883:  {
        "module":      "Module 2 — MQTT Attack Suite",
        "reason":      "Encrypted MQTT detected on port 8883",
        "priority":    "MEDIUM"
    },
    5683:  {
        "module":      "Module 3 — CoAP Attack Suite",
        "reason":      "CoAP service detected on port 5683",
        "priority":    "HIGH"
    },
    5684:  {
        "module":      "Module 3 — CoAP Attack Suite",
        "reason":      "Encrypted CoAP detected on port 5684",
        "priority":    "MEDIUM"
    },
    80:    {
        "module":      "Module 4 — HTTP/Web IoT Suite",
        "reason":      "HTTP web interface detected on port 80",
        "priority":    "MEDIUM"
    },
    443:   {
        "module":      "Module 4 — HTTP/Web IoT Suite",
        "reason":      "HTTPS web interface detected on port 443",
        "priority":    "MEDIUM"
    },
    8080:  {
        "module":      "Module 4 — HTTP/Web IoT Suite",
        "reason":      "Alternative HTTP interface on port 8080",
        "priority":    "HIGH"
    },
    8443:  {
        "module":      "Module 4 — HTTP/Web IoT Suite",
        "reason":      "Alternative HTTPS interface on port 8443",
        "priority":    "MEDIUM"
    },
    502:   {
        "module":      "Module 3 — CoAP Attack Suite",
        "reason":      "Modbus industrial protocol on port 502",
        "priority":    "CRITICAL"
    },
    23:    {
        "module":      "Module 4 — HTTP/Web IoT Suite",
        "reason":      "Telnet open — attempt credential attacks",
        "priority":    "CRITICAL"
    },
}

# Maps device types to firmware analysis recommendation
FIRMWARE_DEVICES = [
    "embedded_linux_device",
    "iot_gateway",
    "ip_camera",
    "industrial_controller",
    "generic_iot_device"
]

def calculate_risk_score(profile):
    """
    Calculate an overall risk score for a device (0-100).

    Higher score = higher risk = test this device first.

    Args:
        profile (dict): Fingerprinted device profile

    Returns:
        int: Risk score between 0 and 100
    """
    score = 0

    # Add points for dangerous open ports
    for port in profile.get("ports", []):
        if port in PORT_RISK_SCORES:
            score += PORT_RISK_SCORES[port]

    # Add points for device type risk
    device_type = profile.get("device_type", "unknown_device")
    score += DEVICE_TYPE_RISK.get(device_type, 10)

    # Cap score at 100
    score = min(score, 100)

    return score

def get_risk_label(score):
    """
    Convert numeric risk score to a human-readable label.

    Args:
        score (int): Risk score 0-100

    Returns:
        str: Risk label
    """
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    elif score >= 20:
        return "LOW"
    else:
        return "INFORMATIONAL"

def recommend_modules(profile):
    """
    Recommend AIPET attack modules based on open ports
    and device type.

    Args:
        profile (dict): Fingerprinted device profile

    Returns:
        list: Recommended modules sorted by priority
    """
    recommendations = []
    seen_modules    = set()

    # Check port-based recommendations
    for port in profile.get("ports", []):
        if port in MODULE_RECOMMENDATIONS:
            rec    = MODULE_RECOMMENDATIONS[port]
            module = rec["module"]

            # Avoid duplicate module recommendations
            if module not in seen_modules:
                recommendations.append(rec)
                seen_modules.add(module)

    # Check if firmware analysis is recommended
    device_type = profile.get("device_type", "unknown_device")
    if device_type in FIRMWARE_DEVICES:
        firmware_rec = {
            "module":   "Module 5 — Firmware Analyser",
            "reason":   f"{device_type} detected — firmware analysis recommended",
            "priority": "MEDIUM"
        }
        if firmware_rec["module"] not in seen_modules:
            recommendations.append(firmware_rec)

    # Sort by priority: CRITICAL first, then HIGH, MEDIUM, LOW
    priority_order = {
        "CRITICAL": 0,
        "HIGH":     1,
        "MEDIUM":   2,
        "LOW":      3
    }
    recommendations.sort(
        key=lambda x: priority_order.get(x["priority"], 99)
    )

    return recommendations

def build_complete_profile(fingerprint_profile):
    """
    Build a complete device profile by adding risk scoring
    and module recommendations to a fingerprint profile.

    Args:
        fingerprint_profile (dict): Profile from fingerprint.py

    Returns:
        dict: Complete device profile ready for AI engine
    """
    # Calculate risk
    risk_score = calculate_risk_score(fingerprint_profile)
    risk_label = get_risk_label(risk_score)

    # Get module recommendations
    modules = recommend_modules(fingerprint_profile)

    # Build the complete profile
    complete_profile = {
        "ip":               fingerprint_profile.get("ip"),
        "scan_time":        fingerprint_profile.get("scan_time"),
        "hostname":         fingerprint_profile.get("hostname"),
        "state":            fingerprint_profile.get("state"),
        "ports":            fingerprint_profile.get("ports", []),
        "services":         fingerprint_profile.get("services", {}),
        "device_type":      fingerprint_profile.get("device_type"),
        "confidence":       fingerprint_profile.get("confidence"),
        "risk_indicators":  fingerprint_profile.get(
                                "risk_indicators", []),
        "risk_score":       risk_score,
        "risk_label":       risk_label,
        "recommended_modules": modules,
        "profile_built":    datetime.now().strftime(
                                "%Y-%m-%d %H:%M:%S")
    }

    return complete_profile

def build_all_profiles(fingerprint_results):
    """
    Build complete profiles for all fingerprinted devices.

    Args:
        fingerprint_results (list): List from fingerprint.py

    Returns:
        list: Complete profiles sorted by risk score
               (highest risk first)
    """
    print(f"\n[*] Building complete profiles for "
          f"{len(fingerprint_results)} device(s)...")

    complete_profiles = []
    for profile in fingerprint_results:
        complete = build_complete_profile(profile)
        complete_profiles.append(complete)

        print(f"\n[+] {complete['ip']}")
        print(f"    Device Type:  {complete['device_type']}")
        print(f"    Risk Score:   {complete['risk_score']}/100"
              f" — {complete['risk_label']}")

        if complete['recommended_modules']:
            print(f"    Recommended Modules:")
            for mod in complete['recommended_modules']:
                print(f"       [{mod['priority']}] "
                      f"{mod['module']}")
                print(f"       Reason: {mod['reason']}")

    # Sort by risk score — highest risk first
    complete_profiles.sort(
        key=lambda x: x['risk_score'],
        reverse=True
    )

    return complete_profiles

def load_fingerprint_results(
        filepath="recon/fingerprint_results.json"):
    """Load fingerprint results from JSON file."""
    with open(filepath, 'r') as f:
        return json.load(f)


def save_complete_profiles(
        profiles,
        filepath="recon/complete_profiles.json"):
    """Save complete profiles to JSON file."""
    with open(filepath, 'w') as f:
        json.dump(profiles, f, indent=4)
    print(f"\n[+] Complete profiles saved to {filepath}")


def main():
    """
    Main function — builds complete device profiles.
    """
    print("=" * 60)
    print("  AIPET — Module 1: Profile Builder")
    print("=" * 60)

    # Load fingerprint results
    try:
        fingerprint_results = load_fingerprint_results()
        print(f"[+] Loaded {len(fingerprint_results)}"
              f" fingerprint result(s)")
    except FileNotFoundError:
        print("[-] fingerprint_results.json not found.")
        print("    Run fingerprint.py first.")
        return

    # Build complete profiles
    profiles = build_all_profiles(fingerprint_results)

    # Save results
    save_complete_profiles(profiles)

    # Final summary
    print("\n" + "=" * 60)
    print("  COMPLETE PROFILE SUMMARY")
    print("=" * 60)
    print(f"\n  Total devices profiled: {len(profiles)}")

    for p in profiles:
        print(f"\n  {p['ip']} — {p['device_type']}")
        print(f"  Risk: {p['risk_score']}/100 "
              f"({p['risk_label']})")
        print(f"  Modules to run: "
              f"{len(p['recommended_modules'])}")

    print("\n[+] Module 1 complete.")
    print("[+] Complete profiles ready for AI engine.")
    print("=" * 60)


if __name__ == "__main__":
    main()


