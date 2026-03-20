# =============================================================
# AIPET — AI-Powered Penetration Testing Framework for IoT
# Module 1: Recon Engine — IoT Fingerprinter
# Author: Binyam
# Institution: Coventry University — MSc Cyber Security
#              (Ethical Hacking)
# Date: March 2025
# Licence: MIT
# Description: Identifies IoT device types from scan profiles
#              using port signatures and service banner matching
# =============================================================

import json
import re

# IoT Device Signature Database
SIGNATURES = {

    "mqtt_broker": {
        "ports":    [1883, 8883],
        "services": ["mqtt", "mosquitto"],
        "banners":  ["MQTT", "Mosquitto", "broker"],
        "weight":   9
    },

    "coap_device": {
        "ports":    [5683, 5684],
        "services": ["coap"],
        "banners":  ["CoAP", "coap", "libcoap"],
        "weight":   9
    },

    "ip_camera": {
        "ports":    [554, 8554, 8080, 80],
        "services": ["rtsp", "http"],
        "banners":  ["camera", "ipcam", "IPCamera",
                     "GoAhead", "IPCAM", "webcam",
                     "DVR", "NVR", "Hikvision", "Dahua"],
        "weight":   8
    },

    "iot_gateway": {
        "ports":    [1883, 80, 443, 8080],
        "services": ["http", "https", "mqtt"],
        "banners":  ["gateway", "router", "OpenWrt",
                     "DD-WRT", "lighttpd", "uhttpd"],
        "weight":   7
    },

    "smart_home_hub": {
        "ports":    [8080, 8443, 80, 443, 1883],
        "services": ["http", "https"],
        "banners":  ["hub", "SmartThings", "Home Assistant",
                     "Philips Hue", "zigbee", "zwave",
                     "homekit", "HomeKit"],
        "weight":   8
    },

    "industrial_controller": {
        "ports":    [502, 102, 44818, 47808],
        "services": ["modbus", "s7comm", "bacnet"],
        "banners":  ["Modbus", "Siemens", "Allen-Bradley",
                     "SCADA", "PLC", "RTU", "HMI"],
        "weight":   9
    },

    "network_printer": {
        "ports":    [9100, 515, 631],
        "services": ["ipp", "jetdirect", "lpd"],
        "banners":  ["printer", "Printer", "HP",
                     "Epson", "Canon", "JetDirect"],
        "weight":   8
    },

    "embedded_linux_device": {
        "ports":    [22, 23, 80],
        "services": ["ssh", "telnet", "http"],
        "banners":  ["BusyBox", "busybox", "uClibc",
                     "OpenWrt", "Buildroot", "Boa",
                     "lighttpd", "mini_httpd"],
        "weight":   6
    },

    "voip_device": {
        "ports":    [5060, 5061],
        "services": ["sip"],
        "banners":  ["SIP", "VoIP", "Asterisk",
                     "FreeSWITCH", "INVITE"],
        "weight":   9
    },

    "generic_iot_device": {
        "ports":    [80, 443, 8080, 8443],
        "services": ["http", "https"],
        "banners":  ["IoT", "iot", "embedded",
                     "firmware", "device"],
        "weight":   3
    }
}

# Port-based risk indicators
PORT_RISKS = {
    23:    "CRITICAL — Telnet open: credentials sent in plaintext",
    1883:  "HIGH — MQTT port open: check for authentication bypass",
    5683:  "MEDIUM — CoAP port open: check for unauthenticated access",
    502:   "CRITICAL — Modbus open: industrial protocol, no auth by design",
    102:   "CRITICAL — S7comm open: Siemens PLC protocol exposed",
    8080:  "MEDIUM — Alternative HTTP open: check for admin interfaces",
    8443:  "MEDIUM — Alternative HTTPS open: check certificate validity",
    9100:  "MEDIUM — Printer port open: check for direct print access",
    5060:  "MEDIUM — SIP open: check for VoIP eavesdropping",
    47808: "HIGH — BACnet open: building automation protocol exposed",
}


def fingerprint_device(device_profile):
    """
    Identify the IoT device type from its scan profile.

    Args:
        device_profile (dict): Single device profile from scanner.py

    Returns:
        dict: Enriched profile with device_type, confidence,
              and risk_indicators added
    """
    open_ports      = device_profile.get("ports", [])
    services        = device_profile.get("services", {})
    risk_indicators = []
    scores          = {}

    # Step 1: Score each signature against the device
    for device_type, signature in SIGNATURES.items():
        score = 0

        # Check port matches
        for port in open_ports:
            if port in signature["ports"]:
                score += signature["weight"]

        # Check service and banner matches
        for port_num, service_info in services.items():
            service_name = service_info.get("name", "").lower()
            product      = service_info.get("product", "").lower()
            version      = service_info.get("version", "").lower()
            extrainfo    = service_info.get("extrainfo", "").lower()

            banner_text  = f"{service_name} {product} {version} {extrainfo}"

            for sig_service in signature["services"]:
                if sig_service.lower() in service_name:
                    score += signature["weight"] * 2

            for pattern in signature["banners"]:
                if re.search(pattern.lower(), banner_text):
                    score += signature["weight"] * 3

        scores[device_type] = score

    # Step 2: Determine best match
    best_match  = max(scores, key=scores.get)
    best_score  = scores[best_match]
    total_score = sum(scores.values())

    if total_score > 0:
        confidence = round((best_score / total_score) * 100, 1)
    else:
        confidence = 0.0

    if best_score == 0:
        best_match = "unknown_device"
        confidence = 0.0

    # Step 3: Check port-based risk indicators
    for port in open_ports:
        if port in PORT_RISKS:
            risk_indicators.append({
                "port": port,
                "risk": PORT_RISKS[port]
            })

    # Step 4: Enrich the device profile
    device_profile["device_type"]      = best_match
    device_profile["confidence"]       = confidence
    device_profile["risk_indicators"]  = risk_indicators
    device_profile["all_scores"]       = scores

    return device_profile


def fingerprint_all(scan_results):
    """
    Fingerprint all devices from a scan results list.

    Args:
        scan_results (list): List of device profiles from scanner.py

    Returns:
        list: All profiles enriched with fingerprint data
    """
    print(f"\n[*] Fingerprinting {len(scan_results)} device(s)...")

    enriched_profiles = []
    for profile in scan_results:
        enriched = fingerprint_device(profile)
        enriched_profiles.append(enriched)

        print(f"\n[+] Device: {enriched['ip']}")
        print(f"    Type:       {enriched['device_type']}")
        print(f"    Confidence: {enriched['confidence']}%")

        if enriched['risk_indicators']:
            print(f"    Risks:")
            for risk in enriched['risk_indicators']:
                print(f"       Port {risk['port']}: {risk['risk']}")

    return enriched_profiles


def load_scan_results(filepath="recon/scan_results.json"):
    """Load scan results from JSON file."""
    with open(filepath, 'r') as f:
        return json.load(f)


def save_fingerprints(profiles,
                      filepath="recon/fingerprint_results.json"):
    """Save enriched profiles to JSON file."""
    with open(filepath, 'w') as f:
        json.dump(profiles, f, indent=4)
    print(f"\n[+] Fingerprint results saved to {filepath}")


def main():
    """
    Main function — loads scan results and fingerprints all devices.
    """
    print("=" * 60)
    print("  AIPET — Module 1: IoT Fingerprinter")
    print("=" * 60)

    try:
        scan_results = load_scan_results()
        print(f"[+] Loaded {len(scan_results)} device profile(s)")
    except FileNotFoundError:
        print("[-] scan_results.json not found.")
        print("    Run scanner.py first.")
        return

    enriched = fingerprint_all(scan_results)

    save_fingerprints(enriched)

    print("\n" + "=" * 60)
    print("  FINGERPRINT SUMMARY")
    print("=" * 60)
    for profile in enriched:
        print(f"\n  {profile['ip']}")
        print(f"  Type:       {profile['device_type']}")
        print(f"  Confidence: {profile['confidence']}%")
        print(f"  Open Ports: {profile['ports']}")
        risks = profile.get('risk_indicators', [])
        if risks:
            for r in risks:
                print(f"  Port {r['port']}: {r['risk']}")
        else:
            print(f"  No immediate port-based risks detected")


if __name__ == "__main__":
    main()
