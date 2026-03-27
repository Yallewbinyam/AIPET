# =============================================================
# AIPET — AI-Powered Penetration Testing Framework for IoT
# Module 6: AI Engine — Real NVD Dataset Builder
# Author: Binyam
# Institution: Coventry University — MSc Cyber Security
#              (Ethical Hacking)
# Date: March 2025
# Licence: MIT
# Description: Downloads real IoT CVE data from the NVD
#              (National Vulnerability Database) API and
#              builds a training dataset for the AIPET
#              AI model.
#
#              Replaces the synthetic dataset with real
#              vulnerability data for improved model
#              accuracy and academic credibility.
#
#              NVD API: https://nvd.nist.gov/developers/
# =============================================================

import requests
import pandas as pd
import numpy as np
import json
import os
import time
from datetime import datetime

# ── Constants ─────────────────────────────────────────────────

# NVD API endpoint
NVD_API_URL = (
    "https://services.nvd.nist.gov/rest/json/cves/2.0"
)

# IoT-related search keywords
# Each keyword targets a specific IoT attack category
IOT_KEYWORDS = [
    "MQTT",
    "CoAP",
    "IoT firmware",
    "embedded device",
    "router firmware",
    "IP camera",
    "smart home",
    "industrial IoT",
    "Modbus",
    "Zigbee",
    "hardcoded password",
    "default credentials",
    "telnet IoT",
    "BusyBox",
    "OpenWrt",
]

# Results per page — NVD maximum is 2000
RESULTS_PER_PAGE = 200

# Delay between API requests — NVD rate limit is
# 5 requests per 30 seconds without API key
REQUEST_DELAY = 6

# Output paths
OUTPUT_DIR  = "ai_engine/data"
OUTPUT_FILE = f"{OUTPUT_DIR}/nvd_iot_dataset.csv"
RAW_FILE    = f"{OUTPUT_DIR}/nvd_raw_cves.json"


# ── Feature Extraction ────────────────────────────────────────
def extract_features_from_cve(cve_item):
    """
    Extract AIPET feature vector from a single NVD CVE record.

    Maps NVD CVE fields to the same 26 features used in
    the synthetic dataset so the trained model can be
    applied to real scan results.

    Args:
        cve_item (dict): Single CVE item from NVD API

    Returns:
        dict: Feature vector matching training schema
    """
    features = {
        # Device profile features
        "device_type":                0,
        "open_port_count":            0,
        "port_22":                    0,
        "port_23":                    0,
        "port_80":                    0,
        "port_443":                   0,
        "port_502":                   0,
        "port_1883":                  0,
        "port_5683":                  0,
        "port_8080":                  0,
        "port_8883":                  0,

        # MQTT features
        "mqtt_anonymous":             0,
        "mqtt_default_creds":         0,
        "mqtt_sensitive_data":        0,

        # CoAP features
        "coap_unauth_read":           0,
        "coap_unauth_write":          0,
        "coap_replay":                0,

        # HTTP features
        "http_default_creds":         0,
        "http_admin_exposed":         0,
        "http_sensitive_data":        0,

        # Firmware features
        "firmware_hardcoded_creds":   0,
        "firmware_private_key":       0,
        "firmware_telnet":            0,
        "firmware_vulnerable_component": 0,
        "firmware_debug":             0,
        "firmware_version_risk":      0,

        # Target label
        "severity":                   0
    }

    try:
        cve = cve_item.get("cve", {})

        # Get CVE description
        descriptions = cve.get("descriptions", [])
        description  = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "").lower()
                break

        # ── Extract CVSS severity ──────────────────────────
        # Map CVSS base score to our 4-class severity label
        # 0=Low, 1=Medium, 2=High, 3=Critical
        metrics = cve.get("metrics", {})
        base_score = 0.0

        # Try CVSS v3.1 first (most accurate)
        if "cvssMetricV31" in metrics:
            cvss = metrics["cvssMetricV31"][0]["cvssData"]
            base_score = cvss.get("baseScore", 0.0)
        # Fall back to CVSS v3.0
        elif "cvssMetricV30" in metrics:
            cvss = metrics["cvssMetricV30"][0]["cvssData"]
            base_score = cvss.get("baseScore", 0.0)
        # Fall back to CVSS v2
        elif "cvssMetricV2" in metrics:
            cvss = metrics["cvssMetricV2"][0]["cvssData"]
            base_score = cvss.get("baseScore", 0.0)

        # Map CVSS score to severity label
        if base_score >= 9.0:
            features["severity"] = 3    # Critical
        elif base_score >= 7.0:
            features["severity"] = 2    # High
        elif base_score >= 4.0:
            features["severity"] = 1    # Medium
        else:
            features["severity"] = 0    # Low

        # ── Extract features from description ─────────────
        # Map vulnerability description keywords to features

        # MQTT-related vulnerabilities
        if "mqtt" in description:
            features["port_1883"]     = 1
            features["open_port_count"] += 1
            if any(k in description for k in [
                "anonymous", "unauthenticated", "no auth"
            ]):
                features["mqtt_anonymous"] = 1
            if any(k in description for k in [
                "default", "hardcoded", "credential"
            ]):
                features["mqtt_default_creds"] = 1

        # CoAP-related vulnerabilities
        if "coap" in description:
            features["port_5683"]     = 1
            features["open_port_count"] += 1
            if "unauthenticated" in description:
                features["coap_unauth_read"]  = 1
                features["coap_unauth_write"] = 1

        # Telnet vulnerabilities
        if "telnet" in description:
            features["port_23"]          = 1
            features["firmware_telnet"]  = 1
            features["open_port_count"] += 1

        # Web interface vulnerabilities
        if any(k in description for k in [
            "web interface", "http", "web server",
            "admin panel", "management interface"
        ]):
            features["port_80"]  = 1
            features["open_port_count"] += 1
            if any(k in description for k in [
                "default password", "default credential",
                "hardcoded password"
            ]):
                features["http_default_creds"] = 1
            if "admin" in description:
                features["http_admin_exposed"] = 1

        # Firmware vulnerabilities
        if any(k in description for k in [
            "firmware", "embedded", "flash"
        ]):
            if any(k in description for k in [
                "hardcoded", "hard-coded", "default"
            ]):
                features["firmware_hardcoded_creds"] = 1
            if "private key" in description:
                features["firmware_private_key"] = 1
            if any(k in description for k in [
                "outdated", "vulnerable version", "old version"
            ]):
                features["firmware_vulnerable_component"] = 1
                features["firmware_version_risk"] = 2

        # Modbus/Industrial
        if any(k in description for k in [
            "modbus", "industrial", "scada", "plc"
        ]):
            features["port_502"]       = 1
            features["open_port_count"] += 1
            features["device_type"]    = 6  # industrial

        # BusyBox/embedded Linux
        if "busybox" in description:
            features["firmware_vulnerable_component"] = 1
            features["device_type"] = 7  # embedded_linux

        # SSH vulnerabilities
        if "ssh" in description:
            features["port_22"] = 1
            features["open_port_count"] += 1

        # Router/gateway
        if any(k in description for k in [
            "router", "gateway", "access point"
        ]):
            features["device_type"] = 4  # iot_gateway

        # IP camera
        if any(k in description for k in [
            "camera", "webcam", "ip camera"
        ]):
            features["device_type"] = 3  # ip_camera

        # High severity indicators
        if features["severity"] >= 3:
            features["firmware_version_risk"] = max(
                features["firmware_version_risk"], 3
            )

    except Exception as e:
        pass

    return features


# ── NVD API Fetcher ───────────────────────────────────────────
def fetch_nvd_cves(keyword, max_results=200):
    """
    Fetch CVEs from NVD API for a specific keyword.

    Uses the NVD REST API v2.0. Rate limited to
    5 requests per 30 seconds without an API key.
    We add REQUEST_DELAY seconds between calls.

    Args:
        keyword (str): Search keyword
        max_results (int): Maximum CVEs to fetch

    Returns:
        list: CVE items from NVD API
    """
    all_cves = []
    start_index = 0

    while len(all_cves) < max_results:
        try:
            params = {
                "keywordSearch":  keyword,
                "resultsPerPage": min(
                    RESULTS_PER_PAGE,
                    max_results - len(all_cves)
                ),
                "startIndex":     start_index,
            }

            response = requests.get(
                NVD_API_URL,
                params=params,
                timeout=30
            )

            if response.status_code == 200:
                data         = response.json()
                vulns        = data.get("vulnerabilities", [])
                total        = data.get("totalResults", 0)

                all_cves.extend(vulns)
                start_index += len(vulns)

                print(f"    Fetched {len(all_cves)}/{min(total, max_results)} CVEs for '{keyword}'")

                # Stop if we have all results
                if start_index >= total or not vulns:
                    break

                # Rate limit delay
                time.sleep(REQUEST_DELAY)

            elif response.status_code == 403:
                print(f"    [-] Rate limited — waiting 30s...")
                time.sleep(30)
            else:
                print(
                    f"    [-] API error: {response.status_code}"
                )
                break

        except requests.exceptions.Timeout:
            print(f"    [-] Timeout for '{keyword}'")
            break
        except Exception as e:
            print(f"    [-] Error: {str(e)}")
            break

    return all_cves


# ── Main Dataset Builder ──────────────────────────────────────
def build_nvd_dataset():
    """
    Build IoT vulnerability dataset from real NVD data.

    Downloads CVEs for each IoT keyword, extracts features,
    deduplicates by CVE ID, and saves as CSV for model
    training.

    Returns:
        pd.DataFrame: Complete NVD-based training dataset
    """
    print("=" * 60)
    print("  AIPET — NVD IoT Dataset Builder")
    print("=" * 60)
    print(f"[*] Fetching real IoT CVEs from NVD API...")
    print(f"[*] Keywords: {len(IOT_KEYWORDS)}")
    print(f"[*] This will take several minutes due to")
    print(f"    NVD API rate limiting (6s between requests)")
    print()

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    all_cves    = []
    seen_ids    = set()

    # Fetch CVEs for each keyword
    for i, keyword in enumerate(IOT_KEYWORDS):
        print(f"[{i+1}/{len(IOT_KEYWORDS)}] "
              f"Fetching: '{keyword}'")

        cves = fetch_nvd_cves(keyword, max_results=100)

        # Deduplicate by CVE ID
        new_count = 0
        for cve_item in cves:
            cve_id = cve_item.get("cve", {}).get("id", "")
            if cve_id and cve_id not in seen_ids:
                seen_ids.add(cve_id)
                all_cves.append(cve_item)
                new_count += 1

        print(f"    [+] {new_count} new unique CVEs "
              f"(total: {len(all_cves)})")

        # Rate limit between keywords
        if i < len(IOT_KEYWORDS) - 1:
            time.sleep(REQUEST_DELAY)

    print(f"\n[+] Total unique CVEs collected: {len(all_cves)}")

    # Save raw CVE data
    with open(RAW_FILE, 'w') as f:
        json.dump(all_cves, f, indent=2)
    print(f"[+] Raw CVEs saved to {RAW_FILE}")

    # Extract features from each CVE
    print(f"\n[*] Extracting features from {len(all_cves)} CVEs...")
    rows = []
    for cve_item in all_cves:
        features = extract_features_from_cve(cve_item)
        rows.append(features)

    # Build DataFrame
    df = pd.DataFrame(rows)

    # Show label distribution
    print(f"\n[+] Label distribution:")
    label_names = {
        0: "Low", 1: "Medium", 2: "High", 3: "Critical"
    }
    for label, name in label_names.items():
        count = (df["severity"] == label).sum()
        pct   = (count / len(df)) * 100
        bar   = "█" * int(pct / 2)
        print(f"  {name:10} ({label}): "
              f"{count:4} ({pct:5.1f}%) {bar}")

    # Save dataset
    df.to_csv(OUTPUT_FILE, index=False)
    print(f"\n[+] NVD dataset saved to {OUTPUT_FILE}")
    print(f"[+] Total samples: {len(df)}")
    print(f"[+] Features: {len(df.columns) - 1}")
    print("=" * 60)

    return df


if __name__ == "__main__":
    df = build_nvd_dataset()