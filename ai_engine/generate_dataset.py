# =============================================================
# AIPET — AI-Powered Penetration Testing Framework for IoT
# Module 6: AI Engine — Dataset Generator
# Author: Binyam
# Institution: Coventry University — MSc Cyber Security
#              (Ethical Hacking)
# Date: March 2025
# Licence: MIT
# Description: Generates a realistic IoT vulnerability dataset
#              for training the AIPET AI model.
#              Simulates IoT CVE records from the NVD database
#              combined with device profile features.
#
# In production this would be replaced by real NVD API data.
# The feature structure is identical — only the values change.
# =============================================================

import pandas as pd
import numpy as np
import json
import os
from datetime import datetime

# Set random seed for reproducibility
# This ensures the same dataset is generated every time
# which is essential for academic research reproducibility
np.random.seed(42)

# ── Feature Definitions ───────────────────────────────────────
# These are the features AIPET extracts from device profiles
# and uses to train the AI model.
# Each feature maps to something Module 1-5 can discover.

# Number of training samples to generate
N_SAMPLES = 2000

def generate_dataset():
    """
    Generate a realistic IoT vulnerability training dataset.

    Each row represents one IoT device assessment with:
    - Device profile features (from Module 1)
    - Protocol vulnerability features (from Modules 2-4)
    - Firmware features (from Module 5)
    - Target label: vulnerability severity

    Returns:
        pd.DataFrame: Complete training dataset
    """

    print("=" * 60)
    print("  AIPET — Module 6: Dataset Generator")
    print("=" * 60)
    print(f"[*] Generating {N_SAMPLES} training samples...")

    # ── Device Type Distribution ──────────────────────────────
    # Reflects real-world IoT deployment proportions
    # based on Shodan exposure data
    device_types = np.random.choice(
        [0, 1, 2, 3, 4, 5, 6, 7],
        # 0=unknown, 1=mqtt_broker, 2=coap_device,
        # 3=ip_camera, 4=iot_gateway, 5=smart_home_hub,
        # 6=industrial_controller, 7=embedded_linux
        size=N_SAMPLES,
        p=[0.05, 0.15, 0.10, 0.20, 0.15,
           0.15, 0.10, 0.10]
    )

    # ── Port Features ─────────────────────────────────────────
    # Binary features: 1 = port is open, 0 = port is closed
    # These map directly to Module 1 scanner.py output

    # Port 1883: MQTT (unencrypted) — very common on IoT
    port_1883 = np.random.binomial(1, 0.45, N_SAMPLES)

    # Port 8883: MQTT over TLS — less common, more secure
    port_8883 = np.random.binomial(1, 0.15, N_SAMPLES)

    # Port 5683: CoAP (unencrypted)
    port_5683 = np.random.binomial(1, 0.20, N_SAMPLES)

    # Port 23: Telnet — critical risk when open
    port_23 = np.random.binomial(1, 0.25, N_SAMPLES)

    # Port 22: SSH — common on Linux-based IoT
    port_22 = np.random.binomial(1, 0.55, N_SAMPLES)

    # Port 80: HTTP web interface
    port_80 = np.random.binomial(1, 0.65, N_SAMPLES)

    # Port 443: HTTPS web interface
    port_443 = np.random.binomial(1, 0.30, N_SAMPLES)

    # Port 502: Modbus — industrial protocol, critical
    port_502 = np.random.binomial(1, 0.08, N_SAMPLES)

    # Port 8080: Alternative HTTP — often admin panels
    port_8080 = np.random.binomial(1, 0.35, N_SAMPLES)

    # ── MQTT Vulnerability Features ───────────────────────────
    # From Module 2 — mqtt_attacker.py output

    # Anonymous MQTT connection accepted (no auth)
    mqtt_anonymous = np.where(
        port_1883 == 1,
        np.random.binomial(1, 0.75, N_SAMPLES),
        0  # Cannot be vulnerable if MQTT not open
    )

    # Default MQTT credentials work
    mqtt_default_creds = np.where(
        port_1883 == 1,
        np.random.binomial(1, 0.60, N_SAMPLES),
        0
    )

    # Sensitive data found in MQTT topics
    mqtt_sensitive_data = np.where(
        mqtt_anonymous == 1,
        np.random.binomial(1, 0.50, N_SAMPLES),
        0
    )

    # ── CoAP Vulnerability Features ───────────────────────────
    # From Module 3 — coap_attacker.py output

    # Unauthenticated read access to CoAP resources
    coap_unauth_read = np.where(
        port_5683 == 1,
        np.random.binomial(1, 0.80, N_SAMPLES),
        0
    )

    # Unauthenticated write access to CoAP resources
    coap_unauth_write = np.where(
        coap_unauth_read == 1,
        np.random.binomial(1, 0.60, N_SAMPLES),
        0
    )

    # CoAP replay attack successful
    coap_replay = np.where(
        port_5683 == 1,
        np.random.binomial(1, 0.70, N_SAMPLES),
        0
    )

    # ── HTTP Vulnerability Features ───────────────────────────
    # From Module 4 — http_attacker.py output

    # Default HTTP credentials work
    http_default_creds = np.where(
        port_80 == 1,
        np.random.binomial(1, 0.55, N_SAMPLES),
        0
    )

    # Admin interface accessible without authentication
    http_admin_exposed = np.where(
        port_80 == 1,
        np.random.binomial(1, 0.65, N_SAMPLES),
        0
    )

    # Sensitive data in HTTP responses
    http_sensitive_data = np.where(
        http_admin_exposed == 1,
        np.random.binomial(1, 0.70, N_SAMPLES),
        0
    )

    # ── Firmware Features ─────────────────────────────────────
    # From Module 5 — firmware_analyser.py output

    # Hardcoded credentials found in firmware
    firmware_hardcoded_creds = np.random.binomial(
        1, 0.45, N_SAMPLES
    )

    # Private key found in firmware
    firmware_private_key = np.random.binomial(
        1, 0.20, N_SAMPLES
    )

    # Telnet enabled in firmware configuration
    firmware_telnet = np.where(
        port_23 == 1,
        np.random.binomial(1, 0.85, N_SAMPLES),
        np.random.binomial(1, 0.10, N_SAMPLES)
    )

    # Vulnerable component found (old OpenSSL, OpenSSH etc)
    firmware_vulnerable_component = np.random.binomial(
        1, 0.55, N_SAMPLES
    )

    # Debug mode enabled in firmware
    firmware_debug = np.random.binomial(1, 0.30, N_SAMPLES)

    # ── Firmware Version Risk ─────────────────────────────────
    # 0 = unknown, 1 = current, 2 = outdated, 3 = critical
    firmware_version_risk = np.random.choice(
        [0, 1, 2, 3],
        size=N_SAMPLES,
        p=[0.15, 0.25, 0.35, 0.25]
    )

    # ── Number of Open Ports ──────────────────────────────────
    # More open ports = larger attack surface
    open_port_count = (
        port_1883 + port_8883 + port_5683 +
        port_23 + port_22 + port_80 + port_443 +
        port_502 + port_8080
    )

    # ── Generate Target Labels ────────────────────────────────
    # The label is the overall vulnerability severity:
    # 0 = Low, 1 = Medium, 2 = High, 3 = Critical
    #
    # Labels are generated using a weighted rule system
    # that reflects real-world IoT vulnerability patterns.
    # This is where domain knowledge is encoded into the
    # training data — the same knowledge a human expert
    # would use to assess these findings.

    labels = np.zeros(N_SAMPLES, dtype=int)

    for i in range(N_SAMPLES):
        score = 0

        # Critical risk indicators — high weight
        if port_23[i] == 1:           score += 40  # Telnet
        if port_502[i] == 1:          score += 40  # Modbus
        if mqtt_anonymous[i] == 1:    score += 35  # No MQTT auth
        if firmware_private_key[i]:   score += 35  # Shared key
        if firmware_hardcoded_creds[i]: score += 30 # Hardcoded
        if mqtt_sensitive_data[i]:    score += 30  # Data exposed
        if http_sensitive_data[i]:    score += 30  # Data exposed

        # High risk indicators — medium weight
        if coap_unauth_write[i]:      score += 25  # Write access
        if http_default_creds[i]:     score += 25  # Default creds
        if firmware_vulnerable_component[i]: score += 25
        if firmware_version_risk[i] == 3:    score += 25

        # Medium risk indicators — lower weight
        if coap_unauth_read[i]:       score += 15  # Read access
        if http_admin_exposed[i]:     score += 15  # Admin exposed
        if firmware_debug[i]:         score += 15  # Debug on
        if firmware_telnet[i]:        score += 15  # Telnet config
        if firmware_version_risk[i] == 2: score += 15

        # Device type risk modifier
        if device_types[i] == 6:     score += 20  # Industrial
        elif device_types[i] == 1:   score += 15  # MQTT broker
        elif device_types[i] == 3:   score += 10  # IP camera

        # Open port count modifier
        score += open_port_count[i] * 3

        # Add small random noise to prevent perfect separation
        # Real-world data always has some noise
        score += np.random.randint(-10, 10)

        # Convert score to severity label
        if score >= 80:
            labels[i] = 3    # Critical
        elif score >= 50:
            labels[i] = 2    # High
        elif score >= 25:
            labels[i] = 1    # Medium
        else:
            labels[i] = 0    # Low

    # ── Build DataFrame ───────────────────────────────────────
    # Combine all features into a single DataFrame
    # Column names must match what Module 1-5 produce
    # so the trained model can be applied to real scans

    df = pd.DataFrame({
        # Device profile features (Module 1)
        "device_type":                device_types,
        "open_port_count":            open_port_count,
        "port_22":                    port_22,
        "port_23":                    port_23,
        "port_80":                    port_80,
        "port_443":                   port_443,
        "port_502":                   port_502,
        "port_1883":                  port_1883,
        "port_5683":                  port_5683,
        "port_8080":                  port_8080,
        "port_8883":                  port_8883,

        # MQTT features (Module 2)
        "mqtt_anonymous":             mqtt_anonymous,
        "mqtt_default_creds":         mqtt_default_creds,
        "mqtt_sensitive_data":        mqtt_sensitive_data,

        # CoAP features (Module 3)
        "coap_unauth_read":           coap_unauth_read,
        "coap_unauth_write":          coap_unauth_write,
        "coap_replay":                coap_replay,

        # HTTP features (Module 4)
        "http_default_creds":         http_default_creds,
        "http_admin_exposed":         http_admin_exposed,
        "http_sensitive_data":        http_sensitive_data,

        # Firmware features (Module 5)
        "firmware_hardcoded_creds":   firmware_hardcoded_creds,
        "firmware_private_key":       firmware_private_key,
        "firmware_telnet":            firmware_telnet,
        "firmware_vulnerable_component":
                                firmware_vulnerable_component,
        "firmware_debug":             firmware_debug,
        "firmware_version_risk":      firmware_version_risk,

        # Target label
        "severity":                   labels,
    })

    # ── Save Dataset ──────────────────────────────────────────
    os.makedirs("ai_engine/data", exist_ok=True)
    output_path = "ai_engine/data/iot_vulnerability_dataset.csv"
    df.to_csv(output_path, index=False)

    # ── Print Statistics ──────────────────────────────────────
    print(f"[+] Dataset generated: {N_SAMPLES} samples")
    print(f"[+] Features: {len(df.columns) - 1}")
    print(f"[+] Saved to: {output_path}")
    print()
    print("Label distribution:")
    label_names = {
        0: "Low",
        1: "Medium",
        2: "High",
        3: "Critical"
    }
    for label, name in label_names.items():
        count = (labels == label).sum()
        pct   = (count / N_SAMPLES) * 100
        bar   = "█" * int(pct / 2)
        print(f"  {name:10} ({label}): "
              f"{count:4} samples ({pct:5.1f}%) {bar}")

    print()
    print("Feature correlations with severity:")
    correlations = df.corr()['severity'].drop('severity')
    top_features = correlations.abs().sort_values(
        ascending=False
    ).head(10)
    for feature, corr in top_features.items():
        direction = "+" if corr > 0 else "-"
        print(f"  {direction}{abs(corr):.3f}  {feature}")

    print()
    print("[+] Dataset generation complete")
    print("=" * 60)

    return df


if __name__ == "__main__":
    df = generate_dataset()