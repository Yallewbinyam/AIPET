# AIPET — Explainable AI-Powered Penetration Testing Framework for IoT

> The first open-source framework combining IoT-specific
> protocol attack modules with an **explainable** AI-driven
> vulnerability suggestion engine — telling you not just
> what is vulnerable, but exactly **why**.

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-30%20passing-brightgreen.svg)](tests/)
[![Version](https://img.shields.io/badge/Version-1.0.0-orange.svg)](aipet.py)

---

## What is AIPET?

AIPET is a modular, open-source penetration testing
framework built specifically for IoT environments.
It automates the discovery, testing, and intelligent
prioritisation of vulnerabilities across IoT devices
and protocols — then explains every finding in
plain English using SHAP (SHapley Additive exPlanations).

**One command. Complete IoT security assessment.**
```bash
python3 aipet.py --target 192.168.1.0/24
```

---

## What Makes AIPET Different

| Capability | Existing Tools | AIPET |
|-----------|---------------|-------|
| IoT-specific design | ✗ Generic IT tools | ✅ Built for IoT |
| AI-driven prioritisation | ✗ Not present | ✅ Random Forest |
| Explainable AI (SHAP) | ✗ Black box | ✅ Full explanation |
| MQTT/CoAP coverage | ✗ Partial/none | ✅ Full coverage |
| Firmware analysis | ✗ Separate tools | ✅ Integrated |
| Plain-English findings | ✗ Technical only | ✅ Human readable |
| Open source | ✗ Inconsistent | ✅ MIT licence |

---

## Modules

| # | Module | Status |
|---|--------|--------|
| 01 | Recon Engine | ✅ Complete |
| 02 | MQTT Attack Suite | ✅ Complete |
| 03 | CoAP Attack Suite | ✅ Complete |
| 04 | HTTP/Web IoT Suite | ✅ Complete |
| 05 | Firmware Analyser | ✅ Complete |
| 06 | Explainable AI Engine | ✅ Complete |
| 07 | Report Generator | ✅ Complete |

---

## Quick Start
```bash
# Clone
git clone https://github.com/YOUR_USERNAME/AIPET.git
cd AIPET

# Install
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
sudo apt install nmap binwalk mosquitto -y

# Verify
python3 aipet.py --version

# Demo
python3 aipet.py --demo

# Scan a single network
python3 aipet.py --target 192.168.1.0/24

# Scan multiple networks simultaneously
python3 aipet.py --targets targets.txt --workers 3
```

See [INSTALL.md](INSTALL.md) for full installation guide.

📖 **[User Manual](USER_MANUAL.md)** — Complete guide for all users

📋 **[Responsible Use Policy](RESPONSIBLE_USE.md)** — Legal and ethical guidelines

---

## Sample Output
```
╔══════════════════════════════════════════════════════════════╗
║         AIPET — Explainable AI-Powered IoT Pentest          ║
║                    Framework v1.0.0                          ║
╚══════════════════════════════════════════════════════════════╝

[Module 1] Reconnaissance
[+] Found 3 device(s) — auto-detected: MQTT CoAP HTTP Firmware

[Module 2] MQTT Attack Suite
[!] CRITICAL: Broker accepts anonymous connections
[!] CRITICAL: 17 valid credential sets found

[Module 6] Explainable AI Engine
🚨 PREDICTION: Critical (91.3% confidence)

Key factors:
  + MQTT anonymous access (impact: 43.2%)
  + Firmware version risk (impact: 31.1%)
  + Open port count (impact: 12.4%)

╔══════════════════════════════════════════════╗
║           AIPET PIPELINE COMPLETE            ║
║  Duration: 63.9s  |  Critical: 6  High: 3   ║
╚══════════════════════════════════════════════╝
```

---

## AI Performance

| Metric | Value | Target |
|--------|-------|--------|
| Weighted F1-Score | 0.8614 | ≥ 0.85 ✅ |
| CV Mean F1 | 0.8668 | — ✅ |
| CV Stability (Std) | 0.0108 | < 0.05 ✅ |
| Critical Class F1 | 0.9440 | — ✅ |

---

## Validation

AIPET was validated against **OWASP IoTGoat v1.0** —
an independently developed deliberately vulnerable
IoT firmware image.

**Results vs Manual Assessment:**

| Metric | Manual | AIPET | Improvement |
|--------|--------|-------|-------------|
| Time | 162s | ~30s | 5.4x faster |
| Credential findings | 8 | 279 | 34x more |
| Private keys | 1 | 12 | 12x more |
| Dangerous configs | 0 | 33 | New coverage |

---

## OWASP IoT Top 10 Coverage

| Category | Covered By |
|----------|-----------|
| I1 Weak Passwords | Modules 2, 4, 5 |
| I2 Insecure Network Services | Module 1 |
| I3 Insecure Interfaces | Modules 3, 4 |
| I4 Lack of Secure Update | Module 5 |
| I5 Insecure Components | Module 5 |
| I6 Insufficient Privacy | Modules 2, 3 |
| I7 Insecure Data Transfer | Modules 2, 3, 5 |
| I8 Lack of Device Management | Module 1 |
| I9 Insecure Default Settings | Modules 2, 4 |
| I10 Lack of Physical Hardening | Module 5 |

**10/10 OWASP IoT categories covered.**

---

## Responsible Use

⚠️ **For authorised penetration testing only.**

Never use AIPET against systems you do not have
explicit written permission to test.

See [RESPONSIBLE_USE.md](RESPONSIBLE_USE.md) for
full policy.

---

## Academic Citation
```
Binyam (2025). AIPET: An Explainable AI-Powered
Penetration Testing Framework for IoT Vulnerability
Discovery. MSc Dissertation, Coventry University.
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## Licence

MIT — see [LICENSE](LICENSE)

---

*Developed as part of MSc Cyber Security (Ethical Hacking)
research at Coventry University, 2025.*
