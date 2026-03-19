# AIPET
# AIPET — AI-Powered Penetration Testing Framework for IoT

> The first open-source framework combining IoT-specific protocol 
> attack modules with an AI-driven vulnerability suggestion engine.

**Author:** Binyam  
**Institution:** Coventry University — MSc Cyber Security (Ethical Hacking)  
**Status:** 🔨 Active Development — v0.1  
**Started:** March 2026  

---

## What is AIPET?

AIPET automates the penetration testing workflow for IoT devices.  
It combines automated reconnaissance, protocol-level attack modules  
(MQTT, CoAP, HTTP), firmware analysis, and an AI engine trained on  
global IoT CVE data to rank and prioritise attack paths.

No equivalent open-source tool currently exists.

---

## Modules

| # | Module | Status |
|---|--------|--------|
| 01 | Recon Engine | 🔨 In Development |
| 02 | MQTT Attack Suite | 🔨 In Development |
| 03 | CoAP Attack Suite | 🔨 In Development |
| 04 | HTTP/Web IoT Suite | 🔨 In Development |
| 05 | Firmware Analyser | 🔨 In Development |
| 06 | AI Suggestion Engine | 🔨 In Development |
| 07 | Report Generator | 🔨 In Development |

---

## Tech Stack

- **Language:** Python 3.11+
- **AI/ML:** scikit-learn · TensorFlow
- **Recon:** Nmap · Shodan API · Scapy
- **Protocols:** Mosquitto · CoAPthon3
- **Firmware:** Binwalk · Firmwalker
- **Lab:** QEMU · Firmadyne · IoTGoat

---

## Responsible Use

This framework is designed exclusively for **authorised** 
penetration testing engagements.  
**Never** use against systems you do not have explicit written 
permission to test.  
All development testing is conducted in an isolated virtual lab.

---

## Roadmap

- [ ] Phase 1 — Research & Design (Mar–Apr 2026)
- [ ] Phase 2 — AI/ML Model (Apr–May 2026)
- [ ] Phase 3 — Framework Build (May–Jun 2026)
- [ ] Phase 4 — Testing & Validation (Jul 2026)
- [ ] Phase 5 — Write-up & Release (Aug–Sep 2026)
