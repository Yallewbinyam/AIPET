# AIPET — Weekly Progress Log

---

## Week 1 (17–23 March 2025)

**Completed:**
- Supervisor meeting — project concept approved
- GitHub repository created and configured
- Full project folder structure established
- Python virtual environment set up
- All core libraries installed and verified
  (scikit-learn, TensorFlow, SHAP, paho-mqtt,
   aiocoap, requests, python-nmap)
- VS Code configured as primary IDE
- requirements.txt committed

**Key decisions:**
- Python 3.11 as primary language
- JSON as inter-module communication format
- MIT licence for open-source release

**Status:** On schedule — environment fully ready

---

## Week 2 (24–30 March 2025)

**Completed:**
- OWASP IoT Top 10 read and mapped to AIPET modules
- Literature notes started in docs/
- Module 1 — Recon Engine (3 files):
  - scanner.py — host discovery and port scanning
  - fingerprint.py — IoT device type identification
  - profiles.py — risk scoring and module recommendations
- Module 2 — MQTT Attack Suite:
  - mqtt_attacker.py — 5 attacks, VERSION2 callbacks
  - Mosquitto test broker installed and configured
  - Real findings produced against live broker
- Module 3 — CoAP Attack Suite:
  - coap_test_server.py — vulnerable lab server
  - coap_attacker.py — 4 attacks, async implementation
  - Real findings produced against live CoAP server
- Module 4 — HTTP/Web IoT Suite:
  - http_test_server.py — vulnerable IoT web server
  - http_attacker.py — 4 attacks
  - Real findings produced against live HTTP server
- Module 5 — Firmware Analyser:
  - firmware_analyser.py — 6 analyses
  - fake_firmware/ lab environment created
  - Real findings including Heartbleed detection
- Project direction sharpened to Explainable AI
- SHAP 0.51.0 installed
- README updated with explainable AI positioning

**Key decisions:**
- Upgrade to paho-mqtt VERSION2 callbacks
- Use subprocess for binwalk integration
- Add SHAP explainability as core differentiator
- aiocoap with asyncio for CoAP module

**Status:** 8 weeks ahead of schedule
           5 of 7 modules complete

---

## Week 3 (31 March – 6 April 2025)

**Planned:**
- Module 6 — Explainable AI Engine
- Module 7 — Report Generator
- Main orchestrator (aipet.py)
- Begin integration testing

**Status:** In progress