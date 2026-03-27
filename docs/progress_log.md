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

## Week 3 (31 March – 6 April 2025)

**Completed:**
- Module 6 — Explainable AI Engine:
  - generate_dataset.py — 2,000 sample IoT CVE dataset
  - model_trainer.py — Random Forest, F1: 0.8614 ✅
  - explainer.py — SHAP explanations working
- Module 7 — Report Generator:
  - Professional Markdown + JSON reports
  - Executive summary, AI section, recommendations
- Main orchestrator — aipet.py v1.0.0:
  - One command runs all 7 modules
  - Auto-detects which modules to run per device
  - Full pipeline in 63.9 seconds
- Complete implementation summary documented
- All 7 modules committed to GitHub

**Key decisions:**
- SHAP TreeExplainer for exact values on Random Forest
- 3D array indexing for SHAP 0.51.0 compatibility
- http_attack folder rename to avoid Python stdlib conflict
- argparse CLI with --demo, --target, --mqtt, --coap flags

**Status:** All 7 modules complete
           Main orchestrator working
           Full pipeline validated
           Significantly ahead of schedule
          ## Validation Phase (Week 3 continued)

**IoTGoat Validation:**
- Downloaded OWASP IoTGoat v1.0 Raspberry Pi firmware
- Extracted Squashfs filesystem using binwalk
- Ran AIPET Module 5 against extracted filesystem
- Results: 279 credential patterns, 12 private keys,
  33 dangerous configs, 112 vulnerable components
- Key finding: RSA/EC private keys in libmbedcrypto.so
  shared across all IoTGoat devices
- Limitation documented: BusyBox binary string matching
  produces false positives on error message strings
- Validation confirms AIPET detects real IoT firmware
  vulnerabilities on independently developed targets 
## NVD Dataset Experiment (Week 4)

**Experiment:** Replace synthetic training data with
real NVD IoT CVE data.

**Results:**
- Synthetic only:  F1 = 0.8614 ✅
- NVD only:        F1 = 0.6690 ⚠️
- Combined:        F1 = 0.7862 ⚠️

**Finding:** NVD CVE descriptions lack granular
feature detail (port numbers, protocol flags) needed
for direct model training. Most NVD features were zero
causing feature sparsity.

**Decision:** Retain synthetic dataset for training.
Use NVD data as vulnerability category validation
evidence. Rich NVD feature extraction identified as
future work direction.

**Academic value:** This experiment produced a genuine
research finding about the limitations of NVD data
for ML-based IoT security assessment — documented
honestly in Chapter 6 Discussion.

