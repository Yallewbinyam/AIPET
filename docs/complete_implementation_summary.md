# AIPET — Complete Implementation Summary
## All 7 Modules: Design, Implementation, and Results

**Project:** AIPET — Explainable AI-Powered Penetration 
Testing Framework for IoT Vulnerability Discovery
**Student:** Binyam
**Institution:** Coventry University
**Programme:** MSc Cyber Security (Ethical Hacking)
**Date:** March 2025

---

## Project Overview

AIPET is the first open-source framework combining
IoT-specific protocol attack modules with an explainable
AI-driven vulnerability suggestion engine. It addresses
a documented gap in the IoT security tooling landscape —
no existing tool combines automated IoT protocol testing
with AI-powered vulnerability prioritisation and
plain-English explanations of every finding.

The framework consists of 7 integrated modules forming
a complete penetration testing pipeline:
```
Target IoT Network
        ↓
Module 1: Recon Engine
        ↓
Modules 2-5: Protocol and Firmware Attack Modules
        ↓
Module 6: Explainable AI Engine
        ↓
Module 7: Report Generator
        ↓
Professional Pentest Report
```

---

## Development Environment

| Component | Choice | Reason |
|-----------|--------|--------|
| OS | Kali Linux 2024 | Industry standard pentest platform |
| Language | Python 3.11+ | Rich security and ML library ecosystem |
| IDE | VS Code | Professional IDE with syntax highlighting |
| Version Control | Git + GitHub | Reproducibility and open-source release |
| AI/ML | scikit-learn + SHAP | Proven ML with explainability |
| Virtualisation | QEMU + Firmadyne | Reproducible IoT lab environment |
| Environment | Python venv | Dependency isolation |

---

## Module 1 — Recon Engine

### Purpose
Entry point of the AIPET pipeline. Discovers all IoT
devices on a target network, identifies what type each
device is, scores its risk level, and recommends which
attack modules to run against it.

### Files
- `recon/scanner.py` — host discovery and port scanning
- `recon/fingerprint.py` — IoT device type identification
- `recon/profiles.py` — risk scoring and module recommendations

### How It Works

**scanner.py** uses python-nmap to wrap Nmap in Python.
Runs two scans:
1. Ping scan (`-sn`) — finds live hosts quickly
2. Service scan (`-sV -T4 --top-ports 1000`) — identifies
   software and versions on each open port

Output: `scan_results.json` containing IP, ports,
services, versions, and scan timestamp per device.

**fingerprint.py** implements signature-based IoT device
identification. The SIGNATURES database contains 10
device categories with characteristic port numbers,
service names, and banner text patterns. A weighted
scoring algorithm compares each device profile against
all signatures and selects the best match.

Output: `fingerprint_results.json` adding device_type
and confidence percentage to each profile.

**profiles.py** adds two intelligence layers:
1. Risk score (0-100) combining PORT_RISK_SCORES and
   DEVICE_TYPE_RISK dictionaries
2. Recommended modules list based on open ports —
   port 1883 triggers Module 2, port 5683 triggers
   Module 3, port 80 triggers Module 4

Output: `complete_profiles.json` — final enriched
profiles ready for the AI engine.

### Pipeline
```
scan_results.json
      ↓
fingerprint_results.json
      ↓
complete_profiles.json → AI Engine input
```

### Key Technical Decisions
- JSON inter-module communication for loose coupling
- Signature-based fingerprinting — same approach as Shodan
- Weighted scoring rather than binary matching
- Known limitation: single-signature matches show 100%
  confidence regardless of certainty — documented

### Test Results
```
Target: 10.0.2.15 (Kali Linux machine)
Device: embedded_linux_device (100% confidence)
Port 22: OpenSSH 10.2p1 Debian 5
Risk: 15/100 INFORMATIONAL
Recommended: Module 5 Firmware Analyser
```

### OWASP IoT Top 10 Coverage
- I2: Insecure Network Services — port scanning
- I8: Lack of Device Management — service enumeration

---

## Module 2 — MQTT Attack Suite

### Purpose
Complete offensive assessment of MQTT brokers — the most
widely deployed IoT communication protocol. Tests for
the authentication failures, data exposure, and injection
vulnerabilities that affect the majority of real-world
MQTT deployments.

### Files
- `mqtt/mqtt_attacker.py` — 5 attacks
- `lab/` — Mosquitto test broker (system installation)

### Why MQTT
MQTT uses publish-subscribe architecture through a
central broker. Designed for resource-constrained IoT
devices — prioritised simplicity over security. Most
deployed brokers have no authentication, no encryption,
and no message source validation.

### The 5 Attacks

| Attack | Method | Finding Type |
|--------|--------|-------------|
| 1. Connection Test | Anonymous MQTT connect | Auth bypass |
| 2. Topic Enumeration | Subscribe to # wildcard | Data exposure |
| 3. Auth Bypass | 17 default credential pairs | Weak credentials |
| 4. Message Injection | Publish to discovered topics | Injection |
| 5. Sensitive Data Harvest | Monitor all topics | Data exposure |

### Key Technical Decisions
- paho-mqtt CallbackAPIVersion.VERSION2 — proper fix
  not warning suppression. VERSION2 uses reason_code
  object instead of plain integer rc
- Threading via loop_start()/loop_stop() for async
  message reception
- Mutable list pattern `message_count = [0]` for
  sharing data across thread boundary in closures

### Test Results
```
Target: localhost:1883 (Mosquitto broker)
Attack 1: CRITICAL — anonymous connections accepted
Attack 3: CRITICAL — 17 valid credential sets found
Attack 2: HIGH     — 3 topics, sensitive data found
Attack 4: HIGH     — 3 messages injected successfully
Attack 5: CRITICAL — 4 sensitive patterns captured

Final: Critical 3, High 2, Medium 0, Info 0
```

### OWASP Coverage
- I1: Weak Passwords — Attack 3
- I6: Privacy Protection — Attacks 2, 5
- I7: Insecure Transfer — Attack 1
- I9: Default Settings — Attack 3

---

## Module 3 — CoAP Attack Suite

### Purpose
Direct device-level offensive assessment using CoAP
(Constrained Application Protocol). Unlike MQTT which
attacks a central broker, CoAP attacks individual
devices directly — no middleman.

### Files
- `coap/coap_attacker.py` — 4 attacks
- `lab/coap_test_server.py` — vulnerable CoAP test server

### Why CoAP
CoAP mimics HTTP but runs over UDP for lightweight IoT
communication. No built-in authentication, UDP has no
connection state enabling replay attacks, and the
/.well-known/core discovery endpoint hands attackers a
complete resource map with a single request.

### The 4 Attacks

| Attack | Method | Finding Type |
|--------|--------|-------------|
| 1. Resource Discovery | GET /.well-known/core | Attack surface mapping |
| 2. Unauthenticated Access | GET/PUT all resources | Auth bypass |
| 3. Replay Attack | Duplicate request detection | Protocol weakness |
| 4. Malformed Packets | Oversized/empty payloads | Robustness |

### Key Technical Decisions
- aiocoap with asyncio — async/await for non-blocking
  network operations. Essential because UDP can lose
  packets and AIPET must handle timeouts gracefully
- asyncio.wait_for() with timeout on every request
  prevents hanging on unresponsive devices
- run_coap_attacks() wraps async in asyncio.run()
  for synchronous callers — standard integration pattern

### Test Results
```
Target: coap://localhost:5683
Attack 1: HIGH     — 6 resources discovered
Attack 2: CRITICAL — credentials exposed, writes accepted
Attack 3: HIGH     — 2 resources replay vulnerable
Attack 4: MEDIUM   — empty payload accepted

Final: Critical 1, High 2, Medium 1, Info 0
```

### OWASP Coverage
- I1: Weak Passwords — Attack 2
- I3: Insecure Interfaces — Attack 1
- I5: Insecure Components — Attack 4
- I7: Insecure Transfer — Attack 3
- I9: Default Settings — Attack 2

---

## Module 4 — HTTP/Web IoT Suite

### Purpose
Tests IoT web interfaces for the vulnerabilities specific
to embedded web servers — default credentials, hidden
admin panels, insecure APIs, and common IoT web weaknesses.

### Files
- `http/http_attacker.py` — 4 attacks
- `lab/http_test_server.py` — vulnerable IoT HTTP server

### Why IoT Web Interfaces Are Different
IoT web interfaces differ from regular web apps in three
critical ways:
1. Default credentials are universal across device models
2. The interface controls physical hardware directly
3. Embedded web servers (Boa, lighttpd, GoAhead) are
   ancient, unpatched, and frequently abandoned

### The 4 Attacks

| Attack | Method | Finding Type |
|--------|--------|-------------|
| 1. Default Credentials | POST + Basic Auth testing | Auth bypass |
| 2. Admin Discovery | 30 known IoT admin paths | Hidden interfaces |
| 3. API Security | 12 REST API endpoints | Data exposure |
| 4. Vulnerability Scan | Methods, traversal, headers | Misc weaknesses |

### Key Technical Decisions
- requests library with verify=False for self-signed
  IoT certificates — necessary and documented
- urllib3.disable_warnings() for InsecureRequestWarning
  — appropriate because insecurity is intentional
- Both form POST and HTTP Basic Auth tested —
  IoT devices use inconsistent auth mechanisms
- Sensitive pattern matching rather than specific
  value searching — works on unknown credential values

### Test Results
```
Target: http://localhost:8080
Attack 1: CRITICAL — 24 valid credential sets found
Attack 2: CRITICAL — 8 interfaces exposing sensitive data
Attack 3: CRITICAL — APIs exposing credentials without auth
Attack 4: LOW      — Missing headers, version disclosure

Final: Critical 3, High 0, Medium 0, Info 1
```

### OWASP Coverage
- I1: Weak Passwords — Attack 1
- I3: Insecure Interfaces — Attack 3
- I9: Default Settings — Attacks 1, 2

---

## Module 5 — Firmware Analyser

### Purpose
Analyses IoT firmware at the binary level — finding
hardcoded credentials, private keys, dangerous
configurations, and vulnerable components that are
invisible to network-based testing.

### Files
- `firmware/firmware_analyser.py` — 6 analyses
- `lab/fake_firmware/` — simulated firmware directory

### Why Firmware Analysis Matters
Hardcoded credentials affect every device running that
firmware version globally. Shared private keys allow
mass device impersonation. These vulnerabilities cannot
be fixed at runtime — only by firmware updates that
most IoT devices never receive.

Historical context: The Mirai botnet (2017) exploited
hardcoded credentials in IoT firmware to compromise
600,000+ devices and launch the largest DDoS attack
in history at the time.

### The 6 Analyses

| Analysis | Method | Finding Type |
|----------|--------|-------------|
| 1. Binwalk Scan | subprocess binwalk -B | Firmware structure |
| 2. Credential Hunt | regex on all files | Hardcoded credentials |
| 3. Private Key Scanner | PEM header detection | Crypto material |
| 4. Dangerous Config | regex pattern matching | Telnet, debug mode |
| 5. Sensitive Files | Path-based matching | Shadow, keys, configs |
| 6. Vulnerable Components | Version string matching | Known CVEs |

### Key Technical Decisions
- binwalk called via subprocess not Python API —
  binwalk 2.4.3 Python API is unreliable. subprocess
  approach is version-independent and most reliable
- Files read with errors='ignore' — handles both
  text configs and binary firmware images
- SHA256 hashing of key files — provides evidence
  fingerprint for report and database lookup
- os.walk() with directory exclusion — skips /proc,
  /sys, /dev to prevent infinite loops

### Test Results
```
Target: lab/fake_firmware/
Analysis 1: INFO     — Binary scanned
Analysis 2: CRITICAL — 8 hardcoded credential patterns
Analysis 3: CRITICAL — RSA private key found
Analysis 4: CRITICAL — Telnet + debug mode enabled
Analysis 5: CRITICAL — Shadow file, SSL key present
Analysis 6: CRITICAL — OpenSSL 1.0.1 (Heartbleed)
                        OpenSSH 7.2 (Multiple CVEs)

Final: Critical 5, High 0, Medium 0, Info 1
```

### OWASP Coverage
- I1: Weak Passwords — Analysis 2
- I4: Insecure Updates — Analysis 6
- I5: Insecure Components — Analysis 6
- I7: Insecure Transfer — Analysis 4 (Telnet)
- I10: Physical Hardening — Analysis 3 (shared keys)

---

## Module 6 — Explainable AI Engine

### Purpose
The defining innovation of AIPET. Takes all findings
from Modules 1-5 and predicts vulnerability severity
for each device — then explains exactly WHY using SHAP
(SHapley Additive exPlanations) values and plain-English
summaries.

### Files
- `ai_engine/generate_dataset.py` — training data generation
- `ai_engine/model_trainer.py` — model training and evaluation
- `ai_engine/explainer.py` — SHAP explanation generation
- `ai_engine/data/` — training dataset
- `ai_engine/models/` — saved model and metrics

### Why Explainability Matters
Most AI security tools are black boxes — they give a
finding but cannot explain why. Enterprise security
teams cannot use unexplainable AI for audit and
compliance purposes. AIPET's SHAP layer makes every
prediction transparent, auditable, and defensible.

### The Three Components

**generate_dataset.py** creates 2,000 training samples
with 26 features covering all device profile data from
Modules 1-5. Features are generated with realistic
IoT deployment distributions and labelled using a
weighted scoring system encoding domain knowledge.

**model_trainer.py** trains a Random Forest classifier:
- 200 decision trees for ensemble stability
- class_weight='balanced' to handle class imbalance
  (79% Critical samples in dataset)
- 70/15/15 stratified train/validation/test split
- 5-fold stratified cross-validation for stability

**explainer.py** uses SHAP TreeExplainer:
- Exact SHAP values from tree traversal (no sampling)
- Per-class SHAP values showing feature contributions
- Plain-English explanation generator
- SHAP 0.51.0 format handled — 3D array indexing
  `shap_values[0, :, predicted_class]`

### Model Performance

| Metric | Value | Target | Status |
|--------|-------|--------|--------|
| Weighted F1-Score | 0.8614 | 0.85 | ✅ Above target |
| Precision | 0.8710 | — | ✅ |
| Recall | 0.8567 | — | ✅ |
| Accuracy | 0.8567 | — | ✅ |
| CV Mean F1 | 0.8668 | — | ✅ |
| CV Std Dev | 0.0108 | < 0.05 | ✅ Stable |
| Critical F1 | 0.9440 | — | ✅ Excellent |

### Known Limitations
- Low (F1: 0.57) and Medium (F1: 0.43) class performance
  is weaker due to class imbalance (38 and 108 samples)
- Training data is synthetic — real NVD data would
  improve generalisation to production deployments
- SHAP explanations are approximate for edge cases

### Sample Output
```
PREDICTION: Low (80.2% confidence)

Key factors driving this prediction:
  Increasing severity:
  + Device type classification (impact: 9.4%)
  + Total number of open ports (impact: 5.9%)

  Reducing severity:
  - SSH service port 22 (impact: 1.2%)

Severity probability breakdown:
  Low       80.2%
  Medium    17.0%
  High       2.6%
  Critical   0.3%
```

### Key Technical Decisions
- Random Forest over neural network — interpretable,
  handles mixed features, works with SHAP TreeExplainer,
  no normalisation required
- SHAP over LIME — theoretically grounded (Shapley
  values), consistent global and local explanations,
  exact values for tree models
- Feature vector building from JSON — bridges JSON
  module outputs to numerical model input

---

## Module 7 — Report Generator

### Purpose
Transforms all JSON module outputs into a professional,
human-readable penetration test report combining
technical findings with AI explanations and prioritised
recommendations.

### Files
- `reporting/report_generator.py` — report generation
- `reporting/aipet_report_*.md` — Markdown reports
- `reporting/aipet_report_*.json` — JSON reports

### Report Structure

1. **Header** — date, scope, classification
2. **Table of Contents** — navigation links
3. **Executive Summary** — overall risk rating,
   finding counts, immediate priority actions
4. **Discovered Devices** — profiles, services,
   risk scores, AI predictions per device
5. **Detailed Findings** — all findings from all
   modules, severity-sorted, with recommendations
6. **AI Analysis** — SHAP explanations, probability
   breakdowns, feature contribution tables
7. **Recommendations** — prioritised by severity,
   with specific actionable remediation steps

### Key Technical Decisions
- Markdown as primary format — renders on GitHub,
  converts to PDF, human-readable in any editor
- JSON as secondary format — programmatic access
  for integration with other security tools
- Severity-sorted findings — Critical always first
- Timestamped filenames — preserves report history
  across multiple assessment runs

### Test Results
```
Modules loaded: 6 of 6
Devices: 1
Sections: 5 (Executive, Devices, Findings, AI, Recs)
Output: Markdown + JSON
Generation time: < 1 second
```

---

## Complete OWASP IoT Top 10 Coverage

After all 7 modules:

| OWASP Category | Coverage | Module |
|----------------|----------|--------|
| I1 Weak/Hardcoded Passwords | ✅ Full | 2, 4, 5 |
| I2 Insecure Network Services | ✅ Full | 1 |
| I3 Insecure Ecosystem Interfaces | ✅ Full | 3, 4 |
| I4 Lack of Secure Update | ✅ Full | 5 |
| I5 Insecure/Outdated Components | ✅ Full | 5 |
| I6 Insufficient Privacy | ✅ Full | 2, 3 |
| I7 Insecure Data Transfer | ✅ Full | 2, 3, 5 |
| I8 Lack of Device Management | ✅ Full | 1 |
| I9 Insecure Default Settings | ✅ Full | 2, 4 |
| I10 Lack of Physical Hardening | ✅ Full | 5 |

**10 out of 10 OWASP IoT categories covered.**

---

## Overall Project Statistics
```
Total modules:          7
Total Python files:     14
Total lines of code:    ~3,500
Total findings (tests): Critical 12+, High 6+, Medium 2+
AI F1-score:            86.14% (target: 85%)
CV stability:           Std Dev 0.0108 (target: < 0.05)
OWASP coverage:         10/10 categories
Schedule:               8+ weeks ahead of plan
GitHub commits:         25+
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
| SMB to Enterprise scale | ✗ Enterprise only | ✅ Universal |
| Open source | ✗ Inconsistent | ✅ MIT licence |
| Plain-English findings | ✗ Technical only | ✅ Human readable |

---

## Next Steps
```
1. Main orchestrator (aipet.py)
   Single command runs entire pipeline

2. Integration testing
   End-to-end pipeline validation

3. Virtual lab validation
   Realistic IoT target testing

4. Dissertation write-up
   7 chapters — August deadline

5. GitHub open-source release
   September 2025
```

---

## Dissertation Chapter Mapping

| Chapter | Content | Source |
|---------|---------|--------|
| Ch 1: Introduction | Problem, aims, objectives | Proposal docs |
| Ch 2: Literature Review | IoT security, AI pentest | literature_notes.md |
| Ch 3: Methodology | Design Science Research | technical_decisions.md |
| Ch 4: Implementation | All 7 modules | This document |
| Ch 5: Results | Test findings, F1 scores | Module JSON outputs |
| Ch 6: Discussion | Limitations, comparison | This document |
| Ch 7: Conclusions | Summary, future work | Implementation plan |