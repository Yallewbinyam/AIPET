# AIPET — Progress Summary
## Modules 1 & 2: Recon Engine and MQTT Attack Suite

---

## Development Environment

**Operating System:** Kali Linux 2024 — industry-standard
penetration testing platform with Nmap, Wireshark, and
security tools pre-installed.

**Code Editor:** VS Code — switched from nano after Module 1
for syntax highlighting, error detection, and file explorer.

**Python Environment:** Virtual environment (venv) — isolates
all AIPET dependencies from the system Python installation.
Ensures reproducibility on any machine.

**Version Control:** Git and GitHub — every working file
committed with descriptive messages. Creates timestamped,
authorship-verified record of every decision.

**MQTT Test Broker:** Mosquitto — most widely deployed
open-source MQTT broker. Running locally on Kali for
real, live target testing. All testing in isolated
local environment.

---

## Module 1 — Recon Engine

### Purpose
Entry point of the AIPET pipeline. Answers three questions:
what devices are on the network, what services are they
running, and what type of IoT device is each one.

### Files Built

**scanner.py** — Host discovery and port scanning.
Uses python-nmap to wrap Nmap capabilities in Python.
Two-stage scan: fast ping scan (-sn) to find live hosts,
then service version detection (-sV -T4 --top-ports 1000)
against each live host. Outputs structured JSON device
profiles containing IP, open ports, service names,
software versions, and scan timestamp.

**fingerprint.py** — IoT device type identification.
Reads JSON output from scanner.py and applies signature-
based matching. SIGNATURES database contains 10 IoT
device categories. Weighted scoring algorithm compares
device profile against every signature and selects best
match with confidence percentage. PORT_RISKS dictionary
immediately flags dangerous services like Telnet (23)
and unencrypted MQTT (1883).

**profiles.py** — Complete profile builder.
Adds two intelligence layers to fingerprint output:
(1) Risk score 0-100 combining PORT_RISK_SCORES and
DEVICE_TYPE_RISK, capped at 100.
(2) Ranked list of recommended AIPET modules based on
open ports — port 1883 triggers Module 2, port 5683
triggers Module 3, port 80 triggers Module 4, embedded
devices trigger Module 5.

### Data Pipeline
```
Network Target
      ↓
scanner.py → scan_results.json
      ↓
fingerprint.py → fingerprint_results.json
      ↓
profiles.py → complete_profiles.json
      ↓
Ready for AI Engine
```

### Key Technical Concepts

**Nmap flags** — -sn ping scan, -sV service detection,
-T4 aggressive timing, --top-ports 1000 efficient coverage.

**python-nmap** — wrapper executing Nmap as subprocess,
parsing XML output into Python dictionaries.

**Signature-based fingerprinting** — pattern matching
against known device characteristics. Same technique
used by Shodan and Nmap OS detection.

**Confidence score limitation** — when only one signature
matches, confidence shows 100% regardless of certainty.
Documented as known limitation for dissertation.

**JSON inter-module communication** — loose coupling
means any module runs independently or can be replaced.

### Test Results
Device: 10.0.2.15 (Kali machine)
Type: embedded_linux_device — 100% confidence
Port 22: OpenSSH 10.2p1 Debian 5
Risk: 15/100 INFORMATIONAL
Recommended: Module 5 Firmware Analyser

---

## Module 2 — MQTT Attack Suite

### Purpose
Complete offensive assessment of any MQTT broker.
Tests authentication, maps message topics, injects
messages, and harvests sensitive data from payloads.
First genuinely offensive capability in AIPET.

### Why MQTT Is Critical for IoT Security
MQTT uses publish-subscribe architecture through a
central broker. Designed for constrained environments —
prioritised simplicity over security. Most deployed
brokers have no authentication, no encryption, and
no message validation.

### File Built

**mqtt_attacker.py** — Five sequential attacks.
Uses paho-mqtt with CallbackAPIVersion.VERSION2 —
proper fix, not warning suppression.

**Attack 1 — Connection Test**
Creates MQTT client with no credentials, attempts
connection. VERSION2 on_connect callback receives
reason_code object — reason_code.is_failure=False
means broker accepted anonymous access. CRITICAL finding.

**Attack 2 — Topic Enumeration**
Subscribes to wildcard '#' — matches ALL topics on
entire broker. Captures all messages, builds topic list,
checks payloads against SENSITIVE_PATTERNS for
credentials, location data, medical info, commands.

**Attack 3 — Authentication Bypass**
Iterates 17 common default credential pairs. Creates
fresh MQTT client per attempt. Records all valid
credentials found.

**Attack 4 — Message Injection**
Publishes structured JSON test payload to each
discovered topic without authorisation. Tests whether
broker validates message sources.

**Attack 5 — Sensitive Data Harvester**
Monitors all topics for defined window, checks every
payload for 28 sensitive keyword patterns. Stores
findings with topic, pattern, payload excerpt, timestamp.

### Technical Concepts

**paho-mqtt VERSION2** — upgraded from deprecated
VERSION1. reason_code object replaces plain integer rc.
reason_code.is_failure replaces rc == 0 check.

**MQTT wildcard #** — subscribes to all topics
recursively. Legitimate monitoring feature that becomes
critical attack vector on unauthenticated brokers.

**Python threading** — loop_start() runs MQTT network
loop in background thread. Data shared via mutable
objects (message_count = [0]) because closures cannot
reassign simple variables across thread boundaries.

### Test Results
```
Attack 1: CRITICAL — anonymous connections accepted
Attack 3: CRITICAL — 17 valid credential sets found
Attack 2: HIGH     — 3 topics, 6 messages, sensitive data
Attack 4: HIGH     — 3 messages injected
Attack 5: CRITICAL — 4 sensitive patterns found

Final: Critical 3, High 2, Medium 0, Info 0
```

### OWASP IoT Top 10 Coverage
```
I1  Weak Passwords      → Attack 3 (auth bypass)
I6  Privacy Protection  → Attack 2, 5 (data exposure)
I7  Insecure Transfer   → Attack 1, 2 (no encryption)
I9  Default Settings    → Attack 3 (default credentials)
```

### Dissertation References
- Hintaw et al. (2021) — MQTT vulnerabilities and
  attack vectors. Direct validation of Attack categories.
- OWASP IoT Top 10 — I1, I6, I7, I9 directly addressed.
- Antonakakis et al. (2017) — Mirai botnet. Motivates
  default credential testing in Attack 3.

---

## Module 3 — CoAP Attack Suite

### Purpose
Direct device-level offensive assessment using CoAP
protocol. Unlike MQTT which attacks a central broker,
CoAP attacks individual devices directly — no middleman.

### Why CoAP Is Vulnerable
No built-in authentication — security is device
manufacturer's responsibility. UDP has no connection
state — no built-in duplicate detection enables replay
attacks. /.well-known/core discovery hands attackers
complete attack surface map in one request.

### File Built

**coap_attacker.py** — Four attacks using aiocoap
0.4.17 async client.

**coap_test_server.py** (lab/) — Deliberatly vulnerable
CoAP server with temperature, credentials, control,
and firmware resources.

**Attack 1 — Resource Discovery**
GET to /.well-known/core (RFC 6690). Returns CoRE Link
Format listing all resources. Parsed by splitting on
commas, extracting paths from angle brackets.

**Attack 2 — Unauthenticated Access**
GET and PUT to every discovered resource without
credentials. Checks responses for sensitive patterns.
Tests both read and write access.

**Attack 3 — Replay Attack**
Sends identical PUT request twice, checks if both
succeed. Vulnerable device accepts duplicate requests
— no nonce or timestamp validation.

**Attack 4 — Malformed Packet Injection**
Three tests: oversized 10KB payload, empty PUT payload,
rapid 10-request flood. Checks device robustness and
error message information disclosure.

### Technical Concepts

**aiocoap async** — uses asyncio coroutines not threads.
await pauses function until result arrives without
blocking. asyncio.wait_for() adds timeout.

**CoRE Link Format** — response format from
/.well-known/core. Parsed by splitting on commas and
extracting paths from angle brackets.

**UDP vs TCP for attacks** — no connection handshake,
packets sent fire-and-forget. Makes CoAP faster to
attack — timeouts on every request essential.

**Async entry point** — run_coap_attacks() wraps async
code in asyncio.run() for synchronous callers.

### Test Results
```
Attack 1: HIGH     — 6 resources discovered
Attack 2: CRITICAL — credentials exposed, writes accepted
Attack 3: HIGH     — 2 resources replay vulnerable
Attack 4: MEDIUM   — empty payload accepted

Final: Critical 1, High 2, Medium 1, Info 0
```

### OWASP IoT Top 10 Coverage
```
I1  Weak Passwords      → Attack 2 (no auth required)
I3  Insecure Interfaces → Attack 1 (resource discovery)
I7  Insecure Transfer   → Attack 3 (replay attacks)
I5  Insecure Components → Attack 4 (malformed packets)
I9  Default Settings    → Attack 2 (write access)
```

### Dissertation References
- RFC 7252 — CoAP specification
- RFC 6690 — CoRE Link Forma
- OWASP IoT Top 10 — I1, I3, I5, I7, I9 addressed