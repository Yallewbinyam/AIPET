# AIPET — User Manual
## AI-Powered Penetration Testing Framework for IoT
### Version 1.0.0

**Author:** Binyam  
**Institution:** Coventry University — MSc Cyber Security (Ethical Hacking)  
**Date:** March 2025  

---

## Table of Contents

1. Introduction
2. Installation
3. Running Your First Scan
4. Understanding the Dashboard
5. Understanding Scan Results
6. Understanding AI Explanations
7. Generating Reports
8. Command Line Reference
9. Frequently Asked Questions
10. Responsible Use

---

## 1. Introduction

AIPET (AI-Powered Penetration Testing Framework for IoT)
is an automated security assessment tool designed to find
vulnerabilities in IoT devices and networks. It combines
seven specialist attack modules with an explainable AI
engine that tells you not just what is vulnerable —
but exactly why it matters and what to fix first.

### Who is AIPET for?

**Security Consultants**
Run complete IoT assessments in minutes instead of days.
AIPET automates the technical work so you can focus on
analysis and client communication.

**IT Administrators**
Assess your organisation's IoT devices without needing
specialist penetration testing knowledge. The dashboard
shows results in plain English with clear priority order.

**Security Researchers**
Use AIPET as a platform for IoT security research.
All modules are open source and extensible.

**Students**
Learn IoT security techniques hands-on. AIPET's demo
mode runs against safe local targets so you can see
real attack techniques without any risk.

### What AIPET tests

AIPET covers all 10 categories of the OWASP IoT Top 10:

| Module | What it tests |
|--------|--------------|
| Recon Engine | Device discovery, port scanning, service identification |
| MQTT Attack Suite | MQTT broker authentication, data exposure |
| CoAP Attack Suite | CoAP device access control, replay attacks |
| HTTP/Web Suite | Web interface credentials, admin panel exposure |
| Firmware Analyser | Hardcoded credentials, private keys, vulnerable components |
| AI Engine | Vulnerability prioritisation with SHAP explanations |
| Report Generator | Professional PDF and JSON reports |

---

## 2. Installation

### Quick Install (Recommended)
```bash
git clone https://github.com/YOUR_USERNAME/AIPET.git
cd AIPET
python3 install.py
```

The install script will:
- Check your Python version
- Create a virtual environment
- Install all dependencies
- Install system tools (nmap, binwalk, mosquitto)
- Verify everything works
- Print confirmation when ready

### Manual Install

If the install script fails on any step:
```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Install system tools (Kali Linux / Debian / Ubuntu)
sudo apt install nmap binwalk mosquitto -y
```

### System Requirements

| Component | Minimum |
|-----------|---------|
| Operating System | Kali Linux 2023+ (recommended) |
| Python | 3.11 or higher |
| RAM | 4GB |
| Disk Space | 2GB free |
| Network | Required for scanning |

---

## 3. Running Your First Scan

### Option A — Demo Mode (safest, recommended for beginners)

Demo mode runs AIPET against safe local test servers
that are included with the tool. No real network or
devices are involved. Perfect for learning and testing.

**Step 1 — Start the test servers**

Open three terminals and run one command in each:

Terminal 1:
```bash
sudo systemctl start mosquitto
```

Terminal 2:
```bash
cd AIPET
source venv/bin/activate
python3 lab/coap_test_server.py
```

Terminal 3:
```bash
cd AIPET
source venv/bin/activate
python3 lab/http_test_server.py
```

**Step 2 — Run AIPET**

In a fourth terminal:
```bash
cd AIPET
source venv/bin/activate
python3 aipet.py --demo
```

**Step 3 — View results**

AIPET will run all 7 modules and produce a report.
The full pipeline takes approximately 60-90 seconds.

### Option B — Scan a real network

Only do this if you have written permission to test
the target network and all devices on it.
```bash
# Scan a single device
python3 aipet.py --target 192.168.1.105

# Scan a network range
python3 aipet.py --target 192.168.1.0/24

# Scan with specific modules
python3 aipet.py --target 192.168.1.105 --mqtt --http
```

### Option C — Use the web dashboard
```bash
# Start the backend API
source venv/bin/activate
nohup python3 dashboard/backend/app.py > /tmp/aipet.log 2>&1 &

# Start the frontend
cd dashboard/frontend/aipet-dashboard
npm start
```

Open your browser at http://localhost:3000

---

## 4. Understanding the Dashboard

The AIPET dashboard has five sections accessible
from the left sidebar.

### Dashboard (Home)

The main overview screen showing:

**Risk Gauge** — The circular dial in the top left shows
your overall risk score from 0-100. The colour tells you
the severity:
- Red (80-100) = CRITICAL — immediate action required
- Orange (60-79) = HIGH — urgent attention needed
- Yellow (40-59) = MEDIUM — address promptly
- Green (0-39) = LOW — monitor and maintain

**Devices Found** — Number of IoT devices discovered
on the scanned network.

**Critical Findings** — Number of vulnerabilities
rated Critical severity.

**Total Findings** — All vulnerabilities found across
all modules.

**Findings by Severity** — Pie chart showing the
proportion of findings at each severity level.

**Modules Executed** — List of all AIPET modules
that ran, each with a green checkmark when complete.

### Devices Tab

Shows every IoT device discovered, with:
- IP address and device type
- Open ports
- Risk score and label
- AI severity prediction and confidence percentage
- Full AI explanation of why the device received
  that severity rating
- Severity probability breakdown

### Findings Tab

Shows all vulnerabilities found, sorted by severity
(Critical first). Each finding shows:
- Severity badge (colour coded)
- Name of the attack that found it
- Which module found it and the target
- Click any finding to expand it and see the full
  description of what was found

### AI Analysis Tab

Shows the explainable AI predictions for each device:
- Predicted severity and confidence
- SHAP feature contribution bars — red bars increase
  severity, green bars reduce it
- The length of each bar shows how much that feature
  contributed to the prediction
- Probability breakdown showing likelihood of each
  severity level

### Reports Tab

Lists all generated reports with:
- Report filename and timestamp
- File size
- Download button for each report

---

## 5. Understanding Scan Results

### Severity Levels

| Level | Meaning | Action |
|-------|---------|--------|
| CRITICAL | Immediately exploitable, severe impact | Fix within 24 hours |
| HIGH | Significant risk, likely exploitable | Fix within 1 week |
| MEDIUM | Moderate risk, may require conditions | Fix within 1 month |
| LOW | Minor risk, limited impact | Fix at next maintenance |
| INFO | Informational, no immediate risk | Monitor |

### Common Findings Explained

**MQTT Anonymous Access (CRITICAL)**
The MQTT broker accepts connections without a username
or password. Anyone who can reach the broker can read
all IoT messages and inject commands.
Fix: Configure authentication in mosquitto.conf

**Hardcoded Credentials Found (CRITICAL)**
Username and password combinations were found hard-coded
in device firmware or configuration files. These cannot
be changed by the user and affect every device running
that firmware.
Fix: Issue firmware update, replace affected devices

**Private Key in Firmware (CRITICAL)**
A cryptographic private key was found embedded in the
firmware. Every device running this firmware shares the
same key, allowing traffic decryption and device
impersonation.
Fix: Revoke key, generate unique keys per device,
issue firmware update

**Telnet Enabled (CRITICAL)**
Telnet service is running on the device. Telnet sends
all data including passwords in plain text across the
network where it can be captured.
Fix: Disable Telnet, enable SSH instead

**Default Credentials (CRITICAL)**
The device accepts default username/password combinations
such as admin/admin or admin/password.
Fix: Change all default credentials immediately

**Vulnerable Component (HIGH)**
The firmware contains a software component with known
vulnerabilities — for example OpenSSL 1.0.1 which is
vulnerable to Heartbleed (CVE-2014-0160).
Fix: Update firmware to version with patched components

---

## 6. Understanding AI Explanations

AIPET uses explainable AI to justify every prediction.
This section explains how to read the AI output.

### What SHAP values mean

SHAP (SHapley Additive exPlanations) values show which
features of a device contributed to its risk prediction.

**Positive values (red bars)** — This feature increased
the predicted severity. For example, having port 1883
open (MQTT) pushes the prediction toward higher severity.

**Negative values (green bars)** — This feature reduced
the predicted severity. For example, having an up-to-date
SSH version pushes the prediction toward lower severity.

**Bar length** — How much impact this feature had. A
longer bar means this feature was more important in
making the prediction.

### Example interpretation
```
firmware vulnerable component    +12.6%
device type                       +9.4%
firmware hardcoded creds          +7.6%
open port count                   +5.9%
```

Reading this: The device was predicted HIGH risk
primarily because a vulnerable firmware component was
found (contributing 12.6% to the severity score),
the device type (IoT gateway) carries inherent risk
(9.4%), and hardcoded credentials were detected (7.6%).

### Confidence score

The percentage next to the severity prediction shows
how confident the AI model is. 80%+ is high confidence.
Below 60% means the prediction is less certain and
manual review is recommended.

---

## 7. Generating Reports

AIPET automatically generates a report after every scan.

### Report contents

Every AIPET report contains:
1. Executive Summary — overall risk rating and priority actions
2. Discovered Devices — all devices with their profiles
3. Detailed Findings — all vulnerabilities with descriptions
4. AI Analysis — SHAP explanations for each device
5. Recommendations — prioritised remediation steps

### Report formats

**Markdown (.md)** — Human readable, renders on GitHub,
easily converted to PDF or Word document.

**JSON (.json)** — Machine readable, can be imported
into other security tools or SIEM platforms.

### Downloading reports

**From the dashboard:** Click Reports tab, then
Download button next to any report.

**From the command line:**
```bash
ls reporting/
cat reporting/aipet_report_*.md
```

### Converting to PDF
```bash
# Install pandoc
sudo apt install pandoc -y

# Convert to PDF
pandoc reporting/aipet_report_*.md -o aipet_report.pdf
```

---

## 8. Command Line Reference
```
python3 aipet.py [OPTIONS]

Options:
  --target, -t    Target IP, hostname, or CIDR range
                  Example: 192.168.1.0/24
  --demo          Run against local test servers
  --mqtt          Force run MQTT attack module
  --coap          Force run CoAP attack module
  --http          Force run HTTP attack module
  --firmware      Force run firmware analysis
  --firmware-path Path to firmware file or directory
  --mqtt-port     MQTT port (default: 1883)
  --coap-port     CoAP port (default: 5683)
  --http-port     HTTP port (default: 80)
  --version, -v   Show version number

Examples:
  python3 aipet.py --demo
  python3 aipet.py --target 192.168.1.0/24
  python3 aipet.py --target 192.168.1.105 --mqtt --http
  python3 aipet.py --firmware --firmware-path /path/to/firmware.bin
```

---

## 9. Frequently Asked Questions

**Q: AIPET is not finding any devices**
A: Check that you have permission to scan the target
network. Try running with sudo for Nmap permissions:
sudo python3 aipet.py --target 192.168.1.0/24

**Q: MQTT attack says connection refused**
A: The Mosquitto broker is not running. Start it with:
sudo systemctl start mosquitto

**Q: The AI prediction says Low but I know the device is vulnerable**
A: The AI model was trained on synthetic data and may
not perfectly classify all real-world scenarios. Always
review findings manually alongside the AI prediction.
The AI is a prioritisation aid, not a replacement for
human analysis.

**Q: Can I test my own home router?**
A: Yes — you own it. Run:
python3 aipet.py --target 192.168.1.1 --http
Replace 192.168.1.1 with your router's IP address.

**Q: How do I update AIPET?**
A: Pull the latest version from GitHub:
cd AIPET && git pull && pip install -r requirements.txt

**Q: Can I add my own attack modules?**
A: Yes. See CONTRIBUTING.md for the module template
and how to add new protocol modules.

---

## 10. Responsible Use

AIPET is a penetration testing tool. Using it against
systems you do not own or have explicit written
permission to test is illegal in most jurisdictions.

**Always:**
- Obtain written permission before scanning any network
- Test in an isolated lab environment when learning
- Follow responsible disclosure if you find real vulnerabilities
- Comply with your organisation's security testing policy

**Never:**
- Scan networks or devices without permission
- Use findings to damage or disrupt systems
- Share scan results without the owner's consent

See RESPONSIBLE_USE.md for the full policy.

---

*AIPET v1.0.0 — Coventry University MSc Cyber Security Research*  
*For support open a GitHub issue at the project repository*
