# AIPET Cloud — User Manual
## AI-Powered IoT Security Platform
### Version 2.0.0

**Author:** Binyam Yallew  
**Institution:** Coventry University — MSc Cyber Security (Ethical Hacking)  
**Date:** 2025  

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Platform Overview](#2-platform-overview)
3. [Getting Started — Cloud Platform](#3-getting-started--cloud-platform)
4. [Account Management](#4-account-management)
5. [Subscription Plans](#5-subscription-plans)
6. [Running Scans](#6-running-scans)
7. [Understanding the Dashboard](#7-understanding-the-dashboard)
8. [Understanding Scan Results](#8-understanding-scan-results)
9. [Understanding AI Explanations](#9-understanding-ai-explanations)
10. [Billing and Payments](#10-billing-and-payments)
11. [API Keys (Enterprise)](#11-api-keys-enterprise)
12. [Generating Reports](#12-generating-reports)
13. [Command Line Reference (CLI Tool)](#13-command-line-reference-cli-tool)
14. [Local Development Setup](#14-local-development-setup)
15. [Frequently Asked Questions](#15-frequently-asked-questions)
16. [Responsible Use](#16-responsible-use)

---

## 1. Introduction

AIPET (AI-Powered Penetration Testing Framework for IoT) is a production-ready SaaS platform that automates the discovery, testing, and intelligent prioritisation of vulnerabilities across IoT devices and networks.

AIPET combines seven specialist attack modules with an explainable AI engine that tells you not just what is vulnerable — but exactly why it matters and what to fix first. It delivers everything through a professional cloud dashboard with subscription billing, API access, and automated reporting.

### Who is AIPET for?

**Security Consultants**  
Run complete IoT assessments in minutes instead of days. AIPET automates the technical work so you can focus on analysis and client communication.

**IT Administrators**  
Assess your organisation's IoT devices without needing specialist penetration testing knowledge. The dashboard shows results in plain English with clear priority order.

**Security Researchers**  
Use AIPET as a platform for IoT security research. All modules are open source and extensible.

**Students**  
Learn IoT security techniques hands-on. AIPET's demo mode runs against safe local targets so you can see real attack techniques without any risk.

**Enterprise Security Teams**  
Integrate AIPET into your CI/CD pipelines, SIEM platforms, and security automation workflows using the Enterprise API.

---

## 2. Platform Overview

AIPET v2.0.0 is a full cloud SaaS platform consisting of:

| Component | Technology | Purpose |
|---|---|---|
| Web Dashboard | React 18 | User interface |
| Backend API | Flask 3.0 | Business logic and scan management |
| Database | PostgreSQL 17 | Users, scans, findings, API keys |
| Scan Queue | Celery + Redis | Background scan processing |
| Payment Processing | Stripe | Subscription billing |
| Health Monitor | systemd service | Auto-restart and email alerts |
| Database Backups | cron + pg_dump | Daily automated backups |

### What AIPET tests

AIPET covers all 10 categories of the OWASP IoT Top 10:

| Module | What it tests |
|---|---|
| Recon Engine | Device discovery, port scanning, service identification |
| MQTT Attack Suite | Broker authentication, data exposure, credential brute force |
| CoAP Attack Suite | Access control, replay attacks, unencrypted endpoints |
| HTTP/Web Suite | Web interface credentials, admin panel exposure, CVE scanning |
| Firmware Analyser | Hardcoded credentials, private keys, vulnerable components |
| AI Engine | Vulnerability prioritisation with SHAP explanations |
| Report Generator | Professional PDF and JSON reports |

---

## 3. Getting Started — Cloud Platform

### Step 1 — Open the dashboard

Open your browser and navigate to:

```
http://localhost:3000
```

In production, this will be:

```
https://aipet.io
```

### Step 2 — Create an account

Click **"Don't have an account? Register"** on the login page.

Fill in:
- **Full Name** — your name
- **Email** — your email address
- **Password** — minimum 8 characters

Click **Create Account**.

### Step 3 — Sign in

Enter your email and password, then click **Sign In**.

You will be taken to the main dashboard.

### Step 4 — Run your first scan

Click the **New Scan** button at the bottom of the left sidebar.

Choose:
- **Demo Mode** — safe test scan using local test servers (recommended for first time)
- **Live Scan** — scan a real network (requires authorisation)

Click **Launch Scan**.

---

## 4. Account Management

### Changing your password

1. Click the **Settings** option in the sidebar
2. Enter your current password
3. Enter and confirm your new password
4. Click **Change Password**

Passwords must be at least 8 characters long.

### Signing out

Click the **Sign Out** button at the bottom of the left sidebar. Your session will be ended and you will be returned to the login page.

### Session security

AIPET uses JWT (JSON Web Token) authentication. Your session token expires after 15 minutes of inactivity. You will be automatically redirected to the login page when your session expires.

---

## 5. Subscription Plans

AIPET offers three subscription tiers:

| Feature | Free | Professional | Enterprise |
|---|---|---|---|
| **Price** | £0/month | £49/month | £499/month |
| **Scans per month** | 5 | Unlimited | Unlimited |
| **Parallel networks** | 1 | 3 | 10 |
| **AI analysis** | Basic | Full SHAP | Full SHAP |
| **Report formats** | PDF | All formats | All formats |
| **API access** | No | No | Yes |
| **Support** | Community | Email | Priority + SLA |

### Upgrading your plan

1. Click **Pricing** in the left sidebar
2. Choose your desired plan
3. Click the **Upgrade** button
4. Enter your payment details on the Stripe checkout page
5. Your plan is activated immediately after payment

### Free plan scan limit

Free plan users are limited to 5 scans per calendar month. The limit resets on the 1st of each month.

When you reach the limit, you will be automatically redirected to the Pricing page where you can upgrade to Professional for unlimited scans.

---

## 6. Running Scans

### Starting a scan from the dashboard

1. Click **New Scan** at the bottom of the left sidebar
2. Choose your scan mode:
   - **Demo Mode** — runs against safe local test servers included with AIPET
   - **Live Scan** — scans a real IP address or network range
3. If Live Scan is selected, enter the target IP or CIDR range (e.g. `192.168.1.0/24`)
4. Click **Launch Scan**

### Scan modes

**Demo Mode**  
Runs AIPET against safe local test servers that are included with the tool. No real network or devices are involved. Perfect for learning and testing the platform.

**Live Scan**  
Scans a real network or device. Only use this against systems you own or have explicit written permission to test.

### Scan status

While a scan is running, the sidebar shows a blue pulsing indicator: **Scan in progress...**

The scan runs in the background — you can navigate to other tabs while it completes.

### Scan history

Click **Reports** in the sidebar to see all completed scans and download reports.

### Starting a scan via API (Enterprise)

Enterprise users can trigger scans programmatically:

```bash
curl -X POST https://aipet.io/api/scan/start \
  -H "Content-Type: application/json" \
  -H "X-API-Key: aipet_ent_your_key_here" \
  -d '{
    "target": "192.168.1.0/24",
    "mode": "live"
  }'
```

Response:
```json
{
  "status": "queued",
  "scan_id": 42,
  "target": "192.168.1.0/24",
  "mode": "live"
}
```

---

## 7. Understanding the Dashboard

The AIPET dashboard has seven sections accessible from the left sidebar.

### Dashboard (Home)

The main overview screen showing:

**Risk Gauge** — The circular dial shows your overall risk score from 0-100. The colour indicates severity:
- 🔴 Red (80-100) = CRITICAL — immediate action required
- 🟠 Orange (60-79) = HIGH — urgent attention needed
- 🟡 Yellow (40-59) = MEDIUM — address promptly
- 🟢 Green (0-39) = LOW — monitor and maintain

**Devices Found** — Number of IoT devices discovered on the scanned network.

**Critical Findings** — Number of vulnerabilities rated Critical severity.

**Total Findings** — All vulnerabilities found across all modules.

**Findings by Severity** — Pie chart showing the proportion of findings at each severity level.

**Modules Executed** — List of all AIPET modules that ran, each with a green checkmark when complete.

### Devices Tab

Shows every IoT device discovered, with:
- IP address and device type
- Open ports
- Risk score and label
- AI severity prediction and confidence percentage
- Full AI explanation of why the device received that severity rating
- Severity probability breakdown

### Findings Tab

Shows all vulnerabilities found, sorted by severity (Critical first). Each finding shows:
- Severity badge (colour coded)
- Name of the attack that found it
- Which module found it and the target
- Click any finding to expand it and read the full description

Use the filter buttons to show only Critical, High, Medium, or Low findings. Use the search box to find specific findings by keyword.

### AI Analysis Tab

Shows the explainable AI predictions for each device:
- Predicted severity and confidence percentage
- SHAP feature contribution bars — red bars increase severity, green bars reduce it
- The length of each bar shows how much that feature contributed
- Probability breakdown showing likelihood of each severity level

### Reports Tab

Lists all generated reports. Click **Download** to save any report to your computer.

### Pricing Tab

Shows the three subscription plans with features and pricing. Click **Upgrade** to change your plan.

### Billing Tab

Shows your current subscription status:
- Current plan name and status
- Scans used this month vs your limit
- Days until monthly reset
- **Open Billing Portal** — manage your payment method and view invoices
- **Cancel Subscription** — cancel at end of current billing period

### API Keys Tab (Enterprise only)

Generate and manage API keys for programmatic access. See [Section 11](#11-api-keys-enterprise) for full details.

---

## 8. Understanding Scan Results

### Severity Levels

| Level | Meaning | Recommended Action |
|---|---|---|
| CRITICAL | Immediately exploitable, severe impact | Fix within 24 hours |
| HIGH | Significant risk, likely exploitable | Fix within 1 week |
| MEDIUM | Moderate risk, may require specific conditions | Fix within 1 month |
| LOW | Minor risk, limited impact | Fix at next maintenance |
| INFO | Informational, no immediate risk | Monitor |

### Common Findings Explained

**MQTT Anonymous Access (CRITICAL)**  
The MQTT broker accepts connections without a username or password. Anyone who can reach the broker can read all IoT messages and inject commands.  
*Fix: Configure authentication in mosquitto.conf*

**Hardcoded Credentials Found (CRITICAL)**  
Username and password combinations were found hard-coded in device firmware or configuration files. These cannot be changed by the user and affect every device running that firmware.  
*Fix: Issue firmware update, replace affected devices*

**Private Key in Firmware (CRITICAL)**  
A cryptographic private key was found embedded in the firmware. Every device running this firmware shares the same key, allowing traffic decryption and device impersonation.  
*Fix: Revoke key, generate unique keys per device, issue firmware update*

**Telnet Enabled (CRITICAL)**  
Telnet service is running on the device. Telnet sends all data including passwords in plain text across the network.  
*Fix: Disable Telnet, enable SSH instead*

**Default Credentials (CRITICAL)**  
The device accepts default username/password combinations such as admin/admin.  
*Fix: Change all default credentials immediately*

**Vulnerable Component (HIGH)**  
The firmware contains a software component with known vulnerabilities.  
*Fix: Update firmware to version with patched components*

---

## 9. Understanding AI Explanations

AIPET uses explainable AI to justify every prediction. This section explains how to read the AI output.

### What SHAP values mean

SHAP (SHapley Additive exPlanations) values show which features of a device contributed to its risk prediction.

**Positive values (red bars)** — This feature increased the predicted severity. For example, having port 1883 open (MQTT) pushes the prediction toward higher severity.

**Negative values (green bars)** — This feature reduced the predicted severity. For example, having an up-to-date SSH version pushes the prediction toward lower severity.

**Bar length** — How much impact this feature had. A longer bar means this feature was more important in making the prediction.

### Example interpretation

```
firmware vulnerable component    +12.6%
device type                       +9.4%
firmware hardcoded creds          +7.6%
open port count                   +5.9%
```

Reading this: The device was predicted HIGH risk primarily because a vulnerable firmware component was found (contributing 12.6% to the severity score), the device type (IoT gateway) carries inherent risk (9.4%), and hardcoded credentials were detected (7.6%).

### Confidence score

The percentage next to the severity prediction shows how confident the AI model is. 80%+ is high confidence. Below 60% means the prediction is less certain and manual review is recommended.

### AI Performance

| Metric | Value |
|---|---|
| Weighted F1-Score | 0.8614 |
| CV Mean F1 | 0.8668 |
| Critical Class F1 | 0.9440 |

---

## 10. Billing and Payments

### How payments work

AIPET uses Stripe for all payment processing. Your card details are entered directly on Stripe's secure hosted page — they never pass through AIPET's servers.

### Upgrading your plan

1. Click **Pricing** in the sidebar
2. Click the upgrade button on your chosen plan
3. You are redirected to Stripe's checkout page
4. Enter your card details and click Subscribe
5. Your plan is activated immediately

### Managing your subscription

Click **Billing** in the sidebar, then **Open Billing Portal** to:
- Update your payment method
- View and download invoices
- See your billing history
- Change your plan

### Cancelling your subscription

1. Click **Billing** in the sidebar
2. Click **Cancel Subscription**
3. Confirm the cancellation

Your subscription will cancel at the end of the current billing period. You keep full access until then. After the period ends, your account reverts to the Free plan.

### Payment security

- Card data is processed entirely by Stripe — AIPET never sees your card number
- All payment events are verified using Stripe's webhook signature system
- Stripe is PCI DSS Level 1 certified — the highest level of payment security

### Refunds

Contact support at the GitHub repository to request a refund within 14 days of payment.

---

## 11. API Keys (Enterprise)

Enterprise plan users can generate API keys to integrate AIPET into their own systems, CI/CD pipelines, SIEM platforms, and security automation workflows.

### Generating an API key

1. Click **API Keys** in the left sidebar
2. Enter a descriptive name for the key (e.g. "Production CI/CD" or "SIEM Integration")
3. Click **Generate**
4. **Copy the key immediately** — it is shown only once and cannot be recovered

If you lose a key, revoke it and generate a new one.

### Using an API key

Include the key in the `X-API-Key` header of every request:

```bash
curl -X POST https://aipet.io/api/scan/start \
  -H "Content-Type: application/json" \
  -H "X-API-Key: aipet_ent_your_key_here" \
  -d '{"target": "192.168.1.0/24", "mode": "live"}'
```

### API key limits

| Limit | Value |
|---|---|
| Maximum active keys | 10 per account |
| Requests per hour | 10 |
| Requests per day | 100 |

### Revoking an API key

1. Click **API Keys** in the sidebar
2. Find the key you want to revoke
3. Click **Revoke**
4. Confirm the revocation

Revoked keys stop working immediately. The key record is kept for audit purposes but can no longer be used.

### Security best practices

- Never share API keys or commit them to version control
- Use a different key for each integration (CI/CD, SIEM, etc.)
- Revoke keys immediately if they are compromised
- Rotate keys regularly (every 90 days recommended)
- Use the minimum permissions necessary for each integration

---

## 12. Generating Reports

AIPET automatically generates a report after every scan.

### Report contents

Every AIPET report contains:
1. Executive Summary — overall risk rating and priority actions
2. Discovered Devices — all devices with their profiles
3. Detailed Findings — all vulnerabilities with descriptions
4. AI Analysis — SHAP explanations for each device
5. Recommendations — prioritised remediation steps

### Downloading reports from the dashboard

1. Click **Reports** in the sidebar
2. Find the report you want
3. Click the **Download** button

### Report formats

**Markdown (.md)** — Human readable, renders on GitHub, easily converted to PDF or Word document.

**JSON (.json)** — Machine readable, can be imported into other security tools or SIEM platforms.

### Converting to PDF

```bash
# Install pandoc
sudo apt install pandoc -y

# Convert to PDF
pandoc reporting/aipet_report_*.md -o aipet_report.pdf
```

---

## 13. Command Line Reference (CLI Tool)

The original AIPET CLI tool is still available for direct command-line use.

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

## 14. Local Development Setup

### Prerequisites

| Component | Version |
|---|---|
| Python | 3.11+ |
| Node.js | 18+ |
| PostgreSQL | 17 |
| Redis | 7+ |

### Step 1 — Clone the repository

```bash
git clone https://github.com/Yallewbinyam/AIPET.git
cd AIPET
```

### Step 2 — Create virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Step 3 — Configure environment

```bash
cp .env.example .env
```

Edit `.env` with your values — see `.env.example` for all required variables including your Stripe API keys.

### Step 4 — Start PostgreSQL

```bash
sudo pg_ctlcluster 17 main start
sudo -u postgres psql -p 5433 -c "CREATE USER aipet_user WITH PASSWORD 'aipet_password';"
sudo -u postgres psql -p 5433 -c "CREATE DATABASE aipet_db OWNER aipet_user;"
```

### Step 5 — Start the backend

```bash
export DATABASE_URL=postgresql://aipet_user:aipet_password@localhost:5433/aipet_db
export STRIPE_SECRET_KEY=$(grep STRIPE_SECRET_KEY .env | cut -d= -f2)
python dashboard/backend/app_cloud.py
```

### Step 6 — Start the frontend

```bash
cd dashboard/frontend/aipet-dashboard
npm install
npm start
```

### Step 7 — Open the dashboard

```
http://localhost:3000
```

---

## 15. Frequently Asked Questions

**Q: I forgot my password. How do I reset it?**  
A: Currently, contact support via GitHub Issues. A self-service password reset feature is planned for a future release.

**Q: AIPET is not finding any devices**  
A: Check that you have permission to scan the target network. Try running with sudo for Nmap permissions: `sudo python3 aipet.py --target 192.168.1.0/24`

**Q: My scan limit says 5 but I am on the Professional plan**  
A: Sign out and sign back in to refresh your session token with the updated plan information.

**Q: The AI prediction says Low but I know the device is vulnerable**  
A: The AI model was trained on synthetic data and may not perfectly classify all real-world scenarios. Always review findings manually alongside the AI prediction. The AI is a prioritisation aid, not a replacement for human analysis.

**Q: I lost my API key. Can I recover it?**  
A: No — API keys are shown only once and the raw key is never stored. Revoke the lost key and generate a new one.

**Q: Can I have multiple API keys?**  
A: Yes — Enterprise users can have up to 10 active API keys simultaneously. We recommend one key per integration.

**Q: How do I cancel my subscription?**  
A: Click Billing in the sidebar, then Cancel Subscription. You keep access until the end of your current billing period.

**Q: Is my payment data secure?**  
A: Yes — AIPET uses Stripe for all payment processing. Your card details never touch AIPET's servers. Stripe is PCI DSS Level 1 certified.

**Q: Can I test my own home router?**  
A: Yes — you own it. Run: `python3 aipet.py --target 192.168.1.1 --http`  
Replace 192.168.1.1 with your router's IP address.

**Q: How do I update AIPET?**  
A: `cd AIPET && git pull && pip install -r requirements.txt`

---

## 16. Responsible Use

AIPET is a penetration testing tool. Using it against systems you do not own or have explicit written permission to test is illegal in most jurisdictions.

**Always:**
- Obtain written permission before scanning any network or device
- Test in an isolated lab environment when learning
- Follow responsible disclosure if you find real vulnerabilities
- Comply with your organisation's security testing policy
- Keep API keys secret and rotate them regularly

**Never:**
- Scan networks or devices without permission
- Use findings to damage or disrupt systems
- Share scan results without the owner's consent
- Commit API keys or credentials to version control

See [RESPONSIBLE_USE.md](RESPONSIBLE_USE.md) for the full policy.

---

*AIPET v2.0.0 — Coventry University MSc Cyber Security Research*  
*For support, open a GitHub issue at: https://github.com/Yallewbinyam/AIPET/issues*

---

## 17. AIPET Fix — Remediation Guide

AIPET Fix helps you act on every finding immediately. Instead of just telling you what is wrong, AIPET now tells you exactly how to fix it.

### Viewing a Fix

1. Go to the **Findings** tab in the dashboard
2. Find any vulnerability in the list
3. Click the **View Fix** button on the right side of the finding
4. The Fix Panel will open on the right side of the screen

### The Fix Panel

The Fix Panel shows you everything you need to remediate the vulnerability:

- **Why This Is Dangerous** — a plain English explanation of the risk
- **Time to Fix** — realistic estimate in minutes
- **Difficulty** — Quick Win, Moderate, or Complex
- **Source** — the security standard this fix is based on (OWASP, NIST, CIS)
- **Fix Commands** — exact terminal commands to run on the affected device
- **Copy Commands** — one click to copy all commands to your clipboard
- **Notes** — add your own notes about what you did to fix it

### Running the Fix Commands

The fix commands are designed to be run directly on the affected IoT device. To do this:

1. Copy the commands using the **Copy Commands** button
2. Open a terminal on your computer
3. SSH into the affected device: `ssh admin@<device-ip>`
4. Paste and run the commands
5. Verify the fix worked
6. Return to AIPET and mark the finding as Fixed

For devices with a web admin panel (routers, cameras), the fix instructions describe steps to follow in the browser instead of terminal commands.

### Tracking Fix Status

Each finding has a status that you can update:

| Status | Meaning |
|---|---|
| **Open** | Vulnerability has not been addressed yet |
| **In Progress** | You are currently working on the fix |
| **Fixed** | The vulnerability has been remediated |
| **Accepted Risk** | You have acknowledged the risk and chosen not to fix it |

To update the status, open the Fix Panel and click one of the four status buttons at the bottom.

### Risk Reduction Score

At the top of the Findings tab you will see the **Risk Reduction Score**. This shows:

- How many findings have been resolved
- What percentage of overall risk has been reduced
- A breakdown by status (Open, In Progress, Fixed, Accepted)

The score is weighted by severity — fixing a Critical finding reduces your risk score more than fixing a Low finding. As you fix more vulnerabilities, watch the percentage climb toward 100%.

### Important Note

AIPET Fix provides guidance based on industry standards. Always test fixes in a non-production environment first. Some fixes (such as disabling services) may affect device functionality. Consult your security team before applying fixes to production systems.

---

## 18. AIPET Explain — AI-Powered Plain English Explanations

AIPET Explain uses Claude AI to translate technical security findings into plain English that anyone can understand — from IT managers to CEOs and board members.

### Finding Explanations

Every finding in AIPET now has an AI-generated plain English explanation. To access it:

1. Go to the **Findings** tab
2. Click **View Fix** on any finding
3. Click the **AI Explanation** tab at the top of the Fix Panel
4. Wait 2-3 seconds for Claude to generate the explanation (first time only)
5. Subsequent views load instantly from cache

Each explanation has two sections:

**WHY THIS IS DANGEROUS** — explains the real-world business risk in plain English. What could an attacker actually do? What is the worst case scenario? Written without technical jargon for a business audience.

**WHAT THIS MEANS FOR YOUR BUSINESS** — explains the practical business impact. Is data at risk? Could operations be disrupted? Could there be regulatory consequences?

### Executive Security Report

The Executive Security Report generates a complete board-level security summary for your entire scan with one click.

To generate a report:

1. Go to the **Findings** tab
2. Click the **Executive Report** button next to the risk reduction percentage
3. Wait 3-5 seconds for Claude to write the report
4. Read the four sections — Executive Summary, Key Risks, Immediate Actions, Overall Assessment
5. Click **Copy Report** to copy it to your clipboard
6. Paste it into an email, PowerPoint, or board document

The report is written in professional business English with no technical jargon — suitable for presenting directly to a CEO, board, or senior management team.

---

## 19. AIPET Score — Financial Risk Assessment

AIPET Score translates technical vulnerabilities into financial business impact. Instead of CVSS scores and severity ratings, you see pound figures — helping you prioritise security investment and communicate risk to non-technical stakeholders.

### How to Use AIPET Score

**Step 1 — Tag Your Devices**

1. Go to the **Findings** tab
2. Click **Tag Devices**
3. Select your industry from the dropdown (Healthcare, Financial Services, Manufacturing, etc.)
4. For each device IP, select what that device does in your organisation:
   - Patient Records / Medical
   - Financial / Payment
   - Customer Data
   - Operations / Manufacturing
   - Research / IP
   - HR / Employee Data
   - General IT
   - Infrastructure / Network
   - IoT / Sensor
   - Unknown
5. Click **Save Tags & Close**

You only need to tag devices once. Tags are saved permanently and pre-populated on future visits.

**Step 2 — Calculate Your Score**

1. Click **Calculate Score**
2. AIPET calculates the financial exposure for every finding
3. The Financial Risk Exposure panel displays your results instantly

### Understanding Your Score

**Total Financial Exposure** — the combined pound value of all vulnerabilities based on your industry's average breach costs.

**Per-Finding Breakdown** — each vulnerability shows:
- The pound value of that specific finding
- A proportional bar showing relative impact
- The device business function assigned
- The breach probability percentage for that attack type

**Summary Grid** — four key figures:
- Critical Exposure — total exposure from Critical severity findings
- High Exposure — total exposure from High severity findings
- Medium Exposure — total exposure from Medium severity findings
- Fixed Savings — exposure eliminated by findings you have already fixed

### How the Calculation Works

AIPET Score uses a weighted formula based on UK industry breach cost data:
Industry base costs come from the IBM Cost of a Data Breach Report 2024 and the NCSC UK Cyber Security Breaches Survey 2024.

### Important Disclaimer

Financial exposure figures are estimates based on UK industry average breach costs. Actual costs may vary significantly depending on the size of your organisation, the nature of the data involved, regulatory environment, and incident response capability. These figures are intended to support security investment decisions and stakeholder communication — not to predict exact breach costs. Always consult a qualified security professional and cyber insurance advisor for precise risk quantification.

### Plan Access

AIPET Score is available on **Professional** and **Enterprise** plans. Free plan users will see an upgrade prompt when clicking Tag Devices or Calculate Score.

### Report Sections

| Section | Content |
|---|---|
| Executive Summary | 2-sentence overview of what was assessed and the overall risk level |
| Key Risks Identified | Bullet points describing the most important risks in business language |
| Immediate Actions Required | Numbered list of the top 3 things to do in the next 7 days |
| Overall Security Assessment | Honest assessment of current posture and outlook |

### Caching

AIPET Explain is designed to be cost-efficient. Every explanation is generated once and stored permanently. If you view the same finding explanation multiple times, it loads instantly from the database — Claude is only called once per finding.

The Executive Report is regenerated fresh every time you click the button — so it always reflects your current fix status and latest findings.

### Plan Access

AIPET Explain is available on **Professional** and **Enterprise** plans. Free plan users will see an upgrade prompt when clicking the AI Explanation tab or Executive Report button.

### Important Note

AI-generated explanations are designed to make security findings accessible to non-technical audiences. They should be used alongside, not instead of, technical security advice. For critical decisions, always consult a qualified security professional.