# AIPET Cloud — AI-Powered IoT Security Platform

<div align="center">

![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)
![React](https://img.shields.io/badge/React-18-61DAFB.svg)
![Flask](https://img.shields.io/badge/Flask-3.0-000000.svg)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-17-336791.svg)
![Docker](https://img.shields.io/badge/Docker-Containerised-2496ED.svg)
![Stripe](https://img.shields.io/badge/Stripe-Payments-635BFF.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

**The first production-ready SaaS platform combining IoT-specific penetration testing with explainable AI — telling you not just what is vulnerable, but exactly why.**

[Live Demo](#) · [API Docs](#api-documentation) · [Pricing](#pricing) · [Report a Bug](https://github.com/Yallewbinyam/AIPET/issues)

</div>

---

## Table of Contents

- [Overview](#overview)
- [What Makes AIPET Different](#what-makes-aipet-different)
- [Platform Architecture](#platform-architecture)
- [Features](#features)
- [Pricing Plans](#pricing-plans)
- [Tech Stack](#tech-stack)
- [Quick Start](#quick-start)
- [Local Development Setup](#local-development-setup)
- [API Documentation](#api-documentation)
- [Security](#security)
- [Monitoring & Operations](#monitoring--operations)
- [Roadmap](#roadmap)
- [Academic Context](#academic-context)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

AIPET Cloud is a production-ready SaaS IoT security platform that automates the discovery, testing, and intelligent prioritisation of vulnerabilities across IoT devices and protocols. It combines a powerful penetration testing engine with an explainable AI analysis layer — and delivers everything through a professional cloud dashboard with subscription billing.

Built as an MSc Cyber Security dissertation project at Coventry University, AIPET is designed to compete with enterprise tools like Claroty, Armis, and Nozomi Networks — at a fraction of the cost.

```

         AIPET — Explainable AI-Powered IoT Pentest          
                    Platform v2.0.0                           

[Module 1] Reconnaissance .............. 3 devices found
[Module 2] MQTT Attack Suite ........... CRITICAL: anonymous access
[Module 3] CoAP Attack Suite ........... HIGH: unencrypted endpoints
[Module 4] HTTP/Web IoT Suite .......... HIGH: default credentials
[Module 5] Firmware Analyser ........... 12 private keys found
[Module 6] Explainable AI Engine ....... 91.3% confidence CRITICAL


  Duration: 63.9s  |  Critical: 6  |  High: 3  |  Medium: 4  

```

---

## What Makes AIPET Different

| Capability | Enterprise Tools | AIPET Cloud |
|---|---|---|
| IoT-specific design | Generic IT tools | ✅ Built for IoT |
| AI-driven prioritisation | Not present | ✅ Random Forest (F1: 0.8614) |
| Explainable AI (SHAP) | Black box | ✅ Full explanation |
| MQTT / CoAP coverage | Partial or none | ✅ Full coverage |
| Firmware analysis | Separate tools | ✅ Integrated |
| SaaS subscription model | £50,000+ enterprise | ✅ From £49/month |
| API access | Custom contracts | ✅ Enterprise plan |
| Open source core | Closed source | ✅ MIT licence |

---

## Platform Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        AIPET Cloud                          │
├─────────────────┬───────────────────┬───────────────────────┤
│   React Frontend│   Flask Backend   │   Background Services │
│   (Port 3000)   │   (Port 5001)     │                       │
│                 │                   │                       │
│  • Dashboard    │  • JWT Auth       │  • Celery Workers     │
│  • Findings     │  • REST API       │  • Redis Queue        │
│  • AI Analysis  │  • Stripe Billing │  • Health Monitor     │
│  • Pricing      │  • API Keys       │  • Daily DB Backup    │
│  • Billing      │  • Rate Limiting  │  • Email Alerts       │
│  • API Keys     │  • CORS           │                       │
├─────────────────┴───────────────────┴───────────────────────┤
│                    PostgreSQL Database                       
│              (Users · Scans · Findings · API Keys)          
├─────────────────────────────────────────────────────────────
│                    AIPET Scan Engine                         
│   Recon · MQTT · CoAP · HTTP · Firmware · AI (SHAP)        
└─────────────────────────────────────────────────────────────┘
```

---

## Features

### Security Assessment
- **Network Reconnaissance** — Nmap-based device discovery and fingerprinting
- **MQTT Attack Suite** — Anonymous access, credential brute force, topic enumeration
- **CoAP Attack Suite** — Unencrypted endpoints, resource discovery, replay attacks
- **HTTP/Web IoT Suite** — Default credentials, CVE scanning, web interface testing
- **Firmware Analysis** — Hardcoded credentials, private keys, dangerous configurations
- **Parallel Scanning** — Scan multiple networks simultaneously (Professional/Enterprise)

### Explainable AI Engine
- **Random Forest classifier** trained on IoT vulnerability dataset
- **SHAP (SHapley Additive exPlanations)** — explains every prediction in plain English
- **Weighted F1-Score: 0.8614** — exceeds 0.85 research target
- **Critical class F1: 0.9440** — high precision on most important findings

### Cloud Platform
- **JWT Authentication** — secure login and registration
- **Subscription Billing** — Stripe-powered payments with three tiers
- **API Key Management** — Enterprise users generate programmatic access keys
- **Scan Queue** — Celery-powered background scanning with real-time status
- **PDF Reports** — downloadable assessment reports
- **Rate Limiting** — 200 requests/day, 50/hour per user

### Operations
- **Health Monitoring** — checks server every 60 seconds, auto-restarts on failure
- **Email Alerts** — instant notification on critical errors
- **Daily Backups** — PostgreSQL database backed up automatically at 2am
- **Structured Logging** — every action logged with timestamp, user, and context
- **OWASP IoT Top 10** — full coverage across all 10 categories

---

## Pricing Plans

| | Free | Professional | Enterprise |
|---|---|---|---|
| **Price** | £0/month | £49/month | £499/month |
| **Scans** | 5/month | Unlimited | Unlimited |
| **Parallel networks** | 1 | 3 | 10 |
| **AI analysis** | Basic | Full SHAP | Full SHAP |
| **Reports** | PDF | All formats | All formats |
| **API access** | ✗ | ✗ | ✅ |
| **Support** | Community | Email | Priority + SLA |

---

## Tech Stack

### Backend
| Technology | Version | Purpose |
|---|---|---|
| Python | 3.11+ | Core language |
| Flask | 3.0 | Web framework |
| Flask-JWT-Extended | 4.6 | Authentication |
| Flask-SQLAlchemy | 3.1 | ORM |
| Flask-Limiter | 3.5 | Rate limiting |
| Celery | 5.3 | Background tasks |
| Gunicorn | 21.2 | Production WSGI |
| Stripe | 8.11 | Payment processing |
| psutil | 5.9 | System monitoring |

### Frontend
| Technology | Version | Purpose |
|---|---|---|
| React | 18 | UI framework |
| Axios | 1.6 | HTTP client |
| Recharts | 2.10 | Data visualisation |
| Lucide React | 0.383 | Icons |
| Tailwind CSS | 3.4 | Styling |

### Infrastructure
| Technology | Purpose |
|---|---|
| PostgreSQL 17 | Primary database |
| Redis | Celery message broker |
| Docker + Docker Compose | Containerisation |
| Nginx | Reverse proxy |
| systemd | Service management |
| cron | Scheduled backups |

### AI / ML
| Technology | Purpose |
|---|---|
| scikit-learn | Random Forest classifier |
| SHAP | Explainability layer |
| pandas / numpy | Data processing |

---

## Quick Start

### Prerequisites
- Python 3.11+
- Node.js 18+
- PostgreSQL 17
- Redis
- Docker (optional)

> 📖 For the complete step-by-step installation guide including Docker, Stripe configuration, and troubleshooting, see **[INSTALL.md](INSTALL.md)**

---

### Clone the repository

```bash
git clone https://github.com/Yallewbinyam/AIPET.git
cd AIPET
```

### Option 1 — Docker (recommended)

```bash
# Copy environment template
cp .env.example .env

# Edit .env with your values
nano .env

# Start all services
docker-compose up -d

# Access the dashboard
open http://localhost:3000
```

### Option 2 — Local development

See [Local Development Setup](#local-development-setup) below.

---

## Local Development Setup

### 1. Backend setup

```bash
# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Set up PostgreSQL
sudo pg_ctlcluster 17 main start
sudo -u postgres psql -p 5433 -c "CREATE USER aipet_user WITH PASSWORD 'aipet_password';"
sudo -u postgres psql -p 5433 -c "CREATE DATABASE aipet_db OWNER aipet_user;"

# Configure environment variables
cp .env.example .env
# Edit .env with your Stripe keys and other settings
```

### 2. Environment variables

Create a `.env` file in the project root:

```env
# Database
DATABASE_URL=postgresql://aipet_user:aipet_password@localhost:5433/aipet_db
DB_PASSWORD=aipet_password

# JWT
JWT_SECRET_KEY=your-secret-key-here

# Stripe
STRIPE_SECRET_KEY=sk_test_...
STRIPE_PUBLISHABLE_KEY=pk_test_...
STRIPE_WEBHOOK_SECRET=whsec_...
STRIPE_PRICE_PROFESSIONAL=price_...
STRIPE_PRICE_ENTERPRISE=price_...
STRIPE_SUCCESS_URL=http://localhost:5000/dashboard?payment=success
STRIPE_CANCEL_URL=http://localhost:5000/pricing?payment=cancelled

# Email alerts (optional)
ALERT_EMAIL=your@email.com
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your@gmail.com
SMTP_PASSWORD=your-app-password
```

### 3. Start the backend

```bash
export DATABASE_URL=postgresql://aipet_user:aipet_password@localhost:5433/aipet_db
export STRIPE_SECRET_KEY=$(grep STRIPE_SECRET_KEY .env | cut -d= -f2)
python dashboard/backend/app_cloud.py
```

### 4. Start the frontend

```bash
cd dashboard/frontend/aipet-dashboard
npm install
npm start
```

### 5. Access the platform

Open `http://localhost:3000` in your browser.

---

## API Documentation

All endpoints require a JWT token in the Authorization header:
```
Authorization: Bearer <your_jwt_token>
```

Enterprise users can also use API keys:
```
X-API-Key: aipet_ent_<your_api_key>
```

### Authentication

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/auth/register` | Register a new account |
| POST | `/api/auth/login` | Login and receive JWT token |
| GET | `/api/auth/me` | Get current user profile |
| POST | `/api/auth/change-password` | Change password |

### Scanning

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/scan/start` | Start a new scan |
| GET | `/api/scan/status` | Get current scan status |
| GET | `/api/scan/history` | Get scan history |
| GET | `/api/summary` | Get dashboard summary |

### Payments

| Method | Endpoint | Description |
|---|---|---|
| POST | `/payments/create-checkout-session` | Create Stripe checkout |
| POST | `/payments/webhook` | Stripe webhook handler |
| GET | `/payments/subscription` | Get subscription status |
| POST | `/payments/portal` | Open billing portal |
| POST | `/payments/cancel` | Cancel subscription |

### API Keys (Enterprise only)

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/keys` | Generate a new API key |
| GET | `/api/keys` | List all API keys |
| DELETE | `/api/keys/<id>` | Revoke an API key |

### Usage & Health

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/user/usage` | Get scan usage and plan details |
| GET | `/api/health` | System health check |
| GET | `/api/plans` | Get available plans |

### Example: Start a scan

```bash
curl -X POST https://aipet.io/api/scan/start \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{
    "target": "192.168.1.0/24",
    "mode": "live"
  }'
```

### Example: Using an API key (Enterprise)

```bash
curl -X POST https://aipet.io/api/scan/start \
  -H "Content-Type: application/json" \
  -H "X-API-Key: aipet_ent_your_key_here" \
  -d '{
    "target": "192.168.1.0/24",
    "mode": "live"
  }'
```

---

## Security

AIPET Cloud is built with security at every layer:

- **JWT tokens** — short-lived access tokens with automatic expiry
- **Password hashing** — bcrypt with salt rounds
- **API key hashing** — SHA-256, raw keys never stored
- **Rate limiting** — 200 requests/day, 50/hour per IP
- **CORS** — restricted to approved origins only
- **Stripe** — card data never touches our servers
- **Webhook verification** — HMAC-SHA256 signature on every Stripe event
- **SQL injection** — SQLAlchemy ORM prevents raw SQL injection
- **Error handling** — internal errors never exposed to users

### Responsible Use

⚠️ **AIPET is for authorised penetration testing only.**

Never use AIPET against systems you do not have explicit written permission to test. See [RESPONSIBLE_USE.md](RESPONSIBLE_USE.md) for the full policy.

---

## Monitoring & Operations

### Health Monitor

AIPET includes a systemd-managed health monitor that:
- Checks the server every 60 seconds
- Auto-restarts Flask after 3 consecutive failures
- Sends email alerts on failures

```bash
# Check monitor status
sudo systemctl status aipet-monitor

# View monitor logs
cat /tmp/aipet_monitor.log
```

### Database Backups

Automated daily backups at 2am with 7-day retention:

```bash
# Manual backup
python dashboard/backend/monitoring/backup.py

# List backups
python dashboard/backend/monitoring/backup.py list

# Restore from backup
python dashboard/backend/monitoring/backup.py restore /path/to/backup.sql.gz
```

### Log Files

| File | Contents |
|---|---|
| `/tmp/aipet_cloud.log` | All application events |
| `/tmp/aipet_errors.log` | Errors only |
| `/tmp/aipet_monitor.log` | Health monitor activity |
| `/tmp/aipet_backup.log` | Backup activity |

---

## AI Performance

| Metric | Value | Target |
|---|---|---|
| Weighted F1-Score | **0.8614** | ≥ 0.85 ✅ |
| CV Mean F1 | **0.8668** | — ✅ |
| CV Stability (Std) | **0.0108** | < 0.05 ✅ |
| Critical Class F1 | **0.9440** | — ✅ |
| Training dataset | 2,000 samples | Synthetic IoT data |

---

## OWASP IoT Top 10 Coverage

| Category | Covered By |
|---|---|
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

## Roadmap

| Week | Feature | Status |
|---|---|---|
| 1 | JWT Authentication | ✅ Complete |
| 2 | PostgreSQL + Rate Limiting | ✅ Complete |
| 3 | Gunicorn + Nginx | ✅ Complete |
| 4 | Docker Containerisation | ✅ Complete |
| 5 | Celery Scan Queue | ✅ Complete |
| 6 | Stripe Payment Integration | ✅ Complete |
| 7 | Pricing + Billing UI | ✅ Complete |
| 8 | Monitoring + Logging + Backups | ✅ Complete |
| 9 | API Keys for Enterprise | ✅ Complete |
| 10 | Cloud Deployment (aipet.io) | ⏳ Pending (bank card) |
| 11 | Security Hardening | ✅ Complete |
| 12 | Final Polish + Launch | ✅ Complete |

---

## Academic Context

AIPET was developed as an MSc Cyber Security (Ethical Hacking) dissertation project at Coventry University (2025).

### Validation

AIPET was validated against **OWASP IoTGoat v1.0** — an independently developed deliberately vulnerable IoT firmware image.

| Metric | Manual Assessment | AIPET | Improvement |
|---|---|---|---|
| Time | 162s | ~30s | 5.4× faster |
| Credential findings | 8 | 279 | 34× more |
| Private keys found | 1 | 12 | 12× more |
| Dangerous configs | 0 | 33 | New coverage |

### Citation

```
Binyam, Y. (2025). AIPET Cloud: An Explainable AI-Powered
IoT Security SaaS Platform. MSc Dissertation,
Coventry University.
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## License

MIT — see [LICENSE](LICENSE)

---

<div align="center">

Developed as part of MSc Cyber Security (Ethical Hacking) research at Coventry University, 2025.

**[aipet.io](https://aipet.io)** · [GitHub](https://github.com/Yallewbinyam/AIPET) · [Report Issues](https://github.com/Yallewbinyam/AIPET/issues)

</div>

---

## Phase 2 — Intelligence Layer

Phase 2 transforms AIPET from a scanner into an AI-powered security advisor. Each module adds a new layer of intelligence on top of the core platform.

### AIPET Fix ✅ Complete

Every finding now includes exact remediation guidance:

- **Remediation Knowledge Base** — 30 IoT-specific fixes mapped to attack types, sourced from OWASP IoT Top 10, NIST SP 800-213, and CIS Benchmarks
- **Fix Panel** — slide-out panel showing why the vulnerability is dangerous, exact copy-paste terminal commands, time estimate, and difficulty rating
- **Fix Status Tracking** — mark findings as Open, In Progress, Fixed, or Accepted Risk
- **Risk Reduction Score** — weighted calculation showing percentage of risk resolved, updated in real time as findings are marked fixed
- **Fix API** — three production-ready endpoints: `GET /api/remediation/<finding_id>`, `PATCH /api/findings/<id>/status`, `GET /api/scans/<id>/fix-summary`

### AIPET Explain ✅ Complete

Every finding and scan now has plain English AI explanations powered by Claude:

- **Finding Explanations** — two-paragraph plain English explanation for every vulnerability: why it is dangerous and what it means for the business. Written for non-technical audiences — hospital administrators, factory owners, board members
- **Executive Security Report** — one-click board-level security report for any scan. Includes executive summary, key risks, immediate actions required, and overall assessment. Generated by Claude AI in 3-5 seconds
- **Intelligent Caching** — explanations are generated once and stored. Subsequent requests are served instantly from the database — no repeated API calls
- **Plan Gating** — available on Professional and Enterprise plans, with upgrade prompt for Free users
- **Explain API** — three production-ready endpoints: `GET /api/explain/finding/<id>`, `POST /api/explain/report/<scan_id>`, `GET /api/explain/report/<scan_id>`
- **Token Tracking** — every API call tracks tokens used for cost monitoring as usage scales

### Coming Soon

| Module | Description | Status |
|---|---|---|
| AIPET Explain — Natural Language AI Explanations | ✅ Complete |
| AIPET Score | Financial business impact calculation | 📅 Month 3 |
| AIPET Map | Visual attack path mapping with D3.js | 📅 Month 4 |
| AIPET Predict | CVE monitoring via NVD API | 📅 Month 5 |
| AIPET Watch | Passive 24/7 network anomaly detection | 📅 Month 6 |
| AIPET Ask | Natural language AI security assistant | 📅 Month 7 |

