# AIPET Cloud — Installation Guide
## Version 2.0.0

---

## Table of Contents

1. [System Requirements](#1-system-requirements)
2. [Quick Start — Cloud Platform](#2-quick-start--cloud-platform)
3. [Detailed Setup — Cloud Platform](#3-detailed-setup--cloud-platform)
4. [Docker Installation](#4-docker-installation)
5. [Environment Variables](#5-environment-variables)
6. [Stripe Configuration](#6-stripe-configuration)
7. [Running the Platform](#7-running-the-platform)
8. [CLI Tool Installation](#8-cli-tool-installation)
9. [Troubleshooting](#9-troubleshooting)

---

## 1. System Requirements

### Cloud Platform

| Component | Minimum | Recommended |
|---|---|---|
| Operating System | Kali Linux 2023+ / Ubuntu 22.04+ | Kali Linux 2024 |
| Python | 3.11+ | 3.11+ |
| Node.js | 18+ | 20+ |
| PostgreSQL | 17 | 17 |
| Redis | 7+ | 7+ |
| RAM | 4GB | 8GB |
| Disk | 5GB free | 10GB free |

### CLI Tool Only

| Component | Minimum |
|---|---|
| OS | Kali Linux 2023+ |
| Python | 3.11+ |
| RAM | 4GB |
| Disk | 2GB free |

---

## 2. Quick Start — Cloud Platform

```bash
# Clone the repository
git clone https://github.com/Yallewbinyam/AIPET.git
cd AIPET

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Install Node dependencies
cd dashboard/frontend/aipet-dashboard
npm install
cd ../../..

# Configure environment
cp .env.example .env
# Edit .env with your values (see Section 5)

# Start PostgreSQL
sudo pg_ctlcluster 17 main start

# Set up database
sudo -u postgres psql -p 5433 -c "CREATE USER aipet_user WITH PASSWORD 'your_password';"
sudo -u postgres psql -p 5433 -c "CREATE DATABASE aipet_db OWNER aipet_user;"

# Start backend (Terminal 1)
export DATABASE_URL=postgresql://aipet_user:your_password@localhost:5433/aipet_db
export STRIPE_SECRET_KEY=$(grep STRIPE_SECRET_KEY .env | cut -d= -f2)
python dashboard/backend/app_cloud.py

# Start frontend (Terminal 2)
cd dashboard/frontend/aipet-dashboard
npm start

# Open browser
# http://localhost:3000
```

---

## 3. Detailed Setup — Cloud Platform

### Step 1 — Clone the repository

```bash
git clone https://github.com/Yallewbinyam/AIPET.git
cd AIPET
```

### Step 2 — Create Python virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
```

Always activate the virtual environment before running any AIPET commands:
```bash
source venv/bin/activate
```

### Step 3 — Install Python dependencies

```bash
pip install -r requirements.txt
```

### Step 4 — Install Node.js dependencies

```bash
cd dashboard/frontend/aipet-dashboard
npm install
cd ../../..
```

### Step 5 — Install system tools

```bash
sudo apt update
sudo apt install nmap binwalk mosquitto mosquitto-clients postgresql -y
```

### Step 6 — Configure environment variables

```bash
cp .env.example .env
```

Open `.env` and fill in your values. See [Section 5](#5-environment-variables) for full details.

```bash
nano .env
```

### Step 7 — Start PostgreSQL

```bash
# Start PostgreSQL 17
sudo pg_ctlcluster 17 main start

# Verify it is running
pg_lsclusters
# Should show: 17 main 5433 online
```

### Step 8 — Create the database

```bash
sudo -u postgres psql -p 5433
```

Inside the PostgreSQL prompt:
```sql
CREATE USER aipet_user WITH PASSWORD 'your_password';
CREATE DATABASE aipet_db OWNER aipet_user;
\q
```

### Step 9 — Start Redis (for scan queue)

```bash
sudo systemctl start redis-server
sudo systemctl enable redis-server
```

Verify Redis is running:
```bash
redis-cli ping
# Expected: PONG
```

### Step 10 — Start the backend

Open a terminal and run:

```bash
cd /path/to/AIPET
source venv/bin/activate
export DATABASE_URL=postgresql://aipet_user:your_password@localhost:5433/aipet_db
export STRIPE_SECRET_KEY=$(grep STRIPE_SECRET_KEY .env | cut -d= -f2)
export STRIPE_PRICE_PROFESSIONAL=$(grep STRIPE_PRICE_PROFESSIONAL .env | cut -d= -f2)
export STRIPE_PRICE_ENTERPRISE=$(grep STRIPE_PRICE_ENTERPRISE .env | cut -d= -f2)
export STRIPE_WEBHOOK_SECRET=$(grep STRIPE_WEBHOOK_SECRET .env | cut -d= -f2)
python dashboard/backend/app_cloud.py
```

You should see:
```
============================================================
  AIPET Cloud Backend v2
  Running at: http://localhost:5001
============================================================
```

### Step 11 — Start the frontend

Open a second terminal:

```bash
cd /path/to/AIPET/dashboard/frontend/aipet-dashboard
npm start
```

### Step 12 — Open the dashboard

Open your browser and go to:
```
http://localhost:3000
```

### Step 13 — Set up health monitor (optional but recommended)

```bash
sudo nano /etc/systemd/system/aipet-monitor.service
```

Paste:
```
[Unit]
Description=AIPET Health Monitor
After=network.target

[Service]
Type=simple
User=your_username
WorkingDirectory=/path/to/AIPET
Environment="DATABASE_URL=postgresql://aipet_user:your_password@localhost:5433/aipet_db"
ExecStart=/path/to/AIPET/venv/bin/python dashboard/backend/monitoring/health_monitor.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable aipet-monitor
sudo systemctl start aipet-monitor
```

---

## 4. Docker Installation

Docker is the easiest way to run AIPET Cloud in production.

### Prerequisites

```bash
sudo apt install docker.io docker-compose -y
sudo usermod -aG docker $USER
# Log out and back in for group change to take effect
```

### Start with Docker Compose

```bash
git clone https://github.com/Yallewbinyam/AIPET.git
cd AIPET
cp .env.example .env
# Edit .env with your values
nano .env

# Start all services
docker-compose up -d

# Check all containers are running
docker-compose ps

# View logs
docker-compose logs -f
```

### Stop all services

```bash
docker-compose down
```

### Docker services

| Service | Port | Description |
|---|---|---|
| backend | 5001 | Flask API |
| frontend | 3000 | React dashboard |
| postgres | 5433 | PostgreSQL database |
| redis | 6379 | Celery message broker |
| celery | — | Background scan worker |
| nginx | 80/443 | Reverse proxy |

---

## 5. Environment Variables

Copy `.env.example` to `.env` and fill in all values:

```bash
cp .env.example .env
```

### Required variables

| Variable | Description | Example |
|---|---|---|
| `DATABASE_URL` | PostgreSQL connection string | `postgresql://aipet_user:password@localhost:5433/aipet_db` |
| `JWT_SECRET_KEY` | Secret for JWT tokens (32+ chars) | `your-random-secret-key-here` |
| `SECRET_KEY` | Flask secret key (32+ chars) | `another-random-secret-key` |
| `STRIPE_SECRET_KEY` | Stripe secret key | `sk_test_...` |
| `STRIPE_PUBLISHABLE_KEY` | Stripe publishable key | `pk_test_...` |
| `STRIPE_WEBHOOK_SECRET` | Stripe webhook signing secret | `whsec_...` |
| `STRIPE_PRICE_PROFESSIONAL` | Stripe Price ID for Professional plan | `price_...` |
| `STRIPE_PRICE_ENTERPRISE` | Stripe Price ID for Enterprise plan | `price_...` |

### Optional variables

| Variable | Description | Default |
|---|---|---|
| `ALERT_EMAIL` | Email for critical alerts | None |
| `SMTP_HOST` | SMTP server hostname | `smtp.gmail.com` |
| `SMTP_PORT` | SMTP server port | `587` |
| `SMTP_USER` | SMTP username | None |
| `SMTP_PASSWORD` | SMTP app password | None |
| `FLASK_ENV` | Flask environment | `development` |
| `DOMAIN` | Your domain name | `localhost` |

### Generating secure secret keys

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

Run this twice to get two different keys for `JWT_SECRET_KEY` and `SECRET_KEY`.

---

## 6. Stripe Configuration

### Step 1 — Create a Stripe account

Go to [dashboard.stripe.com](https://dashboard.stripe.com) and create a free account.

### Step 2 — Get API keys

1. Go to **Developers → API keys**
2. Copy the **Publishable key** (`pk_test_...`)
3. Click **Reveal** on the **Secret key** and copy it (`sk_test_...`)
4. Paste both into your `.env` file

### Step 3 — Create products

1. Go to **Product catalogue → Create product**
2. Create **AIPET Professional**:
   - Price: £49.00
   - Billing: Monthly recurring
3. Create **AIPET Enterprise**:
   - Price: £499.00
   - Billing: Monthly recurring
4. Copy the Price IDs (`price_...`) for each product into your `.env` file

### Step 4 — Set up webhooks

1. Go to **Developers → Webhooks → Add destination**
2. Set endpoint URL to: `https://yourdomain.com/payments/webhook`
3. Select events:
   - `checkout.session.completed`
   - `customer.subscription.updated`
   - `customer.subscription.deleted`
4. Copy the **Signing secret** (`whsec_...`) into your `.env` file

### Step 5 — Test with Stripe CLI (local development)

```bash
# Install Stripe CLI
curl -s https://packages.stripe.dev/api/security/keypair/stripe-cli-gpg/public | gpg --dearmor | sudo tee /usr/share/keyrings/stripe.gpg > /dev/null
echo "deb [signed-by=/usr/share/keyrings/stripe.gpg] https://packages.stripe.dev/stripe-cli-debian-local stable main" | sudo tee /etc/apt/sources.list.d/stripe.list
sudo apt update && sudo apt install stripe -y

# Login
stripe login

# Forward webhooks to local server
stripe listen --forward-to localhost:5001/payments/webhook
```

### Test card numbers

Use these card numbers in Stripe test mode:

| Card | Number | Result |
|---|---|---|
| Success | `4242 4242 4242 4242` | Payment succeeds |
| Decline | `4000 0000 0000 0002` | Payment declined |
| 3D Secure | `4000 0025 0000 3155` | Requires authentication |

Use any future expiry date and any 3-digit CVC.

---

## 7. Running the Platform

### Starting everything (development)

**Terminal 1 — PostgreSQL:**
```bash
sudo pg_ctlcluster 17 main start
```

**Terminal 2 — Flask backend:**
```bash
cd /path/to/AIPET
source venv/bin/activate
export DATABASE_URL=postgresql://aipet_user:your_password@localhost:5433/aipet_db
export STRIPE_SECRET_KEY=$(grep STRIPE_SECRET_KEY .env | cut -d= -f2)
export STRIPE_PRICE_PROFESSIONAL=$(grep STRIPE_PRICE_PROFESSIONAL .env | cut -d= -f2)
export STRIPE_PRICE_ENTERPRISE=$(grep STRIPE_PRICE_ENTERPRISE .env | cut -d= -f2)
export STRIPE_WEBHOOK_SECRET=$(grep STRIPE_WEBHOOK_SECRET .env | cut -d= -f2)
python dashboard/backend/app_cloud.py
```

**Terminal 3 — React frontend:**
```bash
cd /path/to/AIPET/dashboard/frontend/aipet-dashboard
npm start
```

**Terminal 4 — Health monitor (optional):**
```bash
cd /path/to/AIPET
source venv/bin/activate
python dashboard/backend/monitoring/health_monitor.py
```

### Stopping everything

```bash
# Stop Flask
fuser -k 5001/tcp

# Stop React
# Press Ctrl+C in Terminal 3

# Stop PostgreSQL
sudo pg_ctlcluster 17 main stop
```

### Running database backups manually

```bash
cd /path/to/AIPET
source venv/bin/activate
python dashboard/backend/monitoring/backup.py
```

---

## 8. CLI Tool Installation

For the original command-line tool only (no cloud features):

```bash
git clone https://github.com/Yallewbinyam/AIPET.git
cd AIPET
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
sudo apt install nmap binwalk mosquitto mosquitto-clients -y
python3 aipet.py --version
```

### Running demo mode

```bash
# Terminal 1
sudo systemctl start mosquitto

# Terminal 2
source venv/bin/activate
python3 lab/coap_test_server.py

# Terminal 3
source venv/bin/activate
python3 lab/http_test_server.py

# Terminal 4
python3 aipet.py --demo
```

---

## 9. Troubleshooting

**ModuleNotFoundError: No module named 'flask_cors'**
```bash
pip install flask-cors
```

**ModuleNotFoundError for any module**
```bash
# Make sure virtual environment is activated
source venv/bin/activate
pip install -r requirements.txt
```

**Port 5001 already in use**
```bash
fuser -k 5001/tcp
python dashboard/backend/app_cloud.py
```

**PostgreSQL connection refused**
```bash
sudo pg_ctlcluster 17 main start
pg_lsclusters  # verify it shows 'online'
```

**DATABASE_URL not being read**  
Set it explicitly in the same terminal session before starting Flask:
```bash
export DATABASE_URL=postgresql://aipet_user:your_password@localhost:5433/aipet_db
python dashboard/backend/app_cloud.py
```

**React app blank or shows errors**
```bash
cd dashboard/frontend/aipet-dashboard
npm install
npm start
```

**Stripe webhook signature error**  
Make sure you are using the webhook secret from the Stripe CLI (for local testing), not the dashboard webhook secret. They are different.

**Nmap permission error**
```bash
sudo python3 aipet.py --target 192.168.1.0/24
```

**Binwalk extraction fails**
```bash
sudo apt install squashfs-tools -y
```

**MQTT connection refused**
```bash
sudo systemctl start mosquitto
```

---

*AIPET v2.0.0 — Coventry University MSc Cyber Security Research*  
*For support, open a GitHub issue at: https://github.com/Yallewbinyam/AIPET/issues*