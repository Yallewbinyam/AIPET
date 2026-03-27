# AIPET — Installation Guide

## System Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| OS | Kali Linux 2023+ | Kali Linux 2024 |
| Python | 3.11+ | 3.11+ |
| RAM | 4GB | 8GB |
| Disk | 2GB free | 5GB free |

---

## Quick Installation

### Step 1 — Clone the repository
```bash
git clone https://github.com/YOUR_USERNAME/AIPET.git
cd AIPET
```

### Step 2 — Create virtual environment
```bash
python3 -m venv venv
source venv/bin/activate
```

### Step 3 — Install dependencies
```bash
pip install -r requirements.txt
```

### Step 4 — Install system tools
```bash
sudo apt update
sudo apt install nmap binwalk mosquitto mosquitto-clients -y
```

### Step 5 — Verify installation
```bash
python3 aipet.py --version
```

Expected output: AIPET v1.0.0

---

## Running AIPET

### Demo Mode
```bash
# Terminal 1
sudo systemctl start mosquitto

# Terminal 2
source venv/bin/activate
python3 lab/coap_test_server.py

# Terminal 3
source venv/bin/activate
python3 lab/http_test_server.py

# Terminal 4 — run AIPET
python3 aipet.py --demo
```

### Live Assessment
```bash
python3 aipet.py --target 192.168.1.0/24
python3 aipet.py --target 192.168.1.105
python3 aipet.py --target 192.168.1.105 --mqtt --coap
```

### Command Line Options
```
--target, -t     Target IP, hostname, or CIDR range
--demo           Run against local test servers
--mqtt           Force run MQTT attack module
--coap           Force run CoAP attack module
--http           Force run HTTP attack module
--firmware       Force run firmware analysis
--firmware-path  Path to firmware file or directory
--mqtt-port      MQTT port (default: 1883)
--coap-port      CoAP port (default: 5683)
--http-port      HTTP port (default: 80)
--version, -v    Show version number
```

---

## Training the AI Model
```bash
python3 ai_engine/generate_dataset.py
python3 ai_engine/model_trainer.py
```

---

## Running Tests
```bash
python3 -m pytest tests/ -v
```
Expected: 30 tests passing.

---

## Troubleshooting

**ModuleNotFoundError:** Activate venv first:
```bash
source venv/bin/activate
```

**Nmap permission error:**
```bash
sudo python3 aipet.py --target 192.168.1.0/24
```

**Binwalk extraction fails:**
```bash
sudo apt install squashfs-tools -y
```

**MQTT connection refused:**
```bash
sudo systemctl start mosquitto
```
