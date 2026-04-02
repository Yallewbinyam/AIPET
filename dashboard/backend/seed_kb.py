"""
AIPET Fix — Remediation Knowledge Base Seeder
Populates the remediation_kb table with 30 IoT vulnerability fixes.
Run once: python dashboard/backend/seed_kb.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from dashboard.backend.app_cloud import create_app
from dashboard.backend.models import db, RemediationKB

REMEDIATION_DATA = [
    {
        "attack_type": "open_telnet",
        "title": "Telnet Open on Port 23",
        "severity": "Critical",
        "explanation": "Telnet transmits all data including usernames and passwords in plain text. Any attacker on the same network can intercept and read everything. Telnet was designed in 1969 before security was a concern and should never be used on any modern device.",
        "fix_commands": "sudo systemctl stop telnet\nsudo systemctl disable telnet\nsudo apt remove telnetd -y",
        "time_estimate_minutes": 2,
        "difficulty": "Quick Win",
        "source": "OWASP IoT Top 10"
    },
    {
        "attack_type": "default_credentials",
        "title": "Default Credentials Not Changed",
        "severity": "Critical",
        "explanation": "The device is using factory default username and password combinations. These are publicly listed in manufacturer documentation and are the first thing every attacker tries. Leaving default credentials is equivalent to leaving your front door unlocked.",
        "fix_commands": "# Access device admin panel\n# Navigate to: Settings > Security > Change Password\n# Set a strong password: minimum 12 characters, mixed case, numbers, symbols\n# Disable default admin account if possible\n# Enable account lockout after 5 failed attempts",
        "time_estimate_minutes": 5,
        "difficulty": "Quick Win",
        "source": "OWASP IoT Top 10"
    },
    {
        "attack_type": "unencrypted_mqtt",
        "title": "MQTT Running Without TLS Encryption",
        "severity": "High",
        "explanation": "MQTT messages are being transmitted in plain text on port 1883. Anyone on the network can read all device messages, inject false commands, and intercept sensitive sensor data. This is especially dangerous for industrial and medical IoT devices.",
        "fix_commands": "# In your MQTT broker config (mosquitto.conf):\nlistener 8883\ncafile /etc/mosquitto/certs/ca.crt\ncertfile /etc/mosquitto/certs/server.crt\nkeyfile /etc/mosquitto/certs/server.key\nrequire_certificate true\n\n# Restart broker:\nsudo systemctl restart mosquitto",
        "time_estimate_minutes": 30,
        "difficulty": "Moderate",
        "source": "OWASP IoT Top 10"
    },
    {
        "attack_type": "mqtt_no_auth",
        "title": "MQTT Broker Allows Anonymous Access",
        "severity": "High",
        "explanation": "The MQTT broker accepts connections from any client without requiring a username or password. This means anyone who can reach the broker can subscribe to all topics and publish any message — including commands to connected devices.",
        "fix_commands": "# In mosquitto.conf:\nallow_anonymous false\npassword_file /etc/mosquitto/passwd\n\n# Create user:\nsudo mosquitto_passwd -c /etc/mosquitto/passwd your_username\n\n# Restart:\nsudo systemctl restart mosquitto",
        "time_estimate_minutes": 10,
        "difficulty": "Quick Win",
        "source": "OWASP IoT Top 10"
    },
    {
        "attack_type": "open_ftp",
        "title": "FTP Service Open on Port 21",
        "severity": "High",
        "explanation": "FTP transmits files and credentials in plain text. Port 21 is one of the most commonly attacked ports on the internet. If FTP is needed for file transfers, it must be replaced with SFTP which encrypts the connection.",
        "fix_commands": "# Disable FTP:\nsudo systemctl stop vsftpd\nsudo systemctl disable vsftpd\n\n# Install SFTP instead (part of SSH):\nsudo apt install openssh-server -y\nsudo systemctl enable ssh",
        "time_estimate_minutes": 5,
        "difficulty": "Quick Win",
        "source": "NIST SP 800-213"
    },
    {
        "attack_type": "open_ssh_root",
        "title": "SSH Root Login Enabled",
        "severity": "High",
        "explanation": "SSH is configured to allow direct root login. This means an attacker who brute-forces the SSH password immediately has full system control. Root login should always be disabled — users should SSH as a normal user and then use sudo.",
        "fix_commands": "# Edit SSH config:\nsudo nano /etc/ssh/sshd_config\n\n# Change this line:\nPermitRootLogin no\n\n# Also add:\nMaxAuthTries 3\nPasswordAuthentication no\n\n# Restart SSH:\nsudo systemctl restart sshd",
        "time_estimate_minutes": 5,
        "difficulty": "Quick Win",
        "source": "CIS Benchmark"
    },
    {
        "attack_type": "http_no_https",
        "title": "Web Interface Running on HTTP Without HTTPS",
        "severity": "High",
        "explanation": "The device web interface transmits login credentials and configuration data without encryption. Any attacker performing a man-in-the-middle attack on the network can capture admin passwords and take control of the device.",
        "fix_commands": "# Generate self-signed certificate:\nopenssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes\n\n# For Nginx:\nserver {\n    listen 443 ssl;\n    ssl_certificate /path/to/cert.pem;\n    ssl_certificate_key /path/to/key.pem;\n}\n\n# Redirect HTTP to HTTPS:\nserver {\n    listen 80;\n    return 301 https://$host$request_uri;\n}",
        "time_estimate_minutes": 20,
        "difficulty": "Moderate",
        "source": "OWASP IoT Top 10"
    },
    {
        "attack_type": "open_vnc",
        "title": "VNC Remote Desktop Open Without Authentication",
        "severity": "Critical",
        "explanation": "VNC is running and accepting connections without requiring a password. This gives any attacker on the network full graphical control of the device — they can see the screen, move the mouse, and type as if they were sitting in front of it.",
        "fix_commands": "# Disable VNC if not needed:\nsudo systemctl stop vncserver\nsudo systemctl disable vncserver\n\n# If VNC is needed, set a strong password:\nvncpasswd\n\n# Restrict to localhost only and use SSH tunnel:\nvncserver -localhost yes",
        "time_estimate_minutes": 5,
        "difficulty": "Quick Win",
        "source": "NIST SP 800-213"
    },
    {
        "attack_type": "open_snmp",
        "title": "SNMP Running with Default Community String",
        "severity": "High",
        "explanation": "SNMP is configured with the default community string 'public' which is publicly known. This allows attackers to read all device configuration, network topology, and system information. SNMPv1 and v2c transmit this string in plain text.",
        "fix_commands": "# Disable SNMPv1 and v2c, use SNMPv3:\nsudo nano /etc/snmp/snmpd.conf\n\n# Remove: rocommunity public\n# Add SNMPv3 user:\ncreateUser myuser SHA mypassword AES myencryptkey\nrouser myuser\n\n# Restart:\nsudo systemctl restart snmpd",
        "time_estimate_minutes": 15,
        "difficulty": "Moderate",
        "source": "CIS Benchmark"
    },
    {
        "attack_type": "outdated_firmware",
        "title": "Device Running Outdated Firmware",
        "severity": "High",
        "explanation": "The device firmware has not been updated and contains known, publicly documented vulnerabilities. Attackers actively scan for devices running outdated firmware because exploits are already written and publicly available for these versions.",
        "fix_commands": "# Check current firmware version in device admin panel\n# Navigate to: Settings > Firmware > Check for Updates\n# Download latest firmware from manufacturer website\n# Backup device configuration before updating\n# Apply firmware update\n# Verify version number after update\n# Re-apply configuration if reset occurred",
        "time_estimate_minutes": 30,
        "difficulty": "Moderate",
        "source": "OWASP IoT Top 10"
    },
    {
        "attack_type": "weak_password_policy",
        "title": "No Password Policy Enforced",
        "severity": "Medium",
        "explanation": "The device or application does not enforce minimum password requirements. Users can set passwords like '1234' or 'password' which can be cracked in seconds. Without a password policy, brute force attacks are trivial.",
        "fix_commands": "# For Linux systems:\nsudo nano /etc/pam.d/common-password\n\n# Add:\npassword requisite pam_pwquality.so minlen=12 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1\n\n# Install pwquality if needed:\nsudo apt install libpam-pwquality -y",
        "time_estimate_minutes": 10,
        "difficulty": "Quick Win",
        "source": "NIST SP 800-63B"
    },
    {
        "attack_type": "no_account_lockout",
        "title": "No Account Lockout After Failed Logins",
        "severity": "Medium",
        "explanation": "The device allows unlimited login attempts without locking the account. This makes it completely vulnerable to brute force attacks where software automatically tries thousands of password combinations per second.",
        "fix_commands": "# For SSH using fail2ban:\nsudo apt install fail2ban -y\nsudo systemctl enable fail2ban\n\n# Configure:\nsudo nano /etc/fail2ban/jail.local\n[sshd]\nenabled = true\nmaxretry = 5\nbantime = 900\nfindtime = 600",
        "time_estimate_minutes": 10,
        "difficulty": "Quick Win",
        "source": "CIS Benchmark"
    },
    {
        "attack_type": "open_redis",
        "title": "Redis Database Exposed Without Authentication",
        "severity": "Critical",
        "explanation": "Redis is accessible on the network without a password. An attacker can read all cached data, write arbitrary data, and in many configurations execute system commands. Redis should never be exposed to the network without authentication.",
        "fix_commands": "# Bind Redis to localhost only:\nsudo nano /etc/redis/redis.conf\n\n# Change:\nbind 127.0.0.1\n\n# Set password:\nrequirepass your_strong_password_here\n\n# Disable dangerous commands:\nrename-command FLUSHALL \"\"\nrename-command CONFIG \"\"\n\n# Restart:\nsudo systemctl restart redis",
        "time_estimate_minutes": 10,
        "difficulty": "Quick Win",
        "source": "OWASP Top 10"
    },
    {
        "attack_type": "coap_no_dtls",
        "title": "CoAP Running Without DTLS Encryption",
        "severity": "High",
        "explanation": "CoAP messages between IoT devices are transmitted without encryption. DTLS (Datagram Transport Layer Security) is the CoAP equivalent of TLS and must be enabled to prevent eavesdropping and message injection attacks.",
        "fix_commands": "# Generate DTLS certificates:\nopenssl ecparam -name prime256v1 -genkey -noout -out coap-key.pem\nopenssl req -new -x509 -key coap-key.pem -out coap-cert.pem -days 365\n\n# Configure your CoAP library to use DTLS\n# Refer to your specific CoAP implementation documentation\n# Common libraries: libcoap, aiocoap, californium",
        "time_estimate_minutes": 45,
        "difficulty": "Complex",
        "source": "RFC 7252"
    },
    {
        "attack_type": "open_database_port",
        "title": "Database Port Exposed to Network",
        "severity": "Critical",
        "explanation": "The database port is accessible from outside the device or server. Databases should never be directly accessible from the network — only the application running on the same machine should be able to connect. Direct database exposure allows credential attacks and data theft.",
        "fix_commands": "# Block database port with firewall:\nsudo ufw deny 5432\nsudo ufw deny 3306\nsudo ufw deny 27017\n\n# Bind database to localhost:\n# PostgreSQL - in postgresql.conf:\nlisten_addresses = 'localhost'\n\n# MySQL - in my.cnf:\nbind-address = 127.0.0.1",
        "time_estimate_minutes": 5,
        "difficulty": "Quick Win",
        "source": "CIS Benchmark"
    },
    {
        "attack_type": "ssl_expired_certificate",
        "title": "SSL Certificate Expired or Invalid",
        "severity": "High",
        "explanation": "The device is using an expired or self-signed SSL certificate. Users and connecting devices receive security warnings and may disable certificate validation entirely — which makes them vulnerable to man-in-the-middle attacks that an attacker can exploit.",
        "fix_commands": "# Install certbot for free Let's Encrypt certificate:\nsudo apt install certbot -y\nsudo certbot certonly --standalone -d yourdomain.com\n\n# Auto-renewal:\nsudo certbot renew --dry-run\n\n# Add to crontab for auto-renewal:\n0 0 1 * * certbot renew --quiet",
        "time_estimate_minutes": 15,
        "difficulty": "Moderate",
        "source": "OWASP IoT Top 10"
    },
    {
        "attack_type": "unnecessary_services",
        "title": "Unnecessary Network Services Running",
        "severity": "Medium",
        "explanation": "The device is running services that are not required for its function. Every running service is an attack surface. A smart camera does not need an FTP server. A temperature sensor does not need a web server. Unused services should always be disabled.",
        "fix_commands": "# List all running services:\nsudo systemctl list-units --type=service --state=running\n\n# Disable unnecessary service:\nsudo systemctl stop service-name\nsudo systemctl disable service-name\n\n# Check open ports:\nsudo ss -tlnp",
        "time_estimate_minutes": 20,
        "difficulty": "Moderate",
        "source": "CIS Benchmark"
    },
    {
        "attack_type": "no_firewall",
        "title": "No Firewall Configured",
        "severity": "High",
        "explanation": "The device has no firewall rules configured. All ports are accessible to anyone on the network. A firewall is the most basic network security control — it should only allow traffic on ports the device actually needs.",
        "fix_commands": "# Enable UFW firewall:\nsudo apt install ufw -y\nsudo ufw default deny incoming\nsudo ufw default allow outgoing\n\n# Allow only needed ports (example):\nsudo ufw allow 22/tcp\nsudo ufw allow 443/tcp\n\n# Enable:\nsudo ufw enable\nsudo ufw status verbose",
        "time_estimate_minutes": 10,
        "difficulty": "Quick Win",
        "source": "NIST SP 800-213"
    },
    {
        "attack_type": "insecure_api",
        "title": "API Endpoint Without Authentication",
        "severity": "High",
        "explanation": "One or more API endpoints accept requests without verifying who is making them. An attacker can call these endpoints directly to read data, trigger actions, or modify device configuration without any credentials.",
        "fix_commands": "# Implement JWT authentication on all endpoints\n# Example for Flask:\nfrom flask_jwt_extended import jwt_required\n\n@app.route('/api/data')\n@jwt_required()\ndef get_data():\n    pass\n\n# Ensure every route that returns data\n# or triggers actions requires authentication",
        "time_estimate_minutes": 60,
        "difficulty": "Complex",
        "source": "OWASP API Security Top 10"
    },
    {
        "attack_type": "hardcoded_credentials",
        "title": "Hardcoded Credentials Found in Firmware",
        "severity": "Critical",
        "explanation": "The device firmware contains hardcoded usernames and passwords embedded directly in the code. These cannot be changed by the user. Every device of this model ships with identical credentials — finding them once gives an attacker access to every device worldwide.",
        "fix_commands": "# This requires a firmware update from the manufacturer\n# Contact manufacturer immediately and report the vulnerability\n# Check manufacturer website for security patches\n# If no patch available, isolate device from network\n# Consider replacing device with one from a security-conscious vendor\n# Report to NCSC if critical infrastructure: https://www.ncsc.gov.uk",
        "time_estimate_minutes": 60,
        "difficulty": "Complex",
        "source": "OWASP IoT Top 10"
    },
    {
        "attack_type": "open_rsync",
        "title": "Rsync Service Exposed on Port 873",
        "severity": "High",
        "explanation": "Rsync is running and accessible from the network. Without proper access controls, attackers can use rsync to download all files from the device or upload malicious files. This has been exploited in several major data breaches.",
        "fix_commands": "# Disable rsync if not needed:\nsudo systemctl stop rsync\nsudo systemctl disable rsync\n\n# If needed, restrict access in /etc/rsyncd.conf:\nhosts allow = 192.168.1.0/24\nhosts deny = *\n\n# Or block with firewall:\nsudo ufw deny 873",
        "time_estimate_minutes": 5,
        "difficulty": "Quick Win",
        "source": "CIS Benchmark"
    },
    {
        "attack_type": "cleartext_storage",
        "title": "Sensitive Data Stored in Plaintext",
        "severity": "High",
        "explanation": "The device stores sensitive information such as passwords, API keys, or personal data in plaintext files. If an attacker gains any access to the filesystem, they immediately have all credentials and sensitive data without needing to crack anything.",
        "fix_commands": "# Encrypt sensitive config files:\ngpg --symmetric --cipher-algo AES256 config.txt\n\n# For passwords, always use hashing:\n# Python example:\nfrom bcrypt import hashpw, gensalt\nhashed = hashpw(password.encode(), gensalt())\n\n# Never store passwords in plaintext\n# Use environment variables for secrets:\nexport API_KEY=your_key\n# Access in code: os.environ.get('API_KEY')",
        "time_estimate_minutes": 60,
        "difficulty": "Complex",
        "source": "OWASP IoT Top 10"
    },
    {
        "attack_type": "no_update_mechanism",
        "title": "No Secure Update Mechanism Available",
        "severity": "Medium",
        "explanation": "The device has no way to receive security updates. Once a vulnerability is discovered, it cannot be patched remotely. This means the device will remain vulnerable forever unless physically replaced. This is a design flaw common in cheap IoT hardware.",
        "fix_commands": "# This requires manufacturer action for firmware updates\n# Short-term mitigations:\n# 1. Isolate device on a separate VLAN\nsudo ip link add link eth0 name eth0.10 type vlan id 10\n\n# 2. Block all inbound connections with firewall\nsudo ufw default deny incoming\n\n# 3. Monitor device traffic for anomalies\n# 4. Plan device replacement with a supported model",
        "time_estimate_minutes": 30,
        "difficulty": "Moderate",
        "source": "NIST SP 800-213"
    },
    {
        "attack_type": "open_upnp",
        "title": "UPnP Enabled and Exposed",
        "severity": "High",
        "explanation": "Universal Plug and Play is enabled on this device. UPnP automatically opens ports in your router without any authentication. Attackers have used UPnP to punch holes in firewalls, redirect traffic, and gain access to internal networks from the internet.",
        "fix_commands": "# Disable UPnP on the device:\n# Navigate to device admin panel\n# Settings > Network > UPnP > Disable\n\n# Also disable on your router:\n# Router admin panel > Advanced > UPnP > Disable\n\n# Verify no unexpected port mappings exist:\n# Router admin > Port Forwarding — remove unknown entries",
        "time_estimate_minutes": 5,
        "difficulty": "Quick Win",
        "source": "NIST SP 800-213"
    },
    {
        "attack_type": "open_nfs",
        "title": "NFS Network File System Exposed",
        "severity": "Critical",
        "explanation": "Network File System shares are accessible from the network, potentially without authentication. NFS was designed for trusted internal networks and has minimal security controls. Exposed NFS shares allow attackers to read and write files directly.",
        "fix_commands": "# Disable NFS if not needed:\nsudo systemctl stop nfs-server\nsudo systemctl disable nfs-server\n\n# If NFS is needed, restrict in /etc/exports:\n/data 192.168.1.0/24(ro,sync,no_root_squash)\n\n# Restart and verify:\nsudo exportfs -ra\nsudo showmount -e localhost",
        "time_estimate_minutes": 10,
        "difficulty": "Quick Win",
        "source": "CIS Benchmark"
    },
    {
        "attack_type": "debug_interface_exposed",
        "title": "Debug Interface Accessible on Network",
        "severity": "Critical",
        "explanation": "A debug or development interface is accessible on the network. Debug interfaces are designed for developers and typically bypass all authentication and security controls. They provide direct access to device internals and are never appropriate in production.",
        "fix_commands": "# Identify and disable the debug service:\nsudo systemctl stop debug-service\nsudo systemctl disable debug-service\n\n# Block the port:\nsudo ufw deny [debug-port]\n\n# Check for debug flags in application config\n# Ensure DEBUG=False in all production configs\n# Remove or comment out any debug endpoints in code",
        "time_estimate_minutes": 15,
        "difficulty": "Moderate",
        "source": "OWASP IoT Top 10"
    },
    {
        "attack_type": "no_logging",
        "title": "Security Event Logging Not Configured",
        "severity": "Medium",
        "explanation": "The device is not logging security events such as failed logins, configuration changes, or connection attempts. Without logs, there is no way to detect an attack in progress or investigate a breach after it occurs. Logging is essential for any device handling sensitive data.",
        "fix_commands": "# Enable system logging:\nsudo apt install rsyslog -y\nsudo systemctl enable rsyslog\n\n# Configure audit logging:\nsudo apt install auditd -y\nsudo systemctl enable auditd\n\n# Log failed logins:\nsudo auditctl -w /var/log/auth.log -p wa -k auth_log\n\n# View logs:\nsudo journalctl -f",
        "time_estimate_minutes": 15,
        "difficulty": "Moderate",
        "source": "NIST SP 800-92"
    },
    {
        "attack_type": "insecure_deserialization",
        "title": "Insecure Deserialization Vulnerability",
        "severity": "Critical",
        "explanation": "The device or application deserializes data from untrusted sources without validation. Insecure deserialization can allow attackers to execute arbitrary code, manipulate application logic, or perform denial of service attacks by sending specially crafted data.",
        "fix_commands": "# Never deserialize data from untrusted sources\n# Use safe formats instead of pickle/Java serialization:\n# Python - use JSON instead of pickle:\nimport json\ndata = json.loads(untrusted_input)  # Safe\n# NOT: pickle.loads(untrusted_input)  # Dangerous\n\n# Validate and sanitise all input before processing\n# Implement integrity checks on serialized data\n# Use allowlists for acceptable classes during deserialization",
        "time_estimate_minutes": 60,
        "difficulty": "Complex",
        "source": "OWASP Top 10"
    },
    {
        "attack_type": "open_memcached",
        "title": "Memcached Exposed on Port 11211",
        "severity": "Critical",
        "explanation": "Memcached is accessible from the network without authentication. This has been used in some of the largest DDoS amplification attacks in history, with attackers using exposed Memcached servers to amplify traffic by up to 51,000x. It also exposes all cached application data.",
        "fix_commands": "# Bind Memcached to localhost:\nsudo nano /etc/memcached.conf\n\n# Change:\n-l 127.0.0.1\n\n# Disable UDP (used in amplification attacks):\n-U 0\n\n# Restart:\nsudo systemctl restart memcached\n\n# Block with firewall:\nsudo ufw deny 11211",
        "time_estimate_minutes": 5,
        "difficulty": "Quick Win",
        "source": "NCSC Advisory"
    },
    {
        "attack_type": "privilege_escalation_risk",
        "title": "Excessive User Privileges Configured",
        "severity": "High",
        "explanation": "User accounts or processes are running with more privileges than required. Following the principle of least privilege, every user and process should have only the minimum permissions needed to perform its function. Excessive privileges mean a compromised account can cause maximum damage.",
        "fix_commands": "# Audit current sudo privileges:\nsudo cat /etc/sudoers\nsudo visudo\n\n# Check user groups:\ngroups username\n\n# Remove from unnecessary groups:\nsudo deluser username groupname\n\n# Run services as dedicated low-privilege users:\nsudo useradd -r -s /bin/false serviceuser\nsudo chown serviceuser:serviceuser /opt/service",
        "time_estimate_minutes": 20,
        "difficulty": "Moderate",
        "source": "CIS Benchmark"
    }
]


def seed():
    app = create_app()
    with app.app_context():
        existing = RemediationKB.query.count()
        if existing > 0:
            print(f"Knowledge base already has {existing} entries. Skipping seed.")
            print("To reseed, delete all rows first: DELETE FROM remediation_kb;")
            return

        count = 0
        for item in REMEDIATION_DATA:
            kb = RemediationKB(**item)
            db.session.add(kb)
            count += 1

        db.session.commit()
        print(f"Successfully seeded {count} remediation entries into the knowledge base.")


if __name__ == "__main__":
    seed()