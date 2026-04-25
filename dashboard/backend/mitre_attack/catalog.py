"""
AIPET X — MITRE ATT&CK Curated Catalog

A curated Python dict covering the ~50 techniques the project actually maps to.
Kept as code (not a DB seed file) so changes are reviewable in PRs.

Sources:
  - Techniques already referenced across ba_anomalies, siem_events, rt_attacks
  - Techniques derivable from ML feature mappings (failed_auth_rate → T1110, etc.)
  - Techniques derivable from common CWEs in CISA KEV catalog
  - ATT&CK descriptions are one-paragraph summaries from attack.mitre.org

To add a technique: add an entry to TECHNIQUE_CATALOG and extend any relevant
mapping dicts (ML_FEATURE_TO_TECHNIQUE, CWE_TO_TECHNIQUE, BEHAVIORAL_ANOMALY_TO_TECHNIQUE).
"""
from __future__ import annotations


TECHNIQUE_CATALOG: dict[str, dict] = {
    "T0817": {
        "technique_id": "T0817", "name": "Drive-by Compromise",
        "tactic": "Initial Access", "tactic_id": "TA0001",
        "description": "Adversaries may gain access to a system through a user visiting a website over the normal course of browsing. Common in ICS/OT contexts where engineering workstations browse vendor portals.",
        "url": "https://attack.mitre.org/techniques/T0817/",
        "platforms": ["Windows", "Linux"], "is_subtechnique": False, "parent_technique": None,
    },
    "T0831": {
        "technique_id": "T0831", "name": "Manipulation of Control",
        "tactic": "Impact", "tactic_id": "TA0105",
        "description": "Adversaries may manipulate physical process control, including setpoints, inputs, outputs, or other parameters, to cause damage or unsafe conditions in ICS environments.",
        "url": "https://attack.mitre.org/techniques/T0831/",
        "platforms": ["Control Server", "Field Controller"], "is_subtechnique": False, "parent_technique": None,
    },
    "T1021": {
        "technique_id": "T1021", "name": "Remote Services",
        "tactic": "Lateral Movement", "tactic_id": "TA0008",
        "description": "Adversaries may use valid accounts to log into a service specifically designed to accept remote connections, such as telnet, SSH, and VNC, then perform actions as the logged-on user.",
        "url": "https://attack.mitre.org/techniques/T1021/",
        "platforms": ["Linux", "Windows", "macOS"], "is_subtechnique": False, "parent_technique": None,
    },
    "T1021.001": {
        "technique_id": "T1021.001", "name": "Remote Services: Remote Desktop Protocol",
        "tactic": "Lateral Movement", "tactic_id": "TA0008",
        "description": "Adversaries may use Valid Accounts to log into a computer using the Remote Desktop Protocol. The adversary may then perform actions as the logged-on user.",
        "url": "https://attack.mitre.org/techniques/T1021/001/",
        "platforms": ["Windows"], "is_subtechnique": True, "parent_technique": "T1021",
    },
    "T1021.002": {
        "technique_id": "T1021.002", "name": "Remote Services: SMB/Windows Admin Shares",
        "tactic": "Lateral Movement", "tactic_id": "TA0008",
        "description": "Adversaries may use Valid Accounts to interact with a remote network share using Server Message Block (SMB) to move laterally.",
        "url": "https://attack.mitre.org/techniques/T1021/002/",
        "platforms": ["Windows"], "is_subtechnique": True, "parent_technique": "T1021",
    },
    "T1021.004": {
        "technique_id": "T1021.004", "name": "Remote Services: SSH",
        "tactic": "Lateral Movement", "tactic_id": "TA0008",
        "description": "Adversaries may use Valid Accounts to log into remote machines using Secure Shell (SSH). SSH is typically used to access and manage remote systems.",
        "url": "https://attack.mitre.org/techniques/T1021/004/",
        "platforms": ["Linux", "macOS", "Network"], "is_subtechnique": True, "parent_technique": "T1021",
    },
    "T1040": {
        "technique_id": "T1040", "name": "Network Sniffing",
        "tactic": "Credential Access", "tactic_id": "TA0006",
        "description": "Adversaries may sniff network traffic to capture information about an environment. Data captured via this technique may include authentication material passed over insecure protocols.",
        "url": "https://attack.mitre.org/techniques/T1040/",
        "platforms": ["Linux", "Windows", "macOS", "Network"], "is_subtechnique": False, "parent_technique": None,
    },
    "T1041": {
        "technique_id": "T1041", "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration", "tactic_id": "TA0010",
        "description": "Adversaries may steal data by exfiltrating it over an existing command and control channel. Stolen data is encoded into the normal communications channel using the same protocol as command and control communications.",
        "url": "https://attack.mitre.org/techniques/T1041/",
        "platforms": ["Linux", "Windows", "macOS"], "is_subtechnique": False, "parent_technique": None,
    },
    "T1046": {
        "technique_id": "T1046", "name": "Network Service Discovery",
        "tactic": "Discovery", "tactic_id": "TA0007",
        "description": "Adversaries may attempt to get a listing of services running on remote hosts and local network infrastructure devices, including those that may be vulnerable to remote exploitation.",
        "url": "https://attack.mitre.org/techniques/T1046/",
        "platforms": ["Linux", "Windows", "macOS", "Network"], "is_subtechnique": False, "parent_technique": None,
    },
    "T1048": {
        "technique_id": "T1048", "name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration", "tactic_id": "TA0010",
        "description": "Adversaries may steal data by exfiltrating it over a different protocol than that used for command and control. Data exfiltration may be performed with a different protocol to avoid detection.",
        "url": "https://attack.mitre.org/techniques/T1048/",
        "platforms": ["Linux", "Windows", "macOS"], "is_subtechnique": False, "parent_technique": None,
    },
    "T1059": {
        "technique_id": "T1059", "name": "Command and Scripting Interpreter",
        "tactic": "Execution", "tactic_id": "TA0002",
        "description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries. These interfaces allow complex operations to be performed and programs written.",
        "url": "https://attack.mitre.org/techniques/T1059/",
        "platforms": ["Linux", "Windows", "macOS", "Network"], "is_subtechnique": False, "parent_technique": None,
    },
    "T1071": {
        "technique_id": "T1071", "name": "Application Layer Protocol",
        "tactic": "Command and Control", "tactic_id": "TA0011",
        "description": "Adversaries may communicate using OSI application layer protocols to avoid detection by blending in with existing traffic. Commands to the remote system may be also embedded within the protocol traffic between the client and server.",
        "url": "https://attack.mitre.org/techniques/T1071/",
        "platforms": ["Linux", "Windows", "macOS", "Network"], "is_subtechnique": False, "parent_technique": None,
    },
    "T1071.001": {
        "technique_id": "T1071.001", "name": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control", "tactic_id": "TA0011",
        "description": "Adversaries may communicate using application layer protocols associated with web traffic to avoid detection and network filtering. Commands to the remote system may be embedded in the protocol traffic.",
        "url": "https://attack.mitre.org/techniques/T1071/001/",
        "platforms": ["Linux", "Windows", "macOS"], "is_subtechnique": True, "parent_technique": "T1071",
    },
    "T1078": {
        "technique_id": "T1078", "name": "Valid Accounts",
        "tactic": "Initial Access", "tactic_id": "TA0001",
        "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.",
        "url": "https://attack.mitre.org/techniques/T1078/",
        "platforms": ["Linux", "Windows", "macOS", "SaaS", "IaaS", "Cloud"], "is_subtechnique": False, "parent_technique": None,
    },
    "T1078.001": {
        "technique_id": "T1078.001", "name": "Valid Accounts: Default Accounts",
        "tactic": "Initial Access", "tactic_id": "TA0001",
        "description": "Adversaries may obtain and abuse credentials of a default account as a means of gaining Initial Access. Default accounts include those built-into an OS or network device.",
        "url": "https://attack.mitre.org/techniques/T1078/001/",
        "platforms": ["Linux", "Windows", "macOS", "Network"], "is_subtechnique": True, "parent_technique": "T1078",
    },
    "T1082": {
        "technique_id": "T1082", "name": "System Information Discovery",
        "tactic": "Discovery", "tactic_id": "TA0007",
        "description": "An adversary may attempt to get detailed information about the operating system and hardware, including version, patches, hotfixes, service packs, and architecture.",
        "url": "https://attack.mitre.org/techniques/T1082/",
        "platforms": ["Linux", "Windows", "macOS", "Network"], "is_subtechnique": False, "parent_technique": None,
    },
    "T1083": {
        "technique_id": "T1083", "name": "File and Directory Discovery",
        "tactic": "Discovery", "tactic_id": "TA0007",
        "description": "Adversaries may enumerate files and directories or may search in specific locations of a host or network share for certain information within a file system.",
        "url": "https://attack.mitre.org/techniques/T1083/",
        "platforms": ["Linux", "Windows", "macOS"], "is_subtechnique": False, "parent_technique": None,
    },
    "T1090": {
        "technique_id": "T1090", "name": "Proxy",
        "tactic": "Command and Control", "tactic_id": "TA0011",
        "description": "Adversaries may use a connection proxy to direct network traffic between systems or act as an intermediary for network communications to a C2 server to avoid direct connections.",
        "url": "https://attack.mitre.org/techniques/T1090/",
        "platforms": ["Linux", "Windows", "macOS", "Network"], "is_subtechnique": False, "parent_technique": None,
    },
    "T1110": {
        "technique_id": "T1110", "name": "Brute Force",
        "tactic": "Credential Access", "tactic_id": "TA0006",
        "description": "Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained. Without knowledge of the password for an account, an adversary may opt to guess.",
        "url": "https://attack.mitre.org/techniques/T1110/",
        "platforms": ["Linux", "Windows", "macOS", "SaaS", "IaaS", "Cloud"], "is_subtechnique": False, "parent_technique": None,
    },
    "T1110.001": {
        "technique_id": "T1110.001", "name": "Brute Force: Password Guessing",
        "tactic": "Credential Access", "tactic_id": "TA0006",
        "description": "Adversaries with no prior knowledge of legitimate credentials within the system or environment may guess passwords to attempt access to accounts.",
        "url": "https://attack.mitre.org/techniques/T1110/001/",
        "platforms": ["Linux", "Windows", "macOS", "Cloud"], "is_subtechnique": True, "parent_technique": "T1110",
    },
    "T1132": {
        "technique_id": "T1132", "name": "Data Encoding",
        "tactic": "Command and Control", "tactic_id": "TA0011",
        "description": "Adversaries may encode data to make the content of command and control traffic more difficult to detect. Command and control may also be performed over binary protocols.",
        "url": "https://attack.mitre.org/techniques/T1132/",
        "platforms": ["Linux", "Windows", "macOS"], "is_subtechnique": False, "parent_technique": None,
    },
    "T1133": {
        "technique_id": "T1133", "name": "External Remote Services",
        "tactic": "Initial Access", "tactic_id": "TA0001",
        "description": "Adversaries may leverage external-facing remote services to initially access and persist within a network. Remote services such as VPNs, Citrix, and other access mechanisms allow users to connect to internal resources.",
        "url": "https://attack.mitre.org/techniques/T1133/",
        "platforms": ["Linux", "Windows", "macOS"], "is_subtechnique": False, "parent_technique": None,
    },
    "T1136": {
        "technique_id": "T1136", "name": "Create Account",
        "tactic": "Persistence", "tactic_id": "TA0003",
        "description": "Adversaries may create an account to maintain access to victim systems. With a sufficient level of access, accounts may be created on the local system or within a domain/cloud tenant.",
        "url": "https://attack.mitre.org/techniques/T1136/",
        "platforms": ["Linux", "Windows", "macOS", "SaaS", "IaaS", "Cloud"], "is_subtechnique": False, "parent_technique": None,
    },
    "T1185": {
        "technique_id": "T1185", "name": "Browser Session Hijacking",
        "tactic": "Collection", "tactic_id": "TA0009",
        "description": "Adversaries may take advantage of security vulnerabilities and improper security practices that result in a diminished or non-existent security posture, ultimately allowing an adversary to steal application session cookies.",
        "url": "https://attack.mitre.org/techniques/T1185/",
        "platforms": ["Windows", "macOS", "Linux"], "is_subtechnique": False, "parent_technique": None,
    },
    "T1190": {
        "technique_id": "T1190", "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access", "tactic_id": "TA0001",
        "description": "Adversaries may attempt to take advantage of a weakness in an Internet-facing computer or program using software, data, or commands in order to cause unintended behavior.",
        "url": "https://attack.mitre.org/techniques/T1190/",
        "platforms": ["Linux", "Windows", "macOS", "Network", "Containers"], "is_subtechnique": False, "parent_technique": None,
    },
    "T1195.003": {
        "technique_id": "T1195.003", "name": "Supply Chain Compromise: Compromise Hardware Supply Chain",
        "tactic": "Initial Access", "tactic_id": "TA0001",
        "description": "Adversaries may manipulate hardware components in products prior to receipt by a final consumer for the purpose of data or system compromise.",
        "url": "https://attack.mitre.org/techniques/T1195/003/",
        "platforms": ["Linux", "Windows", "macOS"], "is_subtechnique": True, "parent_technique": "T1195",
    },
    "T1203": {
        "technique_id": "T1203", "name": "Exploitation for Client Execution",
        "tactic": "Execution", "tactic_id": "TA0002",
        "description": "Adversaries may exploit software vulnerabilities in client applications to execute code. Vulnerabilities can exist in software due to insecure coding practices that can lead to unanticipated behavior.",
        "url": "https://attack.mitre.org/techniques/T1203/",
        "platforms": ["Linux", "Windows", "macOS"], "is_subtechnique": False, "parent_technique": None,
    },
    "T1204": {
        "technique_id": "T1204", "name": "User Execution",
        "tactic": "Execution", "tactic_id": "TA0002",
        "description": "An adversary may rely upon specific actions by a user in order to gain execution. Users may be subjected to social engineering to get them to execute malicious code by opening a malicious document or file.",
        "url": "https://attack.mitre.org/techniques/T1204/",
        "platforms": ["Linux", "Windows", "macOS", "IaaS"], "is_subtechnique": False, "parent_technique": None,
    },
    "T1210": {
        "technique_id": "T1210", "name": "Exploitation of Remote Services",
        "tactic": "Lateral Movement", "tactic_id": "TA0008",
        "description": "Adversaries may exploit remote services to gain unauthorized access to internal systems once inside of a network. Adversaries may use this technique in conjunction with administrator accounts.",
        "url": "https://attack.mitre.org/techniques/T1210/",
        "platforms": ["Linux", "Windows", "macOS"], "is_subtechnique": False, "parent_technique": None,
    },
    "T1486": {
        "technique_id": "T1486", "name": "Data Encrypted for Impact",
        "tactic": "Impact", "tactic_id": "TA0040",
        "description": "Adversaries may encrypt data on target systems or on large numbers of systems in a network to interrupt availability to system and network resources. This is typically done by deploying ransomware.",
        "url": "https://attack.mitre.org/techniques/T1486/",
        "platforms": ["Linux", "Windows", "macOS", "IaaS"], "is_subtechnique": False, "parent_technique": None,
    },
    "T1489": {
        "technique_id": "T1489", "name": "Service Stop",
        "tactic": "Impact", "tactic_id": "TA0040",
        "description": "Adversaries may stop or disable services on a system to render those services unavailable to legitimate users. Stopping critical services or processes can inhibit or stop response to an incident.",
        "url": "https://attack.mitre.org/techniques/T1489/",
        "platforms": ["Linux", "Windows", "macOS"], "is_subtechnique": False, "parent_technique": None,
    },
    "T1499": {
        "technique_id": "T1499", "name": "Endpoint Denial of Service",
        "tactic": "Impact", "tactic_id": "TA0040",
        "description": "Adversaries may perform Endpoint Denial of Service (DoS) attacks to degrade or block the availability of services to users. DoS attacks can target specific services or the system itself.",
        "url": "https://attack.mitre.org/techniques/T1499/",
        "platforms": ["Linux", "Windows", "macOS"], "is_subtechnique": False, "parent_technique": None,
    },
    "T1505": {
        "technique_id": "T1505", "name": "Server Software Component",
        "tactic": "Persistence", "tactic_id": "TA0003",
        "description": "Adversaries may abuse legitimate extensible development features of servers to establish persistent access to systems. Enterprise servers often host features that allow developers to write and install software.",
        "url": "https://attack.mitre.org/techniques/T1505/",
        "platforms": ["Linux", "Windows", "macOS", "Network"], "is_subtechnique": False, "parent_technique": None,
    },
    "T1530": {
        "technique_id": "T1530", "name": "Data from Cloud Storage",
        "tactic": "Collection", "tactic_id": "TA0009",
        "description": "Adversaries may access data objects from improperly secured cloud storage. Many cloud service providers offer solutions for online data object storage such as Amazon S3, Azure Storage, and Google Cloud Storage.",
        "url": "https://attack.mitre.org/techniques/T1530/",
        "platforms": ["IaaS", "SaaS"], "is_subtechnique": False, "parent_technique": None,
    },
    "T1548": {
        "technique_id": "T1548", "name": "Abuse Elevation Control Mechanism",
        "tactic": "Privilege Escalation", "tactic_id": "TA0004",
        "description": "Adversaries may circumvent mechanisms designed to control elevate privileges to gain higher-level permissions, such as abusing sudo, SUID/SGID bits, and other elevation control mechanisms.",
        "url": "https://attack.mitre.org/techniques/T1548/",
        "platforms": ["Linux", "Windows", "macOS"], "is_subtechnique": False, "parent_technique": None,
    },
    "T1550": {
        "technique_id": "T1550", "name": "Use Alternate Authentication Material",
        "tactic": "Lateral Movement", "tactic_id": "TA0008",
        "description": "Adversaries may use alternate authentication material, such as password hashes, Kerberos tickets, and application access tokens, in order to move laterally within an environment.",
        "url": "https://attack.mitre.org/techniques/T1550/",
        "platforms": ["Windows", "SaaS", "Office 365"], "is_subtechnique": False, "parent_technique": None,
    },
    "T1557": {
        "technique_id": "T1557", "name": "Adversary-in-the-Middle",
        "tactic": "Credential Access", "tactic_id": "TA0006",
        "description": "Adversaries may attempt to position themselves between two or more networked devices using adversary-in-the-middle techniques to support follow-on behaviors such as Network Sniffing.",
        "url": "https://attack.mitre.org/techniques/T1557/",
        "platforms": ["Linux", "Windows", "macOS", "Network"], "is_subtechnique": False, "parent_technique": None,
    },
    "T1558": {
        "technique_id": "T1558", "name": "Steal or Forge Kerberos Tickets",
        "tactic": "Credential Access", "tactic_id": "TA0006",
        "description": "Adversaries may attempt to subvert Kerberos authentication by stealing or forging Kerberos tickets to enable Pass the Ticket. Kerberos is an authentication protocol widely used in modern Windows domain environments.",
        "url": "https://attack.mitre.org/techniques/T1558/",
        "platforms": ["Windows"], "is_subtechnique": False, "parent_technique": None,
    },
    "T1565": {
        "technique_id": "T1565", "name": "Data Manipulation",
        "tactic": "Impact", "tactic_id": "TA0040",
        "description": "Adversaries may insert, delete, or manipulate data in order to influence external outcomes or hide activity. The type of modification and the impact it will have depends on the target application and process.",
        "url": "https://attack.mitre.org/techniques/T1565/",
        "platforms": ["Linux", "Windows", "macOS"], "is_subtechnique": False, "parent_technique": None,
    },
    "T1566": {
        "technique_id": "T1566", "name": "Phishing",
        "tactic": "Initial Access", "tactic_id": "TA0001",
        "description": "Adversaries may send phishing messages to gain access to victim systems. All forms of phishing are electronically delivered social engineering. Phishing can be targeted, known as spearphishing.",
        "url": "https://attack.mitre.org/techniques/T1566/",
        "platforms": ["Linux", "Windows", "macOS", "SaaS"], "is_subtechnique": False, "parent_technique": None,
    },
}

# ── CWE → ATT&CK Technique mapping ──────────────────────────────────────────
# Covers the 30 most common CWEs found in CISA KEV entries.
# Confidence: high = direct causal link; medium = plausible but CWE is broad;
#             low = speculative / CWE is very generic.

CWE_TO_TECHNIQUE: dict[str, tuple[str, str]] = {
    # (technique_id, confidence)
    "CWE-22":  ("T1083", "medium"),   # Path Traversal → File Discovery
    "CWE-77":  ("T1059", "high"),     # Command Injection → Command Interpreter
    "CWE-78":  ("T1059", "high"),     # OS Command Injection → Command Interpreter
    "CWE-79":  ("T1071", "medium"),   # XSS → Application Layer Protocol (JS delivery)
    "CWE-89":  ("T1190", "high"),     # SQL Injection → Exploit Public-Facing App
    "CWE-94":  ("T1059", "high"),     # Code Injection → Command Interpreter
    "CWE-120": ("T1499", "medium"),   # Buffer Overflow → DoS
    "CWE-121": ("T1499", "medium"),   # Stack Overflow → DoS / RCE
    "CWE-125": ("T1082", "medium"),   # Out-of-bounds Read → System Info Discovery
    "CWE-190": ("T1499", "medium"),   # Integer Overflow → DoS
    "CWE-200": ("T1082", "medium"),   # Info Exposure → System Info Discovery
    "CWE-269": ("T1548", "high"),     # Improper Privilege Management → Priv Esc
    "CWE-287": ("T1078", "high"),     # Auth Bypass → Valid Accounts
    "CWE-295": ("T1557", "medium"),   # Cert Validation → Adversary-in-the-Middle
    "CWE-306": ("T1078", "high"),     # Missing Auth → Valid Accounts
    "CWE-307": ("T1110", "high"),     # Auth Attempt Restriction → Brute Force
    "CWE-327": ("T1040", "medium"),   # Weak Crypto → Network Sniffing
    "CWE-352": ("T1185", "medium"),   # CSRF → Browser Session Hijacking
    "CWE-362": ("T1499", "low"),      # Race Condition → DoS
    "CWE-400": ("T1499", "medium"),   # Resource Exhaustion → DoS
    "CWE-416": ("T1499", "medium"),   # Use After Free → DoS / RCE
    "CWE-434": ("T1190", "high"),     # Unrestricted Upload → Exploit Public-Facing App
    "CWE-476": ("T1499", "low"),      # NULL Deref → DoS
    "CWE-502": ("T1059", "high"),     # Deserialization → Command Interpreter
    "CWE-601": ("T1566", "medium"),   # URL Redirect → Phishing
    "CWE-611": ("T1190", "high"),     # XXE → Exploit Public-Facing App
    "CWE-732": ("T1548", "medium"),   # Incorrect Permission Assignment → Priv Esc
    "CWE-787": ("T1499", "medium"),   # Out-of-bounds Write → DoS / RCE
    "CWE-862": ("T1078", "high"),     # Missing Authorization → Valid Accounts
    "CWE-863": ("T1548", "high"),     # Incorrect Authorization → Priv Esc
}

# ── ML anomaly SHAP feature → ATT&CK Technique mapping ───────────────────────
# Maps FEATURE_ORDER feature names to (technique_id, confidence).
# Only the "increases_anomaly" direction is meaningful for technique mapping.

ML_FEATURE_TO_TECHNIQUE: dict[str, tuple[str, str]] = {
    "failed_auth_rate":  ("T1110", "high"),    # Brute Force
    "rst_ratio":         ("T1046", "medium"),  # Network Service Discovery (port scan)
    "cve_count":         ("T1190", "high"),    # Exploit Public-Facing Application
    "packet_rate":       ("T1046", "medium"),  # Network Service Discovery
    "byte_rate":         ("T1041", "medium"),  # Exfiltration Over C2 Channel
    "unique_dst_ips":    ("T1046", "high"),    # Network Service Discovery
    "unique_dst_ports":  ("T1046", "high"),    # Network Service Discovery
    "night_activity":    ("T1078", "medium"),  # Valid Accounts (off-hours access)
    "syn_ratio":         ("T1046", "high"),    # Network Service Discovery
    "open_port_count":   ("T1190", "medium"),  # Exploit Public-Facing Application
    "outbound_ratio":    ("T1041", "low"),     # Exfiltration Over C2 Channel
    "protocol_entropy":  ("T1071", "low"),     # Application Layer Protocol
}

# ── Behavioral anomaly_type → ATT&CK Technique mapping ───────────────────────
# Extracted from ANOMALY_TYPES dict in behavioral/routes.py.

BEHAVIORAL_ANOMALY_TO_TECHNIQUE: dict[str, tuple[str, str]] = {
    "traffic_spike":        ("T1071", "medium"),  # Application Layer Protocol
    "new_connection":       ("T1071", "medium"),  # Application Layer Protocol
    "unusual_hours":        ("T1078", "medium"),  # Valid Accounts
    "geo_anomaly":          ("T1078", "high"),    # Valid Accounts (geo = strong signal)
    "protocol_change":      ("T1040", "medium"),  # Network Sniffing
    "data_exfil":           ("T1041", "high"),    # Exfiltration Over C2 Channel
    "lateral_movement":     ("T1021", "high"),    # Remote Services
    "privilege_escalation": ("T1548", "high"),    # Abuse Elevation Control
    "beacon":               ("T1071", "high"),    # Application Layer Protocol (C2)
    "dormant_activation":   ("T1078", "medium"),  # Valid Accounts
}

# ── OTX indicator type → ATT&CK fallback mapping ─────────────────────────────
# No per-pulse technique data in OTX cache; use indicator-type heuristics.

OTX_INDICATOR_TO_TECHNIQUE: dict[str, tuple[str, str]] = {
    "ip":     ("T1071", "low"),   # Application Layer Protocol (C2 comms)
    "domain": ("T1071", "low"),   # Application Layer Protocol (C2 comms)
    "url":    ("T1071", "low"),   # Application Layer Protocol (C2 comms)
    "hash":   ("T1204", "low"),   # User Execution (malicious file)
}

# OTX tag → technique override (wins over indicator-type heuristic)
OTX_TAG_TO_TECHNIQUE: dict[str, tuple[str, str]] = {
    "ransomware": ("T1486", "medium"),  # Data Encrypted for Impact
    "c2":         ("T1071", "medium"),  # Application Layer Protocol
    "botnet":     ("T1071", "medium"),  # Application Layer Protocol
    "phishing":   ("T1566", "medium"),  # Phishing
    "apt":        ("T1566", "low"),     # Phishing (broad APT proxy)
    "malware":    ("T1204", "medium"),  # User Execution
    "trojan":     ("T1204", "medium"),  # User Execution
    "exploit":    ("T1190", "medium"),  # Exploit Public-Facing Application
    "backdoor":   ("T1505", "medium"),  # Server Software Component
}
