# =============================================================
# AIPET — AI-Powered Penetration Testing Framework for IoT
# Module 5: Firmware Analyser
# Author: Binyam
# Institution: Coventry University — MSc Cyber Security
#              (Ethical Hacking)
# Date: March 2025
# Licence: MIT
# Description: Analyses IoT firmware for hardcoded credentials,
#              private keys, dangerous configurations, outdated
#              components, and security misconfigurations.
#              Uses binwalk v2.4.3 via subprocess for extraction
#              and Python's os/re modules for deep analysis.
# =============================================================

import os
import re
import json
import subprocess
import hashlib
from datetime import datetime

# ── Patterns: Hardcoded Credentials ───────────────────────────
# Regular expressions that match common credential patterns
# found hardcoded in IoT firmware files.
# Each pattern is a tuple of (name, regex, severity)
CREDENTIAL_PATTERNS = [
    (
        "Hardcoded Password",
        # Matches: password=value, passwd=value, pwd=value
        r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']?([^\s"\']{4,})',
        "CRITICAL"
    ),
    (
        "Hardcoded Username",
        # Matches: username=value, user=value, login=value
        r'(?i)(username|user|login)\s*[=:]\s*["\']?([^\s"\']{3,})',
        "HIGH"
    ),
    (
        "Hardcoded API Key",
        # Matches: api_key=value, apikey=value, token=value
        r'(?i)(api_key|apikey|api-key|token|secret_key)\s*[=:]\s*["\']?([^\s"\']{8,})',
        "CRITICAL"
    ),
    (
        "AWS Access Key",
        # AWS access keys always start with AKIA
        r'AKIA[0-9A-Z]{16}',
        "CRITICAL"
    ),
    (
        "AWS Secret Key",
        # AWS secret keys are 40-char base64 strings
        r'(?i)(aws_secret|secret_key)\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})',
        "CRITICAL"
    ),
    (
        "WiFi Password",
        # Matches WiFi credential patterns
        r'(?i)(wifi_pass|wpa_pass|wireless_key)\s*[=:]\s*["\']?([^\s"\']{8,})',
        "HIGH"
    ),
    (
        "MQTT Credentials",
        # Matches MQTT username/password patterns
        r'(?i)(mqtt_pass|mqtt_user|mqtt_username)\s*[=:]\s*["\']?([^\s"\']{4,})',
        "HIGH"
    ),
]

# ── Patterns: Private Keys and Certificates ───────────────────
# Strings that indicate cryptographic material is present.
# Finding a private key in firmware means every device
# shipped with that firmware uses the same key — catastrophic.
KEY_PATTERNS = [
    (
        "RSA Private Key",
        r'-----BEGIN RSA PRIVATE KEY-----',
        "CRITICAL"
    ),
    (
        "EC Private Key",
        r'-----BEGIN EC PRIVATE KEY-----',
        "CRITICAL"
    ),
    (
        "Private Key (Generic)",
        r'-----BEGIN PRIVATE KEY-----',
        "CRITICAL"
    ),
    (
        "Certificate",
        r'-----BEGIN CERTIFICATE-----',
        "MEDIUM"
    ),
    (
        "SSH Private Key",
        r'-----BEGIN OPENSSH PRIVATE KEY-----',
        "CRITICAL"
    ),
]

# ── Patterns: Dangerous Configurations ───────────────────────
# Strings indicating security-reducing configurations.
# These suggest the device has dangerous features enabled.
DANGEROUS_CONFIG_PATTERNS = [
    (
        "Telnet Enabled",
        # Telnet sends all data including passwords in plaintext
        r'(?i)(telnet_enabled|enable_telnet)\s*[=:]\s*(true|1|yes|on)',
        "CRITICAL"
    ),
    (
        "Debug Mode Enabled",
        # Debug mode often exposes sensitive information
        r'(?i)(debug_mode|debug_enabled)\s*[=:]\s*(true|1|yes|on)',
        "HIGH"
    ),
    (
        "Default Credentials Flag",
        # Explicit flag indicating default creds are in use
        r'(?i)(use_default|default_creds|factory_default)\s*[=:]\s*(true|1|yes)',
        "CRITICAL"
    ),
    (
        "Hardcoded IP Address",
        # Hardcoded IPs suggest infrastructure exposure
        r'\b(?:192\.168|10\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[01]\.)\d+\.\d+\b',
        "MEDIUM"
    ),
    (
        "Unencrypted Protocol",
        # References to plaintext protocols
        r'(?i)(ftp://|telnet://|http://(?!localhost))',
        "MEDIUM"
    ),
]

# ── Patterns: Outdated/Vulnerable Components ──────────────────
# Version strings for known vulnerable software versions.
# These map to real CVEs in the NVD database.
VULNERABLE_COMPONENT_PATTERNS = [
    (
        "OpenSSL 1.0.x (Heartbleed vulnerable)",
        # OpenSSL 1.0.1 versions are vulnerable to Heartbleed
        r'OpenSSL\s+1\.0\.[01][a-z]?',
        "CRITICAL"
    ),
    (
        "OpenSSH < 7.4 (Multiple CVEs)",
        # Older OpenSSH versions have known vulnerabilities
        r'OpenSSH[_\s]+[1-6]\.\d|OpenSSH[_\s]+7\.[0-3]',
        "HIGH"
    ),
    (
        "BusyBox (Check version for CVEs)",
        # BusyBox is common in IoT — version matters
        r'BusyBox\s+v?[0-9]+\.[0-9]+',
        "MEDIUM"
    ),
    (
        "Outdated Linux Kernel",
        # Old kernel versions have many known exploits
        r'Linux\s+[1-3]\.\d+\.\d+',
        "HIGH"
    ),
    (
        "Vulnerable uClibc",
        # uClibc is used in embedded Linux — has DNS CVEs
        r'uClibc[- ]?[0-9]+\.[0-9]+',
        "MEDIUM"
    ),
    (
        "Boa Web Server (Abandoned)",
        # Boa is abandoned and has unpatched vulnerabilities
        r'Boa[/\s]+0\.[0-9]+',
        "HIGH"
    ),
]

# ── Sensitive File Paths ──────────────────────────────────────
# File paths that should never exist in production firmware.
# Finding these indicates the manufacturer left sensitive
# material in the shipping firmware image.
SENSITIVE_FILE_PATHS = [
    ("/etc/passwd",          "System password file",      "HIGH"),
    ("/etc/shadow",          "Hashed password file",      "CRITICAL"),
    ("/etc/config.conf",     "Device configuration",      "HIGH"),
    ("/etc/wpa_supplicant",  "WiFi credentials",          "HIGH"),
    ("/etc/ssl/private",     "SSL private keys",          "CRITICAL"),
    ("/root/.ssh",           "SSH keys",                  "CRITICAL"),
    ("/tmp/debug",           "Debug output",              "MEDIUM"),
    (".git",                 "Git repository (dev files)","MEDIUM"),
    ("id_rsa",               "RSA private key file",      "CRITICAL"),
    ("server.key",           "SSL server key",            "CRITICAL"),
    ("private.pem",          "PEM private key",           "CRITICAL"),
]


# ── Helper: Calculate file hash ───────────────────────────────
def calculate_hash(filepath):
    """
    Calculate SHA256 hash of a file for integrity verification.
    Used to identify known firmware versions against CVE databases.

    Args:
        filepath (str): Path to the file

    Returns:
        str: SHA256 hex digest or error message
    """
    try:
        # Read file in chunks to handle large firmware files
        sha256 = hashlib.sha256()
        with open(filepath, 'rb') as f:
            # Read 64KB chunks — efficient for large binaries
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        return f"Error: {str(e)}"


# ── Helper: Search file for patterns ─────────────────────────
def search_file(filepath, patterns):
    """
    Search a single file for a list of regex patterns.
    Handles both text and binary files gracefully.

    Args:
        filepath (str): Path to file to search
        patterns (list): List of (name, regex, severity) tuples

    Returns:
        list: Found matches as dictionaries
    """
    findings = []

    try:
        # Read file as text — ignore bytes that cannot be decoded
        with open(filepath, 'r',
                  encoding='utf-8',
                  errors='ignore') as f:
            content = f.read()

        # Search for each pattern
        for pattern_name, regex, severity in patterns:
            matches = re.findall(regex, content)

            if matches:
                # Convert match groups to strings
                match_strings = []
                for match in matches:
                    if isinstance(match, tuple):
                        # Regex group match — join non-empty groups
                        match_str = ': '.join(
                            m for m in match if m
                        )
                    else:
                        match_str = str(match)
                    match_strings.append(match_str)

                findings.append({
                    "file":     filepath,
                    "pattern":  pattern_name,
                    "severity": severity,
                    "matches":  match_strings[:5],  # Max 5 examples
                    "count":    len(matches)
                })

    except PermissionError:
        # Cannot read file — note it but continue
        pass
    except Exception:
        pass

    return findings


# ── Analysis 1: Binwalk Scan ──────────────────────────────────
def run_binwalk_scan(firmware_path):
    """
    Analysis 1: Run binwalk against a firmware file or directory.
    Binwalk identifies embedded file systems, compression types,
    encryption, and known file signatures within firmware.

    We call binwalk as a system subprocess because binwalk 2.4.3
    is most reliably used via command line rather than Python API.

    Args:
        firmware_path (str): Path to firmware file or directory

    Returns:
        dict: Binwalk scan results
    """
    print(f"\n[*] Analysis 1: Running binwalk scan on "
          f"{firmware_path}")

    result = {
        "analysis":      "Binwalk Scan",
        "target":        firmware_path,
        "signatures":    [],
        "finding":       "",
        "severity":      ""
    }

    try:
        # Check if target is a file or directory
        if os.path.isdir(firmware_path):
            # For directories, scan all binary files
            binary_files = []
            for root, dirs, files in os.walk(firmware_path):
                for filename in files:
                    filepath = os.path.join(root, filename)
                    # Only scan files that look like binaries
                    if any(filename.endswith(ext)
                           for ext in ['.bin', '.img',
                                       '.fw', '.rom']):
                        binary_files.append(filepath)

            if not binary_files:
                result["finding"]  = (
                    "No binary firmware files found in directory"
                )
                result["severity"] = "INFO"
                print("[-] No binary files found to scan")
                return result

            # Scan first binary file found
            target_file = binary_files[0]
        else:
            target_file = firmware_path

        print(f"    [*] Scanning: {target_file}")

        # Run binwalk as subprocess
        # -B = scan for signatures
        # -q = quiet mode (less verbose output)
        proc = subprocess.run(
            ['binwalk', '-B', target_file],
            capture_output=True,
            text=True,
            timeout=60  # 60 second timeout for large files
        )

        output = proc.stdout

        if output:
            # Parse binwalk output line by line
            # Format: DECIMAL   HEX       DESCRIPTION
            lines = output.strip().split('\n')
            for line in lines:
                # Skip header lines
                if line.startswith('DECIMAL') or \
                   line.startswith('---') or \
                   not line.strip():
                    continue

                parts = line.split(None, 2)
                if len(parts) >= 3:
                    result["signatures"].append({
                        "offset":      parts[0],
                        "hex_offset":  parts[1],
                        "description": parts[2]
                    })
                    print(f"    [SIGNATURE] {parts[2][:60]}")

        if result["signatures"]:
            result["finding"] = (
                f"Found {len(result['signatures'])} embedded "
                f"signature(s) in firmware"
            )
            result["severity"] = "INFO"
            print(f"[+] Found {len(result['signatures'])} "
                  f"signature(s)")
        else:
            result["finding"]  = "No signatures found"
            result["severity"] = "INFO"
            print("[-] No signatures found")

    except subprocess.TimeoutExpired:
        result["finding"]  = "Binwalk scan timed out"
        result["severity"] = "INFO"
        print("[-] Binwalk scan timed out")
    except FileNotFoundError:
        result["finding"]  = (
            "Binwalk not found — install with: "
            "sudo apt install binwalk"
        )
        result["severity"] = "ERROR"
        print("[-] Binwalk not found")
    except Exception as e:
        result["finding"]  = f"Scan error: {str(e)}"
        result["severity"] = "ERROR"
        print(f"[-] Error: {e}")

    return result


# ── Analysis 2: Credential Hunt ───────────────────────────────
def hunt_credentials(firmware_path):
    """
    Analysis 2: Search entire firmware for hardcoded credentials.

    Recursively walks all files in the firmware directory and
    applies credential regex patterns to find hardcoded
    usernames, passwords, API keys, and cloud credentials.

    This is the most critical analysis — hardcoded credentials
    in firmware affect every device running that firmware version.

    Args:
        firmware_path (str): Path to firmware directory

    Returns:
        dict: Credential hunting results
    """
    print(f"\n[*] Analysis 2: Hunting for hardcoded "
          f"credentials in {firmware_path}")

    result = {
        "analysis":           "Credential Hunt",
        "target":             firmware_path,
        "credentials_found":  [],
        "files_scanned":      0,
        "finding":            "",
        "severity":           ""
    }

    # Walk all files in firmware directory
    if os.path.isfile(firmware_path):
        # Single file mode
        files_to_scan = [firmware_path]
    else:
        # Directory mode — scan everything
        files_to_scan = []
        for root, dirs, files in os.walk(firmware_path):
            # Skip virtual filesystems
            dirs[:] = [
                d for d in dirs
                if d not in ['proc', 'sys', 'dev']
            ]
            for filename in files:
                files_to_scan.append(
                    os.path.join(root, filename)
                )

    print(f"    [*] Scanning {len(files_to_scan)} file(s)...")

    for filepath in files_to_scan:
        result["files_scanned"] += 1
        findings = search_file(filepath, CREDENTIAL_PATTERNS)

        for finding in findings:
            result["credentials_found"].append(finding)
            print(f"    [!] {finding['severity']}: "
                  f"{finding['pattern']} in "
                  f"{os.path.basename(filepath)}")
            # Show first match as evidence
            if finding['matches']:
                print(f"        Evidence: "
                      f"{finding['matches'][0][:80]}")

    # Determine severity
    if result["credentials_found"]:
        critical = [
            f for f in result["credentials_found"]
            if f["severity"] == "CRITICAL"
        ]
        result["finding"] = (
            f"Found {len(result['credentials_found'])} "
            f"hardcoded credential pattern(s) — "
            f"{len(critical)} CRITICAL"
        )
        result["severity"] = "CRITICAL" if critical else "HIGH"
        print(f"[!] {result['severity']}: "
              f"{len(result['credentials_found'])} "
              f"credential pattern(s) found")
    else:
        result["finding"]  = "No hardcoded credentials found"
        result["severity"] = "INFO"
        print("[-] No hardcoded credentials found")

    return result


# ── Analysis 3: Private Key Scanner ──────────────────────────
def scan_private_keys(firmware_path):
    """
    Analysis 3: Scan firmware for embedded private keys
    and certificates.

    Finding a private key in firmware means the same key
    is shared across every device shipped with that firmware.
    This allows mass device impersonation and traffic decryption.

    Args:
        firmware_path (str): Path to firmware directory

    Returns:
        dict: Private key scan results
    """
    print(f"\n[*] Analysis 3: Scanning for private keys "
          f"in {firmware_path}")

    result = {
        "analysis":    "Private Key Scanner",
        "target":      firmware_path,
        "keys_found":  [],
        "finding":     "",
        "severity":    ""
    }

    # Build file list
    if os.path.isfile(firmware_path):
        files_to_scan = [firmware_path]
    else:
        files_to_scan = []
        for root, dirs, files in os.walk(firmware_path):
            dirs[:] = [
                d for d in dirs
                if d not in ['proc', 'sys', 'dev']
            ]
            for filename in files:
                files_to_scan.append(
                    os.path.join(root, filename)
                )

    for filepath in files_to_scan:
        findings = search_file(filepath, KEY_PATTERNS)

        for finding in findings:
            # Calculate hash of the key file as evidence
            file_hash = calculate_hash(filepath)
            finding["file_hash"] = file_hash
            result["keys_found"].append(finding)
            print(f"    [!] {finding['severity']}: "
                  f"{finding['pattern']} found in "
                  f"{os.path.basename(filepath)}")
            print(f"        File hash: {file_hash[:16]}...")

    if result["keys_found"]:
        result["finding"] = (
            f"Found {len(result['keys_found'])} "
            f"private key/certificate(s) embedded in firmware — "
            f"all devices share the same key"
        )
        result["severity"] = "CRITICAL"
        print(f"[!] CRITICAL: {len(result['keys_found'])} "
              f"key(s) found")
    else:
        result["finding"]  = "No private keys found"
        result["severity"] = "INFO"
        print("[-] No private keys found")

    return result


# ── Analysis 4: Dangerous Configuration Scanner ───────────────
def scan_dangerous_configs(firmware_path):
    """
    Analysis 4: Scan firmware for dangerous security
    configurations — telnet enabled, debug mode on,
    hardcoded IPs, insecure protocols.

    These configurations reduce the security posture of
    the device and are often left in production firmware
    by manufacturers for convenience or oversight.

    Args:
        firmware_path (str): Path to firmware directory

    Returns:
        dict: Dangerous configuration scan results
    """
    print(f"\n[*] Analysis 4: Scanning for dangerous "
          f"configurations in {firmware_path}")

    result = {
        "analysis":      "Dangerous Configuration Scanner",
        "target":        firmware_path,
        "configs_found": [],
        "finding":       "",
        "severity":      ""
    }

    # Build file list
    if os.path.isfile(firmware_path):
        files_to_scan = [firmware_path]
    else:
        files_to_scan = []
        for root, dirs, files in os.walk(firmware_path):
            dirs[:] = [
                d for d in dirs
                if d not in ['proc', 'sys', 'dev']
            ]
            for filename in files:
                files_to_scan.append(
                    os.path.join(root, filename)
                )

    for filepath in files_to_scan:
        findings = search_file(
            filepath, DANGEROUS_CONFIG_PATTERNS
        )
        for finding in findings:
            result["configs_found"].append(finding)
            print(f"    [!] {finding['severity']}: "
                  f"{finding['pattern']} in "
                  f"{os.path.basename(filepath)}")

    if result["configs_found"]:
        critical = [
            f for f in result["configs_found"]
            if f["severity"] == "CRITICAL"
        ]
        result["finding"] = (
            f"Found {len(result['configs_found'])} "
            f"dangerous configuration(s)"
        )
        result["severity"] = "CRITICAL" if critical else "HIGH"
        print(f"[!] {result['severity']}: "
              f"{len(result['configs_found'])} "
              f"dangerous config(s) found")
    else:
        result["finding"]  = "No dangerous configurations found"
        result["severity"] = "INFO"
        print("[-] No dangerous configurations found")

    return result


# ── Analysis 5: Sensitive File Finder ────────────────────────
def find_sensitive_files(firmware_path):
    """
    Analysis 5: Check for sensitive files that should not
    exist in production firmware.

    Files like /etc/shadow, private keys, and debug outputs
    should never be present in shipping firmware. Finding them
    indicates poor firmware build processes.

    Args:
        firmware_path (str): Path to firmware directory

    Returns:
        dict: Sensitive file findings
    """
    print(f"\n[*] Analysis 5: Finding sensitive files "
          f"in {firmware_path}")

    result = {
        "analysis":       "Sensitive File Finder",
        "target":         firmware_path,
        "files_found":    [],
        "finding":        "",
        "severity":       ""
    }

    # Walk all files and check against sensitive path list
    if os.path.isfile(firmware_path):
        print("[-] Single file mode — skipping path analysis")
        return result

    for root, dirs, files in os.walk(firmware_path):
        dirs[:] = [
            d for d in dirs
            if d not in ['proc', 'sys', 'dev']
        ]

        for filename in files:
            filepath = os.path.join(root, filename)
            # Get relative path for matching
            rel_path = filepath.replace(firmware_path, '')

            # Check against sensitive path patterns
            for sens_path, description, severity in \
                    SENSITIVE_FILE_PATHS:
                if (sens_path in rel_path or
                        filename == os.path.basename(sens_path)):

                    file_size = os.path.getsize(filepath)
                    file_hash = calculate_hash(filepath)

                    result["files_found"].append({
                        "path":        filepath,
                        "description": description,
                        "severity":    severity,
                        "size":        file_size,
                        "hash":        file_hash
                    })
                    print(f"    [!] {severity}: "
                          f"{description} — {rel_path}")
                    break

    if result["files_found"]:
        critical = [
            f for f in result["files_found"]
            if f["severity"] == "CRITICAL"
        ]
        result["finding"] = (
            f"Found {len(result['files_found'])} "
            f"sensitive file(s) in firmware"
        )
        result["severity"] = "CRITICAL" if critical else "HIGH"
        print(f"[!] {result['severity']}: "
              f"{len(result['files_found'])} "
              f"sensitive file(s) found")
    else:
        result["finding"]  = "No sensitive files found"
        result["severity"] = "INFO"
        print("[-] No sensitive files found")

    return result


# ── Analysis 6: Vulnerable Component Scanner ─────────────────
def scan_vulnerable_components(firmware_path):
    """
    Analysis 6: Scan firmware for known vulnerable software
    component versions.

    Version strings embedded in firmware binaries and config
    files reveal which software components are in use.
    These are matched against patterns for known vulnerable
    versions that have CVEs in the NVD database.

    Args:
        firmware_path (str): Path to firmware directory

    Returns:
        dict: Vulnerable component findings
    """
    print(f"\n[*] Analysis 6: Scanning for vulnerable "
          f"components in {firmware_path}")

    result = {
        "analysis":           "Vulnerable Component Scanner",
        "target":             firmware_path,
        "components_found":   [],
        "finding":            "",
        "severity":           ""
    }

    # Build file list
    if os.path.isfile(firmware_path):
        files_to_scan = [firmware_path]
    else:
        files_to_scan = []
        for root, dirs, files in os.walk(firmware_path):
            dirs[:] = [
                d for d in dirs
                if d not in ['proc', 'sys', 'dev']
            ]
            for filename in files:
                files_to_scan.append(
                    os.path.join(root, filename)
                )

    for filepath in files_to_scan:
        findings = search_file(
            filepath, VULNERABLE_COMPONENT_PATTERNS
        )
        for finding in findings:
            result["components_found"].append(finding)
            print(f"    [!] {finding['severity']}: "
                  f"{finding['pattern']} found in "
                  f"{os.path.basename(filepath)}")
            if finding['matches']:
                print(f"        Version: "
                      f"{finding['matches'][0][:60]}")

    if result["components_found"]:
        critical = [
            f for f in result["components_found"]
            if f["severity"] == "CRITICAL"
        ]
        result["finding"] = (
            f"Found {len(result['components_found'])} "
            f"potentially vulnerable component(s)"
        )
        result["severity"] = "CRITICAL" if critical else "HIGH"
        print(f"[!] {result['severity']}: "
              f"{len(result['components_found'])} "
              f"vulnerable component(s) found")
    else:
        result["finding"]  = "No vulnerable components found"
        result["severity"] = "INFO"
        print("[-] No vulnerable components found")

    return result


# ── Main Orchestrator ─────────────────────────────────────────
def run_firmware_analysis(firmware_path):
    """
    Run all 6 firmware analyses against a target.
    Main entry point for Module 5.

    Analysis order:
        1. Binwalk scan      — identify firmware structure
        2. Credential hunt   — find hardcoded credentials
        3. Private key scan  — find embedded crypto keys
        4. Config scan       — find dangerous configurations
        5. Sensitive files   — find files that should not exist
        6. Component scan    — find vulnerable software versions

    Args:
        firmware_path (str): Path to firmware file or directory

    Returns:
        dict: Complete results from all 6 analyses
    """
    print("=" * 60)
    print("  AIPET — Module 5: Firmware Analyser")
    print(f"  Target: {firmware_path}")
    print("=" * 60)

    # Verify target exists
    if not os.path.exists(firmware_path):
        print(f"[-] Target not found: {firmware_path}")
        return {}

    all_results = {
        "target":    firmware_path,
        "scan_time": datetime.now().strftime(
                         "%Y-%m-%d %H:%M:%S"),
        "analyses":  [],
        "summary":   {
            "critical": 0,
            "high":     0,
            "medium":   0,
            "info":     0
        }
    }

    # Run all 6 analyses
    analyses = [
        run_binwalk_scan(firmware_path),
        hunt_credentials(firmware_path),
        scan_private_keys(firmware_path),
        scan_dangerous_configs(firmware_path),
        find_sensitive_files(firmware_path),
        scan_vulnerable_components(firmware_path),
    ]

    all_results["analyses"] = analyses

    # Tally findings by severity
    for analysis in analyses:
        sev = analysis.get("severity", "").upper()
        if sev == "CRITICAL":
            all_results["summary"]["critical"] += 1
        elif sev == "HIGH":
            all_results["summary"]["high"] += 1
        elif sev == "MEDIUM":
            all_results["summary"]["medium"] += 1
        else:
            all_results["summary"]["info"] += 1

    # Save results
    output_file = "firmware/firmware_results.json"
    with open(output_file, 'w') as f:
        json.dump(all_results, f, indent=4)

    # Print final summary
    print("\n" + "=" * 60)
    print("  FIRMWARE ANALYSIS SUMMARY")
    print("=" * 60)
    print(f"  Target:   {firmware_path}")
    s = all_results["summary"]
    print(f"  Critical: {s['critical']}")
    print(f"  High:     {s['high']}")
    print(f"  Medium:   {s['medium']}")
    print(f"  Info:     {s['info']}")
    print(f"\n[+] Results saved to {output_file}")
    print("=" * 60)

    return all_results


if __name__ == "__main__":
    run_firmware_analysis("lab/_IoTGoat-raspberry-pi2.img.extracted/squashfs-root")# Run against our simulated firmware directory
    