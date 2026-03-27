# AIPET — Progress Summary
## Modules 4 & 5: HTTP/Web IoT Suite and Firmware Analyser

---

## Module 4 — HTTP/Web IoT Suite

### Purpose
Module 4 targets the web interfaces that IoT devices expose
for configuration and management. Unlike traditional web
application testing, IoT web interface testing carries
physical consequences — a compromised admin panel does not
just leak data, it gives an attacker direct control over
hardware in the physical world.

### Why IoT Web Interfaces Are Different
Three fundamental differences from regular web app testing:

**1. Default credentials are almost always present**
IoT devices ship with credentials like admin/admin printed
in the manual. Unlike custom web applications where someone
chose a password, IoT defaults are universal across every
device of that model. An attacker who knows the model knows
the password.

**2. The web interface controls hardware**
A regular web app has a database behind it. An IoT web
interface has GPIO pins, relays, motors, valves, and
sensors behind it. Successful exploitation does not just
compromise data — it compromises the physical world.

**3. Web frameworks are ancient and weak**
IoT devices run stripped-down embedded web servers — Boa,
lighttpd, GoAhead, mini_httpd. These are often years out
of date, rarely patched, and frequently contain known CVEs.
Regular web apps run on modern frameworks with active
security teams. IoT web interfaces run on abandoned code.

### Files Built
**http_attacker.py** — Four sequential attacks against
IoT web interfaces.

**http_test_server.py** (lab/) — Deliberately vulnerable
IoT HTTP server simulating a real device web interface
with admin panel, REST API, configuration pages, and
diagnostic endpoints.

### The Four Attacks

**Attack 1 — Default Credential Testing**
Attempts common default credential pairs against all
discovered login endpoints using both form-based POST
authentication and HTTP Basic Authentication. Uses the
`requests` library with `verify=False` to handle
self-signed IoT certificates. Tests 16 credential pairs
across multiple field name combinations since IoT devices
use inconsistent field names (username/password,
user/pass, login/pwd etc).

Key finding: Our test server accepted all 8 Basic Auth
credential pairs against /admin, /config, and /management
— 24 valid credential sets total. This reflects real
IoT deployments where authentication is implemented
inconsistently or not at all.

**Attack 2 — Admin Interface Discovery**
Systematically requests 30 known IoT admin and sensitive
file paths. Checks each 200 response against the
SENSITIVE_PATTERNS list for credential and configuration
data. Discovers backup files (/config.bak), diagnostic
pages (/diag), setup interfaces (/setup), and management
panels (/management) that are accessible without
authentication.

Key finding: 8 interfaces found exposing sensitive data
including API keys, WiFi passwords, and MQTT credentials.
The /config.bak file is particularly significant — backup
files are a common real-world IoT misconfiguration.

**Attack 3 — API Security Testing**
Tests 12 REST API paths for unauthenticated access and
sensitive data exposure. Uses GET requests to test read
access and POST requests with common injection payloads
to test write access and command injection. Checks all
API responses against SENSITIVE_PATTERNS.

Key finding: /api/v1/config returned full device
configuration including admin credentials and API keys
without any authentication token. This maps directly
to OWASP IoT Top 10 I3 — Insecure Ecosystem Interfaces.

**Attack 4 — Common Vulnerability Scanning**
Tests four vulnerability categories specific to IoT:
dangerous HTTP methods (DELETE, PUT, TRACE), directory
traversal via path manipulation, missing security headers
(X-Frame-Options, Content-Security-Policy etc), and
exposed firmware update endpoints. Also checks for
server version disclosure in HTTP response headers.

Key finding: Server header disclosed BaseHTTP/0.6
Python/3.13.12 — version disclosure allows attackers
to identify known CVEs for the exact software version.

### Technical Concepts Learned

**requests library** — Python's HTTP client library.
`verify=False` disables SSL certificate validation —
necessary because IoT devices use self-signed certificates
that would cause verification failures. `allow_redirects=True`
follows HTTP 302 redirects which IoT admin panels commonly
use after login.

**urllib3 warning suppression** — When using verify=False,
urllib3 raises InsecureRequestWarning on every request.
Suppressing this with `urllib3.disable_warnings()` is
appropriate here because the insecurity is intentional
and documented — we are testing IoT devices, not browsing
the web securely.

**HTTP Basic Authentication** — The oldest HTTP auth
mechanism. Credentials are Base64 encoded (not encrypted)
in the Authorization header. The `requests` library
implements this via the `auth=(username, password)`
parameter. Many IoT devices still use Basic Auth as their
only authentication mechanism.

**Sensitive pattern matching** — Rather than looking for
specific credential values, AIPET searches for the
patterns that indicate credentials are present — the
words "password", "api_key", "secret" etc. This approach
works regardless of the actual credential values and
catches both known and unknown credential formats.

### Test Results
```
Target:   http://localhost:8080
Attack 1: CRITICAL — 24 valid credential sets found
Attack 2: CRITICAL — 8 interfaces exposing sensitive data
Attack 3: CRITICAL — APIs exposing credentials without auth
Attack 4: LOW      — Missing headers, version disclosure

Final Score:
Critical: 3
High:     0
Medium:   0
Info:     1
```

### OWASP IoT Top 10 Coverage
```
I1  Weak/Hardcoded Passwords    → Attack 1 (default creds)
I3  Insecure Ecosystem Interfaces → Attack 3 (API testing)
I9  Insecure Default Settings   → Attack 1, 2
```

### Dissertation References
- OWASP IoT Top 10 (2018) — I1, I3, I9 directly addressed
- OWASP Web Security Testing Guide — methodology basis
- Costin et al. (2014) — large-scale analysis of firmware
  web interfaces, documents prevalence of default credentials

---

## Module 5 — Firmware Analyser

### Purpose
Module 5 analyses IoT firmware for security vulnerabilities
at the binary level. Firmware analysis is the deepest
layer of IoT security assessment — it finds vulnerabilities
that are invisible to network-based testing and that
affect every device running that firmware version globally.

### Why Firmware Analysis Matters

**Hardcoded credentials are permanent**
A weak password can be changed by the user. A hardcoded
credential is burned into the firmware binary and affects
every single device shipped with that version. If 50,000
devices were sold with that firmware, all 50,000 are
simultaneously vulnerable. The user cannot fix it by
changing a setting — the manufacturer must release new
firmware and the user must know to update.

This is exactly how the Mirai botnet worked in 2016.
It found IoT devices with hardcoded default credentials
and used them to compromise over 600,000 devices,
launching the largest DDoS attack in history at the time.

**Shared private keys affect all devices**
If a private SSL/TLS key is embedded in firmware, every
device running that firmware shares the same key. An
attacker who extracts the key from one device can
impersonate or decrypt traffic from every other device
of the same model worldwide.

**Firmware vulnerabilities cannot be patched at runtime**
Unlike software vulnerabilities that can be mitigated
through configuration, firmware vulnerabilities require
a new firmware release. Most IoT devices never receive
firmware updates — making early detection critical.

### Files Built
**firmware_analyser.py** — Six analyses against firmware
files and extracted filesystem directories.

**lab/fake_firmware/** — Simulated firmware directory
structure containing deliberately vulnerable files
representing a real extracted IoT firmware image.

### The Six Analyses

**Analysis 1 — Binwalk Scan**
Runs binwalk v2.4.3 as a system subprocess using
Python's subprocess module. Binwalk identifies embedded
file systems, compression algorithms, encryption markers,
and known file signatures within firmware binaries.
The output reveals the internal structure of the firmware
— which filesystems are present, where they begin, and
what compression is used.

Technical note: binwalk is called via subprocess rather
than as a Python library because binwalk 2.4.3's Python
API is unreliable. The subprocess approach calls the
system binary directly, which is the most reliable and
version-independent approach.

**Analysis 2 — Credential Hunt**
Recursively walks all files in the firmware directory
and applies 7 regular expression patterns to find
hardcoded credentials. Patterns cover passwords,
usernames, API keys, AWS access keys, AWS secret keys,
WiFi passwords, and MQTT credentials.

Each regex is designed to match the pattern of credential
storage rather than specific values — making the scanner
effective against firmware it has never seen before.
Files are read with `errors='ignore'` to handle both
text configuration files and binary firmware images.

Key finding: Found AWS access key AKIAIOSFODNN7EXAMPLE,
AWS secret key, API key, MQTT credentials, and admin
password — all hardcoded in configuration files that
ship with the firmware.

**Analysis 3 — Private Key Scanner**
Searches all files for PEM format cryptographic material
headers — RSA private keys, EC private keys, SSH keys,
and certificates. Calculates SHA256 hash of any file
containing keys as evidence for the report.

Key finding: RSA private key found in /etc/server.key.
This means every device running this firmware shares
the same SSL key — allowing traffic decryption and
device impersonation at scale.

**Analysis 4 — Dangerous Configuration Scanner**
Searches configuration files for settings that reduce
security posture. Telnet enabled sends all traffic
including passwords in plaintext. Debug mode enabled
exposes internal system state. Hardcoded IP addresses
suggest infrastructure that may be exploitable. Plain
HTTP URLs in configuration indicate unencrypted
communication channels.

Key finding: telnet_enabled=true and debug_mode=true
both found in config.conf — two CRITICAL configurations
that should never exist in production firmware.

**Analysis 5 — Sensitive File Finder**
Walks the firmware directory tree and checks every file
path against a list of files that should never exist
in production firmware. /etc/shadow should never be
readable. Private key files should not ship with the
device. Debug output files indicate a development build
was shipped.

Key finding: /etc/shadow, /etc/server.key, and
/etc/config.conf all found — indicating poor firmware
build processes that include sensitive development
material in the shipping image.

**Analysis 6 — Vulnerable Component Scanner**
Searches firmware for version strings of known
vulnerable software components. Version strings are
embedded in both binary files and configuration files.
Matched against patterns for components with documented
CVEs in the NVD database.

Key finding: OpenSSL 1.0.1 (Heartbleed — CVE-2014-0160,
CVSS 7.5) and OpenSSH 7.2 (multiple CVEs) both found
in the firmware binary. These are real, exploitable
vulnerabilities with public proof-of-concept exploits.

### Technical Concepts Learned

**subprocess module** — Python's built-in module for
running system commands. `subprocess.run()` executes
a command and captures stdout and stderr.
`capture_output=True` stores the output in the result
object. `timeout=60` prevents hanging on large files.
`text=True` returns output as a string rather than bytes.

**Regular expressions (re module)** — Pattern matching
engine. `re.findall()` returns all matches of a pattern
in a string. `(?i)` makes the pattern case-insensitive.
`[^\s"\']{4,}` matches any non-whitespace, non-quote
character repeated 4 or more times — capturing credential
values of meaningful length.

**SHA256 hashing** — Cryptographic hash function used
for file integrity verification. Reading files in 65536
byte chunks (`iter(lambda: f.read(65536), b"")`) handles
large firmware files efficiently without loading the
entire file into memory. The hexdigest provides a
fingerprint that can be looked up in firmware databases.

**os.walk()** — Python function that recursively walks
a directory tree yielding (root, dirs, files) tuples.
`dirs[:] = [...]` modifies the list in place to skip
directories like /proc and /sys that could cause
infinite loops or permission errors.

**Binary file reading** — Firmware binaries contain
both binary data and embedded strings. Opening with
`encoding='utf-8', errors='ignore'` reads the file
as text, ignoring bytes that cannot be decoded as
UTF-8. This extracts human-readable strings from
binary files without requiring a dedicated strings tool.

### Test Results
```
Target:   lab/fake_firmware
Analysis 1: INFO     — Binwalk scan completed
Analysis 2: CRITICAL — 8 hardcoded credential patterns
Analysis 3: CRITICAL — RSA private key found
Analysis 4: CRITICAL — Telnet + debug enabled
Analysis 5: CRITICAL — Shadow file, SSL key, config
Analysis 6: CRITICAL — OpenSSL 1.0.1, OpenSSH 7.2

Final Score:
Critical: 5
High:     0
Medium:   0
Info:     1
```

### OWASP IoT Top 10 Coverage
```
I1  Weak/Hardcoded Passwords → Analysis 2 (credential hunt)
I4  Lack of Secure Update    → Analysis 6 (outdated components)
I5  Insecure Components      → Analysis 6 (CVE matching)
I7  Insecure Data Transfer   → Analysis 4 (telnet enabled)
I10 Lack of Physical Hardening → Analysis 3 (shared keys)
```

### Dissertation References
- Costin et al. (2014) — A Large-Scale Analysis of the
  Security of Embedded Firmwares. USENIX Security.
  Direct academic precedent for automated firmware analysis.
- Chen et al. (2016) — Towards Automated Dynamic Analysis
  for Linux-based Embedded Firmware. NDSS. Firmadyne paper.
- CVE-2014-0160 (Heartbleed) — OpenSSL vulnerability
  directly detected by Analysis 6.
- Antonakakis et al. (2017) — Understanding the Mirai
  Botnet. USENIX Security. Motivates hardcoded credential
  detection in Analysis 2.

---

## How Modules 4 and 5 Connect to the Pipeline
```
Module 1 — profiles.py
    Port 80/8080 detected → Module 4 recommended
    embedded_linux_device → Module 5 recommended
           ↓
Module 4 — http_attacker.py
    Admin credentials found
    API keys exposed
    Results → http_results.json
           ↓
Module 5 — firmware_analyser.py
    Hardcoded credentials confirmed
    Private key found
    Vulnerable components identified
    Results → firmware_results.json
           ↓
Module 6 — AI Engine (next)
    All findings aggregated
    Risk prioritised with SHAP explanations
    Attack paths ranked by exploitability
```

---

## Overall Attack Coverage After 5 Modules
```
OWASP IoT Top 10 Coverage:
I1  Weak/Hardcoded Passwords    ✅ Modules 2, 4, 5
I2  Insecure Network Services   ✅ Module 1
I3  Insecure Ecosystem Interfaces ✅ Modules 3, 4
I4  Lack of Secure Update       ✅ Module 5
I5  Insecure Components         ✅ Module 5
I6  Insufficient Privacy        ✅ Modules 2, 3
I7  Insecure Data Transfer      ✅ Modules 2, 3, 5
I8  Lack of Device Management   ✅ Module 1
I9  Insecure Default Settings   ✅ Modules 2, 4
I10 Lack of Physical Hardening  ✅ Module 5

Coverage: 10 out of 10 OWASP IoT categories
```

---

## Current Project Status
```
Modules complete:    5 of 7
Files committed:     18+
Real findings:       Critical 12+, High 6+
Weeks elapsed:       2 of 26
Schedule:            8+ weeks ahead
```