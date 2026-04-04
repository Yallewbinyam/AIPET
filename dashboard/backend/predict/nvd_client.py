"""
AIPET Predict — NVD API Client
Fetches CVE data from the National Vulnerability Database.

The NVD API is free and requires no authentication for basic use.
Rate limit: 5 requests per 30 seconds without API key.

API Documentation: https://nvd.nist.gov/developers/vulnerabilities

Usage:
    from dashboard.backend.predict.nvd_client import fetch_recent_cves
    cves = fetch_recent_cves(days=1)
"""

import json
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime, timedelta, timezone


NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_TIMEOUT = 30


def fetch_recent_cves(days=1, max_results=100):
    """
    Fetches CVEs published in the last N days from the NVD API.

    Args:
        days (int): Number of days to look back (default 1 = last 24 hours)
        max_results (int): Maximum number of CVEs to return (default 100)

    Returns:
        dict: {
            "success": True,
            "cves": [...],
            "total": 42,
            "days": 1
        }

        or on failure:
        {
            "success": False,
            "error": "Error message",
            "cves": []
        }
    """
    try:
        # Calculate date range
        end_date   = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=days)

        # Format dates for NVD API
        start_str = start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
        end_str   = end_date.strftime("%Y-%m-%dT%H:%M:%S.000")

        # Build query parameters
        params = {
            "pubStartDate": start_str,
            "pubEndDate":   end_str,
            "resultsPerPage": min(max_results, 2000),
            "startIndex": 0,
        }

        url = f"{NVD_BASE_URL}?{urllib.parse.urlencode(params)}"

        req = urllib.request.Request(url)
        req.add_header("User-Agent", "AIPET-Security-Platform/2.0")

        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as response:
            data = json.loads(response.read().decode("utf-8"))

        cves = []
        for item in data.get("vulnerabilities", []):
            cve = parse_cve(item)
            if cve:
                cves.append(cve)

        return {
            "success": True,
            "cves":    cves,
            "total":   data.get("totalResults", 0),
            "days":    days,
        }

    except urllib.error.HTTPError as e:
        return {
            "success": False,
            "error":   f"NVD API HTTP error {e.code}: {e.reason}",
            "cves":    []
        }

    except urllib.error.URLError as e:
        return {
            "success": False,
            "error":   f"Failed to reach NVD API: {str(e.reason)}",
            "cves":    []
        }

    except (json.JSONDecodeError, KeyError) as e:
        return {
            "success": False,
            "error":   f"Failed to parse NVD response: {str(e)}",
            "cves":    []
        }

    except Exception as e:
        return {
            "success": False,
            "error":   f"Unexpected error: {str(e)}",
            "cves":    []
        }


def fetch_cve_details(cve_id):
    """
    Fetches full details for a specific CVE ID.

    Args:
        cve_id (str): The CVE ID e.g. "CVE-2024-1234"

    Returns:
        dict: CVE details or None if not found
    """
    try:
        params = {"cveId": cve_id}
        url    = f"{NVD_BASE_URL}?{urllib.parse.urlencode(params)}"

        req = urllib.request.Request(url)
        req.add_header("User-Agent", "AIPET-Security-Platform/2.0")

        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as response:
            data = json.loads(response.read().decode("utf-8"))

        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return None

        return parse_cve(vulnerabilities[0])

    except Exception:
        return None


def parse_cve(item):
    """
    Parses a raw CVE item from the NVD API response into a clean dict.

    Args:
        item (dict): Raw CVE item from NVD API

    Returns:
        dict: Cleaned CVE data or None if parsing fails
    """
    try:
        cve_data = item.get("cve", {})
        cve_id   = cve_data.get("id", "")

        if not cve_id:
            return None

        # Get description (prefer English)
        descriptions = cve_data.get("descriptions", [])
        description  = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break
        if not description and descriptions:
            description = descriptions[0].get("value", "")

        # Get CVSS score and severity
        cvss_score = 0.0
        severity   = "Unknown"
        metrics    = cve_data.get("metrics", {})

        # Try CVSS v3.1 first, then v3.0, then v2.0
        for metric_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            metric_list = metrics.get(metric_key, [])
            if metric_list:
                cvss_data  = metric_list[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", 0.0)
                severity   = cvss_data.get("baseSeverity", "Unknown")
                if not severity and metric_key == "cvssMetricV2":
                    # v2 uses different field name
                    severity = metric_list[0].get("baseSeverity", "Unknown")
                break

        # Normalise severity
        severity = severity.upper()
        if severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            pass
        elif cvss_score >= 9.0:
            severity = "CRITICAL"
        elif cvss_score >= 7.0:
            severity = "HIGH"
        elif cvss_score >= 4.0:
            severity = "MEDIUM"
        elif cvss_score > 0:
            severity = "LOW"
        else:
            severity = "UNKNOWN"

        # Capitalise properly
        severity = severity.capitalize()

        # Get published date
        published_str  = cve_data.get("published", "")
        published_date = None
        if published_str:
            try:
                published_date = datetime.fromisoformat(
                    published_str.replace("Z", "+00:00")
                )
            except ValueError:
                published_date = datetime.now(timezone.utc)

        if not published_date:
            published_date = datetime.now(timezone.utc)

        # Extract keywords for matching
        keywords = extract_keywords(description, cve_id)

        return {
            "cve_id":        cve_id,
            "description":   description,
            "cvss_score":    cvss_score,
            "severity":      severity,
            "published_date": published_date,
            "nvd_url":       f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "keywords":      keywords,
        }

    except Exception:
        return None


def extract_keywords(description, cve_id):
    """
    Extracts matching keywords from a CVE description.
    Used by the matcher to find relevant CVEs for a user's devices.
    """
    keywords = []
    description_lower = description.lower()

    # IoT vendors and products
    iot_keywords = [
        "hikvision", "axis", "bosch", "dahua", "hanwha", "vivotek",
        "dlink", "d-link", "netgear", "asus", "tp-link", "tplink",
        "cisco", "fortinet", "ubiquiti", "mikrotik", "zyxel",
        "siemens", "schneider", "honeywell", "johnson controls",
        "philips", "samsung", "lg", "panasonic", "sony",
        "raspberry", "arduino", "espressif", "esp8266", "esp32",
        "router", "camera", "ip camera", "nvr", "dvr",
        "plc", "scada", "ics", "modbus", "bacnet",
        "mqtt", "coap", "zigbee", "lorawan", "bluetooth",
        "telnet", "ftp", "snmp", "upnp",
        "firmware", "embedded", "iot",
    ]

    for kw in iot_keywords:
        if kw in description_lower:
            keywords.append(kw)

    # Attack types
    attack_keywords = [
        "authentication bypass", "remote code execution", "rce",
        "default credentials", "default password",
        "command injection", "sql injection",
        "buffer overflow", "heap overflow",
        "denial of service", "dos",
        "privilege escalation", "path traversal",
        "cross-site scripting", "xss",
        "man-in-the-middle", "mitm",
        "cleartext", "plaintext", "unencrypted",
        "hardcoded", "hard-coded",
    ]

    for kw in attack_keywords:
        if kw in description_lower:
            keywords.append(kw)

    return list(set(keywords))