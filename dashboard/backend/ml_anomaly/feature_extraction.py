"""
AIPET X — ML Anomaly Feature Extraction from Real Scan Data

Public API:
    extract_features_for_host(user_id, host_ip, as_of=None) -> dict | None

Returns a 12-key dict matching FEATURE_ORDER. Features derived from real scan
data are populated with real values; features that require network telemetry
not yet collected (packet counts, flag ratios, etc.) are set to 0.0 and listed
in the `_synthetic_fields` key so callers know which features are placeholder zeros.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from flask import current_app

from dashboard.backend.ml_anomaly.features import FEATURE_ORDER

# Features we can compute from nmap scan results today.
_REAL_FEATURES = {"open_port_count", "cve_count", "night_activity"}

# Night-time window: 22:00 – 06:00 inclusive (hours 22, 23, 0, 1, 2, 3, 4, 5, 6).
_NIGHT_HOURS = set(range(22, 24)) | set(range(0, 7))

# Minimum number of scans containing this host before night_activity is meaningful.
_MIN_SCANS_FOR_NIGHT = 3


def extract_features_for_host(
    user_id: int,
    host_ip: str,
    as_of: datetime | None = None,
) -> dict | None:
    """Return a feature dict for *host_ip* drawn from real scan results.

    Queries real_scan_results for *user_id*, parses results_json in Python
    (no SQL JSON extraction — keeps it portable and unit-testable), and
    returns a dict keyed by every feature in FEATURE_ORDER.

    Returns None if no completed scan for this user contains *host_ip*.

    Transparent partial-real contract
    ----------------------------------
    - `_synthetic_fields`: list of keys whose value is a placeholder 0.0 because
      the required telemetry is not yet collected by the watch agent.
    - `_source_scan_id`: ID of the most-recent completed scan that contained
      *host_ip* (used for audit / traceability).
    - `_host_ip`: the host IP used for this extraction.
    """
    from dashboard.backend.real_scanner.routes import RealScanResult  # local import avoids circulars

    log = current_app.logger

    cutoff = as_of or datetime.now(timezone.utc).replace(tzinfo=None)

    # Load all completed scans for this user up to *cutoff*, newest first.
    scans = (
        RealScanResult.query
        .filter(
            RealScanResult.user_id == user_id,
            RealScanResult.status == "complete",
            RealScanResult.started_at <= cutoff,
        )
        .order_by(RealScanResult.started_at.desc())
        .all()
    )

    if not scans:
        log.debug("feature_extraction: no completed scans for user_id=%s", user_id)
        return None

    # Walk scans to find every one that contains host_ip, and identify the
    # most recent scan (for port/CVE data) separately.
    most_recent_host_data: dict | None = None
    most_recent_scan_id: str | None = None
    scans_with_host: list[tuple[datetime, dict]] = []  # (started_at, host_entry)

    for scan in scans:
        try:
            hosts = json.loads(scan.results_json or "[]")
        except (json.JSONDecodeError, TypeError):
            log.warning("feature_extraction: bad results_json in scan %s", scan.id)
            continue

        for host in hosts:
            if host.get("ip") == host_ip:
                scans_with_host.append((scan.started_at, host))
                if most_recent_host_data is None:
                    most_recent_host_data = host
                    most_recent_scan_id = scan.id
                break  # only one entry per host per scan

    if most_recent_host_data is None:
        log.debug(
            "feature_extraction: host %s not found in any scan for user_id=%s",
            host_ip, user_id,
        )
        return None

    # ── Real feature: open_port_count ────────────────────────────────────────
    open_ports = most_recent_host_data.get("open_ports", [])
    open_port_count = float(
        most_recent_host_data.get("port_count", len(open_ports))
    )

    # ── Real feature: cve_count ──────────────────────────────────────────────
    # results_json stores CVEs under the key 'cves'; fall back to 'cves_found'
    # for any older scan format, and to the pre-computed 'cve_count' integer.
    cves = most_recent_host_data.get("cves", most_recent_host_data.get("cves_found"))
    if cves is not None:
        cve_count = float(len(cves))
    else:
        cve_count = float(most_recent_host_data.get("cve_count", 0))

    # ── Real feature: night_activity (fraction of scans in night window) ─────
    synthetic_fields: list[str] = []
    if len(scans_with_host) >= _MIN_SCANS_FOR_NIGHT:
        night_count = sum(
            1 for ts, _ in scans_with_host if ts.hour in _NIGHT_HOURS
        )
        night_activity = float(night_count) / len(scans_with_host)
    else:
        night_activity = 0.0
        synthetic_fields.append("night_activity")
        log.debug(
            "feature_extraction: night_activity set to 0.0 — only %d scan(s) for %s "
            "(need >= %d)",
            len(scans_with_host), host_ip, _MIN_SCANS_FOR_NIGHT,
        )

    # ── Placeholder features (require watch-agent telemetry) ─────────────────
    _PLACEHOLDER_KEYS = [
        "packet_rate", "byte_rate", "unique_dst_ports", "unique_dst_ips",
        "syn_ratio", "rst_ratio", "failed_auth_rate", "outbound_ratio", "protocol_entropy",
    ]
    synthetic_fields.extend(_PLACEHOLDER_KEYS)

    feature_values: dict[str, float] = {k: 0.0 for k in FEATURE_ORDER}
    feature_values["open_port_count"] = open_port_count
    feature_values["cve_count"] = cve_count
    feature_values["night_activity"] = night_activity

    return {
        **feature_values,
        "_synthetic_fields": synthetic_fields,
        "_source_scan_id": most_recent_scan_id,
        "_host_ip": host_ip,
    }
