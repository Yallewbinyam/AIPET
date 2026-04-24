"""
AIPET X — ML Anomaly Feature Extraction from Real Scan Data

Public API:
    extract_features_for_host(user_id, host_ip, as_of=None) -> dict | None

Returns a 12-key dict matching FEATURE_ORDER. Features derived from real scan
data are populated with real values; features that require network telemetry
not yet collected (packet counts, flag ratios, etc.) are imputed using
per-feature synthetic class means (see PLACEHOLDER STRATEGY below).

PLACEHOLDER STRATEGY
--------------------
Rather than zero-filling unobserved features (which creates all-zero vectors
that are extreme outliers in the synthetic training distribution), we impute
using the per-feature mean of the *normal* or *anomaly* synthetic class:

- Hosts where open_port_count < _ANOMALY_PORT_THRESHOLD
  AND cve_count < _ANOMALY_CVE_THRESHOLD:
      placeholder = mean of that feature in the synthetic NORMAL class.
  Domain rationale: few ports + few CVEs → low-activity profile.

- Hosts where open_port_count >= _ANOMALY_PORT_THRESHOLD
  OR  cve_count >= _ANOMALY_CVE_THRESHOLD:
      placeholder = mean of that feature in the synthetic ANOMALY class.
  Domain rationale: many open services/CVEs → high-activity profile consistent
  with the port-scan / exfiltration anomaly patterns in training data.

Thresholds are set above the maximum seen in the synthetic normal class
(normal: open_port_count ∈ [1,3], cve_count ∈ [0,2]), so any host clearly
outside the normal scan-data range triggers the anomaly imputation.

Class means are computed ONCE at module load from generate_synthetic() with
the same seed used for training (seed=42, n_normal=5000, n_anomalous=250),
ensuring consistency with the fitted model.

All placeholder values used are recorded in _placeholder_values for audit.
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

# Hosts with open_port_count >= this OR cve_count >= this use anomaly-class means
# as placeholders. Thresholds are set just above the synthetic normal class maxima
# (normal: open_port_count ∈ [1,3], cve_count ∈ [0,2]).
_ANOMALY_PORT_THRESHOLD = 5
_ANOMALY_CVE_THRESHOLD  = 5


def _compute_class_means() -> tuple[dict[str, float], dict[str, float]]:
    """Compute per-feature means for normal and anomaly classes.

    Called once at module load time with the same seed used for training.
    Avoids repeated generation on every request.
    """
    from dashboard.backend.ml_anomaly.training_data import generate_synthetic
    import numpy as np

    X, y = generate_synthetic(n_normal=5000, n_anomalous=250, seed=42)
    X_normal  = X[y == 0]
    X_anomaly = X[y == 1]

    normal_means  = {name: float(X_normal[:, i].mean())  for i, name in enumerate(FEATURE_ORDER)}
    anomaly_means = {name: float(X_anomaly[:, i].mean()) for i, name in enumerate(FEATURE_ORDER)}
    return normal_means, anomaly_means


# Module-level constants — computed once at import, never on a request path.
_NORMAL_MEANS, _ANOMALY_MEANS = _compute_class_means()


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
    - `_synthetic_fields`: list of keys whose value was imputed (not measured).
    - `_placeholder_values`: {feature_name: value_used} for every imputed field.
    - `_placeholder_strategy`: "normal_means" or "anomaly_means" — which class
      was used for imputation and why (for audit / reporting).
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
        night_activity = None  # resolved below via placeholder
        synthetic_fields.append("night_activity")
        log.debug(
            "feature_extraction: night_activity set via placeholder — only %d scan(s) for %s "
            "(need >= %d)",
            len(scans_with_host), host_ip, _MIN_SCANS_FOR_NIGHT,
        )

    # ── Placeholder features (require watch-agent telemetry) ─────────────────
    _PLACEHOLDER_KEYS = [
        "packet_rate", "byte_rate", "unique_dst_ports", "unique_dst_ips",
        "syn_ratio", "rst_ratio", "failed_auth_rate", "outbound_ratio", "protocol_entropy",
    ]
    synthetic_fields.extend(_PLACEHOLDER_KEYS)

    # Choose imputation class: anomaly means for hosts clearly outside the
    # synthetic normal range; normal means for everything else.
    if open_port_count >= _ANOMALY_PORT_THRESHOLD or cve_count >= _ANOMALY_CVE_THRESHOLD:
        placeholder_src = _ANOMALY_MEANS
        placeholder_strategy = (
            f"anomaly_means (open_port_count={open_port_count:.0f} or "
            f"cve_count={cve_count:.0f} exceeds threshold "
            f"port>={_ANOMALY_PORT_THRESHOLD} / cve>={_ANOMALY_CVE_THRESHOLD})"
        )
    else:
        placeholder_src = _NORMAL_MEANS
        placeholder_strategy = (
            f"normal_means (open_port_count={open_port_count:.0f} and "
            f"cve_count={cve_count:.0f} within normal range)"
        )

    # Build the full 12-feature vector.
    feature_values: dict[str, float] = {}
    for k in FEATURE_ORDER:
        feature_values[k] = placeholder_src[k]  # default: imputed

    # Override with real values where available.
    feature_values["open_port_count"] = open_port_count
    feature_values["cve_count"] = cve_count
    feature_values["night_activity"] = (
        night_activity if night_activity is not None else placeholder_src["night_activity"]
    )

    # Record which value was used for each synthetic field (for audit).
    placeholder_values = {k: placeholder_src[k] for k in synthetic_fields}

    return {
        **feature_values,
        "_synthetic_fields":    synthetic_fields,
        "_placeholder_values":  placeholder_values,
        "_placeholder_strategy": placeholder_strategy,
        "_source_scan_id":      most_recent_scan_id,
        "_host_ip":             host_ip,
    }
