"""
AIPET X — Threat Intel Cross-Reference

Checks a scanned host against locally-cached OTX indicators.
All lookups are local DB queries (<100ms) — no live API calls per request.

Severity is derived from pulse tags using a deliberate simple heuristic.
Real calibration is a future task.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

_SEVERITY_TAGS: dict[str, set[str]] = {
    "critical": {"apt", "ransomware", "c2", "command and control", "botnet"},
    "high":     {"malware", "trojan", "exploit", "backdoor", "rootkit"},
    "medium":   {"phishing", "scam", "spam"},
}


def _severity_from_tags(tags: list[str]) -> str:
    tag_set = {t.lower() for t in (tags or [])}
    for sev, keywords in _SEVERITY_TAGS.items():
        if tag_set & keywords:
            return sev
    return "low"


def _parse_description(raw: str | None) -> dict:
    """Parse pulse metadata from the description JSON field."""
    if not raw:
        return {}
    try:
        d = json.loads(raw)
        if isinstance(d, dict):
            return d
    except (json.JSONDecodeError, TypeError):
        pass
    return {}


def check_host_against_threat_intel(
    user_id: int,
    host_ip: str,
    host_data: dict | None = None,
) -> dict:
    """
    Cross-reference a scanned host against locally-cached threat indicators.

    Checks:
      - host_ip directly against ioc_entries.value
      - hostnames from host_data['hostnames'] if provided

    Returns the structured result. NEVER fakes matches — if the indicator
    isn't in ioc_entries, it is not a match.
    """
    from dashboard.backend.threatintel.models import IocEntry

    indicators_to_check: list[tuple[str, str]] = [(host_ip, "ip")]

    if host_data:
        for hostname in (host_data.get("hostnames") or []):
            if hostname and hostname != host_ip:
                indicators_to_check.append((hostname, "domain"))

    matches = []
    seen_ioc_ids: set[int] = set()

    for indicator_value, indicator_category in indicators_to_check:
        # Exact match only — no regex on service banners
        entries = IocEntry.query.filter_by(
            value=indicator_value,
            active=True,
        ).limit(10).all()

        for entry in entries:
            if entry.id in seen_ioc_ids:
                continue
            seen_ioc_ids.add(entry.id)

            meta = _parse_description(entry.description)
            tags = meta.get("tags", [])
            pulse_name = meta.get("pulse_name", entry.threat_type or "unknown")
            pulse_id   = meta.get("pulse_id", "")

            # Use stored severity, or re-derive from tags
            severity = entry.severity.lower() if entry.severity else _severity_from_tags(tags)
            if severity not in ("critical", "high", "medium", "low"):
                severity = _severity_from_tags(tags)

            matches.append({
                "indicator":          indicator_value,
                "indicator_type":     entry.ioc_type,
                "pulse_name":         pulse_name,
                "pulse_id":           pulse_id,
                "first_seen_in_otx":  str(entry.created_at) if entry.created_at else None,
                "tags":               tags,
                "severity":           severity,
                "source":             "alienvault_otx" if entry.feed_id else "local",
                "threat_type":        entry.threat_type,
                "source_ref":         entry.source_ref,
            })

    # Sort by severity (critical first)
    _sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    matches.sort(key=lambda m: _sev_rank.get(m["severity"], 9))
    top_matches = matches[:10]

    highest = matches[0]["severity"] if matches else "none"

    return {
        "status":           "checked",
        "host_ip":          host_ip,
        "matches":          top_matches,
        "match_count":      len(matches),
        "highest_severity": highest,
        "checked_at":       datetime.now(timezone.utc).isoformat(),
    }
