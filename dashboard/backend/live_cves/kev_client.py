"""
AIPET X — CISA KEV API Client

Downloads the CISA Known Exploited Vulnerabilities catalog.
Public endpoint — no API key required.
"""
from __future__ import annotations

import time
from datetime import date, datetime
from typing import Any

import requests

_USER_AGENT = "AIPET-X/0.1"
CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
_MAX_RETRIES   = 2
_RETRY_BACKOFF = 2.0


class CISAKEVClient:
    def __init__(self, timeout: int = 60):
        self.timeout = timeout
        self._session = requests.Session()
        self._session.headers.update({
            "User-Agent": _USER_AGENT,
            "Accept":     "application/json",
        })

    def fetch_catalog(self) -> dict:
        """
        Download the full CISA KEV JSON.  Retries up to 2 times on 5xx or
        connection error.  Returns the parsed dict on success.
        """
        last_exc: Exception | None = None
        for attempt in range(_MAX_RETRIES + 1):
            try:
                resp = self._session.get(CISA_KEV_URL, timeout=self.timeout)
                if resp.status_code >= 500 and attempt < _MAX_RETRIES:
                    time.sleep(_RETRY_BACKOFF)
                    continue
                resp.raise_for_status()
                return resp.json()
            except requests.exceptions.RequestException as exc:
                last_exc = exc
                if attempt < _MAX_RETRIES:
                    time.sleep(_RETRY_BACKOFF)
        raise RuntimeError(f"CISA KEV fetch failed after {_MAX_RETRIES + 1} attempts: {last_exc}")

    def normalize_entries(self, raw: dict) -> list[dict]:
        """
        Map CISA's camelCase JSON to snake_case model fields.
        Returns a list of dicts ready for upsert into kev_catalog.
        """
        now = datetime.utcnow()
        entries: list[dict] = []
        for v in raw.get("vulnerabilities", []):
            entries.append({
                "cve_id":               v.get("cveID", "").strip(),
                "vendor_project":       (v.get("vendorProject") or "")[:256],
                "product":              (v.get("product") or "")[:256],
                "vulnerability_name":   (v.get("vulnerabilityName") or "")[:512],
                "date_added":           _parse_date(v.get("dateAdded")),
                "short_description":    v.get("shortDescription"),
                "required_action":      v.get("requiredAction"),
                "due_date":             _parse_date(v.get("dueDate")),
                "known_ransomware_use": (v.get("knownRansomwareCampaignUse") or "Unknown")[:16],
                "notes":                v.get("notes"),
                "cwes":                 v.get("cwes") or [],
                "last_synced_at":       now,
            })
        return [e for e in entries if e["cve_id"]]


def _parse_date(s: str | None) -> date | None:
    if not s:
        return None
    try:
        return datetime.strptime(s[:10], "%Y-%m-%d").date()
    except ValueError:
        return None
