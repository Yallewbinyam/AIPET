"""
AIPET X — AlienVault OTX API Client

Reads the key from OTX_API_KEY env var ONLY.
The key is never logged, never included in error messages, never returned
in any API response.

Rate notes (OTX free tier):
  10,000 req/hour — we use bulk pulse endpoints so a full sync is ~10–40 requests.
"""
from __future__ import annotations

import os
import time
from typing import Any

import requests

_USER_AGENT = "AIPET-X/0.1"
_BASE = "https://otx.alienvault.com/api/v1"
_RETRY_STATUSES = {500, 502, 503, 504}
_MAX_RETRIES = 2
_RETRY_BACKOFF = 2.0  # seconds


class OTXClient:
    def __init__(self, api_key: str | None = None, timeout: int = 30):
        raw = api_key or os.environ.get("OTX_API_KEY", "")
        # Strip any accidental angle-bracket wrappers (<key>) from .env
        self.api_key = raw.strip().strip("<>")
        if not self.api_key:
            raise RuntimeError("OTX_API_KEY not configured")
        self._timeout = timeout
        self._session = requests.Session()
        self._session.headers.update({
            "X-OTX-API-KEY": self.api_key,
            "User-Agent": _USER_AGENT,
            "Accept": "application/json",
        })

    def _get(self, path: str, params: dict | None = None) -> dict:
        url = f"{_BASE}{path}"
        last_exc: Exception | None = None
        for attempt in range(_MAX_RETRIES + 1):
            try:
                resp = self._session.get(url, params=params, timeout=self._timeout)
                if resp.status_code in _RETRY_STATUSES and attempt < _MAX_RETRIES:
                    time.sleep(_RETRY_BACKOFF)
                    continue
                resp.raise_for_status()
                return resp.json()
            except requests.exceptions.RequestException as exc:
                # Never include self.api_key in error strings
                last_exc = type(exc)(str(exc).replace(self.api_key, "[REDACTED]"))
                if attempt < _MAX_RETRIES:
                    time.sleep(_RETRY_BACKOFF)
        raise RuntimeError(f"OTX request failed after {_MAX_RETRIES + 1} attempts: {last_exc}")

    def get_user_info(self) -> dict:
        """GET /api/v1/user/me — sanity-check the key is valid."""
        return self._get("/user/me")

    def get_subscribed_pulses(
        self,
        page_size: int = 50,
        max_pages: int = 20,
    ) -> list[dict]:
        """
        Fetch subscribed pulses using the bulk endpoint (not per-IOC lookups).
        Returns a flat list of pulse dicts, each with an 'indicators' list.
        """
        pulses: list[dict] = []
        page = 1
        while page <= max_pages:
            data = self._get(
                "/pulses/subscribed",
                params={"limit": page_size, "page": page},
            )
            results = data.get("results", [])
            pulses.extend(results)
            if not data.get("next"):
                break
            page += 1
        return pulses

    def get_indicator_details(
        self, indicator_type: str, indicator: str
    ) -> dict | None:
        """
        Live lookup for a single indicator (optional — we use local cache by default).
        indicator_type: IPv4 | domain | hostname | URL | FileHash-MD5 etc.
        """
        try:
            return self._get(f"/indicators/{indicator_type}/{indicator}/general")
        except Exception:
            return None
