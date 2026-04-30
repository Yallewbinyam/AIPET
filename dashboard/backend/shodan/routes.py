"""
AIPET X — Shodan API integration routes (Capability 16, v1).

Endpoints:
  GET    /api/shodan/lookup/<ip>     — Shodan host lookup (cached)
  GET    /api/shodan/cache           — list cache entries
  DELETE /api/shodan/cache/<ip>      — clear one cache entry
  GET    /api/shodan/status          — key configured? quota? cache size?

v1 scope adopted 2026-04-30:
- Free-tier endpoints only: `/shodan/host/<ip>` and `/api-info`.
  No `/shodan/host/search` (paid). Tracked for v1.1 once funded.
- 24-hour TTL on the cache. Cache hit returns stored data; cache
  miss calls Shodan once, stores result (positive or negative),
  returns it.
- Trigger model is user-initiated per host (frontend "Look up"
  button per scan result). Free-tier quota is 100 lookups/month —
  automatic enrichment of every scanned host would burn it
  instantly.
- Skip-if-no-key: the module loads identically when SHODAN_API_KEY
  is absent. Routes return HTTP 503 with a clear configured=False
  payload pointing at the env var. Mirrors the PLB-4 (email) and
  PLB-5 (Sentry) patterns.

Library import:
- The `shodan` PyPI package is imported as a top-level name. There
  is no collision with this module's qualified path
  `dashboard.backend.shodan` because Python 3 imports are absolute
  by default and the project's PYTHONPATH puts `/home/byall/AIPET`
  (NOT `/home/byall/AIPET/dashboard/backend/`) on the search path.
- A defensive try/except around the import lets the rest of the
  blueprint load even if the package is missing — endpoints then
  return the same 503 they'd return for a missing API key.
"""
import ipaddress
import json
import os
from datetime import datetime, timedelta, timezone
from flask import Blueprint, current_app, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.models import db
from dashboard.backend.shodan.models import ShodanLookup

try:
    from shodan import Shodan as _ShodanClient
    from shodan import APIError as _ShodanAPIError
    _SHODAN_LIB_AVAILABLE = True
except ImportError:
    _ShodanClient    = None
    _ShodanAPIError  = Exception
    _SHODAN_LIB_AVAILABLE = False

shodan_bp = Blueprint("shodan", __name__)


# ── Constants ────────────────────────────────────────────────
CACHE_TTL = timedelta(hours=24)
SHODAN_API_KEY_ENV = "SHODAN_API_KEY"

NOT_CONFIGURED_MESSAGE = (
    "Shodan not configured — set SHODAN_API_KEY in the environment."
)

# Subset of the raw Shodan host record that the frontend needs.
# Prevents leaking the full ~100-key payload into the response and
# makes the contract obvious. Anything not in this list stays in
# raw_json for advanced consumers; the normalised view is what the
# UI binds to.
HOST_FIELDS = (
    "ip_str", "hostnames", "country_name", "city", "org", "isp",
    "asn", "ports", "tags", "vulns", "last_update", "os",
)


# ── Helpers ──────────────────────────────────────────────────

def _api_key():
    """Return the current Shodan API key or '' when unset.

    Read at call time (not module-load time) so tests can monkeypatch
    os.environ between requests without re-importing the module.
    """
    return os.environ.get(SHODAN_API_KEY_ENV, "") or ""


def _is_configured():
    return bool(_api_key()) and _SHODAN_LIB_AVAILABLE


def _not_configured_response():
    """Standard 503 payload when SHODAN_API_KEY isn't set, OR when
    the `shodan` PyPI package isn't installed. Mirrors PLB-4 / PLB-5
    skip-if-no-creds shape."""
    return jsonify({
        "configured": False,
        "message":    NOT_CONFIGURED_MESSAGE,
        "lib_available": _SHODAN_LIB_AVAILABLE,
    }), 503


def _is_valid_ip(ip):
    """RFC-clean IPv4/IPv6 address (no CIDR, no hostname)."""
    if not ip:
        return False
    try:
        ipaddress.ip_address(ip)
        return True
    except (ValueError, TypeError):
        return False


def _normalise_host(raw):
    """Pick a stable subset out of Shodan's host response.

    Shodan returns ~100 keys per host record, with shape variations
    by service module. The frontend renders a fixed card; binding it
    to a stable subset is more robust than passing through the full
    blob. The full record is still available via cache.raw_json for
    advanced consumers.
    """
    if not isinstance(raw, dict):
        return {}
    out = {}
    for k in HOST_FIELDS:
        if k in raw:
            out[k] = raw[k]
    # Renames so the API uses our naming convention.
    if "ip_str" in out:
        out["ip"] = out.pop("ip_str")
    if "country_name" in out:
        out["country"] = out.pop("country_name")
    return out


def _local_scan_for_ip(user_id, ip):
    """Pull the latest local nmap data for this IP from
    real_scan_results, scoped to the calling user. Returns None if
    no scan has touched the IP."""
    from dashboard.backend.real_scanner.routes import RealScanResult
    scans = (RealScanResult.query
             .filter_by(user_id=user_id, status="complete")
             .order_by(RealScanResult.finished_at.desc().nullslast())
             .limit(20)
             .all())
    for scan in scans:
        try:
            results = json.loads(scan.results_json or "[]")
        except (ValueError, TypeError):
            continue
        if not isinstance(results, list):
            continue
        for host in results:
            if isinstance(host, dict) and host.get("ip") == ip:
                return host
    return None


def _cache_hit(row):
    """True if the cache row is fresher than CACHE_TTL."""
    if row is None or row.looked_up_at is None:
        return False
    age = datetime.utcnow() - row.looked_up_at
    return age < CACHE_TTL


def _meta_dict(row):
    if not row or not row.node_meta:
        return {}
    try:
        return json.loads(row.node_meta) or {}
    except (ValueError, TypeError):
        return {}


def _set_meta(row, **kwargs):
    """Merge kwargs into row.node_meta JSON. Defensive against
    pre-existing malformed JSON."""
    meta = _meta_dict(row)
    meta.update(kwargs)
    row.node_meta = json.dumps(meta, default=str)


def _do_shodan_lookup(ip):
    """Call the live Shodan API for a host. Caller has already
    confirmed _is_configured() is True. Returns:

        ("ok",        host_dict)  on a successful lookup
        ("not_found", None)        when Shodan has no data for the IP
        ("error",     "<msg>")     on any other API failure

    Never raises into the caller; an unexpected error becomes
    ("error", str(e)) so the route can shape it into a 200 with
    cached negative result OR a 502 as preferred.
    """
    try:
        client = _ShodanClient(_api_key())
        data = client.host(ip)
        return ("ok", data)
    except _ShodanAPIError as e:
        msg = str(e) or "Shodan API error"
        # The official lib raises APIError("No information available")
        # for unindexed IPs; treat that as a negative result, not a
        # hard failure.
        if "No information available" in msg or "not found" in msg.lower():
            return ("not_found", None)
        return ("error", msg)
    except Exception as e:  # noqa: BLE001 — we genuinely don't want a
        # transient socket / DNS / SSL failure to 500 the whole route
        return ("error", str(e) or e.__class__.__name__)


# ── Routes ───────────────────────────────────────────────────

@shodan_bp.route("/api/shodan/lookup/<ip>", methods=["GET"])
@jwt_required()
def lookup(ip):
    """Look up an IP via Shodan, transparently caching for 24 hours.

    Response shape (HTTP 200):
        {
          "ip": "...",                    # echoed input
          "configured": true,
          "source": "cache" | "shodan",   # where the data came from
          "looked_up_at": "<iso>",        # cache row timestamp
          "found": true | false,          # Shodan had data?
          "shodan": { …normalised… },     # subset of fields, or {}
          "raw":    { …full payload… },   # full Shodan JSON, or {}
          "local_scan": { …scan host… }   # latest local nmap, or null
        }

    HTTP 400 if `ip` isn't a parseable IP address.
    HTTP 503 if SHODAN_API_KEY is unset OR the shodan lib is missing.
    """
    if not _is_valid_ip(ip):
        return jsonify({"error": "invalid_ip", "ip": ip}), 400

    if not _is_configured():
        return _not_configured_response()

    user_id = int(get_jwt_identity())
    row = ShodanLookup.query.get(ip)

    # ── Cache hit ──
    if _cache_hit(row):
        try:
            raw = json.loads(row.raw_json or "{}")
        except (ValueError, TypeError):
            raw = {}
        meta = _meta_dict(row)
        return jsonify({
            "ip":           ip,
            "configured":   True,
            "source":       "cache",
            "looked_up_at": row.looked_up_at.isoformat() if row.looked_up_at
                            else None,
            "found":        bool(meta.get("found", True)),
            "shodan":       _normalise_host(raw),
            "raw":          raw,
            "local_scan":   _local_scan_for_ip(user_id, ip),
        }), 200

    # ── Cache miss → live lookup ──
    status, payload = _do_shodan_lookup(ip)

    if status == "error":
        # We don't poison the cache with transient errors; let the
        # next request retry. Surface the message verbatim.
        return jsonify({
            "ip":         ip,
            "configured": True,
            "source":     "shodan",
            "error":      "lookup_failed",
            "message":    payload,
        }), 502

    found = (status == "ok")
    raw   = payload if found else {}

    if row is None:
        row = ShodanLookup(ip=ip, raw_json="{}")
        db.session.add(row)

    row.raw_json = json.dumps(raw, default=str)
    row.looked_up_at = datetime.utcnow()
    existing_meta = _meta_dict(row)
    _set_meta(
        row,
        found              = found,
        first_looked_up_by = existing_meta.get("first_looked_up_by", user_id),
        last_looked_up_by  = user_id,
        lookup_count       = int(existing_meta.get("lookup_count", 0)) + 1,
    )
    db.session.commit()

    return jsonify({
        "ip":           ip,
        "configured":   True,
        "source":       "shodan",
        "looked_up_at": row.looked_up_at.isoformat(),
        "found":        found,
        "shodan":       _normalise_host(raw),
        "raw":          raw,
        "local_scan":   _local_scan_for_ip(user_id, ip),
    }), 200


@shodan_bp.route("/api/shodan/cache", methods=["GET"])
@jwt_required()
def list_cache():
    """List every cache entry. Cache is global (Shodan data is the
    same for everyone) so no user filter is applied; node_meta
    records the user IDs that contributed to each entry for audit."""
    rows = (ShodanLookup.query
            .order_by(ShodanLookup.looked_up_at.desc())
            .all())
    return jsonify({
        "entries": [r.to_dict() for r in rows],
        "count":   len(rows),
    })


@shodan_bp.route("/api/shodan/cache/<ip>", methods=["DELETE"])
@jwt_required()
def clear_cache_entry(ip):
    """Delete one cache row by IP. Idempotent: 200 even if the row
    didn't exist (the post-condition is what the user wants — the
    entry is gone)."""
    if not _is_valid_ip(ip):
        return jsonify({"error": "invalid_ip", "ip": ip}), 400
    row = ShodanLookup.query.get(ip)
    if row is not None:
        db.session.delete(row)
        db.session.commit()
        return jsonify({"success": True, "deleted": True, "ip": ip}), 200
    return jsonify({"success": True, "deleted": False, "ip": ip}), 200


@shodan_bp.route("/api/shodan/status", methods=["GET"])
@jwt_required()
def status():
    """Health/configuration probe. Always returns 200 — even when
    the key is unset or the lib is missing — so the frontend can
    render a "configure Shodan" prompt instead of a generic error.

    Quota information requires a live API call (`info()`); when the
    key is configured we make it (cheap; no quota cost), when not
    we omit `quota`.
    """
    cache_count = ShodanLookup.query.count()
    body = {
        "configured":     _is_configured(),
        "lib_available":  _SHODAN_LIB_AVAILABLE,
        "cache_count":    cache_count,
        "cache_ttl_hours":int(CACHE_TTL.total_seconds() // 3600),
    }
    if not _is_configured():
        body["message"] = NOT_CONFIGURED_MESSAGE
        return jsonify(body), 200

    try:
        client = _ShodanClient(_api_key())
        info = client.info()
        # `info` is dict with query_credits, scan_credits,
        # monitored_ips, plan, etc.
        body["quota"] = info
    except Exception as e:  # noqa: BLE001
        body["quota_error"] = str(e) or e.__class__.__name__

    return jsonify(body), 200
