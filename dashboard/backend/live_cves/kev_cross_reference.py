"""
AIPET X — CISA KEV Cross-Reference

Checks a scanned host's CVEs against the locally-cached kev_catalog table.
All lookups are local DB queries — no live CISA API calls per request.

Cross-reference is a single IN-query: O(1) DB roundtrips regardless of
how many CVEs the host has.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone


def check_host_cves_against_kev(user_id: int, host_ip: str) -> dict:
    """
    Cross-reference a scanned host's CVEs against the local kev_catalog.

    Steps:
      1. Fetch the most recent completed real_scan_results row for this user+IP.
      2. Extract all CVE IDs from that scan's results_json.
      3. Single IN-query against kev_catalog — no per-CVE roundtrips.
      4. Build structured result.

    Returns one of:
      {"status": "checked", "host_ip": ..., "host_total_cves": N,
       "kev_hits_count": M, "kev_hits": [...], ...}
      {"status": "no_scan_data", "host_ip": ...}
      {"status": "no_kev_data",  "host_ip": ..., "kev_catalog_size": 0}

    NEVER fakes a KEV hit.
    """
    from dashboard.backend.real_scanner.routes import RealScanResult
    from dashboard.backend.live_cves.models import KevCatalogEntry

    # Search recent completed scans for one that contains host_ip.
    # We check up to 50 recent scans so we find the host even when
    # other scans exist for the same user (e.g. different targets).
    recent_scans = (
        RealScanResult.query
        .filter_by(user_id=user_id, status="complete")
        .order_by(RealScanResult.started_at.desc())
        .limit(50)
        .all()
    )
    if not recent_scans:
        return {"status": "no_scan_data", "host_ip": host_ip}

    # Extract CVE IDs from the most-recent scan that contains host_ip
    cve_ids: list[str] = []
    found_in_scan = False
    for scan in recent_scans:
        try:
            hosts = json.loads(scan.results_json or "[]")
            for host in hosts:
                if host.get("ip") == host_ip:
                    found_in_scan = True
                    for cve in host.get("cves", []):
                        cid = cve.get("cve_id") or cve.get("id", "")
                        if cid:
                            cve_ids.append(cid)
            if found_in_scan:
                break
        except (json.JSONDecodeError, TypeError):
            pass

    if not found_in_scan:
        return {"status": "no_scan_data", "host_ip": host_ip}

    kev_size = KevCatalogEntry.query.count()
    if kev_size == 0:
        return {"status": "no_kev_data", "host_ip": host_ip, "kev_catalog_size": 0}

    # Single IN-query — fast with indexed PK
    hits: list[KevCatalogEntry] = []
    if cve_ids:
        hits = KevCatalogEntry.query.filter(
            KevCatalogEntry.cve_id.in_(cve_ids)
        ).all()

    # Sort: ransomware-associated first, then by date_added desc
    hits.sort(
        key=lambda h: (
            0 if h.known_ransomware_use == "Known" else 1,
            h.date_added.isoformat() if h.date_added else "",
        ),
        reverse=False,
    )

    ransomware_count = sum(1 for h in hits if h.known_ransomware_use == "Known")

    kev_hits_dicts = [_hit_dict(h) for h in hits[:10]]
    result = {
        "status":                    "checked",
        "host_ip":                   host_ip,
        "host_total_cves":           len(cve_ids),
        "kev_hits_count":            len(hits),
        "kev_hits":                  kev_hits_dicts,
        "ransomware_associated_count": ransomware_count,
        "checked_at":                datetime.now(timezone.utc).isoformat(),
        "kev_catalog_size":          kev_size,
    }

    # ── Capability 7a: emit central event (KEV hits only) ────────────────────
    if hits:
        try:
            from dashboard.backend.central_events.adapter import emit_event
            _mitre = None
            try:
                from dashboard.backend.mitre_attack.mitre_mapper import (
                    from_kev_hit, aggregate_techniques,
                )
                _mappings = []
                for h in hits[:5]:
                    cwes = [str(c) for c in (h.cwes or [])]
                    _mappings.extend(from_kev_hit(h.cve_id, cwes))
                _mitre = aggregate_techniques(_mappings) if _mappings else None
            except Exception:
                pass

            sev = "critical" if ransomware_count > 0 else "high"
            first_cve = hits[0].cve_id
            emit_event(
                source_module    = "live_cves",
                source_table     = "kev_catalog",
                source_row_id    = first_cve,
                event_type       = "kev_active_exploitation_detected",
                severity         = sev,
                user_id          = user_id,
                entity           = host_ip,
                entity_type      = "device",
                title            = (
                    f"{len(hits)} actively-exploited CVE"
                    f"{'s' if len(hits) > 1 else ''} detected on {host_ip}"
                ),
                mitre_techniques = _mitre,
                payload          = {
                    "kev_hits":                   kev_hits_dicts[:5],
                    "ransomware_associated_count": ransomware_count,
                    "host_total_cves":             len(cve_ids),
                },
            )
        except Exception:
            pass

    return result


def _hit_dict(entry: "KevCatalogEntry") -> dict:
    return {
        "cve_id":               entry.cve_id,
        "vulnerability_name":   entry.vulnerability_name,
        "vendor_project":       entry.vendor_project,
        "product":              entry.product,
        "date_added":           entry.date_added.isoformat() if entry.date_added else None,
        "due_date":             entry.due_date.isoformat() if entry.due_date else None,
        "known_ransomware_use": entry.known_ransomware_use,
        "short_description":    entry.short_description,
        "required_action":      entry.required_action,
    }
