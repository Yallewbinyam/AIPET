# =============================================================
# AIPET X — Agent Scan Ingest Endpoint
# POST /api/agent/scan-results
# Accepts nmap XML or structured JSON from authenticated agents.
# Writes to real_scan_results (same table as cloud-side scanner).
# Idempotent via agent-provided scan_id.
# =============================================================

import uuid
import json
import datetime

from flask import Blueprint, request, jsonify, current_app

from ..models import db
from ..real_scanner.routes import RealScanResult
from ..agent_keys.auth import agent_key_required
from .models import AgentScanSubmission

agent_scan_ingest_bp = Blueprint("agent_scan_ingest", __name__)

MAX_SCAN_PAYLOAD_BYTES = 50 * 1024 * 1024  # 50 MB


# ── nmap XML parser ───────────────────────────────────────

def _parse_nmap_xml(xml_str: str) -> list:
    """
    Parse nmap XML output into the same host-list format used by
    real_scanner._run_nmap_scan (list of host dicts).
    Uses defusedxml for safe parsing.
    """
    try:
        import defusedxml.ElementTree as ET
    except ImportError:
        import xml.etree.ElementTree as ET  # fallback (less safe)

    try:
        root = ET.fromstring(xml_str)
    except Exception as exc:
        raise ValueError(f"Invalid nmap XML: {exc}") from exc

    hosts = []
    for host_el in root.findall("host"):
        state_el = host_el.find("status")
        if state_el is None or state_el.get("state") != "up":
            continue

        ip = ""
        for addr_el in host_el.findall("address"):
            if addr_el.get("addrtype") == "ipv4":
                ip = addr_el.get("addr", "")
                break
        if not ip:
            for addr_el in host_el.findall("address"):
                if addr_el.get("addrtype") == "ipv6":
                    ip = addr_el.get("addr", "")
                    break

        hostnames = []
        for hn_el in host_el.findall("hostnames/hostname"):
            name = hn_el.get("name", "")
            if name:
                hostnames.append(name)

        os_name = "Unknown"
        os_accuracy = 0
        osmatch_el = host_el.find("os/osmatch")
        if osmatch_el is not None:
            os_name = osmatch_el.get("name", "Unknown")
            os_accuracy = int(osmatch_el.get("accuracy", "0"))

        open_ports = []
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                state_p = port_el.find("state")
                if state_p is None or state_p.get("state") != "open":
                    continue
                portid = int(port_el.get("portid", "0"))
                proto = port_el.get("protocol", "tcp")
                svc = port_el.find("service")
                service = svc.get("name", "unknown") if svc is not None else "unknown"
                product = svc.get("product", "") if svc is not None else ""
                version = svc.get("version", "") if svc is not None else ""
                open_ports.append({
                    "port":    portid,
                    "proto":   proto,
                    "service": service,
                    "product": product,
                    "version": version,
                    "extrainfo": "",
                    "banner":  "",
                })

        host_dict = {
            "ip":          ip,
            "hostnames":   hostnames,
            "status":      "up",
            "os":          os_name,
            "os_accuracy": os_accuracy,
            "open_ports":  open_ports,
            "port_count":  len(open_ports),
            "cves":        [],
            "cve_count":   0,
            "risk_score":  _simple_risk(open_ports),
        }
        if not open_ports:
            host_dict["node_meta"] = {"no_open_ports": True}
        hosts.append(host_dict)

    return hosts


def _parse_json_scan(data: dict) -> list:
    """
    Accept structured JSON: {"hosts": [...]}
    Each host: {"ip", "ports": [{"port", "service", "proto"}], "cves": [...]}
    Normalise to the same format as nmap XML path.
    """
    raw_hosts = data.get("hosts", [])
    if not isinstance(raw_hosts, list):
        raise ValueError("'hosts' must be a list")

    hosts = []
    for h in raw_hosts:
        if not isinstance(h, dict):
            raise ValueError("Each host must be a dict")
        ip = str(h.get("ip", "")).strip()
        if not ip:
            raise ValueError("Each host must have an 'ip' field")

        raw_ports = h.get("ports", []) or []
        open_ports = []
        for p in raw_ports:
            if not isinstance(p, dict):
                continue
            open_ports.append({
                "port":      int(p.get("port", 0)),
                "proto":     str(p.get("proto", "tcp")),
                "service":   str(p.get("service", "unknown")),
                "product":   str(p.get("product", "")),
                "version":   str(p.get("version", "")),
                "extrainfo": str(p.get("extrainfo", "")),
                "banner":    str(p.get("banner", "")),
            })

        cves = [c for c in (h.get("cves") or []) if isinstance(c, dict)]

        host_dict = {
            "ip":          ip,
            "hostnames":   h.get("hostnames") or [],
            "status":      "up",
            "os":          str(h.get("os", "Unknown")),
            "os_accuracy": int(h.get("os_accuracy", 0)),
            "open_ports":  open_ports,
            "port_count":  len(open_ports),
            "cves":        cves,
            "cve_count":   len(cves),
            "risk_score":  _simple_risk(open_ports),
        }
        if not open_ports:
            host_dict["node_meta"] = {"no_open_ports": True}
        hosts.append(host_dict)

    return hosts


def _simple_risk(ports: list) -> int:
    """Mirrors real_scanner._calc_risk (no CVEs — agent provides own CVE data)."""
    risky = {21, 22, 23, 25, 80, 443, 445, 3389, 5900, 8080, 8443}
    score = sum(10 for p in ports if p.get("port") in risky)
    return min(score, 100)


# ── POST /api/agent/scan-results ──────────────────────────

@agent_scan_ingest_bp.route("/api/agent/scan-results", methods=["POST"])
@agent_key_required(permissions=["scan:write"])
def ingest_scan():
    from flask import g

    # Payload size guard
    content_length = request.content_length
    if content_length and content_length > MAX_SCAN_PAYLOAD_BYTES:
        return jsonify({"error": "Payload too large. Maximum 50 MB."}), 413

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "JSON body required"}), 400

    # Required fields
    scan_id = str(data.get("scan_id", "")).strip()
    fmt = str(data.get("format", "")).strip().lower()
    scan_data = data.get("scan_data")
    scan_meta = data.get("scan_metadata") or {}

    if not scan_id:
        return jsonify({"error": "'scan_id' is required"}), 422
    if len(scan_id) > 256:
        return jsonify({"error": "'scan_id' must be <= 256 chars"}), 422
    if fmt not in ("nmap_xml", "json"):
        return jsonify({"error": "'format' must be 'nmap_xml' or 'json'"}), 422
    if scan_data is None:
        return jsonify({"error": "'scan_data' is required"}), 422

    user_id = g.current_user_id
    agent_key_id = g.current_agent_key.id

    # Cross-tenant security: if scan_id exists but belongs to different user → 403
    existing_by_scanid = AgentScanSubmission.query.filter_by(scan_id=scan_id).first()
    if existing_by_scanid:
        if existing_by_scanid.user_id != user_id:
            return jsonify({"error": "Forbidden"}), 403
        # Idempotent — return existing record
        return jsonify({
            "scan_id":       scan_id,
            "real_scan_id":  existing_by_scanid.real_scan_id,
            "ingested_at":   existing_by_scanid.ingested_at.isoformat(),
            "duplicate":     True,
        }), 200

    # Parse scan data
    try:
        if fmt == "nmap_xml":
            if not isinstance(scan_data, str):
                return jsonify({"error": "'scan_data' must be a string for nmap_xml format"}), 422
            hosts = _parse_nmap_xml(scan_data)
        else:
            if not isinstance(scan_data, dict):
                return jsonify({"error": "'scan_data' must be an object for json format"}), 422
            hosts = _parse_json_scan(scan_data)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    # Build a RealScanResult row (same table as cloud scanner)
    target = str(scan_meta.get("target", "agent-scan")).strip()[:256] or "agent-scan"
    host_count = len(hosts)
    cve_count = sum(h.get("cve_count", len(h.get("cves", []))) for h in hosts)

    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    started_at = _parse_dt(scan_meta.get("started_at")) or now
    finished_at = _parse_dt(scan_meta.get("completed_at")) or now

    real_scan_id = str(uuid.uuid4())
    scan_row = RealScanResult(
        id=real_scan_id,
        user_id=user_id,
        target=target,
        status="complete",
        started_at=started_at,
        finished_at=finished_at,
        hosts_found=host_count,
        cve_count=cve_count,
        results_json=json.dumps(hosts),
        error=None,
    )
    db.session.add(scan_row)

    # Idempotency record
    submission = AgentScanSubmission(
        user_id=user_id,
        scan_id=scan_id,
        real_scan_id=real_scan_id,
        agent_key_id=agent_key_id,
    )
    db.session.add(submission)
    db.session.commit()

    # Emit central event (non-fatal)
    try:
        from dashboard.backend.central_events.adapter import emit_event
        emit_event(
            source_module="agent_scan_ingest",
            source_table="real_scan_results",
            source_row_id=real_scan_id,
            event_type="scan_completed",
            severity="info",
            user_id=user_id,
            entity=target,
            entity_type="scan_target",
            title=f"Agent scan completed for {target}",
            payload={
                "host_count": host_count,
                "cve_count":  cve_count,
                "scan_id":    scan_id,
                "format":     fmt,
            },
        )
    except Exception:
        current_app.logger.exception("emit_event failed in agent_scan_ingest (non-fatal)")

    return jsonify({
        "scan_id":      scan_id,
        "real_scan_id": real_scan_id,
        "host_count":   host_count,
        "cve_count":    cve_count,
        "ingested_at":  submission.ingested_at.isoformat(),
        "duplicate":    False,
    }), 200


# ── helpers ───────────────────────────────────────────────

def _parse_dt(val):
    if not val:
        return None
    try:
        s = str(val).replace("Z", "+00:00")
        return datetime.datetime.fromisoformat(s).replace(tzinfo=None)
    except (ValueError, TypeError):
        return None
