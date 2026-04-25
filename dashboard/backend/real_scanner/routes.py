# ============================================================
# AIPET X — Real Network Scanner
# Nmap-based discovery · CVE matching via NVD API
# ============================================================

import uuid, datetime, json, threading, time, requests
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.validation import validate_body, SCAN_TARGET_SCHEMA
from dashboard.backend.models import db
from sqlalchemy import Column, String, Integer, Text, DateTime, Float

real_scanner_bp = Blueprint("real_scanner", __name__)

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
SCAN_TIMEOUT = 300  # 5 min max per scan

# ── Models ────────────────────────────────────────────────

class RealScanResult(db.Model):
    __tablename__ = "real_scan_results"
    id          = Column(String(64), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id     = Column(Integer, nullable=False, index=True)
    target      = Column(String(256), nullable=False)
    status      = Column(String(32), default="pending")   # pending|running|complete|error
    started_at  = Column(DateTime, default=datetime.datetime.utcnow)
    finished_at = Column(DateTime, nullable=True)
    hosts_found = Column(Integer, default=0)
    cve_count   = Column(Integer, default=0)
    results_json= Column(Text, default="[]")
    error       = Column(Text, nullable=True)

    def to_dict(self):
        return {
            "id":          self.id,
            "target":      self.target,
            "status":      self.status,
            "started_at":  self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "hosts_found": self.hosts_found,
            "cve_count":   self.cve_count,
            "results":     json.loads(self.results_json or "[]"),
            "error":       self.error,
        }


# ── CVE lookup ────────────────────────────────────────────

def _fetch_cves(keyword: str, product: str = None) -> list:
    """Query NVD API for CVEs matching a keyword/product string."""
    try:
        params = {"keywordSearch": keyword, "resultsPerPage": 5}
        r = requests.get(NVD_API, params=params, timeout=8)
        if r.status_code != 200:
            return []
        data = r.json()
        cves = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            desc_list = cve.get("descriptions", [])
            desc = next((d["value"] for d in desc_list if d.get("lang") == "en"), "")
            metrics = cve.get("metrics", {})
            cvss_score = None
            severity = "UNKNOWN"
            # Try CVSSv3 first, then v2
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics and metrics[key]:
                    m = metrics[key][0]
                    if key.startswith("cvssMetricV3"):
                        cvss_score = m.get("cvssData", {}).get("baseScore")
                        severity = m.get("cvssData", {}).get("baseSeverity", "UNKNOWN")
                    else:
                        cvss_score = m.get("cvssData", {}).get("baseScore")
                        severity = m.get("baseSeverity", "UNKNOWN")
                    break
            published = cve.get("published", "")[:10]
            cves.append({
                "cve_id":    cve_id,
                "description": desc[:300],
                "cvss_score": cvss_score,
                "severity":   severity,
                "published":  published,
                "url":        f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            })
        return cves
    except Exception:
        return []


def _cve_severity_color(sev: str) -> str:
    return {"CRITICAL": "#ff2d55", "HIGH": "#ff6b00", "MEDIUM": "#ffd60a", "LOW": "#00e5ff"}.get(sev.upper(), "#555")


# ── Nmap scan ─────────────────────────────────────────────

def _run_nmap_scan(scan_id: str, target: str, user_id: int, app):
    """Run nmap in a background thread, update DB when done."""
    with app.app_context():
        scan_obj = RealScanResult.query.get(scan_id)
        if not scan_obj:
            return
        scan_obj.status = "running"
        db.session.commit()

        try:
            import nmap
            nm = nmap.PortScanner()
            # -sV: version detection, -O: OS detection, --top-ports 1000: speed,
            # -T4: aggressive timing, --script=banner: grab banners
            nm.scan(
                hosts=target,
                arguments="-sV -O -T4 --top-ports 1000 --script=banner",
                timeout=SCAN_TIMEOUT,
            )

            hosts_data = []
            total_cves = 0

            for host in nm.all_hosts():
                host_info = nm[host]
                status = host_info.state()
                if status != "up":
                    continue

                # Hostnames
                hostnames = [h["name"] for h in host_info.get("hostnames", []) if h.get("name")]

                # OS detection
                os_matches = host_info.get("osmatch", [])
                os_name = os_matches[0]["name"] if os_matches else "Unknown"
                os_accuracy = int(os_matches[0].get("accuracy", 0)) if os_matches else 0

                # Ports and services
                open_ports = []
                cve_keywords = set()

                for proto in host_info.all_protocols():
                    ports = sorted(host_info[proto].keys())
                    for port in ports:
                        pdata = host_info[proto][port]
                        if pdata.get("state") != "open":
                            continue
                        service = pdata.get("name", "unknown")
                        product = pdata.get("product", "")
                        version = pdata.get("version", "")
                        extra   = pdata.get("extrainfo", "")
                        banner  = ""
                        if "script" in pdata and "banner" in pdata["script"]:
                            banner = pdata["script"]["banner"][:200]

                        port_entry = {
                            "port":     port,
                            "proto":    proto,
                            "service":  service,
                            "product":  product,
                            "version":  version,
                            "extrainfo": extra,
                            "banner":   banner,
                        }
                        open_ports.append(port_entry)

                        # Build CVE keyword from product+version
                        if product:
                            kw = product
                            if version:
                                kw += f" {version.split(' ')[0]}"
                            cve_keywords.add(kw)
                        elif service and service not in ("tcpwrapped", "unknown"):
                            cve_keywords.add(service)

                # Fetch CVEs for discovered services (limit to 5 keywords to avoid rate-limiting)
                matched_cves = []
                for kw in list(cve_keywords)[:5]:
                    cves = _fetch_cves(kw)
                    for c in cves:
                        c["matched_keyword"] = kw
                    matched_cves.extend(cves)
                    if cves:
                        time.sleep(0.6)  # NVD rate limit: 5 req/30s unauthenticated

                # Deduplicate CVEs by cve_id
                seen = set()
                unique_cves = []
                for c in matched_cves:
                    if c["cve_id"] not in seen:
                        seen.add(c["cve_id"])
                        unique_cves.append(c)

                total_cves += len(unique_cves)

                risk_score = _calc_risk(open_ports, unique_cves)

                host_entry = {
                    "ip":           host,
                    "hostnames":    hostnames,
                    "status":       status,
                    "os":           os_name,
                    "os_accuracy":  os_accuracy,
                    "open_ports":   open_ports,
                    "port_count":   len(open_ports),
                    "cves":         unique_cves,
                    "cve_count":    len(unique_cves),
                    "risk_score":   risk_score,
                }
                if not open_ports:
                    host_entry["node_meta"] = {"no_open_ports": True}
                hosts_data.append(host_entry)

            hosts_data.sort(key=lambda h: h["risk_score"], reverse=True)

            scan_obj.status      = "complete"
            scan_obj.finished_at = datetime.datetime.utcnow()
            scan_obj.hosts_found = len(hosts_data)
            scan_obj.cve_count   = total_cves
            scan_obj.results_json = json.dumps(hosts_data)
            db.session.commit()

            try:
                from dashboard.backend.central_events.adapter import emit_event
                duration = (scan_obj.finished_at - scan_obj.started_at).total_seconds() if scan_obj.started_at else None
                emit_event(
                    source_module = "real_scanner",
                    source_table  = "real_scan_results",
                    source_row_id = scan_obj.id,
                    event_type    = "scan_completed",
                    severity      = "info",
                    user_id       = scan_obj.user_id,
                    entity        = scan_obj.target,
                    entity_type   = "scan_target",
                    title         = f"Scan completed for {scan_obj.target}",
                    payload       = {
                        "host_count":             scan_obj.hosts_found,
                        "cve_count":              scan_obj.cve_count,
                        "scan_duration_seconds":  duration,
                    },
                )
            except Exception:
                app.logger.exception("emit_event call site error in real_scanner")

        except Exception as e:
            scan_obj.status = "error"
            scan_obj.error  = str(e)
            scan_obj.finished_at = datetime.datetime.utcnow()
            db.session.commit()


def _calc_risk(ports: list, cves: list) -> int:
    score = 0
    risky = {21, 22, 23, 25, 80, 443, 445, 3389, 5900, 8080, 8443}
    for p in ports:
        if p["port"] in risky:
            score += 10
    for c in cves:
        s = c.get("cvss_score") or 0
        score += int(s * 5)
    return min(score, 100)


# ── Routes ────────────────────────────────────────────────

@real_scanner_bp.route("/api/real-scan/discover", methods=["POST"])
@jwt_required()
@validate_body(SCAN_TARGET_SCHEMA)
def start_discovery():
    from flask import current_app
    uid  = get_jwt_identity()
    data = request.get_json(silent=True) or {}
    target = data.get("target", "").strip()

    if not target:
        return jsonify({"error": "target required (e.g. 192.168.1.0/24 or 192.168.1.1)"}), 400

    # Basic validation — allow IP, CIDR, hostname
    import re
    if not re.match(r'^[\w.:/\-]+$', target):
        return jsonify({"error": "Invalid target format"}), 400

    # Create scan record
    scan = RealScanResult(
        id=str(uuid.uuid4()),
        user_id=uid,
        target=target,
        status="pending",
    )
    db.session.add(scan)
    db.session.commit()

    app = current_app._get_current_object()
    t = threading.Thread(target=_run_nmap_scan, args=(scan.id, target, uid, app), daemon=True)
    t.start()

    return jsonify({"scan_id": scan.id, "status": "pending", "target": target}), 202


@real_scanner_bp.route("/api/real-scan/history", methods=["GET"])
@jwt_required()
def scan_history():
    uid   = get_jwt_identity()
    scans = RealScanResult.query.filter_by(user_id=uid).order_by(RealScanResult.started_at.desc()).limit(20).all()
    return jsonify({"scans": [s.to_dict() for s in scans]}), 200


@real_scanner_bp.route("/api/real-scan/<scan_id>", methods=["GET"])
@jwt_required()
def get_scan(scan_id):
    uid  = get_jwt_identity()
    scan = RealScanResult.query.filter_by(id=scan_id, user_id=uid).first()
    if not scan:
        return jsonify({"error": "Not found"}), 404
    return jsonify(scan.to_dict()), 200


@real_scanner_bp.route("/api/real-scan/<scan_id>", methods=["DELETE"])
@jwt_required()
def delete_scan(scan_id):
    uid  = get_jwt_identity()
    scan = RealScanResult.query.filter_by(id=scan_id, user_id=uid).first()
    if not scan:
        return jsonify({"error": "Not found"}), 404
    db.session.delete(scan)
    db.session.commit()
    return jsonify({"deleted": True}), 200
