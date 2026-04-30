"""
AIPET X — Attack Path Modelling Routes (Capability 14, v1)

Endpoints:
  GET    /api/attackpath/analyses         — list analyses (owner-filtered)
  POST   /api/attackpath/analyse          — run analysis from real scan data
  GET    /api/attackpath/analyses/<id>    — analysis + paths
  DELETE /api/attackpath/analyses/<id>    — delete
  GET    /api/attackpath/stats            — aggregate metrics

Capability 14 v1 ships REAL exploit-path mapping: paths are derived from
the calling user's recent RealScanResult rows, anchored to real CVE rows
(LiveCve + KevCatalogEntry), tagged with MitreTechnique IDs from the
seeded mitre_techniques catalog, and scored from real factors. The legacy
hardcoded TECHNIQUES / ZONES / attack_chains demo data was removed in
the same commit that introduced this routing — see
verification/state-of-system/02-verification-results.md for the prior
"mechanically registered but stub" classification.

Per Capability 14 spec adopted 2026-04-30:
- Entry points: hosts with TCP {22,23,80,443,3389,8080} open OR risk >= 60
- Targets: hosts ranked by (device_risk_score + 10 * KEV-listed-CVE count)
- Each step anchored to a real cve_id from live_cves / kev_catalog
- MITRE technique selected per nmap service via _service_to_technique
- Likelihood: simple average of cvss/10, KEV-listed flag, exploit_public,
  device_risk/100 — clamped to [0, 100]
- Owner filter on /analyses GET only; per-resource owner enforcement on
  GET-by-id / DELETE-by-id is deferred (full multi-tenant tracked
  separately as the wider "Pattern A → Pattern C" carry-over)
"""
import json
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.models import db
from dashboard.backend.attackpath.models import ApAnalysis, ApPath
from dashboard.backend.real_scanner.routes import RealScanResult
from dashboard.backend.live_cves.models import LiveCve, KevCatalogEntry
from dashboard.backend.risk_engine.models import DeviceRiskScore

attackpath_bp = Blueprint("attackpath", __name__)


# ── Constants ────────────────────────────────────────────────
# Internet-facing TCP ports treated as candidate initial-access surfaces.
# Kept as a module-level frozenset for fast membership lookup.
ENTRY_PORTS = frozenset({22, 23, 80, 443, 3389, 8080})

# Cap on how many entry points and targets a single analysis fans out
# across. v1 favours readability over exhaustiveness; raising these is
# cheap once the v1 review establishes the path-quality bar.
MAX_ENTRIES = 5
MAX_TARGETS = 5

# Risk score above which a host without an entry-port is still treated
# as a candidate entry point. Matches the spec ("device_risk_score >= 60").
ENTRY_RISK_FLOOR = 60

# Severity buckets keyed off computed likelihood. Matches the same
# 70/50 cuts the existing _serialize_member-style frontend expects.
SEVERITY_CRITICAL = 70
SEVERITY_HIGH     = 50

# Path is marked .blocked when likelihood is below this — the frontend
# renders blocked paths in a muted style. Below the bucket floor for
# a reason: a Medium-severity unlikely-but-possible path stays visible.
BLOCKED_LIKELIHOOD = 40


# ── Helpers ──────────────────────────────────────────────────

def _service_to_technique(service):
    """Map an nmap-detected service name to a MITRE ATT&CK technique ID.

    Returns the technique_id only — callers join against mitre_techniques
    if they need the full record. Default falls through to T1190
    (Exploit Public-Facing Application) which is the broadest fit and
    lines up with how most internet-edge findings would be classified
    in practice.
    """
    s = (service or "").lower()
    # Brute-forceable shells / remote login
    if s in ("ssh", "telnet", "ftp"):
        return "T1110"
    # Remote desktop / Windows-style remote services
    if s in ("ms-wbt-server", "rdp"):
        return "T1021"
    # Web / HTTP family — exploit public-facing app
    if s in ("http", "https", "http-proxy", "http-alt", "ssl/http"):
        return "T1190"
    # Mail surfaces — phishing-adjacent intrusion vector
    if s in ("smtp", "smtps", "imap", "imaps", "pop3", "pop3s"):
        return "T1566"
    # Network services scanned to plan further moves
    if s in ("snmp", "snmptrap"):
        return "T1046"
    # IoT / OT messaging — sniffing or lateral injection
    if s in ("mqtt", "modbus", "iec-104"):
        return "T1040"
    # Database services — typically exploited via web app chain
    if s in ("mysql", "postgresql", "mssql", "mongodb", "redis"):
        return "T1190"
    return "T1190"


def _extract_cve_id(cve_entry):
    """Tolerate both dict and string CVE shapes in scan results_json.

    real_scanner emits CVE entries as dicts ({"cve_id": ..., "cvss_score": ..});
    older/external feeds may return bare strings. Returns the CVE ID or None.
    """
    if isinstance(cve_entry, dict):
        return cve_entry.get("cve_id") or cve_entry.get("id")
    if isinstance(cve_entry, str):
        return cve_entry
    return None


def _enrich_cve(cve_id):
    """Look up a CVE in live_cves + kev_catalog.

    Returns (cvss_score: float, kev_listed: bool, exploit_public: bool).
    Defaults: cvss=5.0 (mid-range when unknown), kev_listed=False,
    exploit_public=False. KEV-listing is treated as proof of public
    exploitation — KEV is CISA's "actively exploited" catalogue.
    """
    if not cve_id:
        return 5.0, False, False
    live = LiveCve.query.filter_by(cve_id=cve_id).first()
    kev  = KevCatalogEntry.query.filter_by(cve_id=cve_id).first()
    cvss = (live.cvss_score if live and live.cvss_score is not None else 5.0)
    kev_listed = kev is not None
    exploit_public = kev_listed
    return cvss, kev_listed, exploit_public


def _likelihood_from_factors(cvss, kev_listed, exploit_public, device_risk):
    """Simple unweighted average of four normalised factors → 0-100 int.

    Each factor lands in [0, 1]:
      cvss/10            — CVSS scores are 0.0-10.0
      kev_listed         — 1.0 if listed, 0.0 otherwise
      exploit_public     — 1.0 if public exploit known, 0.0 otherwise
      device_risk/100    — DeviceRiskScore is 0-100

    Equal weighting is the v1 baseline. The factor list is intentionally
    short so future calibration (e.g. doubling the KEV weight) is one
    constant change.
    """
    factors = [
        max(0.0, min(1.0, (cvss or 0) / 10.0)),
        1.0 if kev_listed else 0.0,
        1.0 if exploit_public else 0.0,
        max(0.0, min(1.0, (device_risk or 0) / 100.0)),
    ]
    avg = sum(factors) / len(factors)
    return max(0, min(100, int(round(avg * 100))))


def _severity_from_likelihood(likelihood):
    if likelihood >= SEVERITY_CRITICAL:
        return "Critical"
    if likelihood >= SEVERITY_HIGH:
        return "High"
    return "Medium"


def _collect_user_hosts(user_id):
    """Flatten all hosts across the user's most recent complete scans.

    Returns dict[ip] -> host_dict. Dedupes by IP, keeping the freshest
    record across scans. Empty dict if the user has no scans or no
    hosts in any scan.
    """
    scans = (RealScanResult.query
             .filter_by(user_id=user_id, status="complete")
             .order_by(RealScanResult.finished_at.desc().nullslast())
             .limit(20)
             .all())
    hosts_by_ip = {}
    for scan in scans:
        try:
            results = json.loads(scan.results_json or "[]")
        except (ValueError, TypeError):
            continue
        if not isinstance(results, list):
            continue
        for host in results:
            if not isinstance(host, dict):
                continue
            ip = host.get("ip")
            if not ip:
                continue
            if ip not in hosts_by_ip:
                hosts_by_ip[ip] = host
    return hosts_by_ip


def _generate_attack_paths(user_id, scope=None):
    """Generate ApPath rows from the calling user's real scan data.

    Returns a list of unsaved ApPath instances (caller assigns
    analysis_id and commits). Returns [] when there's not enough real
    data to draw a meaningful path — that is honest behaviour, not a
    fallback to demo content. The hardcoded chains the previous
    implementation emitted are intentionally gone.

    The `scope` parameter is accepted for forward compatibility (the
    request route still passes it through to ApAnalysis.scope) but is
    not yet used to filter the host set; per-zone scope filtering is a
    v1.1 nicety.
    """
    hosts_by_ip = _collect_user_hosts(user_id)
    if not hosts_by_ip:
        return []

    risk_lookup = {
        r.entity: r.score
        for r in DeviceRiskScore.query.filter_by(
            user_id=user_id, entity_type="device"
        ).all()
    }

    # ── Entry points ──
    entry_ips = []
    for ip, host in hosts_by_ip.items():
        ports = {p.get("port") for p in (host.get("open_ports") or [])
                 if isinstance(p, dict)}
        risk = risk_lookup.get(ip) or host.get("risk_score") or 0
        if (ports & ENTRY_PORTS) or risk >= ENTRY_RISK_FLOOR:
            entry_ips.append(ip)
    if not entry_ips:
        return []

    # ── Target ranking ──
    # Score = device_risk + 10*KEV_CVE_count. Pre-fetch all KEV-listed
    # CVE IDs the user's hosts mention, in one IN-query, to avoid the
    # N+1 lookup that an inline KEV check would produce.
    all_cve_ids = set()
    for host in hosts_by_ip.values():
        for c in (host.get("cves") or []):
            cid = _extract_cve_id(c)
            if cid:
                all_cve_ids.add(cid)
    kev_hits = set()
    if all_cve_ids:
        kev_hits = {
            row.cve_id
            for row in KevCatalogEntry.query.filter(
                KevCatalogEntry.cve_id.in_(all_cve_ids)
            ).all()
        }

    def _target_rank(host):
        ip = host.get("ip")
        risk = risk_lookup.get(ip) or host.get("risk_score") or 0
        cve_ids = [
            _extract_cve_id(c) for c in (host.get("cves") or [])
        ]
        host_kev_count = sum(1 for cid in cve_ids if cid in kev_hits)
        return risk + 10 * host_kev_count

    targets_sorted = sorted(hosts_by_ip.values(), key=_target_rank, reverse=True)
    target_ips = [
        h["ip"] for h in targets_sorted[:MAX_TARGETS] if h.get("ip")
    ]
    # Strip entry-only collisions when multiple targets exist; if the
    # only target IS the entry, allow same-host self-target (rare but
    # legitimate when a user scans a single high-risk host).
    if len(target_ips) > 1:
        target_ips = [t for t in target_ips if t not in entry_ips] or target_ips[:1]

    # ── Build paths ──
    paths = []
    for entry_ip in entry_ips[:MAX_ENTRIES]:
        entry_host = hosts_by_ip[entry_ip]
        entry_ports = [p for p in (entry_host.get("open_ports") or [])
                       if isinstance(p, dict)]
        if not entry_ports:
            continue

        # Prefer an exposed entry port; else first port the scan saw.
        entry_port = next(
            (p for p in entry_ports if p.get("port") in ENTRY_PORTS),
            entry_ports[0],
        )
        entry_service = (entry_port.get("service") or "unknown")
        entry_technique = _service_to_technique(entry_service)
        entry_cve_id = next(
            (_extract_cve_id(c) for c in (entry_host.get("cves") or [])
             if _extract_cve_id(c)),
            None,
        )

        # Pair each entry with the first target that's not itself
        # (preserving the "self-target if only-one-host" allowance).
        target_ip = next((t for t in target_ips if t != entry_ip),
                         target_ips[0] if target_ips else entry_ip)
        target_host = hosts_by_ip.get(target_ip, entry_host)
        target_ports = [p for p in (target_host.get("open_ports") or [])
                        if isinstance(p, dict)]
        target_port = target_ports[0] if target_ports else None
        target_service = ((target_port.get("service") if target_port else None)
                          or "unknown")
        target_technique = _service_to_technique(target_service)
        target_cve_id = next(
            (_extract_cve_id(c) for c in (target_host.get("cves") or [])
             if _extract_cve_id(c)),
            None,
        )

        # ── Chain construction ──
        chain = []
        techniques = []

        chain.append({
            "device":    entry_ip,
            "action":    (
                f"Exploit {entry_service} on port {entry_port.get('port')} "
                f"(CVE {entry_cve_id})" if entry_cve_id
                else f"Exploit {entry_service} on port {entry_port.get('port')}"
            ),
            "technique": entry_technique,
            "cve_id":    entry_cve_id,
            "zone":      "scanned",
        })
        techniques.append(entry_technique)

        if target_ip != entry_ip:
            chain.append({
                "device":    target_ip,
                "action":    (
                    f"Pivot to {target_ip} via {target_service} "
                    f"(CVE {target_cve_id})" if target_cve_id
                    else f"Pivot to {target_ip} via {target_service}"
                ),
                "technique": target_technique,
                "cve_id":    target_cve_id,
                "zone":      "scanned",
            })
            techniques.append(target_technique)

        # KEV-anchored impact step — only emitted when the target's CVE
        # is on the KEV list, so the path's third step is always a real
        # actively-exploited finding when present.
        kev_match = bool(target_cve_id and target_cve_id in kev_hits)
        if kev_match:
            chain.append({
                "device":    target_ip,
                "action": (
                    f"Execute KEV-listed exploit (CVE {target_cve_id} "
                    "actively exploited per CISA)"
                ),
                "technique": "T1565",  # Data Manipulation — impact tactic
                "cve_id":    target_cve_id,
                "zone":      "scanned",
            })
            techniques.append("T1565")

        # ── Likelihood / severity / impact text ──
        # Prefer the target CVE for scoring (the path's payoff); fall
        # back to the entry CVE if the target had none. Same-host paths
        # collapse to a single CVE which gets used twice — fine.
        score_cve_id = target_cve_id or entry_cve_id
        cvss, kev_listed, exploit_public = _enrich_cve(score_cve_id)
        device_risk = (risk_lookup.get(target_ip)
                       or target_host.get("risk_score") or 0)
        likelihood = _likelihood_from_factors(
            cvss, kev_listed, exploit_public, device_risk
        )
        severity = _severity_from_likelihood(likelihood)
        impact_text = (
            f"KEV-listed CVE {target_cve_id} exploitation"
            if kev_match else
            f"Service compromise on {target_ip}"
        )

        paths.append(ApPath(
            entry_point = entry_ip,
            target      = target_ip,
            severity    = severity,
            hops        = len(chain),
            chain       = json.dumps(chain),
            techniques  = json.dumps(techniques),
            likelihood  = likelihood,
            impact      = impact_text,
            blocked     = likelihood < BLOCKED_LIKELIHOOD,
        ))

    return paths


# ── Routes ───────────────────────────────────────────────────

@attackpath_bp.route("/api/attackpath/analyses", methods=["GET"])
@jwt_required()
def list_analyses():
    """Owner-filtered list. Per Capability 14 v1 spec — list is the
    only endpoint with the filter; per-resource get/delete remain
    open pending the wider multi-tenant pass."""
    user_id = int(get_jwt_identity())
    analyses = (ApAnalysis.query
                .filter_by(created_by=user_id)
                .order_by(ApAnalysis.created_at.desc())
                .all())
    return jsonify({"analyses": [a.to_dict() for a in analyses]})


@attackpath_bp.route("/api/attackpath/analyse", methods=["POST"])
@jwt_required()
def run_analysis():
    """Run a fresh analysis from the calling user's real scan data.

    Always returns 201 with the new analysis row, even when no paths
    were found — an empty path list is an honest report of "no real
    attack surface in your current scan inventory".
    """
    data  = request.get_json(silent=True) or {}
    name  = data.get("name") or (
        f"Attack Path Analysis "
        f"{datetime.now(timezone.utc).strftime('%Y-%m-%d')}"
    )
    scope = data.get("scope", "Full Network")
    user_id = int(get_jwt_identity())

    analysis = ApAnalysis(
        name       = name,
        scope      = scope,
        created_by = user_id,
    )
    db.session.add(analysis)
    db.session.flush()

    paths = _generate_attack_paths(user_id, scope=scope)
    for p in paths:
        p.analysis_id = analysis.id
        db.session.add(p)

    analysis.total_paths    = len(paths)
    analysis.critical_paths = sum(1 for p in paths if p.severity == "Critical")
    analysis.max_depth      = max((p.hops for p in paths), default=0)
    db.session.commit()

    return jsonify({
        "success":  True,
        "analysis": analysis.to_dict(),
        "paths":    [p.to_dict() for p in paths],
    }), 201


@attackpath_bp.route("/api/attackpath/analyses/<int:aid>", methods=["GET"])
@jwt_required()
def get_analysis(aid):
    analysis = ApAnalysis.query.get_or_404(aid)
    paths    = (ApPath.query
                .filter_by(analysis_id=aid)
                .order_by(ApPath.likelihood.desc())
                .all())
    data     = analysis.to_dict()
    data["paths"] = [p.to_dict() for p in paths]
    return jsonify(data)


@attackpath_bp.route("/api/attackpath/analyses/<int:aid>",
                     methods=["DELETE"])
@jwt_required()
def delete_analysis(aid):
    analysis = ApAnalysis.query.get_or_404(aid)
    ApPath.query.filter_by(analysis_id=aid).delete()
    db.session.delete(analysis)
    db.session.commit()
    return jsonify({"success": True})


@attackpath_bp.route("/api/attackpath/stats", methods=["GET"])
@jwt_required()
def attackpath_stats():
    analyses = ApAnalysis.query.all()
    all_paths = ApPath.query.all()
    return jsonify({
        "total_analyses":  len(analyses),
        "total_paths":     len(all_paths),
        "critical_paths":  sum(1 for p in all_paths if p.severity == "Critical"),
        "blocked_paths":   sum(1 for p in all_paths if p.blocked),
        "avg_hops":        round(
            sum(p.hops for p in all_paths) / max(len(all_paths), 1), 1
        ),
        "avg_likelihood":  round(
            sum(p.likelihood for p in all_paths) / max(len(all_paths), 1), 1
        ),
    })
