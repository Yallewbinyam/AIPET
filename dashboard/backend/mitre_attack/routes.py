# ============================================================
# AIPET X — MITRE ATT&CK Catalog Routes
# ============================================================

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.mitre_attack.models import MitreTechnique
from dashboard.backend.validation import MITRE_MAP_DETECTION_SCHEMA, validate_body

mitre_attack_bp = Blueprint("mitre_attack", __name__)


@mitre_attack_bp.route("/api/mitre/techniques", methods=["GET"])
@jwt_required()
def list_techniques():
    """
    GET /api/mitre/techniques?ids=T1110,T1078
    Returns full catalog entries.  No ids param → all techniques.
    """
    ids_param = request.args.get("ids", "").strip()
    if ids_param:
        ids = [i.strip().upper() for i in ids_param.split(",") if i.strip()]
        techniques = MitreTechnique.query.filter(
            MitreTechnique.technique_id.in_(ids)
        ).order_by(MitreTechnique.technique_id).all()
    else:
        techniques = MitreTechnique.query.order_by(MitreTechnique.technique_id).all()

    return jsonify({
        "techniques": [t.to_dict() for t in techniques],
        "count":      len(techniques),
    })


@mitre_attack_bp.route("/api/mitre/techniques/<technique_id>", methods=["GET"])
@jwt_required()
def get_technique(technique_id):
    """GET /api/mitre/techniques/T1110 — single technique or 404."""
    t = db.session.get(MitreTechnique, technique_id.upper())
    if t is None:
        return jsonify({"error": f"Technique {technique_id} not found in catalog"}), 404
    return jsonify(t.to_dict())


@mitre_attack_bp.route("/api/mitre/map_detection", methods=["POST"])
@jwt_required()
@validate_body(MITRE_MAP_DETECTION_SCHEMA)
def map_detection():
    """
    POST /api/mitre/map_detection
    Body: {detection_id: int, source: "ml_anomaly"|"behavioral"|"kev"|"otx"}

    Looks up the detection from its source table and applies the appropriate
    mapper — useful for re-mapping historical detections without rerunning predict_real.
    """
    body         = request.get_json(silent=True) or {}
    detection_id = int(body["detection_id"])
    source       = body["source"]
    user_id      = int(get_jwt_identity())

    from dashboard.backend.mitre_attack.mitre_mapper import (
        from_ml_features, from_behavioral_anomaly, aggregate_techniques,
    )

    mappings = []

    if source == "ml_anomaly":
        from dashboard.backend.ml_anomaly.models import AnomalyDetection
        import json
        det = db.session.get(AnomalyDetection, detection_id)
        if det is None or det.user_id != user_id:
            return jsonify({"error": "Detection not found"}), 404
        contribs = json.loads(det.top_contributors or "[]")
        mappings = from_ml_features(contribs)

    elif source == "behavioral":
        from dashboard.backend.behavioral.models import BaAnomaly
        anom = db.session.get(BaAnomaly, detection_id)
        if anom is None:
            return jsonify({"error": "Behavioral anomaly not found"}), 404
        mappings = from_behavioral_anomaly(anom.anomaly_type)

    aggregated = aggregate_techniques(mappings)
    return jsonify({
        "detection_id": detection_id,
        "source":        source,
        "techniques":    aggregated,
        "technique_count": len(aggregated),
    })


@mitre_attack_bp.route("/api/mitre/stats", methods=["GET"])
@jwt_required()
def mitre_stats():
    """
    GET /api/mitre/stats — catalog size + tactic distribution.
    """
    from sqlalchemy import func
    from dashboard.backend.models import db as _db

    total = MitreTechnique.query.count()
    by_tactic = (
        _db.session.query(MitreTechnique.tactic, func.count())
        .group_by(MitreTechnique.tactic)
        .order_by(func.count().desc())
        .all()
    )

    return jsonify({
        "total_techniques": total,
        "by_tactic": [{"tactic": t, "count": c} for t, c in by_tactic],
    })


# ── db reference (imported after blueprint definition to avoid circular) ─────
from dashboard.backend.models import db
