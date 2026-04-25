"""
AIPET X — ML Anomaly Detection Routes

Endpoints:
  GET  /api/ml/anomaly/features                    — feature order for the 12-vector
  POST /api/ml/anomaly/train                        — train Isolation Forest on synthetic data
  POST /api/ml/anomaly/predict                      — score a single IoT telemetry sample
  POST /api/ml/anomaly/predict_real                 — score a host from real scan data
  GET  /api/ml/anomaly/models                       — last 20 model versions
  GET  /api/ml/anomaly/detections                   — last N detections (cap 200)
  GET  /api/ml/anomaly/detections/<id>/explain      — full SHAP breakdown for one detection
  POST /api/ml/anomaly/retrain_now                  — queue retrain task via Celery
  GET  /api/ml/anomaly/retrain_status/<task_id>     — poll Celery task state
"""
import json
import math
import os
import uuid
from datetime import datetime, timezone

import numpy as np
from celery.result import AsyncResult
from flask import Blueprint, current_app, jsonify, request
from flask_jwt_extended import get_jwt_identity, jwt_required
from sklearn.metrics import f1_score, precision_score, recall_score

from dashboard.backend.ml_anomaly.detector import LATEST_PATH, AnomalyDetector
from dashboard.backend.ml_anomaly.explainer import clear_cache, get_explainer
from dashboard.backend.ml_anomaly.features import FEATURE_ORDER, to_vector
from dashboard.backend.ml_anomaly.models import AnomalyDetection, AnomalyModelVersion
from dashboard.backend.ml_anomaly.training_data import generate_synthetic
from dashboard.backend.models import db
from dashboard.backend.ml_anomaly.feature_extraction import extract_features_for_host
from dashboard.backend.validation import (
    ML_ANOMALY_EXTRACT_SCHEMA,
    ML_ANOMALY_PREDICT_REAL_SCHEMA,
    ML_ANOMALY_PREDICT_SCHEMA,
    ML_ANOMALY_TRAIN_SCHEMA,
    validate_body,
)

ml_anomaly_bp = Blueprint("ml_anomaly", __name__, url_prefix="/api/ml/anomaly")

N_ESTIMATORS = 100
RANDOM_STATE = 42


def _sigmoid(x: float, k: float = 5.0) -> float:
    # decision_function boundary is 0: negative = anomalous, positive = normal
    # After inversion: positive = anomalous; sigmoid centred at 0
    return 1.0 / (1.0 + math.exp(-k * x))


def _severity(score: float, is_anomaly: bool) -> str:
    if not is_anomaly:
        return "low"
    if score < 0.55:
        return "medium"
    if score < 0.75:
        return "high"
    return "critical"


def _load_active_detector():
    version = AnomalyModelVersion.query.filter_by(is_active=True).first()
    if not version:
        return None, None
    detector = AnomalyDetector()
    detector.load(version.model_path)
    return detector, version


# ---------------------------------------------------------------------------
# GET /features
# ---------------------------------------------------------------------------

@ml_anomaly_bp.route("/features", methods=["GET"])
@jwt_required()
def get_features():
    return jsonify({"features": FEATURE_ORDER, "count": len(FEATURE_ORDER)}), 200


# ---------------------------------------------------------------------------
# POST /train
# ---------------------------------------------------------------------------

@ml_anomaly_bp.route("/train", methods=["POST"])
@jwt_required()
@validate_body(ML_ANOMALY_TRAIN_SCHEMA)
def train():
    body = request.get_json(silent=True) or {}

    training_mode = body.get("training_mode", "synthetic")

    if training_mode == "real_scans":
        from dashboard.backend.real_scanner.routes import RealScanResult
        real_count = RealScanResult.query.filter_by(status="complete").count()
        if real_count < 20:
            return jsonify({
                "error": "insufficient real data — at least 20 completed scans required",
                "found": real_count,
            }), 400

    # Use caller-supplied overrides when provided; fall back to data-driven defaults
    n_estimators_override  = body.get("n_estimators")
    contamination_override = body.get("contamination")

    X, y = generate_synthetic(n_normal=5000, n_anomalous=250, seed=RANDOM_STATE)

    # Derive contamination from actual label counts so the value stays correct
    # even when generate_synthetic is monkeypatched with a smaller dataset.
    default_contamination = max(0.01, min(0.45, float(int(y.sum())) / len(X)))
    contamination = float(contamination_override) if contamination_override is not None \
                    else default_contamination
    n_estimators  = int(n_estimators_override) if n_estimators_override is not None \
                    else N_ESTIMATORS

    detector = AnomalyDetector()
    detector.fit(X, FEATURE_ORDER, contamination=contamination,
                 n_estimators=n_estimators, random_state=RANDOM_STATE)

    labels, _ = detector.predict(X)
    prec = float(precision_score(y, labels, zero_division=0))
    rec  = float(recall_score(y, labels,  zero_division=0))
    f1   = float(f1_score(y, labels,      zero_division=0))

    version_tag = datetime.now(timezone.utc).strftime("v%Y%m%d_%H%M%S") + "_" + uuid.uuid4().hex[:6]
    model_path  = os.path.join(
        os.path.dirname(__file__), "models_store", f"iforest_{version_tag}.joblib"
    )
    detector.save(model_path)
    detector.save(LATEST_PATH)

    AnomalyModelVersion.query.filter_by(is_active=True).update({"is_active": False})

    # Clear the SHAP explainer cache — the new model version invalidates old explainers.
    clear_cache()

    mv = AnomalyModelVersion(
        version_tag      = version_tag,
        algorithm        = "isolation_forest",
        contamination    = contamination,
        n_estimators     = n_estimators,
        feature_names    = json.dumps(FEATURE_ORDER),
        training_samples = len(X),
        precision_score  = prec,
        recall_score     = rec,
        f1_score         = f1,
        model_path       = model_path,
        is_active        = True,
        node_meta        = json.dumps({"training_mode": training_mode}),
    )
    db.session.add(mv)
    db.session.commit()

    return jsonify({
        "version":          version_tag,
        "training_samples": len(X),
        "metrics": {
            "precision": round(prec, 4),
            "recall":    round(rec,  4),
            "f1":        round(f1,   4),
        },
        "model_path": model_path,
    }), 200


# ---------------------------------------------------------------------------
# POST /predict
# ---------------------------------------------------------------------------

@ml_anomaly_bp.route("/predict", methods=["POST"])
@jwt_required()
@validate_body(ML_ANOMALY_PREDICT_SCHEMA)
def predict():
    current_user_id = int(get_jwt_identity())
    body = request.get_json() or {}

    target_ip     = body.get("target_ip", "")
    target_device = body.get("target_device", "")
    sample        = body.get("sample", {})

    detector, version = _load_active_detector()
    if detector is None:
        return jsonify({"error": "No trained model found. POST /train first."}), 400

    vec    = to_vector(sample)
    X      = vec.reshape(1, -1)
    labels, scores = detector.predict(X)

    raw_score     = float(scores[0])
    sigmoid_score = _sigmoid(raw_score)
    is_anomaly    = bool(labels[0] == 1)
    severity      = _severity(sigmoid_score, is_anomaly)

    # SHAP explainability (replaces z-score placeholder from Day 2)
    explainer = get_explainer(version.id, detector)
    all_contributors = explainer.explain(vec)          # full 12-feature breakdown
    top_contributors = all_contributors[:5]            # top 5 by |shap_value|

    detection = AnomalyDetection(
        model_version_id = version.id,
        user_id          = current_user_id,
        target_ip        = target_ip,
        target_device    = target_device,
        is_anomaly       = is_anomaly,
        anomaly_score    = round(sigmoid_score, 6),
        severity         = severity,
        feature_vector   = json.dumps(dict(zip(FEATURE_ORDER, vec.tolist()))),
        top_contributors = json.dumps(all_contributors),   # store full 12 for /explain
        node_meta        = json.dumps({
            "contributors_format": "shap_v1",
            "explainer_type":      explainer.explainer_type,
        }),
    )
    db.session.add(detection)
    db.session.commit()

    return jsonify({
        "detection_id":     detection.id,
        "target_ip":        target_ip,
        "target_device":    target_device,
        "is_anomaly":       is_anomaly,
        "anomaly_score":    round(sigmoid_score, 6),
        "severity":         severity,
        "top_contributors": top_contributors,
        "explainer_type":   explainer.explainer_type,
        "model_version":    version.version_tag,
    }), 200


# ---------------------------------------------------------------------------
# GET /models
# ---------------------------------------------------------------------------

@ml_anomaly_bp.route("/models", methods=["GET"])
@jwt_required()
def list_models():
    versions = (
        AnomalyModelVersion.query
        .order_by(AnomalyModelVersion.created_at.desc())
        .limit(20)
        .all()
    )
    return jsonify([v.to_dict() for v in versions]), 200


# ---------------------------------------------------------------------------
# GET /detections
# ---------------------------------------------------------------------------

@ml_anomaly_bp.route("/retrain_now", methods=["POST"])
@jwt_required()
def retrain_now():
    """Queue the retrain_anomaly_model task via Celery and return the task ID.

    Rate-limited in app_cloud.py (2 per hour / 10 per day) using the
    view_functions reassignment pattern — same as /train.
    Returns 202 Accepted immediately; client polls /retrain_status/<task_id>.
    """
    from dashboard.backend.tasks import retrain_anomaly_model
    result = retrain_anomaly_model.delay()
    return jsonify({"status": "queued", "task_id": result.id}), 202


@ml_anomaly_bp.route("/retrain_status/<task_id>", methods=["GET"])
@jwt_required()
def retrain_status(task_id):
    """Return the Celery AsyncResult state for a previously queued retrain task."""
    from dashboard.backend.celery_app import celery
    res = AsyncResult(task_id, app=celery)
    payload = {"task_id": task_id, "state": res.state}
    if res.state == "SUCCESS":
        payload["result"] = res.result
    elif res.state == "FAILURE":
        payload["error"] = str(res.result)
    return jsonify(payload), 200


@ml_anomaly_bp.route("/detections", methods=["GET"])
@jwt_required()
def list_detections():
    limit = min(int(request.args.get("limit", 50)), 200)
    detections = (
        AnomalyDetection.query
        .order_by(AnomalyDetection.detected_at.desc())
        .limit(limit)
        .all()
    )
    return jsonify([d.to_dict() for d in detections]), 200


# ---------------------------------------------------------------------------
# GET /detections/<detection_id>/explain
# ---------------------------------------------------------------------------

@ml_anomaly_bp.route("/detections/<int:detection_id>/explain", methods=["GET"])
@jwt_required()
def explain_detection(detection_id):
    """Return the full SHAP breakdown (all 12 features) for one stored detection.

    - Verifies the detection belongs to the requesting user (403 otherwise).
    - New-format detections (shap_v1) return all 12 SHAP contributors and the
      placeholder_values map showing which features were not real-data-driven.
    - Legacy detections (z-score format) return the stored data with
      format="zscore_legacy" — SHAP is NOT recomputed for legacy rows.
    """
    current_user_id = int(get_jwt_identity())

    detection = db.session.get(AnomalyDetection, detection_id)
    if not detection:
        return jsonify({"error": "Detection not found"}), 404
    if detection.user_id != current_user_id:
        return jsonify({"error": "Forbidden"}), 403

    node_meta = json.loads(detection.node_meta or "{}")
    contributors_format = node_meta.get("contributors_format", "zscore_legacy")
    explainer_type = node_meta.get("explainer_type")

    raw_contributors = json.loads(detection.top_contributors or "[]")
    feature_vector   = json.loads(detection.feature_vector or "{}")

    # Detect legacy rows by structure if node_meta doesn't have the format key
    if contributors_format != "shap_v1" and raw_contributors:
        first = raw_contributors[0] if isinstance(raw_contributors, list) else {}
        if "z_score" in first:
            contributors_format = "zscore_legacy"

    placeholder_values = node_meta.get("placeholder_values")

    mv = db.session.get(AnomalyModelVersion, detection.model_version_id)
    model_version_tag = mv.version_tag if mv else None

    return jsonify({
        "detection_id":  detection_id,
        "model_version": model_version_tag,
        "is_anomaly":    detection.is_anomaly,
        "anomaly_score": detection.anomaly_score,
        "severity":      detection.severity,
        "explanation": {
            "format":              contributors_format,
            "explainer_type":      explainer_type,
            "all_contributors":    raw_contributors,
            "feature_vector_used": feature_vector,
            "placeholder_values":  placeholder_values,
        },
    }), 200


# ---------------------------------------------------------------------------
# POST /extract  — return real feature vector for a scanned host
# ---------------------------------------------------------------------------

@ml_anomaly_bp.route("/extract", methods=["POST"])
@jwt_required()
@validate_body(ML_ANOMALY_EXTRACT_SCHEMA)
def extract():
    user_id = int(get_jwt_identity())
    body    = request.get_json(silent=True) or {}
    host_ip = body.get("host_ip", "").strip()

    features = extract_features_for_host(user_id, host_ip)
    if features is None:
        return jsonify({"error": f"No scan data found for {host_ip} — run a scan first"}), 404
    return jsonify(features), 200


# ---------------------------------------------------------------------------
# POST /predict_real  — score a host using features from real scan data
# ---------------------------------------------------------------------------

@ml_anomaly_bp.route("/predict_real", methods=["POST"])
@jwt_required()
@validate_body(ML_ANOMALY_PREDICT_REAL_SCHEMA)
def predict_real():
    user_id       = int(get_jwt_identity())
    body          = request.get_json(silent=True) or {}
    host_ip       = body.get("host_ip", "").strip()
    target_device = body.get("target_device") or host_ip

    features = extract_features_for_host(user_id, host_ip)
    if features is None:
        return jsonify({"error": "no scan data for this host — run a scan first"}), 404

    detector, version = _load_active_detector()
    if detector is None:
        return jsonify({"error": "No trained model found. POST /train first."}), 400

    # Strip internal metadata keys before building the feature vector.
    sample = {k: v for k, v in features.items() if not k.startswith("_")}

    vec    = to_vector(sample)
    X      = vec.reshape(1, -1)
    labels, scores = detector.predict(X)

    raw_score     = float(scores[0])
    sigmoid_score = _sigmoid(raw_score)
    is_anomaly    = bool(labels[0] == 1)
    severity      = _severity(sigmoid_score, is_anomaly)

    # SHAP explainability
    explainer = get_explainer(version.id, detector)
    all_contributors = explainer.explain(vec)          # full 12-feature breakdown
    top_contributors = all_contributors[:5]            # top 5 by |shap_value|

    synthetic_fields    = features.get("_synthetic_fields", [])
    placeholder_values  = features.get("_placeholder_values", {})
    placeholder_strategy = features.get("_placeholder_strategy", "")

    detection = AnomalyDetection(
        model_version_id = version.id,
        user_id          = user_id,
        target_ip        = host_ip,
        target_device    = target_device,
        is_anomaly       = is_anomaly,
        anomaly_score    = round(sigmoid_score, 6),
        severity         = severity,
        feature_vector   = json.dumps(dict(zip(FEATURE_ORDER, vec.tolist()))),
        top_contributors = json.dumps(all_contributors),   # store full 12 for /explain
        node_meta        = json.dumps({
            "contributors_format":   "shap_v1",
            "explainer_type":        explainer.explainer_type,
            "source":                "real_scan_data",
            "synthetic_fields":      synthetic_fields,
            "placeholder_values":    placeholder_values,
            "placeholder_strategy":  placeholder_strategy,
            "source_scan_id":        features.get("_source_scan_id"),
        }),
    )
    db.session.add(detection)
    db.session.commit()

    # ── Capability 2: per-device behavioral baseline check ───────────────────
    # Non-fatal: if this fails for any reason, the Isolation Forest result is
    # still returned. behavioral_baseline field in the response is always set.
    try:
        from dashboard.backend.behavioral.device_deviation_detector import (
            detect_and_record_deviations,
        )
        beh = detect_and_record_deviations(user_id, host_ip, sample)
        behavioral_baseline = {
            "status":                beh.get("status"),
            "severity":              beh.get("severity"),
            "top_deviations":        beh.get("top_deviations"),
            "baseline_observations": beh.get("baseline_observations"),
            "baseline_confidence":   beh.get("baseline_confidence"),
            "ba_anomaly_id":         beh.get("ba_anomaly_id"),
        }
    except Exception as _beh_exc:
        current_app.logger.exception(
            "predict_real: behavioral check failed for %s: %s", host_ip, _beh_exc
        )
        behavioral_baseline = {"status": "error", "error": str(_beh_exc)}

    # ── Capability 4: threat intelligence cross-reference ────────────────────
    # Non-fatal: if this fails, /predict_real still returns the other results.
    try:
        from dashboard.backend.threatintel.cross_reference import (
            check_host_against_threat_intel,
        )
        # Pass host_data from the most recent scan so hostnames are checked too
        from dashboard.backend.real_scanner.routes import RealScanResult
        _scan = (
            RealScanResult.query
            .filter_by(user_id=user_id, status="complete")
            .order_by(RealScanResult.started_at.desc())
            .first()
        )
        _host_data = None
        if _scan:
            try:
                _hosts = json.loads(_scan.results_json or "[]")
                for _h in _hosts:
                    if _h.get("ip") == host_ip:
                        _host_data = _h
                        break
            except (json.JSONDecodeError, TypeError):
                pass
        ti = check_host_against_threat_intel(user_id, host_ip, _host_data)
        threat_intel = {
            "status":           ti.get("status"),
            "match_count":      ti.get("match_count", 0),
            "highest_severity": ti.get("highest_severity", "none"),
            "matches":          ti.get("matches", []),
            "error":            None,
        }
    except Exception as _ti_exc:
        current_app.logger.exception(
            "predict_real: threat intel check failed for %s: %s", host_ip, _ti_exc
        )
        threat_intel = {"status": "unavailable", "error": str(_ti_exc), "match_count": 0}

    return jsonify({
        "detection_id":        detection.id,
        "target_ip":           host_ip,
        "target_device":       target_device,
        "is_anomaly":          is_anomaly,
        "anomaly_score":       round(sigmoid_score, 6),
        "severity":            severity,
        "top_contributors":    top_contributors,
        "explainer_type":      explainer.explainer_type,
        "model_version":       version.version_tag,
        "synthetic_fields":    synthetic_fields,
        "behavioral_baseline": behavioral_baseline,
        "threat_intel":        threat_intel,
    }), 200
