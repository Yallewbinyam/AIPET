"""
AIPET X — ML Anomaly Detection Routes

Endpoints:
  GET  /api/ml/anomaly/features    — feature order for the 12-vector
  POST /api/ml/anomaly/train       — train Isolation Forest on synthetic data
  POST /api/ml/anomaly/predict     — score a single IoT telemetry sample
  GET  /api/ml/anomaly/models      — last 20 model versions
  GET  /api/ml/anomaly/detections  — last N detections (cap 200)
"""
import json
import math
import os
from datetime import datetime, timezone

import numpy as np
from flask import Blueprint, jsonify, request
from flask_jwt_extended import get_jwt_identity, jwt_required
from sklearn.metrics import f1_score, precision_score, recall_score

from dashboard.backend.ml_anomaly.detector import LATEST_PATH, AnomalyDetector
from dashboard.backend.ml_anomaly.features import FEATURE_ORDER, to_vector
from dashboard.backend.ml_anomaly.models import AnomalyDetection, AnomalyModelVersion
from dashboard.backend.ml_anomaly.training_data import generate_synthetic
from dashboard.backend.models import db

ml_anomaly_bp = Blueprint("ml_anomaly", __name__, url_prefix="/api/ml/anomaly")

CONTAMINATION  = 0.05
N_ESTIMATORS   = 100
RANDOM_STATE   = 42


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
def train():
    X, y = generate_synthetic(n_normal=5000, n_anomalous=250, seed=RANDOM_STATE)

    contamination = 250 / len(X)
    detector = AnomalyDetector()
    detector.fit(X, FEATURE_ORDER, contamination=contamination,
                 n_estimators=N_ESTIMATORS, random_state=RANDOM_STATE)

    # Evaluate on the full labeled synthetic set
    labels, _ = detector.predict(X)
    prec  = float(precision_score(y, labels, zero_division=0))
    rec   = float(recall_score(y, labels, zero_division=0))
    f1    = float(f1_score(y, labels, zero_division=0))

    # Version tag: timestamp-based
    version_tag = datetime.now(timezone.utc).strftime("v%Y%m%d_%H%M%S")
    model_path  = os.path.join(
        os.path.dirname(__file__), "models_store", f"iforest_{version_tag}.joblib"
    )
    detector.save(model_path)
    # Also overwrite the LATEST pointer
    detector.save(LATEST_PATH)

    # Deactivate all prior versions
    AnomalyModelVersion.query.filter_by(is_active=True).update({"is_active": False})

    mv = AnomalyModelVersion(
        version_tag      = version_tag,
        algorithm        = "isolation_forest",
        contamination    = contamination,
        n_estimators     = N_ESTIMATORS,
        feature_names    = json.dumps(FEATURE_ORDER),
        training_samples = len(X),
        precision_score  = prec,
        recall_score     = rec,
        f1_score         = f1,
        model_path       = model_path,
        is_active        = True,
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

    # Top 3 contributors by absolute z-score (placeholder for SHAP on Day 4)
    X_scaled  = detector.scaler.transform(X)
    z_scores  = X_scaled[0]
    top_idx   = np.argsort(np.abs(z_scores))[::-1][:3]
    top_contributors = [
        {"feature": FEATURE_ORDER[int(i)], "z_score": round(float(z_scores[i]), 4)}
        for i in top_idx
    ]

    detection = AnomalyDetection(
        model_version_id = version.id,
        user_id          = current_user_id,
        target_ip        = target_ip,
        target_device    = target_device,
        is_anomaly       = is_anomaly,
        anomaly_score    = round(sigmoid_score, 6),
        severity         = severity,
        feature_vector   = json.dumps(dict(zip(FEATURE_ORDER, vec.tolist()))),
        top_contributors = json.dumps(top_contributors),
    )
    db.session.add(detection)
    db.session.commit()

    return jsonify({
        "detection_id":    detection.id,
        "target_ip":       target_ip,
        "target_device":   target_device,
        "is_anomaly":      is_anomaly,
        "anomaly_score":   round(sigmoid_score, 6),
        "severity":        severity,
        "top_contributors": top_contributors,
        "model_version":   version.version_tag,
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
