# =============================================================
# AIPET Cloud — Main Application v2
# Week 2: PostgreSQL + Rate Limiting + Migrations
# =============================================================

import os
import sys
import json
import subprocess
import threading
from datetime import datetime, timedelta
from flask import Flask, jsonify, request, send_file
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager, jwt_required, get_jwt_identity
)
from flask_migrate import Migrate
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

sys.path.insert(0, '/home/binyam/AIPET')

from dashboard.backend.models import db, User, Scan, Finding
from dashboard.backend.auth.routes import auth_bp
from dashboard.backend.config import config

BASE_DIR = '/home/binyam/AIPET'

# Track running scans
scan_status = {
    "running":   False,
    "progress":  0,
    "message":   "Ready",
    "started":   None,
    "completed": None
}


def create_app(config_name="development"):
    app = Flask(__name__)
    app.config.from_object(config[config_name])

    # Extensions
    CORS(app)
    db.init_app(app)
    Migrate(app, db)
    JWTManager(app)

    # Rate limiter
    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=["200 per day", "50 per hour"],
        storage_uri="memory://"
    )

    # Register blueprints
    app.register_blueprint(auth_bp)

    # Create tables
    with app.app_context():
        db.create_all()

    # ── Error handlers ────────────────────────────────────
    @app.errorhandler(429)
    def ratelimit_handler(e):
        return jsonify({
            "error": "Rate limit exceeded",
            "message": str(e.description)
        }), 429

    @app.errorhandler(401)
    def unauthorized_handler(e):
        return jsonify({
            "error": "Unauthorized",
            "message": "Valid JWT token required"
        }), 401

    # ── Public routes ─────────────────────────────────────
    @app.route("/api/health", methods=["GET"])
    def health():
        # Test database connection
        try:
            db.session.execute(db.text("SELECT 1"))
            db_status = "connected"
        except Exception:
            db_status = "disconnected"

        return jsonify({
            "status":   "online",
            "version":  "2.0.0",
            "mode":     "cloud",
            "database": db_status,
            "time":     datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        })

    @app.route("/api/plans", methods=["GET"])
    def get_plans():
        return jsonify({
            "free": {
                "price_gbp":        0,
                "scans_per_month":  5,
                "parallel_workers": 1,
                "api_access":       False,
                "features": [
                    "5 scans per month",
                    "Single network scanning",
                    "Basic AI analysis",
                    "PDF reports",
                    "Community support"
                ]
            },
            "professional": {
                "price_gbp":        49,
                "scans_per_month":  -1,
                "parallel_workers": 3,
                "api_access":       False,
                "features": [
                    "Unlimited scans",
                    "Parallel scanning (3 networks)",
                    "Full SHAP AI explanations",
                    "All report formats",
                    "Email support"
                ]
            },
            "enterprise": {
                "price_gbp":        499,
                "scans_per_month":  -1,
                "parallel_workers": 10,
                "api_access":       True,
                "features": [
                    "Unlimited scans",
                    "Parallel scanning (10 networks)",
                    "Full AI analysis",
                    "API access",
                    "Priority support",
                    "SLA guarantee",
                    "Custom integrations"
                ]
            }
        })

    # ── Protected routes ──────────────────────────────────
    @app.route("/api/summary", methods=["GET"])
    @jwt_required()
    def get_summary():
        user_id = get_jwt_identity()
        user    = User.query.get(int(user_id))

        def load_json(filepath):
            full_path = os.path.join(BASE_DIR, filepath)
            if not os.path.exists(full_path):
                return None
            try:
                with open(full_path) as f:
                    return json.load(f)
            except Exception:
                return None

        profiles = load_json("recon/complete_profiles.json")
        mqtt     = load_json("mqtt/mqtt_results.json")
        coap     = load_json("coap/coap_results.json")
        http     = load_json("http_attack/http_results.json")
        firmware = load_json("firmware/firmware_results.json")
        pipeline = load_json("aipet_pipeline_results.json")

        # Load parallel results
        results_dir = os.path.join(BASE_DIR, "results")
        if os.path.exists(results_dir):
            for target_dir in os.listdir(results_dir):
                target_path = os.path.join(
                    results_dir, target_dir
                )
                if not os.path.isdir(target_path):
                    continue
                for fname in [
                    "complete_profiles.json",
                    "mqtt_results.json",
                    "http_results.json"
                ]:
                    fpath = os.path.join(target_path, fname)
                    if os.path.exists(fpath):
                        try:
                            with open(fpath) as f:
                                data = json.load(f)
                            if fname == "complete_profiles.json":
                                if not profiles:
                                    profiles = data
                                elif isinstance(profiles, list):
                                    if isinstance(data, list):
                                        profiles.extend(data)
                        except Exception:
                            pass

        critical = high = medium = low = 0
        for result in [mqtt, coap, http, firmware]:
            if result:
                s = result.get("summary", {})
                critical += s.get("critical", 0)
                high     += s.get("high",     0)
                medium   += s.get("medium",   0)

        devices = len(profiles) if isinstance(
            profiles, list
        ) else (1 if profiles else 0)

        if critical > 0:
            overall_risk = "CRITICAL"
            risk_color   = "#ef4444"
        elif high > 0:
            overall_risk = "HIGH"
            risk_color   = "#f97316"
        elif medium > 0:
            overall_risk = "MEDIUM"
            risk_color   = "#eab308"
        else:
            overall_risk = "LOW"
            risk_color   = "#22c55e"

        return jsonify({
            "overall_risk":  overall_risk,
            "risk_color":    risk_color,
            "devices":       devices,
            "findings": {
                "critical": critical,
                "high":     high,
                "medium":   medium,
                "low":      low,
                "total":    critical + high + medium + low
            },
            "last_scan":   pipeline.get(
                "start_time"
            ) if pipeline else None,
            "modules_run": pipeline.get(
                "modules_run", []
            ) if pipeline else [],
            "user": {
                "name":       user.name,
                "plan":       user.plan,
                "scans_used": user.scans_used,
            }
        })

    @app.route("/api/scan/start", methods=["POST"])
    @jwt_required()
    @limiter.limit("10 per hour")
    def start_scan():
        global scan_status
        user_id = get_jwt_identity()
        user    = User.query.get(int(user_id))

        if not user.can_scan():
            return jsonify({
                "error": "Scan limit reached. "
                         "Upgrade to Professional."
            }), 403

        if scan_status["running"]:
            return jsonify({
                "error": "Scan already running"
            }), 400

        data   = request.json or {}
        target = data.get("target", "localhost")
        mode   = data.get("mode", "demo")

        def run_scan():
            global scan_status
            scan_status["running"]  = True
            scan_status["progress"] = 10
            scan_status["message"]  = "Running AIPET scan..."
            scan_status["started"]  = datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )
            try:
                python = os.path.join(
                    BASE_DIR, "venv/bin/python3"
                )
                aipet  = os.path.join(BASE_DIR, "aipet.py")
                cmd    = (
                    [python, aipet, "--demo"]
                    if mode == "demo"
                    else [python, aipet, "--target", target]
                )
                subprocess.run(
                    cmd, cwd=BASE_DIR,
                    capture_output=True, text=True,
                    timeout=300
                )
                scan_status["progress"] = 100
                scan_status["message"]  = "Scan complete"
                user.increment_scan()

                scan = Scan(
                    user_id      = user.id,
                    target       = target,
                    mode         = mode,
                    status       = "complete",
                    started_at   = datetime.now(),
                    completed_at = datetime.now()
                )
                db.session.add(scan)
                db.session.commit()

            except Exception as e:
                scan_status["message"] = f"Error: {str(e)}"
            finally:
                scan_status["running"]   = False
                scan_status["completed"] = datetime.now(
                ).strftime("%Y-%m-%d %H:%M:%S")

        thread = threading.Thread(target=run_scan)
        thread.daemon = True
        thread.start()

        return jsonify({
            "status": "started",
            "target": target
        })

    @app.route("/api/scan/status", methods=["GET"])
    @jwt_required()
    def get_scan_status():
        return jsonify(scan_status)

    @app.route("/api/scan/history", methods=["GET"])
    @jwt_required()
    def get_scan_history():
        user_id = get_jwt_identity()
        scans   = Scan.query.filter_by(
            user_id=int(user_id)
        ).order_by(Scan.created_at.desc()).limit(20).all()
        return jsonify([s.to_dict() for s in scans])

    @app.route("/api/reports", methods=["GET"])
    @jwt_required()
    def get_reports():
        reporting_dir = os.path.join(BASE_DIR, "reporting")
        if not os.path.exists(reporting_dir):
            return jsonify([])
        reports = []
        for filename in os.listdir(reporting_dir):
            if filename.endswith(".md"):
                filepath = os.path.join(
                    reporting_dir, filename
                )
                reports.append({
                    "filename": filename,
                    "size":     os.path.getsize(filepath),
                    "created":  datetime.fromtimestamp(
                        os.path.getctime(filepath)
                    ).strftime("%Y-%m-%d %H:%M:%S")
                })
        reports.sort(
            key=lambda x: x["created"], reverse=True
        )
        return jsonify(reports)

    @app.route("/api/reports/<filename>", methods=["GET"])
    @jwt_required()
    def download_report(filename):
        filepath = os.path.join(
            BASE_DIR, "reporting", filename
        )
        if not os.path.exists(filepath):
            return jsonify({"error": "Not found"}), 404
        return send_file(filepath, as_attachment=True)

    return app


app = create_app(
    os.environ.get("FLASK_ENV", "development")
)

if __name__ == "__main__":
    print("=" * 60)
    print("  AIPET Cloud Backend v2")
    print("  Running at: http://localhost:5001")
    print("=" * 60)
    app.run(host="0.0.0.0", port=5001, debug=True)
