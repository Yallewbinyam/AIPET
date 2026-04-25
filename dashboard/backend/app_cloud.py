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
from flask import Flask, jsonify, request, send_file, redirect

import sentry_sdk
from sentry_sdk.integrations.flask import FlaskIntegration

_sentry_dsn = os.environ.get("SENTRY_DSN", "")
if _sentry_dsn:
    sentry_sdk.init(
        dsn=_sentry_dsn,
        integrations=[FlaskIntegration()],
        traces_sample_rate=1.0,
        send_default_pii=False,
    )
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager, jwt_required, get_jwt_identity
)
from flask_migrate import Migrate
from flask_mail import Mail
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dashboard.backend.validation import (
    validate_body, optional,
    LOGIN_SCHEMA, REGISTER_SCHEMA, SCAN_TARGET_SCHEMA,
    CHANGE_PASSWORD_SCHEMA, TELEMETRY_SCHEMA,
)

sys.path.insert(0, '/home/binyam/AIPET')

from dashboard.backend.models import db, User, Scan, Finding
from dashboard.backend.auth.routes import auth_bp, init_google_oauth
from dashboard.backend.config import config
from dashboard.backend.celery_app import celery
from dashboard.backend.remediation.routes import remediation_bp
from dashboard.backend.explain.routes import explain_bp
from dashboard.backend.score.routes import score_bp
from dashboard.backend.map.routes import map_bp
from dashboard.backend.predict.routes import predict_bp
from dashboard.backend.watch.routes import watch_bp
from dashboard.backend.ask.routes import ask_bp
from dashboard.backend.compliance.routes import compliance_bp
from dashboard.backend.iam.routes import iam_bp, seed_default_roles
from dashboard.backend.iam.models import Role, Permission, UserRole, AuditLog, SSOProvider
from dashboard.backend.protocols.routes import protocols_bp
from dashboard.backend.settings.routes import settings_bp
from dashboard.backend.siem.routes import siem_bp
from dashboard.backend.siem.models import SiemEvent, SiemRule, SiemIncident
from dashboard.backend.threatintel.routes import threatintel_bp
from dashboard.backend.threatintel.models import IocFeed, IocEntry, ThreatMatch
from dashboard.backend.zerotrust.routes import zerotrust_bp
from dashboard.backend.zerotrust.models import ZtDeviceTrust, ZtPolicy, ZtAccessLog
from dashboard.backend.defense.routes import defense_bp
from dashboard.backend.defense.models import DefensePlaybook, DefenseAction
from dashboard.backend.aisoc.routes import aisoc_bp
from dashboard.backend.otics.routes import otics_bp
from dashboard.backend.otics.models import OtDevice, OtScan, OtFinding
from dashboard.backend.multicloud.routes import multicloud_bp
from dashboard.backend.multicloud.models import CloudAccount, CloudAsset, CloudFinding
from dashboard.backend.digitaltwin.routes import twin_bp
from dashboard.backend.digitaltwin.models import TwinNode, TwinEdge, TwinSnapshot
from dashboard.backend.redteam.routes import redteam_bp
from dashboard.backend.redteam.models import RtCampaign, RtAttack
from dashboard.backend.marketplace.routes import marketplace_bp
from dashboard.backend.marketplace.models import MpPlugin, MpInstall, MpReview
from dashboard.backend.timeline.routes import timeline_bp
from dashboard.backend.timeline.models import TimelineEvent
from dashboard.backend.incidents.routes import incidents_bp
from dashboard.backend.incidents.models import IrIncident, IrTask
from dashboard.backend.narrative.routes import narrative_bp
from dashboard.backend.narrative.models import RiskNarrative
from dashboard.backend.attackpath.routes import attackpath_bp
from dashboard.backend.attackpath.models import ApAnalysis, ApPath
from dashboard.backend.identitygraph.routes import identitygraph_bp
from dashboard.backend.identitygraph.models import IgIdentity, IgEdge, IgRisk
from dashboard.backend.behavioral.routes import behavioral_bp
from dashboard.backend.behavioral.models import BaBaseline, BaAnomaly, BaPattern
from dashboard.backend.complianceauto.routes import complianceauto_bp
from dashboard.backend.complianceauto.models import CaFramework, CaControl, CaAssessment
from dashboard.backend.dspm.routes import dspm_bp
from dashboard.backend.dspm.models import DspmDatastore, DspmFinding, DspmScan
from dashboard.backend.costsecurity.routes import costsecurity_bp
from dashboard.backend.costsecurity.models import CsResource, CsRecommendation
from dashboard.backend.apisecurity.routes import apisecurity_bp
from dashboard.backend.apisecurity.models import AsEndpoint, AsFinding, AsScan
from dashboard.backend.supplychain.routes import supplychain_bp
from dashboard.backend.supplychain.models import ScComponent, ScVuln, ScSbom
from dashboard.backend.netvisualizer.routes import netvisualizer_bp
from dashboard.backend.netvisualizer.models import NvNode, NvEdge, NvIssue
from dashboard.backend.terminal.routes import terminal_bp
from dashboard.backend.terminal.models import TerminalSession, TerminalAuditLog
from dashboard.backend.resilience.routes import resilience_bp
from dashboard.backend.resilience.models import ReAsset, RePlan, ReTest
from dashboard.backend.driftdetector.routes import driftdetector_bp
from dashboard.backend.driftdetector.models import DdBaseline, DdDrift, DdScan
from dashboard.backend.timeline_enhanced.routes import timeline_enhanced_bp
from dashboard.backend.code_security.routes import code_security_bp
from dashboard.backend.forensics.routes import forensics_bp
from dashboard.backend.compliance_fabric.routes import compliance_fabric_bp
from dashboard.backend.identity_guardian.routes import identity_guardian_bp
from dashboard.backend.soc_twin.routes import soc_twin_bp
from dashboard.backend.policy_brain.routes import policy_brain_bp
from dashboard.backend.threat_radar.routes import threat_radar_bp
from dashboard.backend.cloud_hardener.routes import cloud_hardener_bp
from dashboard.backend.patch_brain.routes import patch_brain_bp
from dashboard.backend.arch_builder.routes import arch_builder_bp
from dashboard.backend.digital_twin_v2.routes import digital_twin_v2_bp
from dashboard.backend.defense_mesh.routes import defense_mesh_bp
from dashboard.backend.cloud_runtime.routes import cloud_runtime_bp
from dashboard.backend.k8s_analyzer.routes import k8s_analyzer_bp
from dashboard.backend.network_exposure.routes import network_exposure_bp
from dashboard.backend.iam_exposure.routes import iam_exposure_bp
from dashboard.backend.cloud_dashboard.routes import cloud_dashboard_bp
from dashboard.backend.multicloud_scale.routes import multicloud_scale_bp
from dashboard.backend.endpoint_agent.routes import endpoint_agent_bp
from dashboard.backend.itdr.routes import itdr_bp
from dashboard.backend.runtime_protection.routes import runtime_protection_bp
from dashboard.backend.threat_intel_ingest.routes import threat_intel_ingest_bp
from dashboard.backend.adversary_profiling.routes import adversary_profiling_bp
from dashboard.backend.malware_sandbox.routes import malware_sandbox_bp
from dashboard.backend.apm_engine.routes import apm_engine_bp
from dashboard.backend.log_analytics.routes import log_analytics_bp
from dashboard.backend.metrics_traces.routes import metrics_traces_bp
from dashboard.backend.cloud_siem.routes import cloud_siem_bp
from dashboard.backend.realtime_dashboards.routes import realtime_dashboards_bp
from dashboard.backend.synthetic_monitoring.routes import synthetic_monitoring_bp
from dashboard.backend.compliance_automation.routes import compliance_automation_bp
from dashboard.backend.enterprise_rbac.routes import enterprise_rbac_bp
from dashboard.backend.multi_tenant.routes import multi_tenant_bp
from dashboard.backend.enterprise_reporting.routes import enterprise_reporting_bp
from dashboard.backend.calendar.routes import calendar_bp
from dashboard.backend.real_scanner.routes import real_scanner_bp
from dashboard.backend.live_cves.routes import live_cves_bp
from dashboard.backend.live_cves.models import LiveCve, CveSyncLog
from dashboard.backend.agent_monitor.routes import agent_monitor_bp
from dashboard.backend.ml_anomaly.routes import ml_anomaly_bp
from dashboard.backend.ml_anomaly.models import AnomalyModelVersion, AnomalyDetection
from dashboard.backend.timeline_enhanced.models import TeEvent, TeCluster
from dashboard.backend.incidents.models import IrIncident, IrTask
from dashboard.backend.monitoring.logger import setup_logging, get_logger
from dashboard.backend.security import init_security
from dashboard.backend.monitoring.logger import (
    setup_logging,
    log_user_action,
    log_scan_event,
    log_payment_event,
    log_error,
    log_security_event,
    get_logger
)

logger = get_logger("aipet.api")

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

    # Initialise logging — must be done before any routes are called
    setup_logging(app)
    logger = get_logger('app')

    # Initialise security headers
    init_security(app)
    
    # Force HTTPS in production
    # In development this is skipped automatically
    @app.before_request
    def force_https():
        if not app.debug and not request.is_secure and request.host not in ["localhost:5001", "127.0.0.1:5001"]:
            url = request.url.replace("http://", "https://", 1)
            return redirect(url, code=301)

    # Bind extensions to this app instance before first DB use.
    db.init_app(app)
    JWTManager(app)
    Migrate(app, db)

    # Flask-Mail — always read from env vars at startup so start_cloud.sh exports are picked up
    app.config["MAIL_SERVER"]         = os.environ.get("SMTP_HOST",     "smtp.gmail.com")
    app.config["MAIL_PORT"]           = int(os.environ.get("SMTP_PORT", "587"))
    app.config["MAIL_USE_TLS"]        = True
    app.config["MAIL_USE_SSL"]        = False
    app.config["MAIL_USERNAME"]       = os.environ.get("SMTP_USER",     "")
    app.config["MAIL_PASSWORD"]       = os.environ.get("SMTP_PASSWORD", "")
    app.config["MAIL_DEFAULT_SENDER"] = os.environ.get("SMTP_USER",     "noreply@aipet.io")
    Mail(app)

    # Extensions
    CORS(app, resources={
        r"/*": {
            "origins": [
                "http://localhost:3000",
                "http://localhost:3001",
                "https://aipet.io",
                "https://www.aipet.io",
            ],
            "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "allow_headers": ["Content-Type", "Authorization"],
        }
    })

    # ── Rate limiter ──────────────────────────────────────
    # Key: JWT user ID when available, else remote IP.
    def _rate_limit_key():
        from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity
        try:
            verify_jwt_in_request(optional=True)
            uid = get_jwt_identity()
            if uid:
                return f"user:{uid}"
        except Exception:
            pass
        return get_remote_address()

    limiter = Limiter(
        key_func=_rate_limit_key,
        app=app,
        default_limits=["100 per minute", "2000 per day"],
        storage_uri=os.environ.get(
            "FLASK_LIMITER_STORAGE_URI", "redis://localhost:6379/1"
        ),
        in_memory_fallback_enabled=True,  # degrade gracefully if Redis is down
        headers_enabled=True,             # expose X-RateLimit-* headers
    )

    # Register blueprints
    app.register_blueprint(iam_bp)
    app.register_blueprint(auth_bp)
    init_google_oauth(app)
    # Auth endpoints: strict brute-force limits (keyed by IP regardless of JWT).
    # Flask-Limiter 4.x requires the decorated function to be re-assigned back
    # into view_functions — discarding the return value is a silent no-op.
    _login_fn = app.view_functions.get("auth.login")
    if _login_fn:
        _login_fn = limiter.limit("5 per minute",   key_func=get_remote_address)(_login_fn)
        app.view_functions["auth.login"] = _login_fn

    _register_fn = app.view_functions.get("auth.register")
    if _register_fn:
        _register_fn = limiter.limit("3 per minute", key_func=get_remote_address)(_register_fn)
        app.view_functions["auth.register"] = _register_fn

    _forgot_fn = app.view_functions.get("auth.forgot_password")
    if _forgot_fn:
        _forgot_fn = limiter.limit("3 per hour",    key_func=get_remote_address)(_forgot_fn)
        app.view_functions["auth.forgot_password"] = _forgot_fn
    from dashboard.backend.payments.routes import payments_bp
    app.register_blueprint(payments_bp, url_prefix='/payments')
    from dashboard.backend.api_keys.routes import api_keys_bp
    app.register_blueprint(remediation_bp)
    app.register_blueprint(explain_bp)
    app.register_blueprint(score_bp)
    app.register_blueprint(map_bp)
    app.register_blueprint(predict_bp)
    app.register_blueprint(watch_bp)
    app.register_blueprint(ask_bp)
    app.register_blueprint(compliance_bp)
    app.register_blueprint(protocols_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(siem_bp)
    app.register_blueprint(threatintel_bp)
    app.register_blueprint(zerotrust_bp)
    app.register_blueprint(defense_bp)
    app.register_blueprint(aisoc_bp)
    app.register_blueprint(otics_bp)
    app.register_blueprint(multicloud_bp)
    app.register_blueprint(twin_bp)
    app.register_blueprint(redteam_bp)
    app.register_blueprint(marketplace_bp)
    app.register_blueprint(timeline_bp)
    app.register_blueprint(incidents_bp)
    app.register_blueprint(narrative_bp)
    app.register_blueprint(attackpath_bp)
    app.register_blueprint(identitygraph_bp)
    app.register_blueprint(behavioral_bp)
    app.register_blueprint(complianceauto_bp)
    app.register_blueprint(dspm_bp)
    app.register_blueprint(costsecurity_bp)
    app.register_blueprint(apisecurity_bp)
    app.register_blueprint(supplychain_bp)
    app.register_blueprint(netvisualizer_bp)
    app.register_blueprint(terminal_bp)
    app.register_blueprint(resilience_bp)
    app.register_blueprint(driftdetector_bp)
    app.register_blueprint(timeline_enhanced_bp)
    app.register_blueprint(code_security_bp)
    app.register_blueprint(forensics_bp)
    app.register_blueprint(compliance_fabric_bp)
    app.register_blueprint(identity_guardian_bp)
    app.register_blueprint(soc_twin_bp)
    app.register_blueprint(policy_brain_bp)
    app.register_blueprint(threat_radar_bp)
    app.register_blueprint(cloud_hardener_bp)
    app.register_blueprint(patch_brain_bp)
    app.register_blueprint(arch_builder_bp)
    app.register_blueprint(digital_twin_v2_bp)
    app.register_blueprint(defense_mesh_bp)
    app.register_blueprint(cloud_runtime_bp)
    app.register_blueprint(k8s_analyzer_bp)
    app.register_blueprint(network_exposure_bp)
    app.register_blueprint(iam_exposure_bp)
    app.register_blueprint(cloud_dashboard_bp)
    app.register_blueprint(multicloud_scale_bp)
    app.register_blueprint(endpoint_agent_bp)
    app.register_blueprint(itdr_bp)
    app.register_blueprint(runtime_protection_bp)
    app.register_blueprint(threat_intel_ingest_bp)
    app.register_blueprint(adversary_profiling_bp)
    app.register_blueprint(malware_sandbox_bp)
    app.register_blueprint(apm_engine_bp)
    app.register_blueprint(log_analytics_bp)
    app.register_blueprint(metrics_traces_bp)
    app.register_blueprint(cloud_siem_bp)
    app.register_blueprint(realtime_dashboards_bp)
    app.register_blueprint(synthetic_monitoring_bp)
    app.register_blueprint(compliance_automation_bp)
    app.register_blueprint(enterprise_rbac_bp)
    app.register_blueprint(multi_tenant_bp)
    app.register_blueprint(enterprise_reporting_bp)
    app.register_blueprint(calendar_bp)
    app.register_blueprint(real_scanner_bp)
    app.register_blueprint(live_cves_bp)
    app.register_blueprint(agent_monitor_bp)
    app.register_blueprint(api_keys_bp, url_prefix='/api/keys')
    app.register_blueprint(ml_anomaly_bp)
    # /train is expensive — cap it well below the global 100/min default.
    # Flask-Limiter 4.x: must re-assign the return value of limiter.limit()(fn)
    # back into view_functions; discarding the return value has no effect.
    # Must run AFTER app.register_blueprint(ml_anomaly_bp) so the view exists.
    _train_fn = app.view_functions.get("ml_anomaly.train")
    if _train_fn:
        _train_fn = limiter.limit("5 per hour")(_train_fn)
        _train_fn = limiter.limit("20 per day")(_train_fn)
        app.view_functions["ml_anomaly.train"] = _train_fn

    # /retrain_now queues an expensive Celery task — stricter limit than /train
    _retrain_fn = app.view_functions.get("ml_anomaly.retrain_now")
    if _retrain_fn:
        _retrain_fn = limiter.limit("2 per hour")(_retrain_fn)
        _retrain_fn = limiter.limit("10 per day")(_retrain_fn)
        app.view_functions["ml_anomaly.retrain_now"] = _retrain_fn

    # /device/baselines/build_all iterates all scan results — expensive, cap it.
    _build_all_fn = app.view_functions.get("behavioral.build_all_device_baselines")
    if _build_all_fn:
        _build_all_fn = limiter.limit("5 per hour")(_build_all_fn)
        app.view_functions["behavioral.build_all_device_baselines"] = _build_all_fn

    # Setup logging
    setup_logging(
        app=app,
        log_level=os.environ.get("LOG_LEVEL", "INFO")
    )

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
    @app.errorhandler(404)
    def not_found_handler(e):
        return jsonify({
            "error": "Not found",
            "message": "The requested endpoint does not exist.",
            "status": 404
        }), 404

    @app.errorhandler(405)
    def method_not_allowed_handler(e):
        return jsonify({
            "error": "Method not allowed",
            "message": "This HTTP method is not allowed on this endpoint.",
            "status": 405
        }), 405
    @app.errorhandler(500)
    def internal_error_handler(e):
        sentry_sdk.capture_exception(e)
        from dashboard.backend.monitoring.alerting import alert_unhandled_exception
        try:
            user_id = get_jwt_identity()
        except Exception:
            user_id = "unauthenticated"
        alert_unhandled_exception(
            request_path=request.path,
            user_id=user_id,
            error=e
        )
        return jsonify({
            "error": "Internal server error",
            "message": "Something went wrong. Our team has been notified."
        }), 500


    # ── Public routes ─────────────────────────────────────
    @app.route("/api/health", methods=["GET"])
    def health():
        # Test database connection
        try:
            db.session.execute(db.text("SELECT 1"))
            db_status = "connected"
        except Exception as e:
            db_status = "disconnected"
            log_error(e, context="health_check")

        return jsonify({
            "status":   "online",
            "version":  "2.0.0",
            "mode":     "cloud",
            "database": db_status,
            "time":     datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        })

    @app.route("/api/ping", methods=["GET"])
    def ping():
        return jsonify({"status": "ok", "timestamp": datetime.utcnow().isoformat() + "Z"})

    @app.route("/api/sentry-test", methods=["GET"])
    def sentry_test():
        division_by_zero = 1 / 0
        return jsonify({"status": "unreachable"})

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
        logger.info(f"[dashboard] User {user.email} loaded dashboard")

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
    @limiter.limit("10 per hour")
    @limiter.limit("100 per day")
    def start_scan():
        # Accept either JWT token or API key authentication
        # This allows Enterprise users to call the API programmatically
        from dashboard.backend.api_keys.routes import authenticate_api_key

        user = None

        # Try API key first (X-API-Key header)
        api_key_header = request.headers.get('X-API-Key')
        if api_key_header:
            user = authenticate_api_key(api_key_header)
            if not user:
                return jsonify({'error': 'Invalid API key'}), 401

        # Fall back to JWT token
        if not user:
            from flask_jwt_extended import verify_jwt_in_request
            try:
                verify_jwt_in_request()
                user_id = get_jwt_identity()
                user    = User.query.get(int(user_id))
            except Exception:
                return jsonify({
                    'error': 'Authentication required. Provide a JWT token or API key.'
                }), 401

        if not user:
            return jsonify({'error': 'User not found'}), 404

        if not user.can_scan():
            return jsonify({
                "error": "Scan limit reached. "
                         "Upgrade to Professional."
            }), 403

        data          = request.json or {}
        target        = data.get("target", "localhost")
        mode          = data.get("mode", "demo")
        mqtt_port     = data.get("mqtt_port", 1883)
        coap_port     = data.get("coap_port", 5683)
        http_port     = data.get("http_port", 80)
        firmware_path = data.get("firmware_path", None)

        # ── Input validation ───────────────────────────────────
        # Validate mode
        if mode not in ("demo", "live"):
            return jsonify({"error": "Invalid mode. Use 'demo' or 'live'"}), 400

        # Validate ports are integers in valid range
        for port_name, port_val in [
            ("mqtt_port", mqtt_port),
            ("coap_port", coap_port),
            ("http_port", http_port)
        ]:
            if not isinstance(port_val, int) or not (1 <= port_val <= 65535):
                return jsonify({
                    "error": f"Invalid {port_name}. Must be integer between 1 and 65535"
                }), 400

        # Validate target length to prevent buffer overflow attempts
        if len(str(target)) > 255:
            return jsonify({"error": "Target address too long"}), 400
        

        # Create scan record in database
        scan = Scan(
            user_id    = user.id,
            target     = target,
            mode       = mode,
            status     = "queued",
            created_at = datetime.now()
        )
        db.session.add(scan)
        db.session.commit()

        # Increment user scan counter
        user.increment_scan()

        # Log the scan event
        logger.info(f"[scan] User {user.email} started scan — target: {target} mode: {mode} scan_id: {scan.id}")

        # Log scan event
        log_scan_event(
            scan_id = scan.id,
            user_id = user.id,
            event   = "queued",
            details = f"target:{target} mode:{mode}"
        )

        # Submit scan to Celery queue — non-blocking
        try:
            # Import here to avoid circular imports
            from dashboard.backend.tasks import run_scan_task
            run_scan_task.delay(
                scan_id       = scan.id,
                user_id       = user.id,
                target        = target,
                mode          = mode,
                mqtt_port     = mqtt_port,
                coap_port     = coap_port,
                http_port     = http_port,
                firmware_path = firmware_path,
            )
            queued_via = "celery"
        except Exception as celery_err:
            # Log the actual Celery error
            import traceback
            print(f"CELERY ERROR: {celery_err}")
            traceback.print_exc()
            # Celery not available — fall back to threading
            import threading
            import subprocess

            def run_scan_thread():
                global scan_status
                scan_status["running"] = True
                scan_status["progress"] = 0
                scan_status["message"] = "Scan in progress..."
                scan_status["started"] = datetime.now().isoformat()

                python = os.path.join(BASE_DIR, "venv/bin/python3")
                if not os.path.exists(python):
                    python = sys.executable
                aipet = os.path.join(BASE_DIR, "aipet.py")
                cmd = (
                    [python, aipet, "--demo"]
                    if mode == "demo"
                    else [python, aipet, "--target", target]
                )
                try:
                    subprocess.run(
                        cmd, cwd=BASE_DIR,
                        capture_output=True,
                        text=True, timeout=300
                    )
                    with app.app_context():
                        from dashboard.backend.models import db, Scan
                        s = Scan.query.get(scan.id)
                        if s:
                            s.status       = "complete"
                            s.completed_at = datetime.now()
                            db.session.commit()
                            # Fire Slack/Teams alerts for critical/high findings
                            try:
                                from dashboard.backend.settings.routes import notify_finding
                                from dashboard.backend.models import Finding
                                critical_findings = Finding.query.filter_by(
                                    scan_id=scan.id
                                ).filter(
                                    Finding.severity.in_(["CRITICAL", "HIGH"])
                                ).all()
                                for f in critical_findings:
                                    notify_finding(user_id, {
                                        "ip":         f.target,
                                        "name":       f.name,
                                        "severity":   f.severity,
                                        "risk_score": f.risk_score,
                                        "fix":        f.remediation,
                                    })
                            except Exception as notify_err:
                                print(f"Alert notification error: {notify_err}")
                    scan_status["running"]   = False
                    scan_status["progress"]  = 100
                    scan_status["message"]   = "Scan complete"
                    scan_status["completed"] = datetime.now().isoformat()
                except Exception as e:
                    with app.app_context():
                        from dashboard.backend.models import db, Scan
                        s = Scan.query.get(scan.id)
                        if s:
                            s.status = "failed"
                            db.session.commit()
                    scan_status["running"] = False
                    scan_status["message"] = "Scan failed"
                except Exception as e:
                    with app.app_context():
                        from dashboard.backend.models import (
                            db, Scan
                        )
                        s = Scan.query.get(scan.id)
                        if s:
                            s.status = "failed"
                            db.session.commit()

            t = threading.Thread(target=run_scan_thread)
            t.daemon = True
            t.start()
            queued_via = "thread"

        return jsonify({
            "status":     "queued",
            "scan_id":    scan.id,
            "target":     target,
            "mode":       mode,
            "queued_via": queued_via,
        })

    @app.route("/api/scan/status", methods=["GET"])
    @jwt_required()
    def get_scan_status():
        return jsonify(scan_status)
    @app.route("/api/user/usage", methods=["GET"])
    @jwt_required()
    def get_usage():
        user_id = get_jwt_identity()
        user = User.query.get(int(user_id))

        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)
        month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        next_month = month_start.replace(month=month_start.month % 12 + 1)
        days_remaining = (next_month - now).days

        scans_this_month = Scan.query.filter(
            Scan.user_id == user.id,
            Scan.created_at >= month_start
        ).count()

        return jsonify({
            "plan":             user.plan,
            "scans_used":       scans_this_month,
            "scans_limit":      user.scans_limit if user.plan == "free" else None,
            "days_until_reset": max(0, days_remaining),
            "has_api_access":   user.plan == "enterprise",
            "is_paid":          user.plan in ["professional", "enterprise"],
            "stripe_customer_id": user.stripe_customer_id,
        })

    @app.route("/api/scan/history", methods=["GET"])
    @app.route("/api/scans", methods=["GET"])
    @jwt_required()
    def get_scans():
            current_user_id = get_jwt_identity()
            scans = Scan.query.filter_by(
                user_id=current_user_id
            ).order_by(Scan.id.desc()).all()
            return jsonify([s.to_dict() for s in scans]), 200
    @app.route("/api/findings", methods=["GET"])
    @jwt_required()
    def get_findings():
            current_user_id = get_jwt_identity()
            # Get all scans belonging to this user
            user_scans = Scan.query.filter_by(user_id=current_user_id).all()
            scan_ids = [s.id for s in user_scans]
            if not scan_ids:
                return jsonify([]), 200
            # Get all findings for those scans
            findings = Finding.query.filter(
                Finding.scan_id.in_(scan_ids)
            ).order_by(Finding.id.desc()).all()
            return jsonify([f.to_dict() for f in findings]), 200
    @app.route("/api/devices", methods=["GET"])
    @jwt_required()
    def get_devices():
            # Returns unique devices from all findings for this user
            current_user_id = get_jwt_identity()
            user_scans = Scan.query.filter_by(user_id=current_user_id).all()
            scan_ids = [s.id for s in user_scans]
            if not scan_ids:
                return jsonify([]), 200
            findings = Finding.query.filter(
                Finding.scan_id.in_(scan_ids)
            ).all()
            # Group findings by target device
            devices = {}
            for f in findings:
                if f.target not in devices:
                    devices[f.target] = {
                        "target":   f.target,
                        "findings": [],
                        "critical": 0,
                        "high":     0,
                        "medium":   0,
                        "low":      0,
                    }
                devices[f.target]["findings"].append(f.to_dict())
                severity = f.severity.lower()
                if severity in devices[f.target]:
                    devices[f.target][severity] += 1
            return jsonify(list(devices.values())), 200

    @app.route("/api/ai", methods=["GET"])
    @jwt_required()
    def get_ai_results():
            # Returns empty list for now — AI results come in Month 2
            return jsonify([]), 200
    
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

from dashboard.backend.public_scan.routes import public_scan_bp
app.register_blueprint(public_scan_bp)




if __name__ == "__main__":
    print("=" * 60)
    print("  AIPET Cloud Backend v2")
    print("  Running at: http://localhost:5001")
    print("=" * 60)
    app.run(host="0.0.0.0", port=5001,
            debug=True, use_reloader=False)
