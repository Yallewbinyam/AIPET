#!/usr/bin/env python3
# =============================================================
# AIPET — AI-Powered Penetration Testing Framework for IoT
# Dashboard Backend API
# Author: Binyam
# Institution: Coventry University — MSc Cyber Security
# Date: March 2025
# Description: Flask REST API that serves AIPET scan results
#              to the React frontend dashboard.
# =============================================================

import os
import json
import subprocess
import threading
from datetime import datetime
from flask import Flask, jsonify, request, send_file
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# ── Paths ──────────────────────────────────────────────────────
BASE_DIR    = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
RESULTS_DIR = BASE_DIR

# Track running scans
scan_status = {
    "running":   False,
    "progress":  0,
    "message":   "Ready",
    "started":   None,
    "completed": None
}


# ── Helper: Load JSON file ────────────────────────────────────
def load_json(filepath):
    full_path = os.path.join(RESULTS_DIR, filepath)
    if not os.path.exists(full_path):
        return None
    try:
        with open(full_path) as f:
            return json.load(f)
    except Exception:
        return None


# ── API: Health check ─────────────────────────────────────────
@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({
        "status":  "online",
        "version": "1.0.0",
        "time":    datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })


# ── API: Dashboard summary ────────────────────────────────────
@app.route('/api/summary', methods=['GET'])
def get_summary():
    """Return overall dashboard summary."""

    # Load all result files
    profiles  = load_json("recon/complete_profiles.json")
    mqtt      = load_json("mqtt/mqtt_results.json")
    coap      = load_json("coap/coap_results.json")
    http      = load_json("http_attack/http_results.json")
    firmware  = load_json("firmware/firmware_results.json")
    ai        = load_json("ai_engine/ai_results.json")
    pipeline  = load_json("aipet_pipeline_results.json")

    # Count findings
    critical = 0
    high     = 0
    medium   = 0
    low      = 0

    for module_results in [mqtt, coap, http]:
        if module_results:
            summary = module_results.get("summary", {})
            critical += summary.get("critical", 0)
            high     += summary.get("high",     0)
            medium   += summary.get("medium",   0)

    if firmware:
        summary   = firmware.get("summary", {})
        critical += summary.get("critical", 0)
        high     += summary.get("high",     0)
        medium   += summary.get("medium",   0)

    # Device count
    devices = len(profiles) if isinstance(profiles, list) else 0

    # Overall risk
    if critical > 0:
        overall_risk  = "CRITICAL"
        risk_color    = "#ef4444"
    elif high > 0:
        overall_risk  = "HIGH"
        risk_color    = "#f97316"
    elif medium > 0:
        overall_risk  = "MEDIUM"
        risk_color    = "#eab308"
    else:
        overall_risk  = "LOW"
        risk_color    = "#22c55e"

    # Last scan time
    last_scan = None
    if pipeline:
        last_scan = pipeline.get("start_time")

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
        "last_scan":     last_scan,
        "modules_run":   pipeline.get(
            "modules_run", []
        ) if pipeline else []
    })


# ── API: Device profiles ──────────────────────────────────────
@app.route('/api/devices', methods=['GET'])
def get_devices():
    """Return all discovered device profiles."""
    profiles  = load_json("recon/complete_profiles.json")
    ai        = load_json("ai_engine/ai_results.json")

    if not profiles:
        return jsonify([])

    if not isinstance(profiles, list):
        profiles = [profiles]

    # Build AI lookup
    ai_by_ip = {}
    if ai:
        if not isinstance(ai, list):
            ai = [ai]
        for result in ai:
            ip = result.get("ip", "")
            if ip:
                ai_by_ip[ip] = result

    # Enrich profiles with AI predictions
    enriched = []
    for profile in profiles:
        ip  = profile.get("ip", "unknown")
        p   = dict(profile)
        if ip in ai_by_ip:
            ai_data = ai_by_ip[ip]
            p["ai_severity"]   = ai_data.get(
                "prediction", {}
            ).get("predicted_severity", "Unknown")
            p["ai_confidence"] = ai_data.get(
                "prediction", {}
            ).get("confidence", 0)
            p["ai_explanation"] = ai_data.get(
                "explanation", ""
            )
            p["shap_contributions"] = ai_data.get(
                "prediction", {}
            ).get("shap_contributions", {})
        enriched.append(p)

    return jsonify(enriched)


# ── API: Module findings ──────────────────────────────────────
@app.route('/api/findings', methods=['GET'])
def get_findings():
    """Return all findings from all modules."""
    all_findings = []

    # MQTT findings
    mqtt = load_json("mqtt/mqtt_results.json")
    if mqtt:
        for attack in mqtt.get("attacks", []):
            all_findings.append({
                "module":   "MQTT",
                "attack":   attack.get("attack", ""),
                "severity": attack.get("severity", ""),
                "finding":  attack.get("finding", ""),
                "target":   mqtt.get("target", "")
            })

    # CoAP findings
    coap = load_json("coap/coap_results.json")
    if coap:
        for attack in coap.get("attacks", []):
            all_findings.append({
                "module":   "CoAP",
                "attack":   attack.get("attack", ""),
                "severity": attack.get("severity", ""),
                "finding":  attack.get("finding", ""),
                "target":   coap.get("target", "")
            })

    # HTTP findings
    http = load_json("http_attack/http_results.json")
    if http:
        for attack in http.get("attacks", []):
            all_findings.append({
                "module":   "HTTP",
                "attack":   attack.get("attack", ""),
                "severity": attack.get("severity", ""),
                "finding":  attack.get("finding", ""),
                "target":   http.get("target", "")
            })

    # Firmware findings
    firmware = load_json("firmware/firmware_results.json")
    if firmware:
        for analysis in firmware.get("analyses", []):
            all_findings.append({
                "module":   "Firmware",
                "attack":   analysis.get("analysis", ""),
                "severity": analysis.get("severity", ""),
                "finding":  analysis.get("finding", ""),
                "target":   firmware.get("target", "")
            })

    # Sort by severity
    severity_order = {
        "CRITICAL": 0, "HIGH": 1,
        "MEDIUM": 2, "LOW": 3, "INFO": 4
    }
    all_findings.sort(
        key=lambda x: severity_order.get(
            x.get("severity", "INFO"), 4
        )
    )

    return jsonify(all_findings)


# ── API: AI results ───────────────────────────────────────────
@app.route('/api/ai', methods=['GET'])
def get_ai_results():
    """Return AI predictions and SHAP explanations."""
    ai = load_json("ai_engine/ai_results.json")
    if not ai:
        return jsonify([])
    if not isinstance(ai, list):
        ai = [ai]
    return jsonify(ai)


# ── API: Scan status ──────────────────────────────────────────
@app.route('/api/scan/status', methods=['GET'])
def get_scan_status():
    """Return current scan status."""
    return jsonify(scan_status)


# ── API: Start scan ───────────────────────────────────────────
@app.route('/api/scan/start', methods=['POST'])
def start_scan():
    """Start a new AIPET scan."""
    global scan_status

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
        scan_status["progress"] = 0
        scan_status["message"]  = "Starting scan..."
        scan_status["started"]  = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        try:
            python = os.path.join(BASE_DIR, "venv/bin/python3")
            aipet  = os.path.join(BASE_DIR, "aipet.py")

            if mode == "demo":
                cmd = [python, aipet, "--demo"]
            else:
                cmd = [python, aipet, "--target", target]

            scan_status["message"]  = "Running AIPET scan..."
            scan_status["progress"] = 10

            proc = subprocess.run(
                cmd,
                cwd=BASE_DIR,
                capture_output=True,
                text=True,
                timeout=300
            )

            scan_status["progress"] = 100
            scan_status["message"]  = "Scan complete"

        except subprocess.TimeoutExpired:
            scan_status["message"] = "Scan timed out"
        except Exception as e:
            scan_status["message"] = f"Error: {str(e)}"
        finally:
            scan_status["running"]   = False
            scan_status["completed"] = datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )

    thread = threading.Thread(target=run_scan)
    thread.daemon = True
    thread.start()

    return jsonify({
        "status":  "started",
        "target":  target,
        "mode":    mode
    })


# ── API: Reports ──────────────────────────────────────────────
@app.route('/api/reports', methods=['GET'])
def get_reports():
    """List all generated reports."""
    reporting_dir = os.path.join(BASE_DIR, "reporting")
    if not os.path.exists(reporting_dir):
        return jsonify([])

    reports = []
    for filename in os.listdir(reporting_dir):
        if filename.endswith(".md"):
            filepath = os.path.join(reporting_dir, filename)
            reports.append({
                "filename": filename,
                "size":     os.path.getsize(filepath),
                "created":  datetime.fromtimestamp(
                    os.path.getctime(filepath)
                ).strftime("%Y-%m-%d %H:%M:%S")
            })

    reports.sort(key=lambda x: x["created"], reverse=True)
    return jsonify(reports)


# ── API: Download report ──────────────────────────────────────
@app.route('/api/reports/<filename>', methods=['GET'])
def download_report(filename):
    """Download a specific report file."""
    filepath = os.path.join(BASE_DIR, "reporting", filename)
    if not os.path.exists(filepath):
        return jsonify({"error": "Report not found"}), 404
    return send_file(filepath, as_attachment=True)


# ── Run server ────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("  AIPET Dashboard Backend API")
    print("  Running at: http://localhost:5000")
    print("=" * 60)
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )
