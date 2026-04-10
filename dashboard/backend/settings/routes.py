import requests
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.models import db, UserSettings

settings_bp = Blueprint('settings', __name__)


def send_slack_alert(webhook_url, message):
    try:
        resp = requests.post(webhook_url, json={"text": message}, timeout=5)
        return resp.status_code == 200
    except Exception:
        return False



def send_siem_event(webhook_url, finding_data):
    import requests, json
    payload = {
        "source": "AIPET",
        "event_type": "vulnerability_detected",
        "severity": finding_data.get("severity", "unknown").upper(),
        "device": finding_data.get("target", ""),
        "finding": finding_data.get("attack", ""),
        "description": finding_data.get("description", ""),
        "mitre_id": finding_data.get("mitre_id", "T1190"),
        "timestamp": finding_data.get("timestamp", ""),
        "risk_score": finding_data.get("risk_score", 0),
        "platform": "AIPET Cloud v3.0.0"
    }
    try:
        requests.post(webhook_url, json=payload, timeout=5)
    except Exception:
        pass

def send_teams_alert(webhook_url, message):
    try:
        payload = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "summary": "AIPET Alert",
            "themeColor": "00B4D8",
            "title": "AIPET Cloud Alert",
            "text": message
        }
        resp = requests.post(webhook_url, json=payload, timeout=5)
        return resp.status_code in (200, 202)
    except Exception:
        return False


def notify_finding(user_id, finding):
    settings = UserSettings.query.filter_by(user_id=user_id).first()
    if not settings:
        return
    severity = finding.get('severity', '').upper()
    should_notify = (
        (severity == 'CRITICAL' and settings.notify_critical) or
        (severity == 'HIGH' and settings.notify_high)
    )
    if not should_notify:
        return
    message = (
        f"AIPET ALERT - {severity} Finding\n"
        f"Device: {finding.get('ip', 'Unknown')}\n"
        f"Finding: {finding.get('name', 'Unknown')}\n"
        f"Severity: {severity}\n"
        f"Risk Score: {finding.get('risk_score', 'N/A')}\n"
        f"Fix: {finding.get('fix', 'See dashboard')}\n"
        f"View in AIPET: https://aipet.io/dashboard"
    )
    if settings.slack_webhook_url:
        send_slack_alert(settings.slack_webhook_url, message)
    if settings.teams_webhook_url:
        send_teams_alert(settings.teams_webhook_url, message)
    if settings.siem_webhook_url:
        send_siem_event(settings.siem_webhook_url, finding_data if 'finding_data' in dir() else {'severity': 'critical', 'target': '', 'attack': message})


@settings_bp.route('/api/settings', methods=['GET'])
@jwt_required()
def get_settings():
    user_id = get_jwt_identity()
    settings = UserSettings.query.filter_by(user_id=user_id).first()
    if settings:
        return jsonify(settings.to_dict())
    return jsonify({
        'slack_webhook_url': '',
        'siem_webhook_url': '',
        'teams_webhook_url': '',
        'notify_critical':   True,
        'notify_high':       True,
        'notify_cve':        False,
    })


@settings_bp.route('/api/settings', methods=['PUT'])
@jwt_required()
def update_settings():
    user_id = get_jwt_identity()
    data = request.get_json()
    settings = UserSettings.query.filter_by(user_id=user_id).first()
    if not settings:
        settings = UserSettings(user_id=user_id)
        db.session.add(settings)
    settings.slack_webhook_url = data.get('slack_webhook_url', '').strip() or None
    settings.teams_webhook_url = data.get('teams_webhook_url', '').strip() or None
    settings.siem_webhook_url = data.get('siem_webhook_url', '').strip() or None
    settings.notify_critical   = bool(data.get('notify_critical', True))
    settings.notify_high       = bool(data.get('notify_high', True))
    settings.notify_cve        = bool(data.get('notify_cve', False))
    db.session.commit()
    return jsonify({'message': 'Settings saved successfully'})


@settings_bp.route('/api/settings/test-slack', methods=['POST'])
@jwt_required()
def test_slack():
    data = request.get_json()
    webhook_url = data.get('slack_webhook_url', '').strip()
    if not webhook_url:
        return jsonify({'error': 'No Slack webhook URL provided'}), 400
    success = send_slack_alert(
        webhook_url,
        "AIPET Cloud - Slack alerts are connected successfully!"
    )
    if success:
        return jsonify({'message': 'Test message sent to Slack'})
    return jsonify({'error': 'Slack test failed - check your webhook URL'}), 400


@settings_bp.route('/api/settings/test-teams', methods=['POST'])
@jwt_required()
def test_teams():
    data = request.get_json()
    webhook_url = data.get('teams_webhook_url', '').strip()
    if not webhook_url:
        return jsonify({'error': 'No Teams webhook URL provided'}), 400
    success = send_teams_alert(
        webhook_url,
        "AIPET Cloud - Teams alerts are connected successfully!"
    )
    if success:
        return jsonify({'message': 'Test message sent to Teams'})
    return jsonify({'error': 'Teams test failed - check your webhook URL'}), 400

@settings_bp.route('/api/settings/test-siem', methods=['POST'])
@jwt_required()
def test_siem():
    import requests
    webhook_url = request.json.get('siem_webhook_url', '').strip()
    if not webhook_url:
        return jsonify({'error': 'No webhook URL'}), 400
    payload = {
        "source": "AIPET",
        "event_type": "test",
        "severity": "INFO",
        "device": "test-device",
        "finding": "aipet_test_event",
        "description": "AIPET SIEM integration test",
        "mitre_id": "T1190",
        "timestamp": "2026-01-01T00:00:00Z",
        "platform": "AIPET Cloud v3.0.0"
    }
    try:
        r = requests.post(webhook_url, json=payload, timeout=5)
        return jsonify({'success': True, 'status': r.status_code})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
