# =============================================================
# AIPET — AI-Powered Penetration Testing Framework for IoT
# Module 6: AI Engine — SHAP Explainer
# Author: Binyam
# Institution: Coventry University — MSc Cyber Security
#              (Ethical Hacking)
# Date: March 2025
# Licence: MIT
# Description: Generates explainable AI predictions for IoT
#              device vulnerability assessments using SHAP
#              (SHapley Additive exPlanations).
#
#              For each device profile, produces:
#              1. Predicted vulnerability severity
#              2. Confidence score (0.0 - 1.0)
#              3. SHAP explanation of WHY the prediction
#                 was made — which features drove the result
#              4. Plain-English explanation for security teams
#
#              SHAP is based on game theory (Shapley values).
#              Each feature gets a score showing how much it
#              contributed to the prediction — positive values
#              pushed toward higher severity, negative values
#              pushed toward lower severity.
# =============================================================

import pickle
import json
import numpy as np
import pandas as pd
import shap
import os
from datetime import datetime

# ── Constants ─────────────────────────────────────────────────

# Path to trained model
MODEL_PATH = "ai_engine/models/aipet_model.pkl"

# Severity label mapping — matches model_trainer.py
SEVERITY_LABELS = {
    0: "Low",
    1: "Medium",
    2: "High",
    3: "Critical"
}

# Severity colours for report output
SEVERITY_COLORS = {
    "Low":      "ℹ️ ",
    "Medium":   "⚠️ ",
    "High":     "🔴",
    "Critical": "🚨"
}

# Human-readable explanations for each feature
# These turn SHAP values into plain English
FEATURE_EXPLANATIONS = {
    "device_type": "Device type classification",
    "open_port_count": "Total number of open ports",
    "port_22": "SSH service (port 22)",
    "port_23": "Telnet service (port 23) — plaintext protocol",
    "port_80": "HTTP web interface (port 80)",
    "port_443": "HTTPS web interface (port 443)",
    "port_502": "Modbus industrial protocol (port 502)",
    "port_1883": "MQTT broker unencrypted (port 1883)",
    "port_5683": "CoAP service (port 5683)",
    "port_8080": "Alternative HTTP interface (port 8080)",
    "port_8883": "MQTT broker encrypted (port 8883)",
    "mqtt_anonymous": "MQTT broker accepts anonymous connections",
    "mqtt_default_creds": "MQTT default credentials valid",
    "mqtt_sensitive_data": "Sensitive data in MQTT messages",
    "coap_unauth_read": "CoAP resources readable without auth",
    "coap_unauth_write": "CoAP resources writable without auth",
    "coap_replay": "CoAP replay attack successful",
    "http_default_creds": "HTTP default credentials valid",
    "http_admin_exposed": "Admin interface exposed without auth",
    "http_sensitive_data": "Sensitive data in HTTP responses",
    "firmware_hardcoded_creds": "Hardcoded credentials in firmware",
    "firmware_private_key": "Private key embedded in firmware",
    "firmware_telnet": "Telnet enabled in firmware config",
    "firmware_vulnerable_component":
        "Known vulnerable component in firmware",
    "firmware_debug": "Debug mode enabled in firmware",
    "firmware_version_risk": "Firmware version risk level",
}


# ── Load Model ────────────────────────────────────────────────
def load_model(model_path=MODEL_PATH):
    """
    Load the trained AIPET model from disk.

    The model file contains:
    - The trained RandomForestClassifier
    - Feature names (must match input data)
    - Severity label mappings
    - Training timestamp

    Args:
        model_path (str): Path to saved model pickle file

    Returns:
        tuple: (model, feature_names, severity_labels)
    """
    if not os.path.exists(model_path):
        raise FileNotFoundError(
            f"Model not found at {model_path}. "
            f"Run model_trainer.py first."
        )

    with open(model_path, 'rb') as f:
        model_data = pickle.load(f)

    model         = model_data["model"]
    feature_names = model_data["feature_names"]
    labels        = model_data["severity_labels"]

    print(f"[+] Model loaded from {model_path}")
    print(f"    Trained at: {model_data['saved_at']}")
    print(f"    Features:   {len(feature_names)}")

    return model, feature_names, labels


# ── Build Feature Vector ──────────────────────────────────────
def build_feature_vector(device_profile, feature_names):
    """
    Convert a device profile dictionary into a feature
    vector that the AI model can process.

    This is the bridge between AIPET's real scan output
    (JSON dictionaries from Modules 1-5) and the model's
    expected numerical input format.

    The feature vector must have exactly the same features
    in exactly the same order as the training data.
    Any missing features default to 0 (not detected).

    Args:
        device_profile (dict): Complete device profile
            containing results from all modules
        feature_names (list): Expected feature columns

    Returns:
        pd.DataFrame: Single-row feature vector
    """
    # Start with all zeros — features not found default to 0
    features = {name: 0 for name in feature_names}

    # ── Extract Module 1 features ─────────────────────────────
    ports = device_profile.get("ports", [])

    # Map port numbers to feature flags
    port_map = {
        22: "port_22", 23: "port_23",
        80: "port_80", 443: "port_443",
        502: "port_502", 1883: "port_1883",
        5683: "port_5683", 8080: "port_8080",
        8883: "port_8883"
    }
    for port, feature in port_map.items():
        if port in ports and feature in features:
            features[feature] = 1

    # Total open ports
    if "open_port_count" in features:
        features["open_port_count"] = len(ports)

    # Device type encoding
    device_type_map = {
        "unknown_device":         0,
        "mqtt_broker":            1,
        "coap_device":            2,
        "ip_camera":              3,
        "iot_gateway":            4,
        "smart_home_hub":         5,
        "industrial_controller":  6,
        "embedded_linux_device":  7,
    }
    device_type = device_profile.get("device_type", "unknown")
    if "device_type" in features:
        features["device_type"] = device_type_map.get(
            device_type, 0
        )

    # Firmware version risk from risk score
    risk_score = device_profile.get("risk_score", 0)
    if "firmware_version_risk" in features:
        if risk_score >= 80:
            features["firmware_version_risk"] = 3
        elif risk_score >= 50:
            features["firmware_version_risk"] = 2
        elif risk_score >= 25:
            features["firmware_version_risk"] = 1
        else:
            features["firmware_version_risk"] = 0

    # ── Extract Module 2 features (MQTT) ──────────────────────
    mqtt_results = device_profile.get("mqtt_results", {})
    if mqtt_results:
        attacks = mqtt_results.get("attacks", [])
        for attack in attacks:
            name = attack.get("attack", "")

            # Connection test — anonymous access
            if name == "Connection Test":
                if attack.get("connected") and \
                        not attack.get("auth_required"):
                    features["mqtt_anonymous"] = 1

            # Auth bypass — default credentials
            elif name == "Authentication Bypass":
                if attack.get("bypass_found"):
                    features["mqtt_default_creds"] = 1

            # Sensitive data harvest
            elif name == "Sensitive Data Harvest":
                if attack.get("sensitive_found"):
                    features["mqtt_sensitive_data"] = 1

    # ── Extract Module 3 features (CoAP) ──────────────────────
    coap_results = device_profile.get("coap_results", {})
    if coap_results:
        attacks = coap_results.get("attacks", [])
        for attack in attacks:
            name = attack.get("attack", "")

            if name == "Unauthenticated Access":
                if attack.get("readable_resources"):
                    features["coap_unauth_read"] = 1
                if attack.get("writable_resources"):
                    features["coap_unauth_write"] = 1

            elif name == "Replay Attack":
                if attack.get("vulnerable_resources"):
                    features["coap_replay"] = 1

    # ── Extract Module 4 features (HTTP) ──────────────────────
    http_results = device_profile.get("http_results", {})
    if http_results:
        attacks = http_results.get("attacks", [])
        for attack in attacks:
            name = attack.get("attack", "")

            if name == "Default Credential Testing":
                if attack.get("valid_credentials"):
                    features["http_default_creds"] = 1

            elif name == "Admin Interface Discovery":
                if attack.get("admin_found"):
                    features["http_admin_exposed"] = 1
                if attack.get("sensitive_responses"):
                    features["http_sensitive_data"] = 1

    # ── Extract Module 5 features (Firmware) ──────────────────
    firmware_results = device_profile.get(
        "firmware_results", {}
    )
    if firmware_results:
        analyses = firmware_results.get("analyses", [])
        for analysis in analyses:
            name = analysis.get("analysis", "")

            if name == "Credential Hunt":
                if analysis.get("credentials_found"):
                    features["firmware_hardcoded_creds"] = 1

            elif name == "Private Key Scanner":
                if analysis.get("keys_found"):
                    features["firmware_private_key"] = 1

            elif name == "Dangerous Configuration Scanner":
                configs = analysis.get("configs_found", [])
                for config in configs:
                    if "Telnet" in config.get("pattern", ""):
                        features["firmware_telnet"] = 1
                    if "Debug" in config.get("pattern", ""):
                        features["firmware_debug"] = 1

            elif name == "Vulnerable Component Scanner":
                if analysis.get("components_found"):
                    features[
                        "firmware_vulnerable_component"
                    ] = 1

    # Convert to DataFrame — model expects DataFrame input
    return pd.DataFrame([features])[feature_names]


# ── Generate SHAP Explanation ─────────────────────────────────
def generate_shap_explanation(model, feature_vector,
                               feature_names):
    """
    Generate SHAP values for a single prediction.

    SHAP (SHapley Additive exPlanations) uses game theory
    to explain each prediction. For each feature it calculates
    how much that feature contributed to the final prediction.

    TreeExplainer is used for Random Forest models — it
    computes exact SHAP values efficiently by traversing
    the decision trees directly (no sampling required).

    Args:
        model: Trained RandomForestClassifier
        feature_vector (pd.DataFrame): Single device features
        feature_names (list): Feature column names

    Returns:
        dict: SHAP values and explanation data
    """
    # TreeExplainer computes exact SHAP values for tree models
    # Much faster and more accurate than KernelExplainer
    explainer = shap.TreeExplainer(model)

    # Calculate SHAP values for this prediction
    # Returns array of shape (n_classes, n_features)
    # One SHAP value per feature per class
    shap_values = explainer.shap_values(feature_vector)

    # Get the predicted class
    predicted_class = model.predict(feature_vector)[0]
    probabilities   = model.predict_proba(feature_vector)[0]
    confidence      = probabilities[predicted_class]
    
    # Get SHAP values for the predicted class
    # Handle both old SHAP (list of arrays) and
    # new SHAP 0.51+ (3D array: samples x features x classes)
    if isinstance(shap_values, list):
        # Old format — list of (n_samples, n_features) arrays
        class_shap_values = shap_values[predicted_class][0]
    else:
        # New format — single (n_samples, n_features, n_classes)
        class_shap_values = shap_values[0, :, predicted_class]

    # Build feature contribution dictionary
    # Sorted by absolute contribution (most important first)
    contributions = {}
    for i, feature in enumerate(feature_names):
        contributions[feature] = float(class_shap_values[i])

    # Sort by absolute SHAP value — largest impact first
    sorted_contributions = dict(
        sorted(
            contributions.items(),
            key=lambda x: abs(x[1]),
            reverse=True
        )
    )

    return {
        "predicted_class":    int(predicted_class),
        "predicted_severity": SEVERITY_LABELS[predicted_class],
        "confidence":         round(float(confidence), 4),
        "probabilities": {
            SEVERITY_LABELS[i]: round(float(p), 4)
            for i, p in enumerate(probabilities)
        },
        "shap_contributions": sorted_contributions,
        "expected_value":     float(
            explainer.expected_value[predicted_class]
            if isinstance(explainer.expected_value, np.ndarray)
            else explainer.expected_value
        )
    }


# ── Generate Plain English Explanation ───────────────────────
def generate_plain_english(shap_explanation,
                            feature_vector,
                            feature_names):
    """
    Convert SHAP values into a plain-English explanation
    that a security team can understand and act on.

    This is the key innovation of AIPET's explainability
    layer. Instead of just giving a severity rating, AIPET
    tells the analyst exactly WHY a device is rated that way
    — which specific findings drove the AI's conclusion.

    Args:
        shap_explanation (dict): SHAP output from
                                  generate_shap_explanation()
        feature_vector (pd.DataFrame): Device features
        feature_names (list): Feature column names

    Returns:
        str: Human-readable explanation
    """
    severity   = shap_explanation["predicted_severity"]
    confidence = shap_explanation["confidence"] * 100
    contribs   = shap_explanation["shap_contributions"]

    # Get feature values for context
    feature_vals = feature_vector.iloc[0].to_dict()

    # Build explanation text
    lines = []
    lines.append(
        f"Predicted Severity: {severity} "
        f"(confidence: {confidence:.1f}%)"
    )
    lines.append("")
    lines.append("Key factors driving this prediction:")

    # Show top 5 positive contributors
    # (features that increased severity)
    positive_factors = [
        (feat, val) for feat, val in contribs.items()
        if val > 0.01 and feature_vals.get(feat, 0) > 0
    ][:5]

    if positive_factors:
        lines.append("")
        lines.append("  Increasing severity:")
        for feature, shap_val in positive_factors:
            explanation = FEATURE_EXPLANATIONS.get(
                feature, feature
            )
            pct = abs(shap_val) * 100
            lines.append(
                f"  + {explanation} "
                f"(impact: {pct:.1f}%)"
            )

    # Show top 3 negative contributors
    # (features that reduced severity)
    negative_factors = [
        (feat, val) for feat, val in contribs.items()
        if val < -0.01
    ][:3]

    if negative_factors:
        lines.append("")
        lines.append("  Reducing severity:")
        for feature, shap_val in negative_factors:
            explanation = FEATURE_EXPLANATIONS.get(
                feature, feature
            )
            pct = abs(shap_val) * 100
            lines.append(
                f"  - {explanation} "
                f"(impact: {pct:.1f}%)"
            )

    # Add probability breakdown
    lines.append("")
    lines.append("Severity probability breakdown:")
    for sev, prob in shap_explanation["probabilities"].items():
        bar = "█" * int(prob * 20)
        lines.append(f"  {sev:10} {prob*100:5.1f}%  {bar}")

    return "\n".join(lines)


# ── Main Prediction Function ──────────────────────────────────
def predict_and_explain(device_profile):
    """
    Generate an explainable vulnerability prediction for
    a single IoT device profile.

    This is the main entry point for Module 6.
    Takes a complete device profile (combining all
    Module 1-5 results) and produces:
    - Severity prediction
    - Confidence score
    - SHAP feature contributions
    - Plain-English explanation

    Args:
        device_profile (dict): Complete device profile
            with results from all AIPET modules

    Returns:
        dict: Complete explainable prediction
    """
    # Load model
    model, feature_names, labels = load_model()

    # Build feature vector from device profile
    feature_vector = build_feature_vector(
        device_profile, feature_names
    )

    # Generate SHAP explanation
    shap_explanation = generate_shap_explanation(
        model, feature_vector, feature_names
    )

    # Generate plain English explanation
    plain_english = generate_plain_english(
        shap_explanation, feature_vector, feature_names
    )

    # Build complete result
    result = {
        "ip":             device_profile.get("ip", "unknown"),
        "device_type":    device_profile.get(
                              "device_type", "unknown"
                          ),
        "prediction":     shap_explanation,
        "explanation":    plain_english,
        "feature_vector": feature_vector.iloc[0].to_dict(),
        "predicted_at":   datetime.now().strftime(
                              "%Y-%m-%d %H:%M:%S"
                          )
    }

    return result


# ── Run on all complete profiles ──────────────────────────────
def run_ai_engine(profiles_path="recon/complete_profiles.json",
                  output_path="ai_engine/ai_results.json"):
    """
    Run the AI engine on all device profiles from Module 1.

    Loads complete_profiles.json, enriches each profile
    with an explainable AI prediction, and saves results.

    Args:
        profiles_path (str): Path to complete profiles JSON
        output_path (str): Path to save AI results

    Returns:
        list: All predictions with explanations
    """
    print("=" * 60)
    print("  AIPET — Module 6: Explainable AI Engine")
    print("=" * 60)

    # Load device profiles
    try:
        with open(profiles_path, 'r') as f:
            profiles = json.load(f)
        print(f"[+] Loaded {len(profiles)} device profile(s)")
    except FileNotFoundError:
        print(f"[-] Profiles not found at {profiles_path}")
        print("    Run Module 1 first.")
        return []

    all_predictions = []

    for profile in profiles:
        ip = profile.get("ip", "unknown")
        print(f"\n[*] Analysing device: {ip}")
        print(f"    Type: {profile.get('device_type', 'unknown')}")

        # Generate prediction and explanation
        result = predict_and_explain(profile)

        severity   = result["prediction"]["predicted_severity"]
        confidence = result["prediction"]["confidence"] * 100
        icon       = SEVERITY_COLORS.get(severity, "")

        print(f"\n{icon} PREDICTION: {severity} "
              f"({confidence:.1f}% confidence)")
        print()
        print(result["explanation"])
        print()

        all_predictions.append(result)

    # Save all predictions
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(all_predictions, f, indent=4)

    print("\n" + "=" * 60)
    print("  AI ENGINE SUMMARY")
    print("=" * 60)
    print(f"  Devices analysed: {len(all_predictions)}")

    # Tally by severity
    severity_counts = {}
    for pred in all_predictions:
        sev = pred["prediction"]["predicted_severity"]
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    for sev, count in severity_counts.items():
        icon = SEVERITY_COLORS.get(sev, "")
        print(f"  {icon} {sev}: {count}")

    print(f"\n[+] Results saved to {output_path}")
    print("=" * 60)

    return all_predictions


if __name__ == "__main__":
    run_ai_engine()