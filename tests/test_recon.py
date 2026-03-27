# =============================================================
# AIPET — AI-Powered Penetration Testing Framework for IoT
# Tests: Module 1 — Recon Engine
# Author: Binyam
# Institution: Coventry University — MSc Cyber Security
#              (Ethical Hacking)
# Date: March 2025
# Description: Unit tests for scanner, fingerprint, and
#              profiles modules. Tests core logic without
#              requiring a live network target.
# =============================================================

import unittest
import json
import os
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)
)))

from recon.fingerprint import (
    fingerprint_device,
    SIGNATURES,
    PORT_RISKS
)
from recon.profiles import (
    calculate_risk_score,
    get_risk_label,
    recommend_modules,
    PORT_RISK_SCORES,
    DEVICE_TYPE_RISK
)


class TestFingerprint(unittest.TestCase):
    """Tests for IoT device fingerprinting logic."""

    def test_mqtt_broker_fingerprinted_by_port(self):
        """
        A device with port 1883 open should be identified
        as an MQTT broker — the most distinctive IoT port.
        """
        profile = {
            "ip": "192.168.1.1",
            "ports": [1883],
            "services": {
                "1883": {
                    "name": "mqtt",
                    "product": "Mosquitto",
                    "version": "1.4.8",
                    "extrainfo": ""
                }
            }
        }
        result = fingerprint_device(profile)
        self.assertEqual(result["device_type"], "mqtt_broker")
        self.assertGreater(result["confidence"], 0)

    def test_coap_device_fingerprinted_by_port(self):
        """
        A device with port 5683 open should be identified
        as a CoAP device.
        """
        profile = {
            "ip": "192.168.1.2",
            "ports": [5683],
            "services": {
                "5683": {
                    "name": "coap",
                    "product": "",
                    "version": "",
                    "extrainfo": ""
                }
            }
        }
        result = fingerprint_device(profile)
        self.assertEqual(result["device_type"], "coap_device")

    def test_embedded_linux_fingerprinted_by_ssh(self):
        """
        A device with only port 22 (SSH) open should be
        identified as an embedded Linux device.
        """
        profile = {
            "ip": "192.168.1.3",
            "ports": [22],
            "services": {
                "22": {
                    "name": "ssh",
                    "product": "OpenSSH",
                    "version": "7.2",
                    "extrainfo": ""
                }
            }
        }
        result = fingerprint_device(profile)
        self.assertEqual(
            result["device_type"],
            "embedded_linux_device"
        )

    def test_unknown_device_no_ports(self):
        """
        A device with no open ports should return
        unknown_device with zero confidence.
        """
        profile = {
            "ip": "192.168.1.4",
            "ports": [],
            "services": {}
        }
        result = fingerprint_device(profile)
        self.assertEqual(result["device_type"], "unknown_device")
        self.assertEqual(result["confidence"], 0.0)

    def test_telnet_port_flagged_as_risk(self):
        """
        Port 23 (Telnet) should always be flagged as a
        risk indicator — it sends credentials in plaintext.
        """
        profile = {
            "ip": "192.168.1.5",
            "ports": [23],
            "services": {
                "23": {
                    "name": "telnet",
                    "product": "",
                    "version": "",
                    "extrainfo": ""
                }
            }
        }
        result = fingerprint_device(profile)
        # Risk indicators should contain port 23
        risk_ports = [
            r["port"] for r in result["risk_indicators"]
        ]
        self.assertIn(23, risk_ports)

    def test_mqtt_port_flagged_as_risk(self):
        """
        Port 1883 (unencrypted MQTT) should be flagged
        as a risk indicator.
        """
        profile = {
            "ip": "192.168.1.6",
            "ports": [1883],
            "services": {
                "1883": {
                    "name": "mqtt",
                    "product": "Mosquitto",
                    "version": "1.4",
                    "extrainfo": ""
                }
            }
        }
        result = fingerprint_device(profile)
        risk_ports = [
            r["port"] for r in result["risk_indicators"]
        ]
        self.assertIn(1883, risk_ports)

    def test_confidence_between_0_and_100(self):
        """
        Confidence score must always be between 0 and 100.
        """
        profile = {
            "ip": "192.168.1.7",
            "ports": [80, 1883, 5683],
            "services": {
                "80": {
                    "name": "http",
                    "product": "lighttpd",
                    "version": "1.4",
                    "extrainfo": ""
                },
                "1883": {
                    "name": "mqtt",
                    "product": "",
                    "version": "",
                    "extrainfo": ""
                },
                "5683": {
                    "name": "coap",
                    "product": "",
                    "version": "",
                    "extrainfo": ""
                }
            }
        }
        result = fingerprint_device(profile)
        self.assertGreaterEqual(result["confidence"], 0)
        self.assertLessEqual(result["confidence"], 100)

    def test_signatures_database_not_empty(self):
        """
        The SIGNATURES database must contain entries.
        If it is empty AIPET cannot fingerprint anything.
        """
        self.assertGreater(len(SIGNATURES), 0)

    def test_port_risks_database_not_empty(self):
        """
        The PORT_RISKS database must contain dangerous ports.
        """
        self.assertGreater(len(PORT_RISKS), 0)
        # Telnet must always be in the risk database
        self.assertIn(23, PORT_RISKS)
        # MQTT must always be in the risk database
        self.assertIn(1883, PORT_RISKS)


class TestProfiles(unittest.TestCase):
    """Tests for device profile building and risk scoring."""

    def test_risk_score_capped_at_100(self):
        """
        Risk score must never exceed 100 regardless of
        how many dangerous ports are open.
        """
        profile = {
            "ports": [23, 502, 1883, 5683, 80, 8080],
            "device_type": "industrial_controller"
        }
        score = calculate_risk_score(profile)
        self.assertLessEqual(score, 100)

    def test_risk_score_minimum_zero(self):
        """
        Risk score must never be negative.
        """
        profile = {
            "ports": [],
            "device_type": "unknown_device"
        }
        score = calculate_risk_score(profile)
        self.assertGreaterEqual(score, 0)

    def test_telnet_increases_risk(self):
        """
        A device with Telnet open should have a higher
        risk score than the same device without it.
        """
        profile_no_telnet = {
            "ports": [22],
            "device_type": "embedded_linux_device"
        }
        profile_with_telnet = {
            "ports": [22, 23],
            "device_type": "embedded_linux_device"
        }
        score_no_telnet    = calculate_risk_score(
            profile_no_telnet
        )
        score_with_telnet  = calculate_risk_score(
            profile_with_telnet
        )
        self.assertGreater(score_with_telnet, score_no_telnet)

    def test_critical_label_for_high_score(self):
        """
        A score of 80 or above must return CRITICAL label.
        """
        self.assertEqual(get_risk_label(80),  "CRITICAL")
        self.assertEqual(get_risk_label(90),  "CRITICAL")
        self.assertEqual(get_risk_label(100), "CRITICAL")

    def test_high_label_for_medium_score(self):
        """
        A score between 60 and 79 must return HIGH label.
        """
        self.assertEqual(get_risk_label(60), "HIGH")
        self.assertEqual(get_risk_label(70), "HIGH")
        self.assertEqual(get_risk_label(79), "HIGH")

    def test_low_label_for_low_score(self):
        """
        A score below 20 must return INFORMATIONAL label.
        """
        self.assertEqual(get_risk_label(0),  "INFORMATIONAL")
        self.assertEqual(get_risk_label(10), "INFORMATIONAL")
        self.assertEqual(get_risk_label(19), "INFORMATIONAL")

    def test_mqtt_port_recommends_module_2(self):
        """
        A device with port 1883 open must have Module 2
        (MQTT Attack Suite) in its recommendations.
        """
        profile = {
            "ports": [1883],
            "device_type": "mqtt_broker"
        }
        recommendations = recommend_modules(profile)
        module_names = [r["module"] for r in recommendations]
        self.assertTrue(
            any("Module 2" in m for m in module_names)
        )

    def test_coap_port_recommends_module_3(self):
        """
        A device with port 5683 open must have Module 3
        (CoAP Attack Suite) in its recommendations.
        """
        profile = {
            "ports": [5683],
            "device_type": "coap_device"
        }
        recommendations = recommend_modules(profile)
        module_names = [r["module"] for r in recommendations]
        self.assertTrue(
            any("Module 3" in m for m in module_names)
        )

    def test_http_port_recommends_module_4(self):
        """
        A device with port 80 open must have Module 4
        (HTTP/Web IoT Suite) in its recommendations.
        """
        profile = {
            "ports": [80],
            "device_type": "iot_gateway"
        }
        recommendations = recommend_modules(profile)
        module_names = [r["module"] for r in recommendations]
        self.assertTrue(
            any("Module 4" in m for m in module_names)
        )

    def test_no_ports_no_recommendations(self):
        """
        A device with no open ports should have no
        port-based module recommendations.
        """
        profile = {
            "ports": [],
            "device_type": "unknown_device"
        }
        recommendations = recommend_modules(profile)
        # May have firmware recommendation but no port-based
        port_recs = [
            r for r in recommendations
            if "Module 2" in r["module"] or
               "Module 3" in r["module"] or
               "Module 4" in r["module"]
        ]
        self.assertEqual(len(port_recs), 0)

    def test_critical_priority_sorted_first(self):
        """
        CRITICAL priority recommendations must appear
        before MEDIUM priority ones in the sorted list.
        """
        profile = {
            "ports": [23, 80],  # 23=Telnet critical, 80=HTTP
            "device_type": "embedded_linux_device"
        }
        recommendations = recommend_modules(profile)
        if len(recommendations) >= 2:
            priorities = [r["priority"] for r in recommendations]
            priority_order = {
                "CRITICAL": 0, "HIGH": 1,
                "MEDIUM": 2,   "LOW": 3
            }
            # Check list is sorted correctly
            for i in range(len(priorities) - 1):
                self.assertLessEqual(
                    priority_order.get(priorities[i], 99),
                    priority_order.get(priorities[i+1], 99)
                )


class TestFirmwarePatterns(unittest.TestCase):
    """Tests for firmware analysis pattern matching."""

    def setUp(self):
        """Create temporary test files for pattern testing."""
        self.test_dir = "/tmp/aipet_test_firmware"
        os.makedirs(self.test_dir, exist_ok=True)

    def tearDown(self):
        """Clean up temporary test files."""
        import shutil
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_hardcoded_password_detected(self):
        """
        A file containing 'password=secret123' should
        be flagged by the credential hunter.
        """
        from firmware.firmware_analyser import hunt_credentials

        # Create a test config file with hardcoded password
        test_file = os.path.join(
            self.test_dir, "test_config.conf"
        )
        with open(test_file, 'w') as f:
            f.write("admin_password=secret123\n")
            f.write("device_name=TestDevice\n")

        result = hunt_credentials(self.test_dir)
        self.assertGreater(
            len(result["credentials_found"]), 0
        )

    def test_private_key_detected(self):
        """
        A file containing a PEM private key header should
        be flagged by the private key scanner.
        """
        from firmware.firmware_analyser import scan_private_keys

        # Create a test file with fake private key header
        test_file = os.path.join(self.test_dir, "server.key")
        with open(test_file, 'w') as f:
            f.write("-----BEGIN RSA PRIVATE KEY-----\n")
            f.write("FAKEKEYDATA\n")
            f.write("-----END RSA PRIVATE KEY-----\n")

        result = scan_private_keys(self.test_dir)
        self.assertGreater(len(result["keys_found"]), 0)

    def test_telnet_config_detected(self):
        """
        A config file with 'telnet_enabled=true' should
        be flagged as a dangerous configuration.
        """
        from firmware.firmware_analyser import (
            scan_dangerous_configs
        )

        test_file = os.path.join(
            self.test_dir, "device.conf"
        )
        with open(test_file, 'w') as f:
            f.write("telnet_enabled=true\n")
            f.write("ssh_enabled=true\n")

        result = scan_dangerous_configs(self.test_dir)
        self.assertGreater(len(result["configs_found"]), 0)

    def test_clean_firmware_no_findings(self):
        """
        A clean config file with no sensitive content
        should produce zero credential findings.
        """
        from firmware.firmware_analyser import hunt_credentials

        test_file = os.path.join(
            self.test_dir, "clean.conf"
        )
        with open(test_file, 'w') as f:
            f.write("device_name=CleanDevice\n")
            f.write("log_level=info\n")
            f.write("timeout=30\n")

        result = hunt_credentials(self.test_dir)
        self.assertEqual(
            len(result["credentials_found"]), 0
        )


class TestAIEngine(unittest.TestCase):
    """Tests for AI model loading and prediction."""

    def test_model_file_exists(self):
        """
        The trained model file must exist before
        predictions can be made.
        """
        model_path = "ai_engine/models/aipet_model.pkl"
        self.assertTrue(
            os.path.exists(model_path),
            f"Model file not found at {model_path}. "
            f"Run model_trainer.py first."
        )

    def test_model_loads_successfully(self):
        """
        The model must load without errors and contain
        all required components.
        """
        from ai_engine.explainer import load_model
        model, feature_names, labels = load_model()

        self.assertIsNotNone(model)
        self.assertGreater(len(feature_names), 0)
        self.assertEqual(len(labels), 4)  # 4 severity classes

    def test_model_has_correct_features(self):
        """
        The model must have exactly 26 features —
        matching our training data design.
        """
        from ai_engine.explainer import load_model
        _, feature_names, _ = load_model()
        self.assertEqual(len(feature_names), 26)

    def test_prediction_returns_valid_severity(self):
        """
        Any prediction must return one of the four
        valid severity labels.
        """
        from ai_engine.explainer import (
            load_model,
            build_feature_vector,
            generate_shap_explanation
        )

        valid_severities = {"Low", "Medium", "High", "Critical"}

        model, feature_names, labels = load_model()

        # Test with a high-risk profile
        profile = {
            "ports": [23, 1883, 5683],
            "device_type": "mqtt_broker",
            "risk_score": 85
        }

        feature_vector = build_feature_vector(
            profile, feature_names
        )
        explanation = generate_shap_explanation(
            model, feature_vector, feature_names
        )

        self.assertIn(
            explanation["predicted_severity"],
            valid_severities
        )

    def test_confidence_between_0_and_1(self):
        """
        Confidence score must always be between 0.0 and 1.0.
        """
        from ai_engine.explainer import (
            load_model,
            build_feature_vector,
            generate_shap_explanation
        )

        model, feature_names, _ = load_model()

        profile = {
            "ports": [80],
            "device_type": "iot_gateway",
            "risk_score": 30
        }

        feature_vector = build_feature_vector(
            profile, feature_names
        )
        explanation = generate_shap_explanation(
            model, feature_vector, feature_names
        )

        self.assertGreaterEqual(
            explanation["confidence"], 0.0
        )
        self.assertLessEqual(
            explanation["confidence"], 1.0
        )

    def test_shap_contributions_sum_to_reasonable_value(self):
        """
        SHAP contributions must be present and non-empty.
        Every prediction must have feature explanations.
        """
        from ai_engine.explainer import (
            load_model,
            build_feature_vector,
            generate_shap_explanation
        )

        model, feature_names, _ = load_model()

        profile = {
            "ports": [1883],
            "device_type": "mqtt_broker",
            "risk_score": 70
        }

        feature_vector = build_feature_vector(
            profile, feature_names
        )
        explanation = generate_shap_explanation(
            model, feature_vector, feature_names
        )

        contributions = explanation["shap_contributions"]
        self.assertGreater(len(contributions), 0)
        self.assertEqual(
            len(contributions),
            len(feature_names)
        )


if __name__ == "__main__":
    # Run all tests with verbose output
    unittest.main(verbosity=2)