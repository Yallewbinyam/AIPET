# =============================================================
# AIPET — Parallel Scanning
# Component 4: Result Aggregator
# Author: Binyam
# Institution: Coventry University — MSc Cyber Security
# Date: March 2025
# Description: Merges results from all parallel scans into
#              a single unified report. Combines findings,
#              deduplicates devices, and sorts by severity.
# =============================================================

import os
import sys
import json
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)
)))

from parallel.result_isolation import (
    list_completed_targets,
    load_result,
    get_result_dir
)


SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH":     1,
    "MEDIUM":   2,
    "LOW":      3,
    "INFO":     4
}


def aggregate_findings(targets, base_dir="results"):
    """
    Aggregate all findings from multiple scan targets.

    Args:
        targets (list): List of scanned targets
        base_dir (str): Base results directory

    Returns:
        dict: Unified findings from all targets
    """
    all_findings  = []
    all_devices   = []
    all_ai        = []
    modules_run   = set()
    total_counts  = {
        "critical": 0, "high": 0,
        "medium":   0, "low":  0
    }

    for target in targets:
        result_dir = get_result_dir(target, base_dir)

        # ── Collect device profiles ───────────────────────
        profiles = load_result(
            target, "complete_profiles.json", base_dir
        )
        if profiles:
            if isinstance(profiles, list):
                all_devices.extend(profiles)
            else:
                all_devices.append(profiles)

        # ── Collect MQTT findings ─────────────────────────
        mqtt = load_result(
            target, "mqtt_results.json", base_dir
        )
        if mqtt:
            modules_run.add("Module 2: MQTT")
            for attack in mqtt.get("attacks", []):
                all_findings.append({
                    "module":   "MQTT",
                    "target":   target,
                    "attack":   attack.get("attack", ""),
                    "severity": attack.get("severity", "INFO"),
                    "finding":  attack.get("finding", ""),
                })
            summary = mqtt.get("summary", {})
            for sev in total_counts:
                total_counts[sev] += summary.get(sev, 0)

        # ── Collect CoAP findings ─────────────────────────
        coap = load_result(
            target, "coap_results.json", base_dir
        )
        if coap:
            modules_run.add("Module 3: CoAP")
            for attack in coap.get("attacks", []):
                all_findings.append({
                    "module":   "CoAP",
                    "target":   target,
                    "attack":   attack.get("attack", ""),
                    "severity": attack.get("severity", "INFO"),
                    "finding":  attack.get("finding", ""),
                })
            summary = coap.get("summary", {})
            for sev in total_counts:
                total_counts[sev] += summary.get(sev, 0)

        # ── Collect HTTP findings ─────────────────────────
        http = load_result(
            target, "http_results.json", base_dir
        )
        if http:
            modules_run.add("Module 4: HTTP")
            for attack in http.get("attacks", []):
                all_findings.append({
                    "module":   "HTTP",
                    "target":   target,
                    "attack":   attack.get("attack", ""),
                    "severity": attack.get("severity", "INFO"),
                    "finding":  attack.get("finding", ""),
                })
            summary = http.get("summary", {})
            for sev in total_counts:
                total_counts[sev] += summary.get(sev, 0)

        # ── Collect Firmware findings ─────────────────────
        firmware = load_result(
            target, "firmware_results.json", base_dir
        )
        if firmware:
            modules_run.add("Module 5: Firmware")
            for analysis in firmware.get("analyses", []):
                all_findings.append({
                    "module":   "Firmware",
                    "target":   target,
                    "attack":   analysis.get("analysis", ""),
                    "severity": analysis.get("severity", "INFO"),
                    "finding":  analysis.get("finding", ""),
                })
            summary = firmware.get("summary", {})
            for sev in total_counts:
                total_counts[sev] += summary.get(sev, 0)

        # ── Collect AI results ────────────────────────────
        ai = load_result(
            target, "ai_results.json", base_dir
        )
        if ai:
            modules_run.add("Module 6: AI Engine")
            if isinstance(ai, list):
                all_ai.extend(ai)
            else:
                all_ai.append(ai)

    # ── Sort findings by severity ─────────────────────────
    all_findings.sort(
        key=lambda x: SEVERITY_ORDER.get(
            x.get("severity", "INFO"), 4
        )
    )

    # ── Determine overall risk ────────────────────────────
    if total_counts["critical"] > 0:
        overall_risk  = "CRITICAL"
        risk_color    = "#ef4444"
    elif total_counts["high"] > 0:
        overall_risk  = "HIGH"
        risk_color    = "#f97316"
    elif total_counts["medium"] > 0:
        overall_risk  = "MEDIUM"
        risk_color    = "#eab308"
    else:
        overall_risk  = "LOW"
        risk_color    = "#22c55e"

    return {
        "targets":      targets,
        "target_count": len(targets),
        "devices":      all_devices,
        "device_count": len(all_devices),
        "findings":     all_findings,
        "ai_results":   all_ai,
        "modules_run":  sorted(list(modules_run)),
        "summary": {
            "overall_risk":  overall_risk,
            "risk_color":    risk_color,
            "critical":      total_counts["critical"],
            "high":          total_counts["high"],
            "medium":        total_counts["medium"],
            "low":           total_counts["low"],
            "total":         sum(total_counts.values()),
        },
        "generated_at": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
    }


def generate_unified_report(
    aggregated, output_dir="reporting"
):
    """
    Generate a unified markdown report from aggregated results.

    Args:
        aggregated (dict): Aggregated results from all scans
        output_dir (str): Directory to save report

    Returns:
        str: Path to generated report
    """
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = os.path.join(
        output_dir,
        f"aipet_parallel_report_{timestamp}.md"
    )

    summary  = aggregated["summary"]
    targets  = aggregated["targets"]
    findings = aggregated["findings"]
    devices  = aggregated["devices"]

    with open(report_path, "w") as f:
        # Header
        f.write("# AIPET Parallel Scan Report\n\n")
        f.write(f"**Generated:** {aggregated['generated_at']}\n")
        f.write(f"**Networks Scanned:** "
                f"{aggregated['target_count']}\n")
        f.write(f"**Devices Discovered:** "
                f"{aggregated['device_count']}\n")
        f.write(f"**Overall Risk:** "
                f"{summary['overall_risk']}\n\n")

        # Targets
        f.write("## Networks Scanned\n\n")
        for t in targets:
            f.write(f"- {t}\n")
        f.write("\n")

        # Executive Summary
        f.write("## Executive Summary\n\n")
        f.write(f"| Severity | Count |\n")
        f.write(f"|----------|-------|\n")
        f.write(f"| CRITICAL | {summary['critical']} |\n")
        f.write(f"| HIGH     | {summary['high']}     |\n")
        f.write(f"| MEDIUM   | {summary['medium']}   |\n")
        f.write(f"| LOW      | {summary['low']}      |\n")
        f.write(f"| **TOTAL**| **{summary['total']}**|\n\n")

        # Findings
        f.write("## All Findings (Sorted by Severity)\n\n")
        for finding in findings:
            sev = finding["severity"]
            f.write(f"### [{sev}] {finding['attack']}\n")
            f.write(f"**Module:** {finding['module']} | ")
            f.write(f"**Target:** {finding['target']}\n\n")
            f.write(f"{finding['finding']}\n\n")
            f.write("---\n\n")

    # Save JSON version
    json_path = report_path.replace(".md", ".json")
    with open(json_path, "w") as f:
        json.dump(aggregated, f, indent=4)

    return report_path


if __name__ == "__main__":
    print("Testing result aggregator...")

    # Create mock results for testing
    import tempfile
    import shutil

    test_base = tempfile.mkdtemp()
    test_targets = ["192.168.1.0/24", "10.0.0.0/24"]

    # Create mock MQTT results for target 1
    target1_dir = os.path.join(
        test_base, "192.168.1.0_24"
    )
    os.makedirs(target1_dir, exist_ok=True)

    mock_mqtt = {
        "target": "192.168.1.0/24",
        "attacks": [
            {
                "attack":   "Connection Test",
                "severity": "CRITICAL",
                "finding":  "Anonymous access allowed"
            },
            {
                "attack":   "Message Injection",
                "severity": "HIGH",
                "finding":  "Messages injected"
            }
        ],
        "summary": {
            "critical": 1, "high": 1,
            "medium": 0, "low": 0
        }
    }
    with open(
        os.path.join(target1_dir, "mqtt_results.json"), "w"
    ) as f:
        json.dump(mock_mqtt, f)

    # Create mock HTTP results for target 2
    target2_dir = os.path.join(
        test_base, "10.0.0.0_24"
    )
    os.makedirs(target2_dir, exist_ok=True)

    mock_http = {
        "target": "10.0.0.0/24",
        "attacks": [
            {
                "attack":   "Default Credentials",
                "severity": "CRITICAL",
                "finding":  "admin/admin accepted"
            }
        ],
        "summary": {
            "critical": 1, "high": 0,
            "medium": 0, "low": 0
        }
    }
    with open(
        os.path.join(target2_dir, "http_results.json"), "w"
    ) as f:
        json.dump(mock_http, f)

    # Test aggregation
    aggregated = aggregate_findings(
        test_targets, base_dir=test_base
    )

    # Verify results
    assert aggregated["target_count"] == 2, "Wrong target count"
    assert aggregated["summary"]["critical"] == 2, (
        "Wrong critical count"
    )
    assert aggregated["summary"]["high"] == 1, (
        "Wrong high count"
    )
    assert aggregated["summary"]["overall_risk"] == "CRITICAL"
    assert len(aggregated["findings"]) == 3, (
        "Wrong finding count"
    )

    # Verify sorting — CRITICAL should come first
    assert aggregated["findings"][0]["severity"] == "CRITICAL"

    print("  [PASS] Findings aggregated from 2 targets")
    print("  [PASS] Critical count: 2 (1 from each target)")
    print("  [PASS] Findings sorted by severity")
    print("  [PASS] Overall risk: CRITICAL")

    # Test report generation
    report_path = generate_unified_report(
        aggregated,
        output_dir=os.path.join(test_base, "reports")
    )
    assert os.path.exists(report_path)
    print(f"  [PASS] Unified report generated")

    # Cleanup
    shutil.rmtree(test_base)

    print("\n[+] Result aggregator ready")
    print("[+] Merges findings from all parallel scans")
