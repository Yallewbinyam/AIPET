# =============================================================
# AIPET — AI-Powered Penetration Testing Framework for IoT
# Main Orchestrator
# Author: Binyam
# Institution: Coventry University — MSc Cyber Security
#              (Ethical Hacking)
# Date: March 2025
# Licence: MIT
# Description: Main entry point for AIPET.
#              Orchestrates all 7 modules in sequence.
#              A single command runs the complete IoT
#              penetration testing pipeline from
#              reconnaissance to professional report.
#
# Usage:
#   python3 aipet.py --target 192.168.1.0/24
#   python3 aipet.py --target 192.168.1.105
#   python3 aipet.py --target localhost --mqtt --coap --http
#   python3 aipet.py --demo
# =============================================================

import argparse
import json
import os
import sys
import time
from datetime import datetime

# ── Add project root to Python path ───────────────────────────
# This allows importing from all module subdirectories
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ── Module imports ─────────────────────────────────────────────
# Import each module's main entry point function

# Module 1 — Recon Engine
from recon.scanner      import discover_hosts, scan_ports
from recon.fingerprint  import fingerprint_all, load_scan_results
from recon.profiles     import build_all_profiles, save_complete_profiles

# Module 2 — MQTT Attack Suite
from mqtt.mqtt_attacker import run_mqtt_attacks

# Module 3 — CoAP Attack Suite
from coap.coap_attacker import run_coap_attacks

# Module 4 — HTTP/Web IoT Suite
from http_attack.http_attacker import run_http_attacks

# Module 5 — Firmware Analyser
from firmware.firmware_analyser import run_firmware_analysis

# Module 6 — Explainable AI Engine
from ai_engine.explainer import run_ai_engine

# Module 7 — Report Generator
from reporting.report_generator import generate_report


# ── Constants ─────────────────────────────────────────────────

VERSION = "1.0.0"

BANNER = f"""
╔══════════════════════════════════════════════════════════════╗
║         AIPET — Explainable AI-Powered IoT Pentest          ║
║                    Framework v{VERSION}                        ║
║                                                              ║
║  Coventry University — MSc Cyber Security (Ethical Hacking) ║
║                                                              ║
║  ⚠️  For authorised penetration testing only               ║
║  ⚠️  Never use against systems without written permission   ║
╚══════════════════════════════════════════════════════════════╝
"""

# Port to module mapping
# Tells AIPET which attack modules to run per open port
PORT_MODULE_MAP = {
    1883:  "mqtt",    # MQTT unencrypted
    8883:  "mqtt",    # MQTT encrypted
    5683:  "coap",    # CoAP
    5684:  "coap",    # CoAP encrypted
    80:    "http",    # HTTP
    443:   "http",    # HTTPS
    8080:  "http",    # Alternative HTTP
    8443:  "http",    # Alternative HTTPS
}

# Device types that warrant firmware analysis
FIRMWARE_DEVICE_TYPES = [
    "embedded_linux_device",
    "iot_gateway",
    "ip_camera",
    "industrial_controller",
    "mqtt_broker",
    "generic_iot_device",
]


# ── Helper: Print section header ──────────────────────────────
def print_section(title, module_num=None):
    """Print a formatted section header."""
    num = f"[Module {module_num}] " if module_num else ""
    print(f"\n{'═' * 60}")
    print(f"  {num}{title}")
    print(f"{'═' * 60}")


# ── Helper: Print status ──────────────────────────────────────
def print_status(message, status="info"):
    """Print a formatted status message."""
    icons = {
        "info":    "[*]",
        "success": "[+]",
        "warning": "[!]",
        "error":   "[-]",
        "skip":    "[~]"
    }
    icon = icons.get(status, "[*]")
    print(f"{icon} {message}")


# ── Helper: Save JSON ─────────────────────────────────────────
def save_json(data, filepath):
    """Save data to JSON file."""
    # Only create directory if filepath has a directory component
    dirpath = os.path.dirname(filepath)
    if dirpath:
        os.makedirs(dirpath, exist_ok=True)
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=4)


# ── Demo Mode ─────────────────────────────────────────────────
def start_demo_servers():
    """
    Automatically start all required demo servers.
    Starts Mosquitto, CoAP test server, and HTTP test
    server in background so the user does not need to
    open multiple terminals.

    Returns:
        list: Started subprocess objects
    """
    import subprocess
    import time

    processes = []
    python = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "venv/bin/python3"
    )

    print_status("Auto-starting demo servers...")

    # Start Mosquitto MQTT broker
    try:
        result = subprocess.run(
            ["sudo", "systemctl", "start", "mosquitto"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            print_status("Mosquitto MQTT broker started", "success")
        else:
            print_status("Mosquitto may already be running", "warning")
    except Exception as e:
        print_status(f"Could not start Mosquitto: {e}", "warning")

    # Start CoAP test server
    try:
        coap_proc = subprocess.Popen(
            [python, "lab/coap_test_server.py"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=os.path.dirname(os.path.abspath(__file__))
        )
        processes.append(coap_proc)
        print_status("CoAP test server started", "success")
    except Exception as e:
        print_status(f"Could not start CoAP server: {e}", "warning")

    # Start HTTP test server
    try:
        http_proc = subprocess.Popen(
            [python, "lab/http_test_server.py"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=os.path.dirname(os.path.abspath(__file__))
        )
        processes.append(http_proc)
        print_status("HTTP test server started", "success")
    except Exception as e:
        print_status(f"Could not start HTTP server: {e}", "warning")

    # Wait for servers to initialise
    print_status("Waiting for servers to initialise...")
    time.sleep(3)
    print_status("All demo servers ready", "success")
    print()

    return processes


def run_demo():
    """
    Run AIPET in demo mode against local test servers.
    Automatically starts all required servers.
    No manual setup needed - perfect for new users.
    """
    print_status("Running in DEMO mode")
    print_status("Auto-starting all required servers...")
    print()

    # Auto-start all demo servers
    processes = start_demo_servers()

    # Run with localhost as target, all modules enabled
    run_pipeline(
        target="localhost",
        run_mqtt=True,
        run_coap=True,
        run_http=True,
        run_firmware=True,
        firmware_path="lab/fake_firmware",
        mqtt_port=1883,
        coap_port=5683,
        http_port=8080,
        demo_mode=True
    )


# ── Main Pipeline ─────────────────────────────────────────────
def run_pipeline(
    target,
    run_mqtt=False,
    run_coap=False,
    run_http=False,
    run_firmware=False,
    firmware_path=None,
    mqtt_port=1883,
    coap_port=5683,
    http_port=80,
    demo_mode=False,
    skip_recon=False
):
    """
    Run the complete AIPET penetration testing pipeline.

    Executes all enabled modules in sequence, passing
    results from each module to the next. Automatically
    determines which attack modules to run based on
    Module 1 reconnaissance results.

    Args:
        target (str): Target IP, hostname, or CIDR range
        run_mqtt (bool): Force run MQTT module
        run_coap (bool): Force run CoAP module
        run_http (bool): Force run HTTP module
        run_firmware (bool): Force run Firmware module
        firmware_path (str): Path to firmware file/directory
        mqtt_port (int): MQTT broker port
        coap_port (int): CoAP device port
        http_port (int): HTTP web interface port
        demo_mode (bool): Skip recon, use test servers
        skip_recon (bool): Skip Module 1 if already run
    """
    start_time = time.time()
    print(BANNER)

    print_status(f"Target:    {target}")
    print_status(f"Started:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print_status(f"Mode:      {'DEMO' if demo_mode else 'LIVE'}")
    print()

    # Track which modules ran and their results
    pipeline_results = {
        "target":     target,
        "start_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "modules_run":[],
        "summary":    {}
    }

    # ── MODULE 1: Reconnaissance ───────────────────────────────
    print_section("Reconnaissance", 1)

    if demo_mode or skip_recon:
        # In demo mode use existing profiles
        print_status("Loading existing device profiles...")
        try:
            with open("recon/complete_profiles.json") as f:
                device_profiles = json.load(f)
            print_status(
                f"Loaded {len(device_profiles)} profile(s)",
                "success"
            )
        except FileNotFoundError:
            print_status(
                "No profiles found. Running full recon...",
                "warning"
            )
            device_profiles = []
    else:
        # Run full reconnaissance
        print_status(f"Discovering hosts on {target}...")
        live_hosts = discover_hosts(target)

        if not live_hosts:
            print_status(
                "No live hosts found. Check target range.",
                "error"
            )
            return

        print_status(
            f"Found {len(live_hosts)} live host(s)",
            "success"
        )

        # Scan ports on each host
        scan_results = []
        for host in live_hosts:
            profile = scan_ports(host)
            scan_results.append(profile)

        # Save scan results
        save_json(scan_results, "recon/scan_results.json")

        # Fingerprint all devices
        print_status("Fingerprinting devices...")
        fingerprinted = fingerprint_all(scan_results)
        save_json(fingerprinted, "recon/fingerprint_results.json")

        # Build complete profiles
        print_status("Building device profiles...")
        device_profiles = build_all_profiles(fingerprinted)
        save_complete_profiles(device_profiles)

    pipeline_results["modules_run"].append("Module 1: Recon")
    pipeline_results["devices_found"] = len(device_profiles)

    if not device_profiles:
        print_status("No device profiles. Cannot continue.", "error")
        return

    # ── Auto-detect which modules to run ──────────────────────
    # Based on open ports found in reconnaissance
    for profile in device_profiles:
        ports = profile.get("ports", [])

        # Check each open port against module map
        for port in ports:
            if port in PORT_MODULE_MAP:
                module = PORT_MODULE_MAP[port]
                if module == "mqtt":
                    run_mqtt = True
                    mqtt_port = port
                elif module == "coap":
                    run_coap = True
                    coap_port = port
                elif module == "http":
                    run_http = True
                    if port != 443:  # Skip HTTPS for now
                        http_port = port

        # Check if firmware analysis recommended
        device_type = profile.get("device_type", "")
        if device_type in FIRMWARE_DEVICE_TYPES:
            run_firmware = True

    print_status(
        f"Auto-detected modules: "
        f"{'MQTT ' if run_mqtt else ''}"
        f"{'CoAP ' if run_coap else ''}"
        f"{'HTTP ' if run_http else ''}"
        f"{'Firmware' if run_firmware else ''}",
        "success"
    )

    # ── MODULE 2: MQTT Attack Suite ───────────────────────────
    if run_mqtt:
        print_section("MQTT Attack Suite", 2)

        # Use target IP or first device IP
        mqtt_target = (
            target if demo_mode
            else device_profiles[0].get("ip", target)
        )

        mqtt_results = run_mqtt_attacks(mqtt_target, mqtt_port)
        pipeline_results["modules_run"].append("Module 2: MQTT")
        pipeline_results["mqtt_summary"] = (
            mqtt_results.get("summary", {})
        )
    else:
        print_status("MQTT module skipped — port 1883 not found", "skip")

    # ── MODULE 3: CoAP Attack Suite ───────────────────────────
    if run_coap:
        print_section("CoAP Attack Suite", 3)

        coap_target = (
            target if demo_mode
            else device_profiles[0].get("ip", target)
        )

        coap_results = run_coap_attacks(coap_target, coap_port)
        pipeline_results["modules_run"].append("Module 3: CoAP")
        pipeline_results["coap_summary"] = (
            coap_results.get("summary", {})
        )
    else:
        print_status("CoAP module skipped — port 5683 not found", "skip")

    # ── MODULE 4: HTTP Attack Suite ───────────────────────────
    if run_http:
        print_section("HTTP/Web IoT Suite", 4)

        http_target = (
            target if demo_mode
            else device_profiles[0].get("ip", target)
        )

        http_results = run_http_attacks(
            http_target, http_port
        )
        pipeline_results["modules_run"].append("Module 4: HTTP")
        pipeline_results["http_summary"] = (
            http_results.get("summary", {})
        )
    else:
        print_status("HTTP module skipped — port 80 not found", "skip")

    # ── MODULE 5: Firmware Analyser ───────────────────────────
    if run_firmware:
        print_section("Firmware Analyser", 5)

        # Use provided path or default lab firmware
        fw_path = firmware_path or "lab/fake_firmware"

        if os.path.exists(fw_path):
            firmware_results = run_firmware_analysis(fw_path)
            pipeline_results["modules_run"].append(
                "Module 5: Firmware"
            )
            pipeline_results["firmware_summary"] = (
                firmware_results.get("summary", {})
            )
        else:
            print_status(
                f"Firmware path not found: {fw_path}",
                "warning"
            )
            print_status(
                "Skipping firmware analysis",
                "skip"
            )
    else:
        print_status(
            "Firmware module skipped — not applicable",
            "skip"
        )

    # ── MODULE 6: Explainable AI Engine ───────────────────────
    print_section("Explainable AI Engine", 6)

    ai_results = run_ai_engine(
        profiles_path="recon/complete_profiles.json",
        output_path="ai_engine/ai_results.json"
    )
    pipeline_results["modules_run"].append("Module 6: AI Engine")
    pipeline_results["ai_predictions"] = len(ai_results)

    # ── MODULE 7: Report Generator ────────────────────────────
    print_section("Report Generator", 7)

    report_path = generate_report()
    pipeline_results["modules_run"].append("Module 7: Report")
    pipeline_results["report_path"] = report_path

    # ── Pipeline Complete ──────────────────────────────────────
    elapsed = time.time() - start_time
    pipeline_results["end_time"]     = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )
    pipeline_results["elapsed_seconds"] = round(elapsed, 2)

    # Save pipeline summary
    save_json(
        pipeline_results,
        "aipet_pipeline_results.json"
    )

    # Print final summary
    print(f"\n{'╔' + '═'*58 + '╗'}")
    print(f"║{'AIPET PIPELINE COMPLETE':^58}║")
    print(f"{'╠' + '═'*58 + '╣'}")
    print(f"║  Target:    {target:<45}║")
    print(f"║  Devices:   {len(device_profiles):<45}║")
    print(f"║  Modules:   {len(pipeline_results['modules_run']):<45}║")
    print(f"║  Duration:  {elapsed:.1f} seconds{'':<37}║")
    print(f"║  Report:    {str(report_path):<45}║")
    print(f"{'╚' + '═'*58 + '╝'}")

    # Count total findings
    total_critical = sum([
        pipeline_results.get("mqtt_summary", {}).get("critical", 0),
        pipeline_results.get("coap_summary", {}).get("critical", 0),
        pipeline_results.get("http_summary", {}).get("critical", 0),
    ])
    total_high = sum([
        pipeline_results.get("mqtt_summary", {}).get("high", 0),
        pipeline_results.get("coap_summary", {}).get("high", 0),
        pipeline_results.get("http_summary", {}).get("high", 0),
    ])

    if total_critical > 0:
        print(f"\n🚨 {total_critical} CRITICAL finding(s) — "
              f"immediate action required")
    if total_high > 0:
        print(f"🔴 {total_high} HIGH finding(s) — "
              f"address urgently")

    print(f"\n[+] Full report: {report_path}")
    print(f"[+] Pipeline results: aipet_pipeline_results.json")

    return pipeline_results


# ── Argument Parser ───────────────────────────────────────────
def parse_arguments():
    """
    Parse command line arguments for AIPET.

    Supports:
    - --target: IP, hostname, or CIDR range to scan
    - --demo: Run against local test servers
    - --mqtt: Force run MQTT module
    - --coap: Force run CoAP module
    - --http: Force run HTTP module
    - --firmware: Force run firmware analysis
    - --firmware-path: Path to firmware file/directory
    - --mqtt-port: MQTT port (default 1883)
    - --coap-port: CoAP port (default 5683)
    - --http-port: HTTP port (default 80)
    """
    parser = argparse.ArgumentParser(
        description=(
            "AIPET — Explainable AI-Powered IoT "
            "Penetration Testing Framework"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 aipet.py --target 192.168.1.0/24
  python3 aipet.py --target 192.168.1.105 --mqtt --http
  python3 aipet.py --target localhost --mqtt-port 1883
  python3 aipet.py --demo
  python3 aipet.py --target 10.0.0.1 --firmware --firmware-path /path/to/firmware.bin

Documentation:
  User Manual:     cat USER_MANUAL.md
  Install Guide:   cat INSTALL.md
  Responsible Use: cat RESPONSIBLE_USE.md
  GitHub:          https://github.com/YOUR_USERNAME/AIPET
        """
    )

    parser.add_argument(
        "--target", "-t",
        type=str,
        help="Target IP address, hostname, or CIDR range"
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run in demo mode against local test servers"
    )
    parser.add_argument(
        "--mqtt",
        action="store_true",
        help="Force run MQTT attack module"
    )
    parser.add_argument(
        "--coap",
        action="store_true",
        help="Force run CoAP attack module"
    )
    parser.add_argument(
        "--http",
        action="store_true",
        help="Force run HTTP attack module"
    )
    parser.add_argument(
        "--firmware",
        action="store_true",
        help="Force run firmware analysis module"
    )
    parser.add_argument(
        "--firmware-path",
        type=str,
        default=None,
        help="Path to firmware file or extracted directory"
    )
    parser.add_argument(
        "--mqtt-port",
        type=int,
        default=1883,
        help="MQTT broker port (default: 1883)"
    )
    parser.add_argument(
        "--coap-port",
        type=int,
        default=5683,
        help="CoAP device port (default: 5683)"
    )
    parser.add_argument(
        "--http-port",
        type=int,
        default=80,
        help="HTTP web interface port (default: 80)"
    )
    parser.add_argument(
        "--version", "-v",
        action="version",
        version=f"AIPET v{VERSION}"
    )

    parser.add_argument(
        "--targets",
        type=str,
        default=None,
        help="Path to file with multiple targets for parallel scanning"
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=3,
        help="Maximum parallel scans (default: 3)"
    )
    return parser.parse_args()


# ── Entry Point ───────────────────────────────────────────────
if __name__ == "__main__":
    args = parse_arguments()

    # Validate arguments
    if not args.target and not args.demo and not args.targets:
        print(BANNER)
        print("Error: Please specify --target, --targets, or --demo")
        print()
        print("Examples:")
        print("  python3 aipet.py --target 192.168.1.0/24")
        print("  python3 aipet.py --targets targets.txt --workers 3")
        print("  python3 aipet.py --demo")
        sys.exit(1)

    # Run parallel scanning across multiple targets
    if args.targets:
        from parallel.parallel_scanner import (
            ParallelScanner,
            load_targets_from_file
        )
        from parallel.result_aggregator import (
            aggregate_findings,
            generate_unified_report
        )

        print(BANNER)

        # Load targets from file
        try:
            targets = load_targets_from_file(args.targets)
        except FileNotFoundError as e:
            print(f"Error: {e}")
            sys.exit(1)
        except ValueError as e:
            print(f"Error: {e}")
            sys.exit(1)

        print_status(
            f"Parallel mode: {len(targets)} targets, "
            f"{args.workers} workers"
        )

        # Run parallel scans
        scanner = ParallelScanner(
            max_workers=args.workers,
            base_dir="results"
        )
        results = scanner.scan(
            targets,
            run_mqtt=True,
            run_coap=True,
            run_http=True,
            run_firmware=bool(args.firmware_path),
            firmware_path=args.firmware_path,
            mqtt_port=args.mqtt_port,
            coap_port=args.coap_port,
            http_port=args.http_port,
        )

        # Aggregate all results
        print_status("Aggregating results from all scans...")
        aggregated = aggregate_findings(
            targets, base_dir="results"
        )

        # Generate unified report
        report_path = generate_unified_report(aggregated)
        print_status(
            f"Unified report: {report_path}", "success"
        )

        summary = aggregated["summary"]
        print()
        print("=" * 60)
        print("  PARALLEL SCAN SUMMARY")
        print("=" * 60)
        print(f"  Networks:  {aggregated['target_count']}")
        print(f"  Devices:   {aggregated['device_count']}")
        print(f"  Critical:  {summary['critical']}")
        print(f"  High:      {summary['high']}")
        print(f"  Medium:    {summary['medium']}")
        print(f"  Overall:   {summary['overall_risk']}")
        print(f"  Report:    {report_path}")
        print("=" * 60)

    # Run in demo mode
    elif args.demo:
        run_demo()

    # Run against specified target
    else:
        run_pipeline(
            target=args.target,
            run_mqtt=args.mqtt,
            run_coap=args.coap,
            run_http=args.http,
            run_firmware=args.firmware,
            firmware_path=args.firmware_path,
            mqtt_port=args.mqtt_port,
            coap_port=args.coap_port,
            http_port=args.http_port,
        )
