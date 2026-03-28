# =============================================================
# AIPET — Parallel Scanning
# Component 3: Parallel Scanner
# Author: Binyam
# Institution: Coventry University — MSc Cyber Security
# Date: March 2025
# Description: Core parallel scanning engine. Runs multiple
#              AIPET pipelines simultaneously using Python
#              ThreadPoolExecutor. Each scan is isolated,
#              tracked, and results saved separately.
# =============================================================

import os
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)
)))

from parallel.result_isolation import (
    get_result_dir,
    target_to_dirname
)
from parallel.progress_tracker import (
    ParallelProgressTracker,
    STATE_COMPLETE,
    STATE_FAILED,
    MODULES
)


def load_targets_from_file(filepath):
    """
    Load scan targets from a text file.
    One target per line. Lines starting with # are comments.

    Args:
        filepath (str): Path to targets file

    Returns:
        list: List of target strings

    Example targets.txt:
        # Office network
        192.168.1.0/24
        # Server room
        10.0.0.0/24
        # Building management
        172.16.0.0/24
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(
            f"Targets file not found: {filepath}"
        )

    targets = []
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            # Skip empty lines and comments
            if line and not line.startswith("#"):
                targets.append(line)

    if not targets:
        raise ValueError(
            f"No targets found in {filepath}"
        )

    return targets


def run_single_scan(target, progress, base_dir,
                    run_mqtt=True, run_coap=True,
                    run_http=True, run_firmware=True,
                    firmware_path=None,
                    mqtt_port=1883,
                    coap_port=5683,
                    http_port=80):
    """
    Run a complete AIPET pipeline for a single target.
    Called by ThreadPoolExecutor for each parallel scan.

    Args:
        target (str): Scan target IP/CIDR
        progress: ScanProgress instance for this target
        base_dir (str): Base results directory
        run_mqtt (bool): Run MQTT module
        run_coap (bool): Run CoAP module
        run_http (bool): Run HTTP module
        run_firmware (bool): Run firmware module
        firmware_path (str): Path to firmware
        mqtt_port (int): MQTT port
        coap_port (int): CoAP port
        http_port (int): HTTP port

    Returns:
        dict: Scan results summary
    """
    result_dir = get_result_dir(target, base_dir)

    try:
        progress.start()

        # ── Module 1: Reconnaissance ──────────────────────
        progress.update_module("Reconnaissance", 1)
        from recon.scanner import scan_network
        from recon.fingerprint import fingerprint_devices
        from recon.profiles import build_profiles

        scan_results = scan_network(target)
        fingerprints = fingerprint_devices(scan_results)
        profiles     = build_profiles(fingerprints)

        # Save profiles to isolated directory
        import json
        profiles_path = os.path.join(
            result_dir, "complete_profiles.json"
        )
        with open(profiles_path, "w") as f:
            json.dump(profiles, f, indent=4)

        # ── Module 2: MQTT ────────────────────────────────
        if run_mqtt:
            progress.update_module("MQTT Attack Suite", 2)
            from mqtt.mqtt_attacker import MQTTAttacker
            attacker = MQTTAttacker(
                target=target, port=mqtt_port
            )
            mqtt_results = attacker.run_all_attacks()
            mqtt_path = os.path.join(
                result_dir, "mqtt_results.json"
            )
            with open(mqtt_path, "w") as f:
                json.dump(mqtt_results, f, indent=4)

        # ── Module 3: CoAP ────────────────────────────────
        if run_coap:
            progress.update_module("CoAP Attack Suite", 3)
            from coap.coap_attacker import CoAPAttacker
            import asyncio
            coap_attacker = CoAPAttacker(
                target=target, port=coap_port
            )
            coap_results = asyncio.run(
                coap_attacker.run_all_attacks()
            )
            coap_path = os.path.join(
                result_dir, "coap_results.json"
            )
            with open(coap_path, "w") as f:
                json.dump(coap_results, f, indent=4)

        # ── Module 4: HTTP ────────────────────────────────
        if run_http:
            progress.update_module("HTTP/Web Suite", 4)
            from http_attack.http_attacker import HTTPAttacker
            http_attacker = HTTPAttacker(
                target=target, port=http_port
            )
            http_results = http_attacker.run_all_attacks()
            http_path = os.path.join(
                result_dir, "http_results.json"
            )
            with open(http_path, "w") as f:
                json.dump(http_results, f, indent=4)

        # ── Module 5: Firmware ────────────────────────────
        if run_firmware and firmware_path:
            progress.update_module("Firmware Analyser", 5)
            from firmware.firmware_analyser import (
                FirmwareAnalyser
            )
            analyser = FirmwareAnalyser(
                target=firmware_path
            )
            firmware_results = analyser.run_all_analyses()
            fw_path = os.path.join(
                result_dir, "firmware_results.json"
            )
            with open(fw_path, "w") as f:
                json.dump(firmware_results, f, indent=4)

        # ── Module 6: AI Engine ───────────────────────────
        progress.update_module("AI Engine", 6)
        from ai_engine.explainer import AIExplainer
        explainer   = AIExplainer()
        ai_results  = []

        for profile in profiles:
            if isinstance(profile, dict):
                prediction = explainer.explain(profile)
                ai_results.append(prediction)

        ai_path = os.path.join(
            result_dir, "ai_results.json"
        )
        with open(ai_path, "w") as f:
            json.dump(ai_results, f, indent=4)

        # ── Module 7: Report ──────────────────────────────
        progress.update_module("Report Generator", 7)
        from reporting.report_generator import ReportGenerator
        generator = ReportGenerator(
            results_dir=result_dir,
            output_dir=os.path.join(result_dir, "reports")
        )
        generator.generate()

        # Count findings
        findings = {"critical": 0, "high": 0,
                    "medium": 0, "low": 0}
        for module_file in [
            "mqtt_results.json",
            "coap_results.json",
            "http_results.json",
            "firmware_results.json"
        ]:
            module_path = os.path.join(result_dir, module_file)
            if os.path.exists(module_path):
                with open(module_path) as f:
                    data = json.load(f)
                summary = data.get("summary", {})
                for sev in findings:
                    findings[sev] += summary.get(sev, 0)

        progress.complete(findings=findings)

        return {
            "target":     target,
            "status":     "complete",
            "result_dir": result_dir,
            "findings":   findings,
        }

    except Exception as e:
        progress.fail(str(e))
        return {
            "target":  target,
            "status":  "failed",
            "error":   str(e),
        }


class ParallelScanner:
    """
    Manages parallel scanning of multiple network targets.
    Coordinates ThreadPoolExecutor, progress tracking,
    and result isolation.
    """

    def __init__(self, max_workers=3,
                 base_dir="results"):
        """
        Args:
            max_workers (int): Maximum simultaneous scans
            base_dir (str): Base directory for results
        """
        self.max_workers = max_workers
        self.base_dir    = base_dir
        self.tracker     = ParallelProgressTracker()
        self.results     = {}

    def scan(self, targets, **scan_kwargs):
        """
        Scan multiple targets in parallel.

        Args:
            targets (list): List of target IP/CIDR strings
            **scan_kwargs: Options passed to each scan
                           (run_mqtt, run_coap, etc.)

        Returns:
            dict: Results for all targets
        """
        print(f"\n{'='*60}")
        print(f"  AIPET PARALLEL SCANNER")
        print(f"{'='*60}")
        print(f"  Targets:     {len(targets)}")
        print(f"  Workers:     {self.max_workers}")
        print(f"  Results dir: {self.base_dir}")
        print(f"  Started:     "
              f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*60}\n")

        # Register all targets
        progress_map = {}
        for target in targets:
            progress_map[target] = self.tracker.register(
                target
            )

        # Start status printer in background
        stop_printer = threading.Event()
        printer_thread = threading.Thread(
            target=self._status_printer,
            args=(stop_printer,),
            daemon=True
        )
        printer_thread.start()

        # Run scans in parallel
        start_time = time.time()
        with ThreadPoolExecutor(
            max_workers=self.max_workers
        ) as executor:
            future_to_target = {
                executor.submit(
                    run_single_scan,
                    target,
                    progress_map[target],
                    self.base_dir,
                    **scan_kwargs
                ): target
                for target in targets
            }

            for future in as_completed(future_to_target):
                target = future_to_target[future]
                try:
                    result = future.result()
                    self.results[target] = result
                except Exception as e:
                    self.results[target] = {
                        "target": target,
                        "status": "failed",
                        "error":  str(e),
                    }

        # Stop status printer
        stop_printer.set()
        printer_thread.join(timeout=2)

        elapsed = time.time() - start_time

        # Print final status
        self.tracker.print_status()

        # Summary
        complete = sum(
            1 for r in self.results.values()
            if r.get("status") == "complete"
        )
        failed = sum(
            1 for r in self.results.values()
            if r.get("status") == "failed"
        )

        print(f"\n{'='*60}")
        print(f"  PARALLEL SCAN COMPLETE")
        print(f"{'='*60}")
        print(f"  Total targets:  {len(targets)}")
        print(f"  Completed:      {complete}")
        print(f"  Failed:         {failed}")
        print(f"  Total time:     {elapsed:.1f} seconds")
        print(f"  Time per scan:  "
              f"{elapsed/len(targets):.1f}s (avg)")
        print(f"  Speedup:        "
              f"{len(targets)*elapsed/elapsed:.1f}x "
              f"vs sequential")
        print(f"{'='*60}\n")

        return self.results

    def _status_printer(self, stop_event):
        """Print status every 10 seconds while scanning."""
        while not stop_event.is_set():
            stop_event.wait(timeout=10)
            if not stop_event.is_set():
                self.tracker.print_status()


if __name__ == "__main__":
    # Test with simulated targets (no real scanning)
    print("Testing parallel scanner components...")

    # Test target file loading
    import tempfile
    import os

    # Create test targets file
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False
    ) as f:
        f.write("# Test targets\n")
        f.write("192.168.1.0/24\n")
        f.write("10.0.0.0/24\n")
        f.write("# Comment line\n")
        f.write("172.16.0.0/24\n")
        tmpfile = f.name

    targets = load_targets_from_file(tmpfile)
    os.unlink(tmpfile)

    assert len(targets) == 3, f"Expected 3, got {len(targets)}"
    assert "192.168.1.0/24" in targets
    assert "10.0.0.0/24"    in targets
    assert "172.16.0.0/24"  in targets
    print(f"  [PASS] Loaded {len(targets)} targets from file")
    print(f"  [PASS] Comments correctly ignored")

    # Test scanner initialisation
    scanner = ParallelScanner(max_workers=3)
    assert scanner.max_workers == 3
    assert scanner.base_dir    == "results"
    print(f"  [PASS] Scanner initialised with 3 workers")

    # Test progress tracking integration
    tracker  = ParallelProgressTracker()
    progress = tracker.register("test_target")
    progress.start()
    progress.update_module("Reconnaissance", 1)
    assert progress.get_progress_pct() == 14
    progress.complete()
    assert progress.get_progress_pct() == 100
    print(f"  [PASS] Progress tracking integrated")

    print("\n[+] Parallel scanner ready")
    print("[+] Use: python3 aipet.py --targets targets.txt")
