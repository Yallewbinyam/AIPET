# =============================================================
# AIPET — Parallel Scanning
# Component 1: Result Isolation
# Author: Binyam
# Institution: Coventry University — MSc Cyber Security
# Date: March 2025
# Description: Manages isolated result directories for each
#              parallel scan target. Prevents result files
#              from different scans overwriting each other.
# =============================================================

import os
import json
import re
from datetime import datetime


def target_to_dirname(target):
    """
    Convert a target IP/CIDR to a safe directory name.

    192.168.1.0/24  becomes  192.168.1.0_24
    10.0.0.1        becomes  10.0.0.1
    localhost       becomes  localhost

    Args:
        target (str): IP address, CIDR range, or hostname

    Returns:
        str: Safe directory name
    """
    # Replace / with _ for CIDR notation
    safe = target.replace("/", "_")
    # Remove any other unsafe characters
    safe = re.sub(r"[^a-zA-Z0-9._-]", "_", safe)
    return safe


def get_result_dir(target, base_dir="results"):
    """
    Get the result directory path for a specific target.
    Creates the directory if it does not exist.

    Args:
        target (str): Scan target
        base_dir (str): Base results directory

    Returns:
        str: Path to result directory for this target
    """
    dirname  = target_to_dirname(target)
    result_dir = os.path.join(base_dir, dirname)
    os.makedirs(result_dir, exist_ok=True)
    return result_dir


def get_result_path(target, filename, base_dir="results"):
    """
    Get the full path for a result file for a specific target.

    Args:
        target (str): Scan target
        filename (str): Result filename (e.g. mqtt_results.json)
        base_dir (str): Base results directory

    Returns:
        str: Full path to result file
    """
    result_dir = get_result_dir(target, base_dir)
    return os.path.join(result_dir, filename)


def save_result(target, filename, data, base_dir="results"):
    """
    Save result data to isolated target directory.

    Args:
        target (str): Scan target
        filename (str): Result filename
        data (dict): Data to save as JSON
        base_dir (str): Base results directory

    Returns:
        str: Path where file was saved
    """
    filepath = get_result_path(target, filename, base_dir)
    with open(filepath, "w") as f:
        json.dump(data, f, indent=4)
    return filepath


def load_result(target, filename, base_dir="results"):
    """
    Load result data from isolated target directory.

    Args:
        target (str): Scan target
        filename (str): Result filename
        base_dir (str): Base results directory

    Returns:
        dict: Loaded JSON data or None if not found
    """
    filepath = get_result_path(target, filename, base_dir)
    if not os.path.exists(filepath):
        return None
    try:
        with open(filepath, "r") as f:
            return json.load(f)
    except Exception:
        return None


def list_completed_targets(base_dir="results"):
    """
    List all targets that have completed results.

    Returns:
        list: List of target directory names
    """
    if not os.path.exists(base_dir):
        return []
    return [
        d for d in os.listdir(base_dir)
        if os.path.isdir(os.path.join(base_dir, d))
    ]


def get_scan_summary(target, base_dir="results"):
    """
    Get a summary of what results exist for a target.

    Args:
        target (str): Scan target

    Returns:
        dict: Summary of available result files
    """
    result_dir = get_result_dir(target, base_dir)
    files      = os.listdir(result_dir)

    return {
        "target":     target,
        "result_dir": result_dir,
        "files":      files,
        "has_mqtt":   "mqtt_results.json"     in files,
        "has_coap":   "coap_results.json"     in files,
        "has_http":   "http_results.json"     in files,
        "has_firmware":"firmware_results.json" in files,
        "has_ai":     "ai_results.json"       in files,
        "has_recon":  "complete_profiles.json" in files,
    }


if __name__ == "__main__":
    # Test result isolation
    print("Testing result isolation...")

    # Test directory name conversion
    tests = [
        ("192.168.1.0/24", "192.168.1.0_24"),
        ("10.0.0.1",       "10.0.0.1"),
        ("localhost",      "localhost"),
    ]

    all_passed = True
    for target, expected in tests:
        result = target_to_dirname(target)
        status = "PASS" if result == expected else "FAIL"
        if status == "FAIL":
            all_passed = False
        print(f"  [{status}] {target} -> {result}")

    # Test save and load
    test_data = {"test": "data", "value": 42}
    saved_path = save_result(
        "test_target", "test_results.json", test_data,
        base_dir="/tmp/aipet_test_results"
    )
    loaded = load_result(
        "test_target", "test_results.json",
        base_dir="/tmp/aipet_test_results"
    )

    if loaded == test_data:
        print("  [PASS] Save and load result")
    else:
        print("  [FAIL] Save and load result")
        all_passed = False

    # Cleanup test
    import shutil
    shutil.rmtree("/tmp/aipet_test_results", ignore_errors=True)

    print()
    if all_passed:
        print("[+] All tests passed — Result isolation ready")
    else:
        print("[-] Some tests failed")
