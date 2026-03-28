#!/usr/bin/env python3
# =============================================================
# AIPET — AI-Powered Penetration Testing Framework for IoT
# Installation Script
# Author: Binyam
# Institution: Coventry University — MSc Cyber Security
# Date: March 2025
# Usage: python3 install.py
# =============================================================

import os
import sys
import subprocess
import platform

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

def print_header():
    print(f"""
{BLUE}{BOLD}╔══════════════════════════════════════════════════════════════╗
║         AIPET — Installation Script v1.0.0                  ║
║         AI-Powered IoT Penetration Testing Framework        ║
╚══════════════════════════════════════════════════════════════╝{RESET}
""")

def print_step(step, total, message):
    print(f"\n{BLUE}[{step}/{total}]{RESET} {message}")

def print_success(message):
    print(f"{GREEN}[+]{RESET} {message}")

def print_error(message):
    print(f"{RED}[-]{RESET} {message}")

def print_warning(message):
    print(f"{YELLOW}[!]{RESET} {message}")

def run_command(command, capture=True):
    try:
        result = subprocess.run(
            command, shell=True,
            capture_output=capture, text=True
        )
        return result.returncode == 0, result.stdout, result.stderr
    except Exception as e:
        return False, "", str(e)

def check_python():
    print_step(1, 6, "Checking Python version...")
    version = sys.version_info
    if version.major < 3 or version.minor < 11:
        print_error(f"Python 3.11+ required. Found: {version.major}.{version.minor}")
        return False
    print_success(f"Python {version.major}.{version.minor}.{version.micro} OK")
    return True

def create_venv():
    print_step(2, 6, "Creating virtual environment...")
    if os.path.exists("venv"):
        print_warning("Virtual environment already exists — skipping")
        return True
    success, out, err = run_command("python3 -m venv venv")
    if success:
        print_success("Virtual environment created at ./venv")
        return True
    print_error(f"Failed to create venv: {err}")
    return False

def install_python_deps():
    print_step(3, 6, "Installing Python dependencies...")
    pip = "venv/bin/pip"
    if not os.path.exists(pip):
        print_error("Virtual environment not found")
        return False
    run_command(f"{pip} install --upgrade pip --quiet")
    success, out, err = run_command(
        f"{pip} install -r requirements.txt --quiet"
    )
    if success:
        print_success("Python dependencies installed")
        return True
    print_error(f"Failed: {err}")
    return False

def install_system_tools():
    print_step(4, 6, "Checking system tools...")
    tools = {"nmap": "nmap", "binwalk": "binwalk", "mosquitto": "mosquitto"}
    all_installed = True
    for tool, package in tools.items():
        success, _, _ = run_command(f"which {tool}")
        if success:
            print_success(f"{tool} already installed")
        else:
            print_warning(f"Installing {package}...")
            success, _, _ = run_command(
                f"sudo apt install {package} -y", capture=False
            )
            if success:
                print_success(f"{tool} installed")
            else:
                print_error(f"Failed to install {tool} — install manually: sudo apt install {package}")
                all_installed = False
    return all_installed

def verify_installation():
    print_step(5, 6, "Verifying Python packages...")
    python = "venv/bin/python3"
    checks = [
        ("scikit-learn", "import sklearn"),
        ("pandas",       "import pandas"),
        ("shap",         "import shap"),
        ("paho-mqtt",    "import paho.mqtt.client"),
        ("aiocoap",      "import aiocoap"),
        ("requests",     "import requests"),
        ("python-nmap",  "import nmap"),
    ]
    all_ok = True
    for name, stmt in checks:
        success, _, _ = run_command(f'{python} -c "{stmt}"')
        if success:
            print_success(f"{name}")
        else:
            print_error(f"{name} — NOT FOUND")
            all_ok = False
    return all_ok

def run_quick_test():
    print_step(6, 6, "Running version check...")
    python = "venv/bin/python3"
    success, out, err = run_command(f"{python} aipet.py --version")
    if success and "AIPET" in out:
        print_success(f"{out.strip()}")
        return True
    print_error("Version check failed")
    return False

def main():
    print_header()
    steps = [
        check_python,
        create_venv,
        install_python_deps,
        install_system_tools,
        verify_installation,
        run_quick_test,
    ]
    passed = 0
    for step in steps:
        if step():
            passed += 1
        else:
            print_warning("Continuing despite error...")

    print('\n' + '='*60)
    if passed == len(steps):
        print(f"{GREEN}{BOLD}  INSTALLATION COMPLETE{RESET}")
        print('='*60)
        print("""
Quick start:
  source venv/bin/activate
  python3 aipet.py --demo

Scan a target:
  python3 aipet.py --target 192.168.1.0/24

Run tests:
  python3 -m pytest tests/ -v

Documentation:
  cat USER_MANUAL.md        (User Manual)
  cat INSTALL.md            (Install Guide)
  cat RESPONSIBLE_USE.md    (Responsible Use Policy)
""")
    else:
        print(f"  INSTALLATION PARTIAL ({passed}/{len(steps)} steps)")
        print("  Check errors above and install missing components manually.")

if __name__ == "__main__":
    main()
