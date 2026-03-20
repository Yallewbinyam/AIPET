# Block 1 — Header comment
# Block 2 — Imports
# Block 3 — PortScanner object
# Block 4 — discover_hosts function
# Block 5 — scan_ports function
# Block 6 — save_results function
# Block 7 — main function

# -------------------------------------------------------------
# AIPET - AI Powered Penetration Testiong Framework for IoT
# Module 1: Recon Engine -Scanner
# Author: Binyam
# Institution: Coventry University - MSc Cyber Security (Ethical Hacking)
# Date: March 2025
# Licence: MIT
# Description: Host Discovery and port scanning for IoT targets


import nmap
import socket
import json
from datetime import datetime

# Initialise the Nmap port scanner
nm = nmap.PortScanner()

def discover_hosts(network_range):
    """
    Discover live hosts on the target network range.

    Args:
        network_range (str): Target network e.g. '192.168.100.0/24'

    Returns:
        list: List of live IP addresses as strings
    """
    print(f"[*] Starting host discovery on {network_range}")

    # Run a ping scan — fast, just checks who is alive
    nm.scan(hosts=network_range, arguments='-sn')

    # Extract only the hosts that are 'up' (responding)
    live_hosts = [
        host for host in nm.all_hosts()
        if nm[host].state() == 'up'
    ]

    print(f"[+] Found {len(live_hosts)} live host(s)")
    return live_hosts


def scan_ports(host):
    """
    Scan open ports and detect services on a single host.

    Args:
        host (str): Target IP address e.g. '192.168.100.10'

    Returns:
        dict: Device scan results including ports and services
    """
    print(f"[*] Scanning ports on {host}")

    # Run service version detection on top 1000 ports
    nm.scan(
        hosts=host,
        arguments='-sV -T4 --top-ports 1000'
    )

    # Build the device profile dictionary
    device_profile = {
        "ip": host,
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "hostname": "",
        "state": "",
        "ports": [],
        "services": {}
    }

    # Check if host responded to the scan
    if host not in nm.all_hosts():
        print(f"[-] Host {host} did not respond")
        return device_profile

    # Get hostname if available
    try:
        device_profile["hostname"] = socket.gethostbyaddr(host)[0]
    except socket.herror:
        device_profile["hostname"] = "unknown"

    # Get host state (up/down)
    device_profile["state"] = nm[host].state()

    # Extract open ports and service information
    for protocol in nm[host].all_protocols():
        ports = nm[host][protocol].keys()

        for port in sorted(ports):
            port_info = nm[host][protocol][port]

            # Only record open ports
            if port_info['state'] == 'open':
                device_profile["ports"].append(port)
                device_profile["services"][port] = {
                    "protocol": protocol,
                    "state":    port_info['state'],
                    "name":     port_info['name'],
                    "product":  port_info['product'],
                    "version":  port_info['version'],
                    "extrainfo":port_info['extrainfo']
                }

    print(f"[+] Found {len(device_profile['ports'])} open port(s) on {host}")
    return device_profile

def save_results(results, output_file="scan_results.json"):
    """
    Save scan results to a JSON file.

    Args:
        results (list): List of device profiles
        output_file (str): Output filename
    """
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=4)
    print(f"[+] Results saved to {output_file}")

def main():
    """
    Main function — runs a full recon scan on a target network.
    """
    # ── CHANGE THIS to your virtual lab network range ──
    target_network = "10.0.2.15"

    print("=" * 60)
    print("  AIPET — Module 1: Recon Engine")
    print("=" * 60)

    # Step 1: Discover live hosts
    live_hosts = discover_hosts(target_network)

    if not live_hosts:
        print("[-] No live hosts found. Check your network range.")
        return

    # Step 2: Scan each live host
    all_profiles = []
    for host in live_hosts:
        profile = scan_ports(host)
        all_profiles.append(profile)

    # Step 3: Save results
    save_results(all_profiles, "recon/scan_results.json")

    # Step 4: Print summary
    print("\n" + "=" * 60)
    print("  SCAN SUMMARY")
    print("=" * 60)
    for profile in all_profiles:
        print(f"\nDevice: {profile['ip']}")
        print(f"Hostname: {profile['hostname']}")
        print(f"Open Ports: {profile['ports']}")
        for port, service in profile['services'].items():
            print(f"  Port {port}: {service['name']} "
                  f"{service['product']} {service['version']}")


if __name__ == "__main__":
    main()
