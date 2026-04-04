"""
AIPET Watch — Network Monitoring Agent
Passive network traffic monitor using Scapy.

This agent runs on the customer's local network and:
1. Captures network packets passively (invisible to devices)
2. Builds traffic statistics per device
3. Detects anomalies vs stored baseline
4. Reports alerts to AIPET Cloud API

Usage:
    # Live mode (requires sudo):
    sudo python3 agent.py --api-url https://aipet.io --token YOUR_TOKEN

    # Test mode (no sudo required):
    python3 agent.py --test --api-url http://localhost:5001 --token YOUR_TOKEN

Architecture:
    Customer Network → Agent (Scapy) → AIPET Cloud API → Dashboard
"""

import os
import sys
import json
import time
import argparse
import threading
import urllib.request
import urllib.error
from datetime import datetime, timezone
from collections import defaultdict


# ── Try to import Scapy ───────────────────────────────────────────────────
SCAPY_AVAILABLE = False
try:
    from scapy.all import sniff, IP, TCP, UDP, ARP
    SCAPY_AVAILABLE = True
except ImportError:
    pass


# ── Configuration ─────────────────────────────────────────────────────────
DEFAULT_INTERVAL  = 60    # seconds between baseline comparisons
DEFAULT_INTERFACE = None  # None = auto-detect
REPORT_TIMEOUT    = 10    # seconds for API calls


class TrafficStats:
    """
    Tracks traffic statistics for a single device IP.
    Thread-safe using a lock.
    """
    def __init__(self, ip):
        self.ip           = ip
        self.lock         = threading.Lock()
        self.packet_count = 0
        self.byte_count   = 0
        self.ports_seen   = set()
        self.protocols    = set()
        self.dest_ips     = set()
        self.first_seen   = datetime.now(timezone.utc)
        self.last_seen    = datetime.now(timezone.utc)

    def update(self, packet_size, dst_port=None, protocol=None, dest_ip=None):
        with self.lock:
            self.packet_count += 1
            self.byte_count   += packet_size
            self.last_seen     = datetime.now(timezone.utc)
            if dst_port:  self.ports_seen.add(dst_port)
            if protocol:  self.protocols.add(protocol)
            if dest_ip:   self.dest_ips.add(dest_ip)

    def to_dict(self):
        with self.lock:
            return {
                "ip":           self.ip,
                "packet_count": self.packet_count,
                "byte_count":   self.byte_count,
                "ports_seen":   list(self.ports_seen),
                "protocols":    list(self.protocols),
                "dest_ips":     list(self.dest_ips)[:10],  # limit to 10
                "first_seen":   self.first_seen.isoformat(),
                "last_seen":    self.last_seen.isoformat(),
            }

    def reset(self):
        with self.lock:
            self.packet_count = 0
            self.byte_count   = 0
            self.ports_seen   = set()
            self.protocols    = set()
            self.dest_ips     = set()


class AIPETWatchAgent:
    """
    The main AIPET Watch agent.
    Captures traffic, detects anomalies, reports to cloud.
    """

    def __init__(self, api_url, token, interface=None,
                 interval=DEFAULT_INTERVAL, test_mode=False):
        self.api_url   = api_url.rstrip("/")
        self.token     = token
        self.interface = interface
        self.interval  = interval
        self.test_mode = test_mode
        self.running   = False
        self.stats     = {}  # ip → TrafficStats
        self.baselines = {}  # ip → baseline dict
        self.lock      = threading.Lock()

        print(f"AIPET Watch Agent initialised")
        print(f"  API URL:    {self.api_url}")
        print(f"  Interval:   {self.interval}s")
        print(f"  Mode:       {'TEST' if test_mode else 'LIVE (Scapy)'}")
        print(f"  Interface:  {self.interface or 'auto-detect'}")

    def get_or_create_stats(self, ip):
        """Gets or creates a TrafficStats object for a device IP."""
        with self.lock:
            if ip not in self.stats:
                self.stats[ip] = TrafficStats(ip)
            return self.stats[ip]

    def packet_handler(self, packet):
        """
        Processes each captured packet.
        Called by Scapy for every packet on the network.
        """
        try:
            if not packet.haslayer(IP):
                return

            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            size   = len(packet)

            # Determine protocol
            protocol = "other"
            dst_port = None

            if packet.haslayer(TCP):
                protocol = "tcp"
                dst_port = packet[TCP].dport
                # Identify well-known protocols
                if dst_port == 23:   protocol = "telnet"
                elif dst_port == 21: protocol = "ftp"
                elif dst_port == 22: protocol = "ssh"
                elif dst_port == 80: protocol = "http"
                elif dst_port == 443: protocol = "https"
                elif dst_port == 8080: protocol = "http-alt"
                elif dst_port == 5672: protocol = "amqp"

            elif packet.haslayer(UDP):
                protocol = "udp"
                dst_port = packet[UDP].dport
                if dst_port == 1883:  protocol = "mqtt"
                elif dst_port == 8883: protocol = "mqtt-tls"
                elif dst_port == 5683: protocol = "coap"
                elif dst_port == 161:  protocol = "snmp"
                elif dst_port == 53:   protocol = "dns"
                elif dst_port == 67:   protocol = "dhcp"

            # Update source device stats
            src_stats = self.get_or_create_stats(src_ip)
            src_stats.update(size, dst_port, protocol, dst_ip)

        except Exception:
            pass

    def detect_anomalies(self, ip, current_stats):
        """
        Compares current traffic stats against stored baseline
        and returns a list of anomalies.
        """
        anomalies = []
        baseline  = self.baselines.get(ip)

        if not baseline:
            return anomalies

        # Check for new protocols not in baseline
        baseline_protocols = set(baseline.get("protocols", []))
        current_protocols  = set(current_stats.get("protocols", []))
        new_protocols      = current_protocols - baseline_protocols

        suspicious = {"telnet", "ftp", "snmp"}
        for proto in new_protocols:
            severity = "High" if proto in suspicious else "Medium"
            anomalies.append({
                "type":        "new_protocol_detected",
                "severity":    severity,
                "description": f"New protocol detected on {ip}: {proto}",
                "details":     {
                    "protocol":   proto,
                    "device_ip":  ip,
                }
            })

        # Check for traffic spike (5x normal)
        baseline_packets = baseline.get("avg_packets_per_interval", 0)
        current_packets  = current_stats.get("packet_count", 0)
        if baseline_packets > 0 and current_packets > baseline_packets * 5:
            anomalies.append({
                "type":        "traffic_spike",
                "severity":    "High",
                "description": f"Traffic spike detected on {ip}: {current_packets} packets (normal: ~{baseline_packets})",
                "details":     {
                    "current_packets":  current_packets,
                    "baseline_packets": baseline_packets,
                    "device_ip":        ip,
                }
            })

        # Check for connections to many new IPs (potential scanning)
        baseline_dest_count = baseline.get("avg_dest_ips", 0)
        current_dest_count  = len(current_stats.get("dest_ips", []))
        if baseline_dest_count > 0 and current_dest_count > baseline_dest_count * 3:
            anomalies.append({
                "type":        "network_scan_detected",
                "severity":    "Critical",
                "description": f"Possible network scan from {ip}: connecting to {current_dest_count} IPs (normal: ~{baseline_dest_count})",
                "details":     {
                    "current_dest_count":  current_dest_count,
                    "baseline_dest_count": baseline_dest_count,
                    "device_ip":           ip,
                }
            })

        return anomalies

    def report_to_cloud(self, endpoint, data):
        """
        Sends data to the AIPET Cloud API.
        Returns True if successful, False otherwise.
        """
        try:
            url     = f"{self.api_url}{endpoint}"
            payload = json.dumps(data).encode("utf-8")

            req = urllib.request.Request(url, data=payload, method="POST")
            req.add_header("Content-Type",  "application/json")
            req.add_header("Authorization", f"Bearer {self.token}")

            with urllib.request.urlopen(req, timeout=REPORT_TIMEOUT) as resp:
                return resp.status == 200

        except Exception as e:
            print(f"  [Warning] Failed to report to cloud: {e}")
            return False

    def fetch_baselines(self):
        """Fetches stored baselines from the AIPET Cloud API."""
        try:
            url = f"{self.api_url}/api/watch/baselines"
            req = urllib.request.Request(url)
            req.add_header("Authorization", f"Bearer {self.token}")

            with urllib.request.urlopen(req, timeout=REPORT_TIMEOUT) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                for b in data:
                    self.baselines[b["device_ip"]] = b.get("baseline_data", {})
                print(f"  Loaded {len(self.baselines)} device baselines")

        except Exception as e:
            print(f"  [Warning] Could not fetch baselines: {e}")

    def run_check_cycle(self):
        """
        Runs one monitoring cycle:
        1. Collects current traffic stats
        2. Detects anomalies
        3. Reports to cloud
        4. Resets stats for next cycle
        """
        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Running check cycle...")

        with self.lock:
            current_stats = {ip: s.to_dict() for ip, s in self.stats.items()}

        all_anomalies = []
        for ip, stats in current_stats.items():
            anomalies = self.detect_anomalies(ip, stats)
            all_anomalies.extend(anomalies)

        # Report traffic summary
        if current_stats:
            self.report_to_cloud("/api/watch/report", {
                "stats":     current_stats,
                "anomalies": all_anomalies,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })
            print(f"  Devices seen: {len(current_stats)}")
            print(f"  Anomalies:    {len(all_anomalies)}")
            for a in all_anomalies:
                print(f"  ⚠ [{a['severity']}] {a['description']}")
        else:
            print("  No traffic captured this interval")

        # Reset stats for next cycle
        with self.lock:
            for stats in self.stats.values():
                stats.reset()

    def run_test_mode(self):
        """
        Simulates network traffic for testing without Scapy.
        Generates realistic traffic patterns for demonstration.
        """
        import random
        print("\nRunning in TEST MODE — simulating network traffic")
        print("In production, this captures real packets with Scapy\n")

        test_devices = ["192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4"]
        protocols    = ["tcp", "udp", "http", "mqtt", "ssh"]

        cycle = 0
        while self.running:
            # Simulate packets for each device
            for ip in test_devices:
                stats = self.get_or_create_stats(ip)
                # Simulate 10-50 packets per device per cycle
                num_packets = random.randint(10, 50)
                for _ in range(num_packets):
                    proto   = random.choice(protocols)
                    port    = random.choice([80, 443, 22, 1883, 8080, 23])
                    dest_ip = f"192.168.1.{random.randint(1, 10)}"
                    stats.update(
                        packet_size=random.randint(64, 1500),
                        dst_port=port,
                        protocol=proto,
                        dest_ip=dest_ip
                    )

                # Simulate anomaly on cycle 2 — new telnet protocol
                if cycle == 2 and ip == "192.168.1.4":
                    stats.update(256, 23, "telnet", "192.168.1.99")
                    print(f"  [Simulated] Telnet traffic from {ip} to 192.168.1.99")

            time.sleep(5)
            self.run_check_cycle()
            cycle += 1

            if cycle >= 3:
                print("\nTest mode complete — 3 cycles finished")
                break

    def start(self):
        """Starts the AIPET Watch agent."""
        self.running = True

        print("\n" + "="*60)
        print("  AIPET Watch Agent Starting")
        print("="*60)

        # Fetch baselines from cloud
        self.fetch_baselines()

        if self.test_mode:
            self.run_test_mode()
            return

        if not SCAPY_AVAILABLE:
            print("\n[Error] Scapy is not installed.")
            print("Install with: pip install scapy")
            print("Or run with --test flag for test mode")
            return

        print(f"\nStarting passive capture on interface: {self.interface or 'default'}")
        print("Press Ctrl+C to stop\n")

        # Start periodic check in background thread
        def periodic_check():
            while self.running:
                time.sleep(self.interval)
                if self.running:
                    self.run_check_cycle()

        check_thread = threading.Thread(target=periodic_check, daemon=True)
        check_thread.start()

        # Start Scapy capture (blocking)
        try:
            sniff(
                iface=self.interface,
                prn=self.packet_handler,
                store=False,
                stop_filter=lambda p: not self.running
            )
        except KeyboardInterrupt:
            self.running = False
            print("\nAIPET Watch Agent stopped.")
        except Exception as e:
            print(f"\n[Error] Capture failed: {e}")
            if "permission" in str(e).lower():
                print("Hint: Run with sudo for packet capture")

    def stop(self):
        """Stops the agent."""
        self.running = False


def main():
    parser = argparse.ArgumentParser(
        description="AIPET Watch — Network Monitoring Agent"
    )
    parser.add_argument("--api-url",   required=True,  help="AIPET Cloud API URL")
    parser.add_argument("--token",     required=True,  help="AIPET API token")
    parser.add_argument("--interface", default=None,   help="Network interface (e.g. eth0)")
    parser.add_argument("--interval",  type=int, default=60, help="Check interval in seconds")
    parser.add_argument("--test",      action="store_true",  help="Run in test mode (no Scapy)")

    args = parser.parse_args()

    agent = AIPETWatchAgent(
        api_url   = args.api_url,
        token     = args.token,
        interface = args.interface,
        interval  = args.interval,
        test_mode = args.test,
    )

    agent.start()


if __name__ == "__main__":
    main()