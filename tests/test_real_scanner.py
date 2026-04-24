# =============================================================
# AIPET X — API tests: real_scanner blueprint
#
# Tests scanner code changes from Day 2.5:
#   - Removed --open nmap flag so hosts with zero open ports
#     are persisted (previously suppressed from all_hosts()).
#   - Hosts with zero open ports get node_meta.no_open_ports=True.
# =============================================================
import json
from unittest.mock import patch

import pytest


class _FakePortScanner:
    """Minimal nmap.PortScanner stub returning one host with no open ports."""

    def scan(self, hosts, arguments, timeout=None):
        pass

    def all_hosts(self):
        return ["10.0.3.9"]

    def __getitem__(self, host):
        return _FakeHostNoOpenPorts()


class _FakeHostNoOpenPorts:
    def state(self):
        return "up"

    def get(self, key, default=None):
        return {"hostnames": [], "osmatch": []}.get(key, default)

    def all_protocols(self):
        return ["tcp"]

    def __getitem__(self, proto):
        return {}  # no ports for any protocol


def test_scanner_persists_host_with_zero_open_ports(flask_app, test_user):
    """A host that is reachable but has no open ports must be stored in
    results_json with port_count=0 and node_meta.no_open_ports=True.
    Previously, the --open nmap flag silently suppressed such hosts."""
    from dashboard.backend.models import db
    from dashboard.backend.real_scanner.routes import RealScanResult, _run_nmap_scan

    scan = RealScanResult(
        user_id=test_user.id,
        target="10.0.3.9",
        status="pending",
    )
    db.session.add(scan)
    db.session.commit()
    scan_id = scan.id

    with patch("nmap.PortScanner", return_value=_FakePortScanner()):
        _run_nmap_scan(scan_id, "10.0.3.9", test_user.id, flask_app)

    # _run_nmap_scan commits via its own nested app context; expire the outer
    # session's identity map so we read the updated row from the DB.
    db.session.expire_all()
    result = db.session.get(RealScanResult, scan_id)
    assert result.status == "complete"
    assert result.hosts_found == 1

    hosts = json.loads(result.results_json)
    assert len(hosts) == 1
    host = hosts[0]
    assert host["port_count"] == 0
    assert host["open_ports"] == []
    assert host.get("node_meta", {}).get("no_open_ports") is True
