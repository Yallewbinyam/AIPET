"""
AIPET X — Load Testing (Locust) — 100 concurrent users
  LoginUser     (15) — POST /api/auth/login
  DashboardUser (60) — GET  /api/health
  ScanUser      (15) — POST /api/real-scan/discover
  ReportUser    (10) — POST /api/enterprise-reporting/generate

Run (web UI):
  locust -f locustfile.py --host http://localhost:5001

Run (headless, 100 users, 10/s ramp, 2-min soak):
  locust -f locustfile.py --host http://localhost:5001 \
         --headless -u 100 -r 10 --run-time 120s
"""

import random
import time

from locust import HttpUser, TaskSet, between, events, task

# ---------------------------------------------------------------------------
# Shared test credentials (register once, reused by all virtual users)
# ---------------------------------------------------------------------------
TEST_EMAIL    = "loadtest@aipet.local"
TEST_PASSWORD = "LoadTest123!"
TEST_NAME     = "Load Tester"

REPORT_TYPES  = ["executive", "ciso", "compliance", "incident", "trend"]
ORGS          = ["AIPET Corp", "Test Org", "Acme Security", "NHS Trust London"]
DISCOVER_IPS  = ["127.0.0.1", "192.168.1.1", "192.168.1.0/24", "10.0.0.1"]


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def _ensure_registered(client):
    """Idempotent — 409 if already exists is fine."""
    client.post(
        "/api/auth/register",
        json={"email": TEST_EMAIL, "password": TEST_PASSWORD, "name": TEST_NAME},
        name="/api/auth/register [setup]",
    )


def _login(client):
    res = client.post(
        "/api/auth/login",
        json={"email": TEST_EMAIL, "password": TEST_PASSWORD},
        name="/api/auth/login [setup]",
    )
    return res.json().get("token") if res.status_code == 200 else None


# ---------------------------------------------------------------------------
# Task sets
# ---------------------------------------------------------------------------

class LoginTasks(TaskSet):
    """LoginUser — repeatedly exercises POST /api/auth/login."""

    def on_start(self):
        _ensure_registered(self.client)

    @task
    def login(self):
        self.client.post(
            "/api/auth/login",
            json={"email": TEST_EMAIL, "password": TEST_PASSWORD},
            name="/api/auth/login",
        )


class DashboardTasks(TaskSet):
    """DashboardUser — high-frequency GET /api/health plus authenticated reads."""

    token = None

    def on_start(self):
        _ensure_registered(self.client)
        self.token = _login(self.client)

    def _get(self, path, name=None):
        if not self.token:
            self.token = _login(self.client)
        self.client.get(path, headers=_auth(self.token) if self.token else {}, name=name or path)

    @task(8)
    def health(self):
        """Primary DashboardUser task — GET /api/health."""
        self.client.get("/api/health", name="/api/health")

    @task(4)
    def ping(self):
        self.client.get("/api/ping", name="/api/ping")

    @task(3)
    def summary(self):
        self._get("/api/summary")

    @task(2)
    def findings(self):
        self._get("/api/findings")

    @task(1)
    def scans(self):
        self._get("/api/scans")


class ScanTasks(TaskSet):
    """ScanUser — POST /api/real-scan/discover."""

    token = None

    def on_start(self):
        _ensure_registered(self.client)
        self.token = _login(self.client)

    @task
    def discover(self):
        if not self.token:
            self.token = _login(self.client)
            if not self.token:
                return
        self.client.post(
            "/api/real-scan/discover",
            json={
                "target": random.choice(DISCOVER_IPS),
                "ports":  "22,80,443,8080",
                "mode":   "fast",
            },
            headers=_auth(self.token),
            name="/api/real-scan/discover",
        )


class ReportTasks(TaskSet):
    """ReportUser — POST /api/enterprise-reporting/generate."""

    token = None

    def on_start(self):
        _ensure_registered(self.client)
        self.token = _login(self.client)

    def _post(self, path, payload, name):
        if not self.token:
            self.token = _login(self.client)
            if not self.token:
                return
        self.client.post(path, json=payload, headers=_auth(self.token), name=name)

    @task(4)
    def generate(self):
        """Primary ReportUser task — POST /api/enterprise-reporting/generate."""
        self._post(
            "/api/enterprise-reporting/generate",
            {
                "report_type":  random.choice(REPORT_TYPES),
                "organisation": random.choice(ORGS),
                "period":       "Q1 2026",
            },
            name="/api/enterprise-reporting/generate",
        )

    @task(1)
    def history(self):
        if not self.token:
            self.token = _login(self.client)
        if self.token:
            self.client.get(
                "/api/enterprise-reporting/history",
                headers=_auth(self.token),
                name="/api/enterprise-reporting/history",
            )


# ---------------------------------------------------------------------------
# User classes — weights sum to 100 for clean 100-user runs
# ---------------------------------------------------------------------------

class LoginUser(HttpUser):
    """15 % of load — POST /api/auth/login"""
    tasks     = [LoginTasks]
    wait_time = between(2, 6)
    weight    = 15


class DashboardUser(HttpUser):
    """60 % of load — GET /api/health (+ authenticated reads)"""
    tasks     = [DashboardTasks]
    wait_time = between(1, 3)
    weight    = 60


class ScanUser(HttpUser):
    """15 % of load — POST /api/real-scan/discover"""
    tasks     = [ScanTasks]
    wait_time = between(5, 15)
    weight    = 15


class ReportUser(HttpUser):
    """10 % of load — POST /api/enterprise-reporting/generate"""
    tasks     = [ReportTasks]
    wait_time = between(3, 10)
    weight    = 10


# ---------------------------------------------------------------------------
# Summary hook
# ---------------------------------------------------------------------------

@events.quitting.add_listener
def on_quitting(environment, **kwargs):
    s = environment.stats.total
    print("\n========== AIPET Load Test Summary ==========")
    print(f"  Requests:  {s.num_requests}")
    print(f"  Failures:  {s.num_failures}  ({s.fail_ratio * 100:.1f}%)")
    print(f"  Avg (ms):  {s.avg_response_time:.0f}")
    print(f"  p95 (ms):  {s.get_response_time_percentile(0.95):.0f}")
    print(f"  p99 (ms):  {s.get_response_time_percentile(0.99):.0f}")
    print(f"  RPS:       {s.current_rps:.1f}")
    print("=============================================\n")
