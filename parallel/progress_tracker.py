# =============================================================
# AIPET — Parallel Scanning
# Component 2: Progress Tracker
# Author: Binyam
# Institution: Coventry University — MSc Cyber Security
# Date: March 2025
# Description: Tracks real-time progress of parallel scans.
#              Each scan reports its current module and status.
#              Thread-safe using Python's threading.Lock.
# =============================================================

import threading
import time
from datetime import datetime


# ── Scan States ───────────────────────────────────────────────
STATE_QUEUED    = "QUEUED"
STATE_RUNNING   = "RUNNING"
STATE_COMPLETE  = "COMPLETE"
STATE_FAILED    = "FAILED"

# ── Module Names ──────────────────────────────────────────────
MODULES = [
    "Reconnaissance",
    "MQTT Attack Suite",
    "CoAP Attack Suite",
    "HTTP/Web Suite",
    "Firmware Analyser",
    "AI Engine",
    "Report Generator",
]


class ScanProgress:
    """
    Tracks progress of a single scan target.
    Thread-safe — multiple scans update simultaneously.
    """

    def __init__(self, target):
        self.target       = target
        self.state        = STATE_QUEUED
        self.current_module = None
        self.module_index = 0
        self.total_modules = len(MODULES)
        self.started_at   = None
        self.completed_at = None
        self.error        = None
        self.findings     = {
            "critical": 0,
            "high":     0,
            "medium":   0,
            "low":      0,
        }
        self._lock = threading.Lock()

    def start(self):
        """Mark scan as started."""
        with self._lock:
            self.state      = STATE_RUNNING
            self.started_at = datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )

    def update_module(self, module_name, module_index):
        """Update current module being executed."""
        with self._lock:
            self.current_module = module_name
            self.module_index   = module_index

    def complete(self, findings=None):
        """Mark scan as complete with final findings."""
        with self._lock:
            self.state        = STATE_COMPLETE
            self.completed_at = datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )
            self.current_module = "Complete"
            self.module_index   = self.total_modules
            if findings:
                self.findings = findings

    def fail(self, error):
        """Mark scan as failed with error message."""
        with self._lock:
            self.state        = STATE_FAILED
            self.completed_at = datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )
            self.error        = str(error)

    def get_progress_pct(self):
        """Get progress as percentage 0-100."""
        with self._lock:
            if self.state == STATE_QUEUED:
                return 0
            if self.state == STATE_COMPLETE:
                return 100
            if self.total_modules == 0:
                return 0
            return int(
                (self.module_index / self.total_modules) * 100
            )

    def get_elapsed_seconds(self):
        """Get elapsed time in seconds."""
        if not self.started_at:
            return 0
        start = datetime.strptime(
            self.started_at, "%Y-%m-%d %H:%M:%S"
        )
        if self.completed_at:
            end = datetime.strptime(
                self.completed_at, "%Y-%m-%d %H:%M:%S"
            )
        else:
            end = datetime.now()
        return int((end - start).total_seconds())

    def to_dict(self):
        """Convert to dictionary for JSON serialisation."""
        with self._lock:
            return {
                "target":         self.target,
                "state":          self.state,
                "current_module": self.current_module,
                "module_index":   self.module_index,
                "total_modules":  self.total_modules,
                "progress_pct":   self.get_progress_pct(),
                "elapsed_seconds":self.get_elapsed_seconds(),
                "started_at":     self.started_at,
                "completed_at":   self.completed_at,
                "error":          self.error,
                "findings":       self.findings,
            }


class ParallelProgressTracker:
    """
    Tracks progress of all parallel scans simultaneously.
    Thread-safe central registry of all scan states.
    """

    def __init__(self):
        self._scans = {}
        self._lock  = threading.Lock()

    def register(self, target):
        """Register a new scan target."""
        with self._lock:
            self._scans[target] = ScanProgress(target)
        return self._scans[target]

    def get(self, target):
        """Get progress tracker for a target."""
        with self._lock:
            return self._scans.get(target)

    def get_all(self):
        """Get all scan progress as list of dicts."""
        with self._lock:
            return [
                scan.to_dict()
                for scan in self._scans.values()
            ]

    def get_summary(self):
        """Get overall summary of all scans."""
        with self._lock:
            total    = len(self._scans)
            queued   = sum(
                1 for s in self._scans.values()
                if s.state == STATE_QUEUED
            )
            running  = sum(
                1 for s in self._scans.values()
                if s.state == STATE_RUNNING
            )
            complete = sum(
                1 for s in self._scans.values()
                if s.state == STATE_COMPLETE
            )
            failed   = sum(
                1 for s in self._scans.values()
                if s.state == STATE_FAILED
            )

            # Aggregate findings
            total_findings = {
                "critical": 0, "high": 0,
                "medium": 0, "low": 0
            }
            for scan in self._scans.values():
                for sev, count in scan.findings.items():
                    total_findings[sev] += count

            return {
                "total":          total,
                "queued":         queued,
                "running":        running,
                "complete":       complete,
                "failed":         failed,
                "total_findings": total_findings,
            }

    def print_status(self):
        """Print current status of all scans to terminal."""
        print("\n" + "=" * 60)
        print("  AIPET PARALLEL SCAN STATUS")
        print("=" * 60)

        with self._lock:
            for target, scan in self._scans.items():
                pct    = scan.get_progress_pct()
                elapsed = scan.get_elapsed_seconds()
                bar    = "█" * (pct // 5) + "░" * (20 - pct // 5)

                state_colors = {
                    STATE_QUEUED:   "⏳",
                    STATE_RUNNING:  "🔄",
                    STATE_COMPLETE: "✅",
                    STATE_FAILED:   "❌",
                }
                icon = state_colors.get(scan.state, "?")

                print(f"  {icon} {target:<20} "
                      f"[{bar}] {pct:3}% "
                      f"({elapsed}s)")

                if scan.current_module:
                    print(f"     └─ {scan.current_module}")

        summary = self.get_summary()
        print(f"\n  Total: {summary['total']} | "
              f"Running: {summary['running']} | "
              f"Complete: {summary['complete']} | "
              f"Failed: {summary['failed']}")
        print("=" * 60)


# ── Global tracker instance ───────────────────────────────────
# Shared across all parallel scan threads
tracker = ParallelProgressTracker()


if __name__ == "__main__":
    print("Testing progress tracker...")

    # Simulate 3 parallel scans
    t1 = tracker.register("192.168.1.0/24")
    t2 = tracker.register("10.0.0.0/24")
    t3 = tracker.register("172.16.0.0/24")

    # Simulate scan 1 running
    t1.start()
    t1.update_module("Reconnaissance", 1)

    # Simulate scan 2 running further
    t2.start()
    t2.update_module("MQTT Attack Suite", 2)

    # Simulate scan 3 complete
    t3.start()
    t3.complete(findings={
        "critical": 3, "high": 2,
        "medium": 1, "low": 0
    })

    # Print status
    tracker.print_status()

    # Test summary
    summary = tracker.get_summary()
    print(f"\nSummary: {summary}")

    # Verify thread safety with concurrent updates
    errors = []

    def update_scan(scan, module, index):
        try:
            scan.update_module(module, index)
        except Exception as e:
            errors.append(str(e))

    import threading
    threads = []
    for i in range(10):
        t = threading.Thread(
            target=update_scan,
            args=(t1, f"Module {i}", i)
        )
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    if not errors:
        print("\n[+] Thread safety test passed")
    else:
        print(f"\n[-] Thread safety errors: {errors}")

    print("[+] Progress tracker ready")
