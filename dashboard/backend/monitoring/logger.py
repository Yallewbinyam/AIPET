# =============================================================
# AIPET Cloud — Structured Logging
# =============================================================
# What this file does:
#   Sets up professional logging for AIPET Cloud.
#   Every important event is recorded to a log file
#   with timestamp, level, and full details.
#
# Log files:
#   /tmp/aipet_cloud.log     — all events
#   /tmp/aipet_errors.log    — errors only
#
# Log rotation:
#   Each log file max 10MB
#   Keeps last 5 files
#   Never fills the disk
# =============================================================

import os
import sys
import logging
import logging.handlers
from datetime import datetime

# ── Log file paths ────────────────────────────────────────────
LOG_DIR      = os.environ.get("LOG_DIR", "/tmp")
MAIN_LOG     = os.path.join(LOG_DIR, "aipet_cloud.log")
ERROR_LOG    = os.path.join(LOG_DIR, "aipet_errors.log")
ACCESS_LOG   = os.path.join(LOG_DIR, "aipet_access.log")

# ── Log format ────────────────────────────────────────────────
# What each log line looks like:
# 2026-03-29 10:15:23 INFO     auth         User logged in
LOG_FORMAT = (
    "%(asctime)s %(levelname)-8s %(name)-12s %(message)s"
)
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def setup_logging(app=None, log_level="INFO"):
    """
    Set up structured logging for AIPET Cloud.

    Creates three handlers:
    1. Console  — shows logs in terminal (development)
    2. Main file — all logs rotated at 10MB
    3. Error file — errors only for quick scanning

    Args:
        app:       Flask app instance (optional)
        log_level: Minimum log level (default: INFO)
    """
    # Create formatter
    formatter = logging.Formatter(
        fmt=LOG_FORMAT, datefmt=DATE_FORMAT
    )

    # Get root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level.upper()))

    # Remove existing handlers
    root_logger.handlers.clear()

    # ── Handler 1: Console output ─────────────────────────────
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    # ── Handler 2: Main log file ──────────────────────────────
    # Rotates when file reaches 10MB
    # Keeps last 5 files
    main_handler = logging.handlers.RotatingFileHandler(
        MAIN_LOG,
        maxBytes  = 10 * 1024 * 1024,  # 10MB
        backupCount = 5,
        encoding  = "utf-8"
    )
    main_handler.setLevel(logging.INFO)
    main_handler.setFormatter(formatter)
    root_logger.addHandler(main_handler)

    # ── Handler 3: Error log file ─────────────────────────────
    # Only records WARNING and above
    # Easier to scan for problems
    error_handler = logging.handlers.RotatingFileHandler(
        ERROR_LOG,
        maxBytes    = 10 * 1024 * 1024,  # 10MB
        backupCount = 5,
        encoding    = "utf-8"
    )
    error_handler.setLevel(logging.WARNING)
    error_handler.setFormatter(formatter)
    root_logger.addHandler(error_handler)

    # Silence noisy libraries
    logging.getLogger("werkzeug").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy").setLevel(logging.WARNING)
    logging.getLogger("celery").setLevel(logging.WARNING)
    logging.getLogger("stripe").setLevel(logging.WARNING)

    if app:
        app.logger.info("AIPET Cloud logging initialised")
        app.logger.info(f"Main log:  {MAIN_LOG}")
        app.logger.info(f"Error log: {ERROR_LOG}")

    return root_logger


def get_logger(name):
    """
    Get a named logger for a specific module.

    Usage:
        from dashboard.backend.monitoring.logger import get_logger
        logger = get_logger(__name__)
        logger.info("User logged in")
        logger.error("Scan failed")

    Args:
        name: Module name (use __name__)

    Returns:
        logging.Logger instance
    """
    return logging.getLogger(name)


# ── Convenience logging functions ─────────────────────────────
def log_user_action(user_id, action, details=None):
    """Log a user action for audit trail."""
    logger = get_logger("aipet.audit")
    msg = f"user:{user_id} action:{action}"
    if details:
        msg += f" details:{details}"
    logger.info(msg)


def log_scan_event(scan_id, user_id, event, details=None):
    """Log a scan lifecycle event."""
    logger = get_logger("aipet.scan")
    msg = f"scan:{scan_id} user:{user_id} event:{event}"
    if details:
        msg += f" details:{details}"
    logger.info(msg)


def log_payment_event(user_id, event, amount=None,
                      plan=None):
    """Log a payment event."""
    logger = get_logger("aipet.payment")
    msg = f"user:{user_id} event:{event}"
    if amount:
        msg += f" amount:£{amount}"
    if plan:
        msg += f" plan:{plan}"
    logger.info(msg)


def log_error(error, context=None):
    """Log an error with full context."""
    logger = get_logger("aipet.error")
    msg = f"error:{str(error)}"
    if context:
        msg += f" context:{context}"
    logger.error(msg, exc_info=True)


def log_security_event(event, ip_address=None,
                       user_id=None, details=None):
    """Log a security relevant event."""
    logger = get_logger("aipet.security")
    msg = f"event:{event}"
    if ip_address:
        msg += f" ip:{ip_address}"
    if user_id:
        msg += f" user:{user_id}"
    if details:
        msg += f" details:{details}"
    logger.warning(msg)
