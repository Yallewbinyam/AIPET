# =============================================================
# AIPET Cloud — Celery Application
# =============================================================
# What this file does:
#   Creates the Celery application that manages background
#   scan tasks. Celery connects to Redis as its message
#   broker — Redis is the post box where scan jobs wait
#   until a worker picks them up.
#
# How it works:
#   1. User submits scan via dashboard
#   2. Flask adds scan job to Redis queue
#   3. Celery worker picks up job from Redis
#   4. Worker runs the full AIPET pipeline
#   5. Results saved to database
#   6. User sees results in dashboard
# =============================================================

import os
import sys
from celery import Celery

# Add project root to path
BASE_DIR = '/app' if os.path.exists('/app') else '/home/binyam/AIPET'
sys.path.insert(0, BASE_DIR)

# Redis connection URL
# In development: redis://localhost:6379/0
# In production:  redis://:password@redis:6379/0
REDIS_URL = os.environ.get(
    "REDIS_URL", "redis://localhost:6379/0"
)

# Database URL for Celery results backend
DATABASE_URL = os.environ.get(
    "DATABASE_URL", "sqlite:///aipet_dev.db"
)

# Create Celery application
celery = Celery(
    "aipet_cloud",
    broker=REDIS_URL,
    backend=REDIS_URL,
    include=["dashboard.backend.tasks"]
)

# Celery configuration
celery.conf.update(
    # Task settings
    task_serializer        = "json",
    accept_content         = ["json"],
    result_serializer      = "json",
    timezone               = "UTC",
    enable_utc             = True,

    # Result expiry — keep results for 24 hours
    result_expires         = 86400,

    # Task routing
    task_routes = {
        "dashboard.backend.tasks.run_scan_task": {"queue": "scans"},
        "dashboard.backend.tasks.sync_nvd_cves": {"queue": "celery"},
    },

    # Celery Beat — periodic tasks
    beat_schedule = {
        "sync-nvd-cves-hourly": {
            "task":     "dashboard.backend.tasks.sync_nvd_cves",
            "schedule": 3600,          # every 1 hour
            "kwargs":   {"days_back": 1},
        },
        "retrain-anomaly-model-daily": {
            "task":     "dashboard.backend.tasks.retrain_anomaly_model",
            "schedule": 86400,         # every 24 hours
        },
    },

    # Worker settings
    worker_prefetch_multiplier = 1,
    task_acks_late             = True,

    # Retry settings
    task_max_retries    = 3,
    task_default_retry_delay = 30,
)


def get_celery_app():
    """Return the configured Celery application."""
    return celery
