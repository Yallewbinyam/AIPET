# =============================================================
# AIPET Cloud — Gunicorn Configuration
# =============================================================
# What is Gunicorn?
# Gunicorn is a production Python web server.
# It runs multiple workers simultaneously so many users
# can use AIPET Cloud at the same time without waiting.
#
# Flask dev server: 1 user at a time
# Gunicorn:         100+ users simultaneously
# =============================================================

import multiprocessing

# Server socket
bind    = "0.0.0.0:5001"
backlog = 2048

# Worker processes
# Use 2 workers in containers to avoid resource issues
# Scale with docker-compose --scale aipet-worker=N
import os
if os.path.exists('/app'):
    # Inside Docker container
    workers = 2
else:
    # On bare metal — use full CPU count
    workers = multiprocessing.cpu_count() * 2 + 1
worker_class = "sync"
worker_connections = 1000
timeout  = 120
keepalive = 2

# Logging
accesslog = "/tmp/aipet_access.log"
errorlog  = "/tmp/aipet_error.log"
loglevel  = "info"
access_log_format = (
    '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s"'
)

# Process naming
proc_name = "aipet_cloud"

# Security
limit_request_line   = 4096
limit_request_fields = 100

# Restart workers after this many requests
# Prevents memory leaks in long-running processes
max_requests          = 1000
max_requests_jitter   = 50

def on_starting(server):
    print("=" * 60)
    print("  AIPET Cloud — Gunicorn Production Server")
    print(f"  Workers: {workers}")
    print(f"  Binding: {bind}")
    print("=" * 60)
