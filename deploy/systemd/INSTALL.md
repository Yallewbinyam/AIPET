# AIPET X — Celery systemd Installation Guide

Install these service files on the production DigitalOcean droplet to have
Celery worker and Beat managed by systemd (auto-restart on failure/reboot,
proper logging, clean shutdown).

## Prerequisites

- AIPET X code deployed to `/opt/aipet/`
- Virtual environment at `/opt/aipet/venv/`
- Production `.env` file at `/opt/aipet/.env` with at minimum:
  ```
  DATABASE_URL=postgresql://...
  REDIS_URL=redis://localhost:6379/0
  FLASK_LIMITER_STORAGE_URI=redis://localhost:6379/1
  ```
- Dedicated system user: `sudo useradd --system --home /opt/aipet --shell /sbin/nologin aipet`
- Log directory: `sudo mkdir -p /var/log/aipet && sudo chown aipet:aipet /var/log/aipet`
- PID directory: `sudo mkdir -p /opt/aipet/pids && sudo chown aipet:aipet /opt/aipet/pids`
- Redis and PostgreSQL running as system services

## Installation Steps

### 1. Copy the service files

```bash
sudo cp aipet-celery-worker.service /etc/systemd/system/
sudo cp aipet-celery-beat.service   /etc/systemd/system/
```

### 2. Edit the service files if needed

The templates use `/opt/aipet` and `aipet` user. If your paths differ:

```bash
sudo nano /etc/systemd/system/aipet-celery-worker.service
sudo nano /etc/systemd/system/aipet-celery-beat.service
```

### 3. Reload systemd and enable the services

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now aipet-celery-worker.service
sudo systemctl enable --now aipet-celery-beat.service
```

### 4. Verify

```bash
sudo systemctl status aipet-celery-worker.service
sudo systemctl status aipet-celery-beat.service
```

Expected output: `active (running)` for both.

Confirm the worker is responding:

```bash
cd /opt/aipet && source venv/bin/activate
celery -A dashboard.backend.celery_app inspect ping --timeout 10
```

Expected: `aipet-worker@<hostname>: pong`

### 5. Check logs

```bash
sudo tail -f /var/log/aipet/celery_worker.log
sudo tail -f /var/log/aipet/celery_beat.log
```

Or via journald:

```bash
sudo journalctl -u aipet-celery-worker -f
sudo journalctl -u aipet-celery-beat -f
```

## After a Code Deployment

When you `git pull` new code on the production server:

```bash
sudo systemctl restart aipet-celery-worker.service
sudo systemctl restart aipet-celery-beat.service
```

Beat will rebuild its schedule from the updated `celery_app.py` on restart.

## Stopping the Services

```bash
sudo systemctl stop aipet-celery-beat.service    # stop Beat first
sudo systemctl stop aipet-celery-worker.service  # then worker
```

Beat first — so no new tasks are scheduled while the worker shuts down.

## Important: Only One Beat Instance

**Never run more than one `aipet-celery-beat` instance.** Multiple Beat
processes each fire every scheduled task independently, causing duplicate
NVD syncs, duplicate ML retrains, etc. Scale Celery **workers** horizontally
(multiple worker instances are fine); Beat is always a single process.

## Disabling (rollback)

```bash
sudo systemctl disable --now aipet-celery-worker.service
sudo systemctl disable --now aipet-celery-beat.service
```
