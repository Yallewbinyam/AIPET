# =============================================================
# AIPET Cloud — Database Backup
# Backs up PostgreSQL daily.
# Keeps last 7 days of backups.
# Run manually or via cron job.
# =============================================================

import os
import subprocess
import gzip
import shutil
from datetime import datetime, timedelta


# ── Configuration ─────────────────────────────────────────────
DB_NAME     = os.environ.get("DB_NAME",     "aipet_db")
DB_USER     = os.environ.get("DB_USER",     "aipet_user")
DB_HOST     = os.environ.get("DB_HOST",     "localhost")
DB_PORT     = os.environ.get("DB_PORT",     "5433")

# Where to store backups
BACKUP_DIR  = "/home/binyam/AIPET/backups"

# How many days to keep backups
RETENTION_DAYS = 7


# ── Helpers ────────────────────────────────────────────────────
def log(message, level="INFO"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"{timestamp} [{level}] {message}")


def ensure_backup_dir():
    """Create backup directory if it doesn't exist."""
    os.makedirs(BACKUP_DIR, exist_ok=True)


# ── Create backup ──────────────────────────────────────────────
def create_backup():
    """
    Dump the PostgreSQL database to a compressed .sql.gz file.
    The filename includes the timestamp so you can identify it.
    Example: aipet_db_2026-03-30_14-00-00.sql.gz
    """
    ensure_backup_dir()

    timestamp   = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename    = f"{DB_NAME}_{timestamp}.sql"
    gz_filename = filename + ".gz"
    filepath    = os.path.join(BACKUP_DIR, filename)
    gz_filepath = os.path.join(BACKUP_DIR, gz_filename)

    log(f"Starting backup: {gz_filename}")

    try:
        # pg_dump creates a SQL dump of the entire database.
        # We pipe it directly to gzip to compress it.
        # PGPASSWORD is set so pg_dump doesn't ask for a password.
        env = os.environ.copy()
        env["PGPASSWORD"] = os.environ.get("DB_PASSWORD", "aipet_password")

        with open(filepath, "w") as f:
            result = subprocess.run(
                [
                    "pg_dump",
                    "-h", DB_HOST,
                    "-p", DB_PORT,
                    "-U", DB_USER,
                    "-d", DB_NAME,
                    "--no-password",
                ],
                stdout=f,
                stderr=subprocess.PIPE,
                env=env
            )

        if result.returncode != 0:
            error = result.stderr.decode()
            log(f"pg_dump failed: {error}", "ERROR")
            if os.path.exists(filepath):
                os.remove(filepath)
            return None

        # Compress the file
        with open(filepath, "rb") as f_in:
            with gzip.open(gz_filepath, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)

        # Remove the uncompressed file
        os.remove(filepath)

        size_mb = os.path.getsize(gz_filepath) / (1024 * 1024)
        log(f"Backup created: {gz_filename} ({size_mb:.2f} MB)")
        return gz_filepath

    except Exception as e:
        log(f"Backup failed: {e}", "ERROR")
        return None


# ── Delete old backups ─────────────────────────────────────────
def cleanup_old_backups():
    """
    Delete backup files older than RETENTION_DAYS.
    This prevents backups from filling up your disk.
    """
    ensure_backup_dir()
    cutoff = datetime.now() - timedelta(days=RETENTION_DAYS)
    deleted = 0

    for filename in os.listdir(BACKUP_DIR):
        if not filename.endswith(".sql.gz"):
            continue

        filepath = os.path.join(BACKUP_DIR, filename)
        modified = datetime.fromtimestamp(os.path.getmtime(filepath))

        if modified < cutoff:
            os.remove(filepath)
            log(f"Deleted old backup: {filename}")
            deleted += 1

    log(f"Cleanup complete — {deleted} old backup(s) deleted")


# ── Restore backup ─────────────────────────────────────────────
def restore_backup(gz_filepath):
    """
    Restore the database from a .sql.gz backup file.
    USE WITH CAUTION — this overwrites the current database.

    Usage:
        python backup.py restore /path/to/backup.sql.gz
    """
    if not os.path.exists(gz_filepath):
        log(f"Backup file not found: {gz_filepath}", "ERROR")
        return False

    log(f"Restoring from: {gz_filepath}", "WARN")
    log("WARNING: This will overwrite the current database!", "WARN")

    try:
        env = os.environ.copy()
        env["PGPASSWORD"] = os.environ.get("DB_PASSWORD", "aipet_password")

        # Decompress and pipe directly to psql
        with gzip.open(gz_filepath, "rb") as f:
            result = subprocess.run(
                [
                    "psql",
                    "-h", DB_HOST,
                    "-p", DB_PORT,
                    "-U", DB_USER,
                    "-d", DB_NAME,
                ],
                stdin=f,
                stderr=subprocess.PIPE,
                env=env
            )

        if result.returncode != 0:
            log(f"Restore failed: {result.stderr.decode()}", "ERROR")
            return False

        log("Database restored successfully")
        return True

    except Exception as e:
        log(f"Restore failed: {e}", "ERROR")
        return False


# ── List backups ───────────────────────────────────────────────
def list_backups():
    """Show all available backups with their sizes."""
    ensure_backup_dir()
    backups = []

    for filename in sorted(os.listdir(BACKUP_DIR), reverse=True):
        if not filename.endswith(".sql.gz"):
            continue
        filepath = os.path.join(BACKUP_DIR, filename)
        size_mb  = os.path.getsize(filepath) / (1024 * 1024)
        modified = datetime.fromtimestamp(os.path.getmtime(filepath))
        backups.append({
            "filename": filename,
            "size_mb":  round(size_mb, 2),
            "created":  modified.strftime("%Y-%m-%d %H:%M:%S"),
            "path":     filepath,
        })

    return backups


# ── Run directly ───────────────────────────────────────────────
if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "restore":
        if len(sys.argv) < 3:
            print("Usage: python backup.py restore <path_to_backup.sql.gz>")
            sys.exit(1)
        restore_backup(sys.argv[2])

    elif len(sys.argv) > 1 and sys.argv[1] == "list":
        backups = list_backups()
        if not backups:
            print("No backups found.")
        for b in backups:
            print(f"{b['created']}  {b['filename']}  ({b['size_mb']} MB)")

    else:
        # Default: create a backup and clean up old ones
        create_backup()
        cleanup_old_backups()