#!/usr/bin/env bash
# =============================================================
# AIPET X -- Database restore
#
# Drops + recreates the target database, then loads a .sql.gz dump.
#
# Usage:
#   ./scripts/restore.sh <backup.sql.gz> <target_db_name>
#       Refuses to run if target_db_name == aipet_db (production
#       guard). Use --i-know-what-im-doing as a third arg to override.
#
#   ./scripts/restore.sh <backup.sql.gz> aipet_db --i-know-what-im-doing
#       Restore into aipet_db. ONLY do this in a real disaster
#       recovery; the prior aipet_db is destroyed.
#
# Why a typo guard?
#   "Restore into the same name" is the surface that destroys
#   production. Forcing a different name for normal use means
#   accidental restores produce a side-database that can be
#   inspected, not a wiped prod database.
#
# Env (all optional, same defaults as backup.sh):
#   PGHOST          default localhost
#   PGPORT          default 5433
#   PGADMIN_USER    default aipet_admin    (CREATEDB role)
#   PGADMIN_PASSWORD default aipet_admin_password (dev only)
# =============================================================
set -Eeuo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ $# -lt 2 ]]; then
    cat >&2 <<EOF
Usage:
  $0 <backup.sql.gz> <target_db_name>
  $0 <backup.sql.gz> aipet_db --i-know-what-im-doing

Examples:
  $0 backups/aipet_db_2026-04-28_01-57-24_pre-stamp.sql.gz aipet_restore_test
  $0 backups/aipet_db_2026-04-28_02-00-00.sql.gz aipet_db --i-know-what-im-doing
EOF
    exit 2
fi

DUMP="$1"
TARGET_DB="$2"
SAFETY="${3:-}"

if [[ ! -f "$DUMP" ]]; then
    echo "[XX] dump file not found: $DUMP" >&2
    exit 1
fi
if ! gunzip -t "$DUMP" 2>/dev/null; then
    echo "[XX] dump is not a valid gzip file: $DUMP" >&2
    exit 1
fi

# Read only the DB-related keys from .env without `source`-ing it
# (see backup.sh comment for rationale -- other env keys may have
# unquoted spaces that break bash sourcing).
read_dotenv_key() {
    local key="$1" file="$REPO_ROOT/.env"
    [[ -f "$file" ]] || return 0
    # `|| true` so a missing key (grep exit 1) does not trip set -e
    grep -E "^${key}=" "$file" 2>/dev/null | head -1 | cut -d= -f2- || true
}

PGHOST="${PGHOST:-localhost}"
PGPORT="${PGPORT:-5433}"
PGADMIN_USER="${PGADMIN_USER:-aipet_admin}"
PGADMIN_PASSWORD="${PGADMIN_PASSWORD:-$(read_dotenv_key PGADMIN_PASSWORD)}"
PGADMIN_PASSWORD="${PGADMIN_PASSWORD:-aipet_admin_password}"
APP_USER="${PGUSER:-aipet_user}"

# --- Production safety guard --------------------------------------
if [[ "$TARGET_DB" == "aipet_db" && "$SAFETY" != "--i-know-what-im-doing" ]]; then
    cat >&2 <<EOF
[XX] Refusing to restore into target_db=aipet_db without explicit override.

This is the production database. Restoring into it will DESTROY current
data. If you really mean to restore prod (e.g. after a real outage),
re-run with the explicit flag:

  $0 "$DUMP" aipet_db --i-know-what-im-doing

For verification / testing, restore into a different DB name:

  $0 "$DUMP" aipet_restore_test
EOF
    exit 1
fi

echo "[..] target DB:    $TARGET_DB"
echo "[..] dump:         $DUMP"
echo "[..] admin role:   $PGADMIN_USER (CREATEDB)"
echo "[..] app role:     $APP_USER (will own the restored DB)"
echo

# --- Drop + recreate target -------------------------------------
echo "[..] DROP DATABASE IF EXISTS $TARGET_DB"
PGPASSWORD="$PGADMIN_PASSWORD" psql \
    --host="$PGHOST" --port="$PGPORT" --username="$PGADMIN_USER" \
    --dbname=postgres \
    -c "DROP DATABASE IF EXISTS \"$TARGET_DB\";" >/dev/null

echo "[..] CREATE DATABASE $TARGET_DB OWNER $APP_USER"
PGPASSWORD="$PGADMIN_PASSWORD" psql \
    --host="$PGHOST" --port="$PGPORT" --username="$PGADMIN_USER" \
    --dbname=postgres \
    -c "CREATE DATABASE \"$TARGET_DB\" OWNER \"$APP_USER\";" >/dev/null

# --- Load dump --------------------------------------------------
echo "[..] loading dump (decompress | psql)"
LOG="/tmp/aipet-restore-$(date +%s).log"
if ! gunzip -c "$DUMP" \
   | PGPASSWORD="$PGADMIN_PASSWORD" psql \
        --host="$PGHOST" --port="$PGPORT" --username="$PGADMIN_USER" \
        --dbname="$TARGET_DB" \
        --quiet --single-transaction --set ON_ERROR_STOP=on \
   > "$LOG" 2>&1; then
    echo "[XX] psql restore failed; last 30 lines of log:" >&2
    tail -30 "$LOG" >&2
    echo "    full log: $LOG" >&2
    exit 1
fi

# --- Quick sanity --------------------------------------------------
TABLE_COUNT=$(PGPASSWORD="$PGADMIN_PASSWORD" psql \
    --host="$PGHOST" --port="$PGPORT" --username="$PGADMIN_USER" \
    --dbname="$TARGET_DB" -At \
    -c "SELECT count(*) FROM information_schema.tables WHERE table_schema='public';")

echo "[OK] restore complete; $TABLE_COUNT public tables in $TARGET_DB"
echo "     log: $LOG"
