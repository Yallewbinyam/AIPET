#!/usr/bin/env bash
# =============================================================
# AIPET X -- Database backup
#
# pg_dump | gzip > backups/aipet_db_<ts>.sql.gz
# Exits non-zero on any failure. Safe to run any time. Idempotent.
#
# Usage:
#   ./scripts/backup.sh              # default name aipet_db_<ts>.sql.gz
#   ./scripts/backup.sh foo          # tag the file: aipet_db_<ts>_foo.sql.gz
#
# Env (all optional, defaults match .env):
#   PGHOST          default localhost
#   PGPORT          default 5433
#   PGUSER          default aipet_user
#   PGPASSWORD      default aipet_password    (read from .env if not set)
#   DB_NAME         default aipet_db
#   BACKUP_DIR      default <repo>/backups
# =============================================================
set -Eeuo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TAG="${1:-}"

# Read just the DB-related keys from .env without `source`-ing it
# (other keys may legitimately contain unquoted spaces -- e.g. an
# SMTP_PASSWORD that's a 4-word app password -- which would break
# bash sourcing). We only need the DB connection bits.
read_dotenv_key() {
    local key="$1" file="$REPO_ROOT/.env"
    [[ -f "$file" ]] || return 0
    # `|| true` so a missing key (grep exit 1) does not trip set -e
    grep -E "^${key}=" "$file" 2>/dev/null | head -1 | cut -d= -f2- || true
}
DB_PASSWORD_FROM_ENV="$(read_dotenv_key DB_PASSWORD)"
PGPASSWORD_FROM_ENV="$(read_dotenv_key PGPASSWORD)"

PGHOST="${PGHOST:-localhost}"
PGPORT="${PGPORT:-5433}"
PGUSER="${PGUSER:-aipet_user}"
PGPASSWORD="${PGPASSWORD:-$PGPASSWORD_FROM_ENV}"
PGPASSWORD="${PGPASSWORD:-$DB_PASSWORD_FROM_ENV}"
PGPASSWORD="${PGPASSWORD:-aipet_password}"
DB_NAME="${DB_NAME:-aipet_db}"
BACKUP_DIR="${BACKUP_DIR:-$REPO_ROOT/backups}"

mkdir -p "$BACKUP_DIR"

TS="$(date +%Y-%m-%d_%H-%M-%S)"
if [[ -n "$TAG" ]]; then
    OUT="$BACKUP_DIR/${DB_NAME}_${TS}_${TAG}.sql.gz"
else
    OUT="$BACKUP_DIR/${DB_NAME}_${TS}.sql.gz"
fi

echo "[..] backup -> $OUT"

# pg_dump | gzip with `set -o pipefail` ensures pg_dump's failure is detected
# even though the gzip on the right side returns 0.
PGPASSWORD="$PGPASSWORD" pg_dump \
    --host="$PGHOST" \
    --port="$PGPORT" \
    --username="$PGUSER" \
    --dbname="$DB_NAME" \
    --no-password \
  | gzip -c > "$OUT"

# Verify the gzip is valid and non-empty
if [[ ! -s "$OUT" ]]; then
    echo "[XX] backup produced empty file" >&2
    rm -f "$OUT"
    exit 1
fi
gunzip -t "$OUT"

SIZE=$(du -h "$OUT" | cut -f1)
LINES=$(gunzip -c "$OUT" | wc -l)
echo "[OK] backup wrote $SIZE ($LINES decompressed lines) to:"
echo "     $OUT"
