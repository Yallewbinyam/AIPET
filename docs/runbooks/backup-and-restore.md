# Database backup and restore -- runbook

This runbook is the canonical procedure for taking, retaining, and
verifying PostgreSQL backups of `aipet_db`. It is owned by ops; the
in-app backup module under `dashboard/backend/monitoring/backup.py`
is being deprecated in favour of the shell scripts documented here.

## TL;DR

```
./scripts/backup.sh                       # ad-hoc backup, timestamped, gzipped
./scripts/backup.sh pre-deploy            # tag the file
./scripts/restore.sh BACKUP.sql.gz aipet_restore_test
                                          # restore into a SEPARATE db
                                          # (refuses target=aipet_db without flag)
```

Backups land in `<repo>/backups/`, which is gitignored and must NEVER
be committed.

## When to back up

| Event                                         | Cadence                  |
|-----------------------------------------------|--------------------------|
| Routine                                       | Daily, automated         |
| Before any `alembic upgrade`                  | Always, manually         |
| Before a destructive ad-hoc SQL operation     | Always, manually         |
| Before a major code release                   | Always, manually         |
| As part of incident response                  | Before any triage write  |

The daily run should be a cron entry on the production host:

```cron
# /etc/cron.d/aipet-backup
0 2 * * *  byall  cd /home/byall/AIPET && ./scripts/backup.sh daily \
                  >> /var/log/aipet/backup.log 2>&1
```

## Where backups go

`<repo>/backups/aipet_db_<YYYY-MM-DD_HH-MM-SS>[_<tag>].sql.gz`

* Owned by the user that ran the script (typically `byall` on dev,
  the deploy user in prod).
* `.gz`-compressed; `gunzip -t` is part of the backup script's
  acceptance check, so any backup that lands has been gzip-verified.
* Production must replicate this directory off-host (S3, B2,
  another machine, ...). A backup that lives only on the database
  server is one disk failure away from worthless.

## Retention policy

Recommend a Grandfather-Father-Son rotation:

| Tier   | Keep   | Action when older                  |
|--------|--------|------------------------------------|
| daily  | 7      | delete                             |
| weekly | 4      | (keep the Sunday daily until rotation date) |
| monthly| 3      | (keep the 1st-of-month daily until rotation) |

The current `dashboard/backend/monitoring/backup.py` enforces only the
7-daily tier. If you adopt the runbook in production, implement
weekly/monthly via either a thin pruning script or a managed service
(Restic / BorgBackup / ...).

## Restore -- standard verification flow

The whole point of having backups is being able to use them. Test a
restore at least once a month, and immediately after any change to the
schema or the backup tooling.

```
LATEST=$(ls -1 backups/aipet_db_*.sql.gz | tail -1)
./scripts/restore.sh "$LATEST" aipet_restore_test

# Sanity-check
PGPASSWORD=aipet_password psql -h localhost -p 5433 -U aipet_user \
    -d aipet_restore_test \
    -c "SELECT count(*) FROM information_schema.tables WHERE table_schema='public';"

# Authoritative row-count diff (replace this snippet with your CI helper)
python3 -c "
import psycopg2
def cnt(db):
    c = psycopg2.connect(host='localhost', port=5433, user='aipet_user',
                         password='aipet_password', dbname=db).cursor()
    c.execute(\"SELECT tablename FROM pg_tables WHERE schemaname='public'\")
    out = {}
    for (t,) in c.fetchall():
        c.execute(f'SELECT count(*) FROM \"{t}\";')
        out[t] = c.fetchone()[0]
    return out
a, b = cnt('aipet_db'), cnt('aipet_restore_test')
diffs = [(t, a.get(t), b.get(t)) for t in sorted(set(a)|set(b)) if a.get(t)!=b.get(t)]
print(f'tables_diff: {len(diffs)}')
for t, av, bv in diffs: print(f'  {t}: src={av}  restored={bv}')
"

# When done
PGPASSWORD=aipet_admin_password psql -h localhost -p 5433 -U aipet_admin \
    -d postgres -c "DROP DATABASE aipet_restore_test;"
```

If `tables_diff` is anything other than 0, the backup is **not**
restoring cleanly. STOP. Investigate. Don't trust that backup.

## Restore -- real disaster recovery

Only after you have:

1. Convinced yourself the live `aipet_db` is genuinely unrecoverable
   (recent activity matters more than the dump's age; once you
   restore, anything written since the dump is gone).
2. Notified anyone who depends on AIPET that there will be downtime
   and possible data rollback.
3. Stopped all writers (Gunicorn workers, Celery worker, Celery Beat).
4. Taken a final "current broken state" backup so you can study the
   incident later -- `./scripts/backup.sh pre-restore-of-DD-MM-YY`.

Then:

```
./scripts/restore.sh BACKUP.sql.gz aipet_db --i-know-what-im-doing
```

The `--i-know-what-im-doing` flag is the typo guard: without it the
script refuses target=`aipet_db`. This exists because muscle-memory
typing the same name twice is the #1 way ops engineers wipe production.

After the restore:

```
# Stamp the alembic version so future migrations resume cleanly
ALEMBIC_DATABASE_URL=postgresql://aipet_admin:aipet_admin_password@localhost:5433/aipet_db \
  venv/bin/alembic current
# If the result is missing, the dump pre-dates PLB-1's stamp; run:
ALEMBIC_DATABASE_URL=... venv/bin/alembic stamp head
```

Then bring the workers back up.

## What can go wrong (and what to do)

| Symptom                                   | Likely cause                                           | Action                                                                  |
|-------------------------------------------|--------------------------------------------------------|-------------------------------------------------------------------------|
| `gzip: invalid compressed data`           | Backup file truncated mid-write                        | Use the prior day's backup. Investigate disk full / kill of pg_dump.   |
| `psql: ERROR: role "aipet_admin" does not exist` | Restoring to a host without the migration role | Pre-create both roles before running restore.sh. See `alembic/README`. |
| `permission denied for table alembic_version`| Restored DB owner is admin but app user lost grant  | `GRANT SELECT ON alembic_version TO aipet_user;`                       |
| Restore succeeds but row counts differ    | Source DB is being written to during the dump          | Run `pg_dump` against a quiesced DB or use a pg_basebackup snapshot.   |
| The restore.sh refuses with "production guard" | Working as designed                                  | If you really mean it, add `--i-know-what-im-doing`. If not, change the target name. |

## See also

* `alembic/README` -- the migrations workflow that lives alongside this
* `verification/plb1/PLB-1-alembic-baseline-2026-04-28.md` -- the
  closure report that established the procedure
* `dashboard/backend/monitoring/backup.py` -- legacy in-app backup
  (still scheduled by Celery; will be retired in a follow-up commit)
