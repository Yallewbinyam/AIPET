# PLB-1 -- Alembic baseline + tested backup/restore

| Field | Value |
| --- | --- |
| **Date** | 2026-04-28 |
| **Branch / starting HEAD** | `main` / `6323aacf` |
| **Models** | 165 `__tablename__` + 1 `db.Table('role_permissions')` = 166 entities |
| **Live tables (`aipet_db.public`)** | 166 |
| **Match before stamp** | exact |
| **Final stamped revision** | `68d67bfc6697 (head)` "baseline schema" |
| **Tester** | Claude Code |

## Summary

PLB-1 **CLOSED**. Five commits, each per-phase, all on `main`:

| Phase | SHA | Title |
| --- | --- | --- |
| 1 | `bba5c2a6` | install and configure Alembic |
| 2 | `68d0f14c` | baseline migration with full schema review |
| 3 | `d757d110` | baseline migration verified bidirectional |
| 4 | `cf4f81f5` | stamp aipet_db at baseline revision |
| 5 | `d25b2c62` | tested backup/restore procedure with runbook |
| 6 | (this commit) | report, CLAUDE.md, push |

## Phase results

### Phase 0 -- recon

- 165 model `__tablename__` + 1 `role_permissions` `db.Table()` = 166;
  matches the 166 user tables in `aipet_db.public`.
- `db.create_all()` is called once in `app_cloud.create_app()` line 483
  (NOT a request handler) and runs at gunicorn worker boot.
- `flask-migrate==4.1.0` is in `requirements_cloud.txt` but never wired:
  no `Migrate(app, db)` call anywhere. Recommended for removal in a
  follow-up commit (see "Recommendations" below).
- No `metadata` column anywhere -- in DB or in any model.

### Phase 1 -- Alembic installed and configured

- Pinned `alembic>=1.13` in both `requirements.txt` and
  `requirements_cloud.txt`.
- `alembic init alembic` produced the directory + `alembic.ini`.
- `alembic/env.py` rewritten to:
  * prepend repo root to `sys.path`
  * read `.env` (so `DATABASE_URL` is set in fresh shells)
  * prefer `ALEMBIC_DATABASE_URL` over `DATABASE_URL`
  * import the live app factory so every blueprint's models register on
    `db.metadata` before autogenerate inspects it
  * `compare_type=True`, `compare_server_default=True` to catch column
    type / default drift on future autogenerate runs.
- Acceptance: `alembic current` connects, prints empty (no revision).

### Phase 2 -- baseline generated and reviewed

The naive autogenerate against the live DB produced an empty migration
(0 `create_table` calls) -- **expected**, since `db.create_all()` has
been keeping the schema and the models in lock-step.

To get a true baseline, autogenerate was re-run against an empty
throwaway DB (`aipet_alembic_test`, owned by `aipet_user`, created via
the new admin role -- see "Database roles" below). Result:

- `alembic/versions/68d67bfc6697_baseline_schema.py`
  * 2,765 lines / 148 KB
  * 166 `op.create_table` (matches the live count)
  * 54 `op.create_index`, 2 `op.create_unique_constraint`
  * 166 `op.drop_table` in `downgrade()` in dependency-safe reverse order

- `alembic/versions/REVIEW_baseline.md` -- the review document. Key
  findings: **0 manual additions required**. The `pg_dump -s` diff
  between the live DB and the test DB after `alembic upgrade head` is
  27 lines, 100 % alembic-only artefacts (the `alembic_version` table
  + its PK + session-specific `\restrict`/`\unrestrict` tokens that
  pg_dump 17 emits with random per-session IDs).

- `alembic/versions/PHASE3_evidence/{live_schema.sql, test_schema_after_upgrade.sql, diff_live_vs_test.txt}`
  preserved as reference for future drift detection.

Hard-rule check passes:
- `grep "sa.Column('metadata'" baseline_schema.py` -> 0 matches.
- `grep "sa.Column('node_meta'" baseline_schema.py` -> 75 matches.

### Phase 3 -- bidirectional verification on a throwaway DB

Throwaway DB `aipet_alembic_test` was used. Three rounds:

1. `alembic upgrade head` from empty -> 167 tables (166 user +
   alembic_version), version pointer = `68d67bfc6697`. Diff vs live
   pg_dump -s: 27 alembic-only lines.
2. `alembic downgrade base` -> 0 user tables. `alembic_version` retained
   (alembic bookkeeping convention) with its `version_num` row removed.
3. `alembic upgrade head` (round 2) -> 167 tables again, identical diff.

Throwaway DB dropped at end. Full transcript at
`alembic/versions/PHASE3_evidence/phase3_transcript.txt`.

### Phase 4 -- stamping the live DB

Pre-stamp backup taken via the new shell scripts:
`backups/aipet_db_2026-04-28_01-57-24_pre-stamp.sql.gz`
(227 KB compressed, 12,927 lines decompressed, gzip -t verified).

**Incident: empty `alembic_version` table found in `aipet_db` before
the stamp.** The hard-rule procedure called for STOPPING in this case;
investigation confirmed it was an artefact of my own Phase 1 `alembic
current` smoke test (alembic's online MigrationContext auto-creates
the version table on first online connection even if no revision has
been stamped). Evidence:
* table empty (0 rows, `n_tup_ins=0`)
* owner = `aipet_user` (the role the smoke test ran under)
* not present in any prior commit
* no pre-existing `alembic.ini` on disk before today

Resolved via user-approved Path A: `DROP TABLE alembic_version`
(lossless, 0 rows) followed by `alembic stamp head`. Final state:
* `alembic current` -> `68d67bfc6697 (head)`
* `aipet_db.public` table count -> 167
* App smoke test (`from dashboard.backend.app_cloud import app`) -> OK
* `pytest --collect-only` -> 450 tests collected (unchanged)

The stamp ran under `aipet_admin`, so the new `alembic_version` is
owned by that role and `aipet_user` couldn't read it. Granted
`SELECT ON alembic_version TO aipet_user` so ops queries work; admin
keeps write privileges.

### Phase 5 -- tested backup / restore

`scripts/backup.sh` + `scripts/restore.sh` shipped, both ASCII / CRLF
clean, both `set -Eeuo pipefail`, both lint-clean (`bash -n`).

Defensive `.env` handling: rather than `set -a; source .env`, the
scripts grep specific keys (`PGPASSWORD`, `DB_PASSWORD`,
`PGADMIN_PASSWORD`). This is required because `.env` contains
legitimately-unquoted-spaced values (Gmail SMTP app password is
4 space-separated words) that bash sourcing chokes on.

`scripts/restore.sh` has a typo guard: it **refuses** `target=aipet_db`
unless the caller passes `--i-know-what-im-doing` as the third arg.
Verified live: refusal exits 1, friendly stderr explaining how to
override or how to use a side-database name.

Round-trip test:
1. `./scripts/backup.sh roundtrip` -> 224 KB
2. `./scripts/restore.sh <fresh.sql.gz> aipet_restore_test`
3. **Authoritative `count(*)` on every table both sides: 167 tables,
   `diff_count = 0`** (an initial `pg_stat_user_tables.n_live_tup`
   diff was a stats artefact, not real divergence; ANALYZE'd both
   sides to confirm).
4. `aipet_restore_test` dropped.

Evidence at `verification/plb1/evidence/`.

### Phase 6 -- this report + CLAUDE.md updates + push

Written; pushed (final SHA recorded below).

## Database roles (the production-grade twist agreed mid-session)

A new dedicated migration role was created to keep `aipet_user`
restricted:

| Role | Attributes | Purpose |
| --- | --- | --- |
| `aipet_user` | LOGIN, **no CREATEDB** | Application connections at runtime |
| `aipet_admin` | LOGIN, **CREATEDB**, inherits from `aipet_user` | Migration tooling only |

Two URLs flow from this:

- `DATABASE_URL=postgresql://aipet_user:aipet_password@localhost:5433/aipet_db`
  -- the application's connection string.
- `ALEMBIC_DATABASE_URL=postgresql://aipet_admin:aipet_admin_password@localhost:5433/aipet_db`
  -- the migration tooling's connection string. Read first by
  `alembic/env.py`; falls back to `DATABASE_URL` for upgrade/stamp on
  hosts where the admin role hasn't been provisioned yet.

`aipet_admin_password` is a development placeholder. **Production
must replace this value via secrets management (Vault / AWS Secrets
Manager / 1Password / ...) and remove it from `.env` before
deployment.** Both `alembic/README` and `docs/runbooks/backup-and-restore.md`
flag this requirement.

## Incidents during PLB-1

### Incident 1 -- pre-existing empty `alembic_version` table

See "Phase 4" above. **Cause**: my Phase 1 verification step ran
`alembic current` against `aipet_db`. Alembic's online MigrationContext
auto-creates the version table on first connection so it can read the
current revision. With no stamp yet, the table is created empty.

The hard-rule procedure said "STOP and investigate". I did, with the
user's prompting. Investigation took ~5 minutes and confirmed zero
risk of pre-existing migration history. Resolution was a single DROP
followed by the canonical `alembic stamp head`.

**Lesson for future Alembic adoption work**: on a database that has
no migration history, run `alembic stamp head` BEFORE any read-only
alembic command (`current`, `history`, ...). If `current` is run first
it leaves an empty version table that subsequent procedures must then
deal with.

This lesson is captured in `alembic/README` under "Authoring a
migration" so future contributors don't hit the same surprise.

### Incident 2 -- `set -e` + grep no-match in shell scripts

`scripts/backup.sh` initially failed on first run because `set -Eeuo
pipefail` propagated grep's exit-1 (no match) through a function
called via command substitution. Fixed with `|| true` on the grep
pipeline. ~3 minutes lost.

### Incident 3 -- `.env` is shell-ill-formed

`set -a; source .env` died on `SMTP_PASSWORD=hvlq mcku jggo uisv`
(unquoted Gmail app password with spaces, which bash interprets as
`mcku` etc. being commands). The fix was already-defensive: the
scripts only need a handful of DB-related keys, and now grep them out
without sourcing the rest. **This also avoids the side-effect of
exporting unrelated secrets** (Anthropic API key, OTX key, JWT secret)
into the script's environment.

## Recommendations (deferred, NOT closures)

### Remove flask-migrate

`flask-migrate==4.1.0` sits in `requirements_cloud.txt` but is never
wired (`Migrate(app, db)` is never called anywhere). Future
contributors might assume migrations should go through flask-migrate
when they should go through pure alembic per `alembic/README`.

**Suggested follow-up commit**: remove the line from
`requirements_cloud.txt` and confirm pytest collection still passes.
The transitive alembic dependency will continue via the explicit
`alembic>=1.13` pin we added in Phase 1.

### Retire `dashboard/backend/monitoring/backup.py`

The in-app backup module has hardcoded `/home/binyam/AIPET/backups`
paths and a restore() that overwrites `aipet_db` with no typo guard.
The runbook now points at the shell scripts. Retirement would mean:
1. Remove the Celery beat schedule entry that triggers it (if any).
2. Delete the module.
3. Document the cron-based replacement in the runbook.

This is a follow-up commit, not a PLB-1 closure item.

### Move `aipet_admin_password` to a secret store

For development the placeholder value is fine. Production deployment
must source it from Vault / AWS Secrets Manager / 1Password and remove
the line from `.env`. This is part of the production deployment
checklist, not PLB-1.

## Closure protocol

PLB-1 row in CLAUDE.md updated to:
`Closed (commit <PHASE-6-SHA>, 2026-04-28). 5 phases / 5 commits / 1
runbook / 1 stamped baseline. Live tested forward, back, and
restore-into-test-DB row-count identical.`

PLB count after this closure: **4 Open / 5 Closed** (was 5/4).
