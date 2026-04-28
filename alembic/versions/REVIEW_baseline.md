# PLB-1 -- Baseline migration review

**Migration**: `68d67bfc6697_baseline_schema.py`
**Generated**: 2026-04-28
**Generator command**:
```
ALEMBIC_DATABASE_URL=postgresql://aipet_admin:aipet_admin_password@localhost:5433/aipet_alembic_test \
  alembic revision --autogenerate -m "baseline schema"
```
**Reviewer**: Claude Code (PLB-1 sweep)

## Result

**0 manual additions required.** Autogenerate captured every table,
column, index, unique index, sequence, and primary-key constraint
present in the live `aipet_db` exactly. The diff between
`pg_dump -s` of the live database and `pg_dump -s` of an empty test
database after `alembic upgrade head` is **27 lines, 100 % explained
by alembic-only artefacts** (the `alembic_version` table + its PK +
session-specific `\restrict`/`\unrestrict` tokens that pg_dump 17
emits with random per-session IDs).

## Counts

|                       | live (aipet_db) | test (after upgrade) | diff |
|-----------------------|-----------------|----------------------|------|
| `CREATE TABLE`        | 166             | 167                  | +1 alembic_version |
| `CREATE INDEX`        | 54              | 54                   | 0    |
| `CREATE UNIQUE INDEX` | 2               | 2                    | 0    |
| `CREATE SEQUENCE`     | 92              | 92                   | 0    |

166 model entities (165 `__tablename__` + 1 `db.Table('role_permissions')`)
match the 166 tables in `aipet_db.public`.

## Hard-rule checks (PLB-1 hard rules)

* **No `metadata` column anywhere.** Confirmed by:
  ```
  grep -nE "sa\.Column\(\s*'metadata'\s*," 68d67bfc6697_baseline_schema.py
  ```
  → no matches. Also verified at the DB level:
  ```
  SELECT * FROM information_schema.columns WHERE column_name='metadata';
  ```
  → no rows.
* **`node_meta` columns**: 75 occurrences across the baseline -- the
  designated convention.
* **No competitor names**: `grep` for the names of typical IoT-security
  vendors against the migration body returns zero matches.

## What autogenerate omitted on purpose

PostgreSQL `SERIAL` columns are represented as `Integer + autoincrement`
plus an implicit owned sequence. Alembic logged 28 messages of the form
"Detected sequence named '<x>_id_seq' as owned by integer column ...,
assuming SERIAL and omitting" -- this is correct, the sequence is
recreated implicitly by `op.create_table(..., sa.Column('id', sa.Integer,
primary_key=True))` because the column also has `autoincrement=True`.

Verified: `aipet_alembic_test` after upgrade has 92 sequences vs 92 in
live -- exact match.

## Things alembic does NOT autogenerate

This migration captures the *current* state. Any of the following that
exist in the live DB are NOT in the migration:

* Custom triggers and stored functions -- none in the live DB
  (verified: `SELECT count(*) FROM information_schema.triggers
  WHERE trigger_schema='public';` returns 0).
* Custom check constraints -- none in models (verified: no `CheckConstraint`
  literal in `dashboard/backend/**/*.py`).
* Materialised views -- none.
* Comments / extensions -- none beyond pg_catalog defaults.

If any of these are added later, every new alembic revision must
include them as `op.execute()` blocks.

## Phase 3 verification (this review's evidence)

The following evidence is preserved at
`alembic/versions/PHASE3_evidence/`:

* `live_schema.sql` -- `pg_dump -s` of `aipet_db` taken at 2026-04-28
  before any alembic operation against it. Reference for all future
  drift detection.
* `test_schema_after_upgrade.sql` -- `pg_dump -s` of
  `aipet_alembic_test` after `alembic upgrade head` from empty.
* `diff_live_vs_test.txt` -- the 27-line diff above, explained line by
  line.

Phase 3 will additionally exercise `downgrade base` and a second
`upgrade head` round-trip against the same throwaway DB.

## Sign-off

The baseline migration:

1. Creates every table that exists in the live `aipet_db`.
2. Creates every index, unique index, and sequence.
3. Drops them in dependency-safe reverse order in `downgrade()`.
4. Does NOT contain any `metadata` column.
5. Required no manual edits beyond the autogenerate output.

Approved for commit.
