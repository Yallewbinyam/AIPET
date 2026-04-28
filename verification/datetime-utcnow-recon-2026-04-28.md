# `datetime.utcnow()` Deprecation Cleanup — Recon

**Date:** 2026-04-28
**Status:** Recon only. **No code changes made. Not started.**
**Reason for deferral:** Recon revealed the task is 60-90 min + a model migration + an agent rebuild, not the 30-min mechanical task the brief assumed. Splitting into three sub-tasks so a future session can pick up sub-task (i) cleanly without re-doing recon.

---

## Why we deferred

The original brief framed this as "pure mechanical cleanup, ~30 min". Recon showed:

1. **130 callsites across 46 files** (vs the brief's ~50 threshold).
2. **3 callsites are in agent code that ships to customer machines** — modifying them requires version bump (v1.2.0 → v1.2.1), `.deb` rebuild, Windows installer rebuild + PLB-9-style live re-verify on the Win11 VM, new installer SHA256, CLAUDE.md PLB-9 row update. None of that is "mechanical".
3. **Soft-delete test fixtures (21 callsites in one file) insert naive datetimes into `AgentDevice.deleted_at` / `first_seen` / `last_seen`**, all declared as `Column(DateTime)` (naive, no `timezone=True`). Switching fixtures to aware datetimes will surface naive-vs-aware comparison errors. Resolving correctly likely cascades into widening the model columns to `DateTime(timezone=True)` — a real Alembic migration, not a fixture tweak.
4. **Half-cleanup is worse than no-cleanup-yet** for codebase consistency: new code next week wouldn't know which pattern to follow.

The right move is one focused session per sub-task, not a rushed pass at the tail end of a long day.

---

## Scope (verified by grep, deduped)

| Area | Files | Callsites |
|---|---|---|
| `dashboard/backend/` (routes + models + tasks) | 41 | 102 |
| `dashboard/backend/app_cloud.py` | 1 | 1 |
| `tests/test_zzzzzzzzzzzzzzz_soft_delete.py` | 1 | 21 |
| **Agent (ships to customers)** | 3 | 6 |
| **TOTAL** | **46** | **130** |

`utcfromtimestamp`: **0 callsites** — nothing to do there.

### Agent files (DO NOT touch in sub-tasks (i) or (ii))

- `agent/aipet_agent.py` — 2 callsites (top-level source)
- `agent/packaging/deb/opt/aipet-agent/aipet_agent.py` — 2 callsites (`.deb` payload)
- `agent/packaging/windows/aipet_agent.py` — 2 callsites (Windows installer payload)

All 6 callsites are the same pattern: `now = datetime.utcnow().isoformat()` for telemetry timestamp strings. Migration itself is trivial; the rebuild + re-verify cost is what makes this its own sub-task.

### Top per-file counts (full list in grep below)

```
21  tests/test_zzzzzzzzzzzzzzz_soft_delete.py
 6  dashboard/backend/agent_monitor/routes.py
 5  dashboard/backend/tasks.py
 5  dashboard/backend/forensics/routes.py
 4  dashboard/backend/iam/models.py
 4  dashboard/backend/enterprise_reporting/routes.py
 4  dashboard/backend/digital_twin_v2/routes.py
 4  dashboard/backend/code_security/routes.py
 3  dashboard/backend/threat_intel_ingest/routes.py
 3  dashboard/backend/real_scanner/routes.py
 3  dashboard/backend/network_exposure/routes.py
 3  dashboard/backend/defense_mesh/routes.py
 3  dashboard/backend/calendar/routes.py
 2  (× 19 files at 2 calls each — see grep)
 1  (× 9 files at 1 call each — see grep)
```

### Reproduce the recon

```bash
grep -rln "datetime\.utcnow\b" --include="*.py" \
  --exclude-dir=venv --exclude-dir=node_modules --exclude-dir=.git \
  /home/byall/AIPET

grep -rc "datetime\.utcnow\b" --include="*.py" \
  --exclude-dir=venv --exclude-dir=node_modules --exclude-dir=.git \
  /home/byall/AIPET | grep -v ':0$' | sort -t: -k2 -nr
```

---

## Risk hits flagged for awareness (not exhaustive)

- `dashboard/backend/forensics/routes.py:137` — `utcnow() - timedelta(hours=...)`. Arith works on aware datetimes; output stays aware. Low risk on its own; downstream may compare to a DB field — verify column tz when sub-task (i) runs.
- `dashboard/backend/iam/models.py` and `dashboard/backend/live_cves/models.py` — `datetime.utcnow` used as a SQLAlchemy `default=` callable on `Column(DateTime)` (naive). Replacing with `lambda: datetime.now(timezone.utc)` writes aware datetimes into a naive column. SQLite silently strips tz; PostgreSQL raises (psycopg2). Decide: tag column with `timezone=True` (Alembic migration) **or** keep `default=` writing naive via `lambda: datetime.now(timezone.utc).replace(tzinfo=None)`. The first is cleaner; the second is the temporary-no-migration path.
- `tests/test_zzzzzzzzzzzzzzz_soft_delete.py` — 21 raw `datetime.datetime.utcnow()` insertions. The test predates the soft-delete v1 work and uses naive datetimes throughout. Sub-task (ii) will likely uncover whether the model columns need to be widened to `DateTime(timezone=True)` to match real-world UTC semantics.

---

## Three-sub-task split

### Sub-task (i) — backend src cleanup (estimated 60-90 min)

**Scope:** 103 callsites across 42 files (`dashboard/backend/**` + `app_cloud.py`).

**Deliverable:** Every `datetime.utcnow()` in those files becomes `datetime.now(timezone.utc)`. Adjust imports per existing file style. Single commit. Pytest must still pass.

**Known risk:** the SQLAlchemy `default=datetime.utcnow` callsites (`iam/models.py`, `live_cves/models.py`, possibly others) interact with naive `Column(DateTime)`. **Decision needed at the start of the session:** widen all such columns to `DateTime(timezone=True)` (more invasive, requires Alembic migration but matches PLB-1 standards) **or** wrap with `.replace(tzinfo=None)` (faster, preserves wire format). PLB-1 follow-up notes argue strongly for the first path going forward.

**Out of scope:** soft-delete test (sub-task ii), agent files (sub-task iii).

**Acceptance:**
- Zero `datetime.utcnow()` in `dashboard/backend/**` and `app_cloud.py`.
- `pytest` still 498 passing (or higher if soft-delete test cleanup is bundled).
- Zero `DeprecationWarning: ...utcnow()` from non-test source files in pytest output.
- App smoke: `python -c "from dashboard.backend.app_cloud import app; print('ok')"` returns ok.

### Sub-task (ii) — soft-delete test cleanup (estimated 30-60 min, depends on what (i) decided)

**Scope:** 21 callsites in `tests/test_zzzzzzzzzzzzzzz_soft_delete.py`, plus possibly:
- `dashboard/backend/agent_monitor/models.py` (`AgentDevice` columns) — widening `first_seen` / `last_seen` / `deleted_at` to `DateTime(timezone=True)` if (i) chose that path
- A new Alembic revision if columns are widened
- `dashboard/backend/agent_monitor/routes.py` (6 callsites — already covered by (i)) but verify the `soft_delete()` / `restore()` lifecycle methods still write the right shape

**Deliverable:** 21 callsites converted; test still passes; if columns widened, Alembic revision committed.

**Acceptance:**
- Zero `datetime.utcnow()` in `tests/`.
- `pytest tests/test_zzzzzzzzzzzzzzz_soft_delete.py -v` all passing.
- If migration: round-trip verified (`alembic upgrade head` → `downgrade base` → `upgrade head`).

### Sub-task (iii) — agent v1.2.1 release (estimated 2-4 hr including live re-verify)

**Scope:** 6 callsites across the 3 agent files. Bundle naturally with the next intentional agent release.

**Deliverable:**
- Version bumped 1.2.0 → 1.2.1 in:
  - `agent/aipet_agent.py` (`__version__` constant)
  - `agent/packaging/deb/DEBIAN/control` (`Version:` field)
  - `agent/packaging/windows/install_windows.bat` (display strings)
  - `agent/packaging/deb/usr/share/doc/aipet-agent/changelog.Debian` if it exists
- `.deb` rebuilt: `dpkg-deb --build agent/packaging/deb/ agent/packaging/aipet-agent_1.2.1_all.deb`
- Windows installer ZIP rebuilt
- New SHA256 for the Windows installer
- PLB-9-style live re-verify on the Win11 VM (full 19-item checklist OR a delta-only re-verify if scope is just the timestamp string change — operator's call)
- CLAUDE.md PLB-9 row updated with new SHA + re-verify date
- Capability 13 Day 3 row updated with new SHA

**Acceptance:**
- Zero `datetime.utcnow()` in `agent/**`.
- Linux .deb installs cleanly, telemetry flowing.
- Windows installer installs cleanly, telemetry flowing.
- New installer SHA256 documented.

**Risk:** the change itself is one-line per file, but the operator-time cost of the re-verify is real. Don't bundle (iii) into (i) or (ii); it gets its own session with the VM warmed up.

---

## Future-session pickup notes

- **Pre-flight check:** `git status` should be clean. The recon results in this file are still valid as long as no one touches `datetime.utcnow()` in the meantime; re-run the grep at the top of the session to confirm count.
- **Order:** start with sub-task (i). Sub-task (ii) depends on a decision made in (i). Sub-task (iii) is independent and can be done at any time — schedule it with the next agent feature/fix.
- **Commit style:** one commit per sub-task. Title prefix: `chore(datetime): ...`. Body should reference this recon file.
- **Don't bundle:** do not bundle (i) + (ii) + (iii) into one mega-PR. The agent rebuild is too high-risk to ship as part of a "mechanical chore".
