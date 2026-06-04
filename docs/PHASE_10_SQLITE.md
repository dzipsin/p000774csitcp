# Phase 10 — SQLite persistence

The previous backend wrote one JSON file per incident into `reports/`.
That worked but lost most history value on every restart and didn't
support cross-run queries cheaply. Phase 10 replaced it with a SQLite
database (`data/reports.db`) using a hybrid schema — indexed columns
for the fields commonly filtered or sorted on, plus a `full_report_json`
blob containing the entire template-v1 payload.

The JSON backend was retained as an ablation switch for a while but
later retired once the migration settled. SQLite is now the only
storage layer; there is no `[storage].backend` knob.

## What changed

| Concern | Before (JSON) | After (SQLite) |
|---|---|---|
| Storage location | `reports/inc_<id>.json` | `data/reports.db` (WAL + SHM sidecars) |
| Reads on dashboard load | Glob + parse N JSON files | Indexed SELECT, sorted by `generated_at DESC` |
| Cross-run history | Lost on restart (in-memory cache only) | Persistent across restarts |
| Filter by source IP / attack type / severity | Linear scan in Python | Indexed SQL query |
| Aggregate stats | Not implemented | `aggregate_stats(since_epoch)` |
| Retention | Manual delete | Background sweeper, configurable |
| Concurrency | File locks per save | WAL — many readers, one writer at a time |
| Migration | n/a | None — fresh database on first run |

## Schema

Two tables, both bootstrapped idempotently:

```sql
CREATE TABLE incidents (
    incident_id        TEXT PRIMARY KEY,
    source_ip          TEXT NOT NULL,
    status             TEXT NOT NULL,
    overall_severity   TEXT NOT NULL,
    overall_cvss       REAL NOT NULL,
    repeat_offender    INTEGER NOT NULL,
    total_alerts       INTEGER NOT NULL,
    detected_attacks   TEXT NOT NULL,             -- JSON array
    generated_at       TEXT NOT NULL,             -- ISO-8601 UTC
    last_updated_at    TEXT NOT NULL,
    first_seen         TEXT,
    last_seen          TEXT,
    report_version     TEXT,
    classification_counts TEXT NOT NULL,          -- JSON object
    model_used         TEXT,
    provider_type      TEXT,
    generation_status  TEXT,
    full_report_json   TEXT NOT NULL              -- entire template_v1
);

CREATE TABLE alerts (
    alert_id        TEXT NOT NULL,
    incident_id     TEXT NOT NULL,
    src_ip          TEXT,
    signature       TEXT,
    signature_id    INTEGER,
    timestamp       TEXT,
    attack_type     TEXT,
    classification  TEXT,
    severity        TEXT,
    PRIMARY KEY (alert_id, incident_id),
    FOREIGN KEY (incident_id) REFERENCES incidents(incident_id) ON DELETE CASCADE
);
```

Indices on `source_ip`, `status`, `generated_at DESC`, `overall_severity`,
`repeat_offender`; on alerts also `src_ip`, `attack_type`, `signature_id`.

The `alerts` table is denormalised from the report so historical
"all alerts from IP X across all sessions" queries don't need to parse
the JSON blob for every report.

## Configuration

```toml
[storage]
db_path                  = "data/reports.db"
retention_days           = 90                # 0 = never expire
cleanup_interval_seconds = 3600              # 0 = no automatic cleanup
```

`db_path` is resolved relative to the repo root (parent of `src/`)
unless absolute. The `data/` directory is created if missing.

`data/` is in `.gitignore` — the database is local-machine state, not
project artefact.

## API additions

Five new endpoints, all backed by ReportDatabase query methods. The
`_require_query_backend` guard checks `hasattr` on the storage object
before each call, so swapping in a stand-in storage that doesn't
implement one of the methods degrades to `503` rather than crashing.

| Method | Path | Returns |
|---|---|---|
| `GET` | `/api/incidents/by-ip/<source_ip>?hours=N` | All incidents from a source IP, optionally bounded to last N hours |
| `GET` | `/api/incidents/by-attack/<attack_type>?hours=N` | All incidents whose `detected_attacks` array contains attack_type |
| `GET` | `/api/incidents/by-severity/<severity>` | Filter by `overall_severity` (critical / high / low) |
| `GET` | `/api/incidents/stats?hours=N` | Counts by status / severity / attack type plus repeat_offenders |
| `POST` | `/api/incidents/cleanup` | Manually trigger retention sweep, returns `{dropped: N}` |

Existing endpoints unchanged:

| Method | Path | Returns |
|---|---|---|
| `GET` | `/api/incidents` | Newest-first list, full payloads |
| `GET` | `/api/incidents/<incident_id>` | One incident, full payload |
| `POST` | `/api/incidents/regenerate` | Force regen all in-memory + recently-closed |
| `POST` | `/api/incidents/clear` | Clear cache + delete from storage |

The evaluation harness reads `/api/incidents` and is unaffected.

## Concurrency model

- Each Python thread that touches the database gets its own
  `sqlite3.Connection` cached via `threading.local`. SQLite connections
  are not safe to share across threads in the default threadsafety mode.
- WAL journal mode (`PRAGMA journal_mode=WAL`) allows concurrent readers
  even while a writer is committing. The dashboard's `GET /api/incidents`
  reads don't block while a worker is saving a regenerated report.
- `synchronous=NORMAL` — durable enough for the demo workload, flushes
  after each commit but skips the full disk sync on each write.
- All writes wrapped in explicit `BEGIN ... COMMIT` / `ROLLBACK` so
  the alerts-table rewrite (delete + reinsert per incident) is atomic.
- `foreign_keys=ON` so deleting an incident cascades to its alerts row.

## Retention sweeper

When `retention_days > 0` and `cleanup_interval_seconds > 0`, a daemon
thread runs `cleanup_expired()` on a tick. First pass happens
immediately at startup so already-expired rows are gone before the
dashboard renders. Loop wakes via `Event.wait()` so shutdown joins
cleanly within ~2 seconds.

Set `retention_days = 0` to keep everything forever. Set
`cleanup_interval_seconds = 0` to disable the automatic sweeper but
keep `cleanup_expired()` callable via `POST /api/incidents/cleanup`.

## Migration from the JSON backend

**None.** Per the locked decision in `docs/HANDOFF.md`, this is a fresh
start. Existing `reports/inc_*.json` files are not imported. Operator
can delete them manually if they want to declutter the repo:

```powershell
Remove-Item reports\*.json
```

The `reports/` directory is still gitignored, so deleting locally has
no effect on the repository.

## Operational notes

- **Backup the database** before any destructive operation. The whole
  history is in one file:
  ```bash
  cp data/reports.db data/reports.db.bak.$(date +%s)
  ```
  Doing this while the app is running is safe under WAL — the
  consistent on-disk state is captured.
- **Inspect from the shell** with `sqlite3`:
  ```bash
  sqlite3 data/reports.db
  .schema incidents
  SELECT incident_id, source_ip, overall_severity, generated_at
    FROM incidents
   ORDER BY generated_at DESC
   LIMIT 10;
  ```
- **Reset the database** while the app is stopped:
  ```bash
  rm data/reports.db data/reports.db-wal data/reports.db-shm
  ```
  Next run bootstraps a fresh schema.

## What this does NOT change

- Report content / template_v1 schema — unchanged.
- Dashboard rendering — reads the same JSON shape from `/api/incidents`.
- ReportGenerator — saves to `storage` the same way as before; only the
  concrete storage class changed.
- Evaluation harness — reads `/api/incidents`, format identical.
- Existing test suites — all green against ReportDatabase.
