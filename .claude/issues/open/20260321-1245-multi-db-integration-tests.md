# Issue: Multi-Database Integration Tests

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260321-1245

## Created: 2026-03-21-12-45

## Closed:

## Status: open

## Priority: medium

## Difficulty: medium

## Description

All storage layer tests currently run via in-memory SQLite only. Database-specific code paths (SQL dialect differences, UPSERT syntax, schema validation, type mapping) for PostgreSQL and MySQL/MariaDB are only verified by manual Docker testing. This leaves DB-specific bugs (like the `LAST_INSERT_ID()` race condition found during MySQL PR review) undetected until manual testing.

A CI matrix running the same test suite against all supported backends (SQLite, PostgreSQL, MySQL, MariaDB) would catch dialect-specific issues automatically.

### What's currently untested by automation

- PostgreSQL: `RETURNING *`, `$1/$2` parameter binding, `BIGSERIAL`, `TIMESTAMPTZ`, `JSONB`, `ON CONFLICT ... DO UPDATE SET ... EXCLUDED.col`
- MySQL: `ON DUPLICATE KEY UPDATE ... AS new`, `LAST_INSERT_ID()`, `AUTO_INCREMENT`, `DATETIME(6)`, `CAST` in INFORMATION_SCHEMA queries
- MariaDB: JSON -> LONGTEXT compatibility, `mysql_types_compatible()` validation

## Related Issues

- `20260226-2021` MySQL/MariaDB Database Support (completed) -- PR review identified need for integration tests
- `20260321-1234` SQLite last_insert_rowid() Race Condition (open) -- found via same PR review
- `20260226-2025` E2E Tests (open) -- broader testing initiative

## Approach

### Phase 1: Local `cargo test` with Docker (no CI cost)

Make existing `store_type` tests runnable against any backend locally:

1. Fix `dotenvy::from_filename_override` -> `from_filename` in `test_utils.rs` so env vars take precedence over `.env_test`
2. Verify existing tests pass with PostgreSQL/MySQL/MariaDB via Docker:
   ```bash
   docker compose -f db/postgresql/docker-compose.yaml up -d
   GENERIC_DATA_STORE_TYPE=postgres \
   GENERIC_DATA_STORE_URL=postgres://demo:demo@localhost/demo \
   cargo test --manifest-path oauth2_passkey/Cargo.toml
   ```
3. Fix any DB-specific test failures (SQLite-specific PRAGMA queries, SQL dialect issues, etc.)
4. Add a `utils/test_all_backends.sh` convenience script

### Phase 2: CI integration (develop branch only)

Add GitHub Actions workflow for multi-DB testing, triggered only on push to `develop`:

- Service containers (postgres, mysql, mariadb) with matrix strategy
- **Not on PRs** -- PR CI stays SQLite-only for fast feedback
- Cost estimate: +12 min billable/run (4 min x 3 backends), ~2 hours/month at 20 merges
- Wall-clock impact: 0 (parallel jobs)
- Free tier (2000 min/month) is sufficient

### Key findings

- `.env_test` uses `dotenvy::from_filename_override` which **overrides** env vars -- must change to `from_filename` (fallback) for env var switching to work
- `test_utils.rs` has SQLite-specific code (`extract_sqlite_file_path`, DB file cleanup) that needs guards for non-SQLite backends
- Existing `store_type` tests are backend-agnostic (use Store trait dispatch) -- should work with minimal changes

## Related Files

- `oauth2_passkey/src/test_utils.rs` (init_test_environment, dotenvy loading)
- `oauth2_passkey/src/userdb/storage/store_type/tests.rs`
- `oauth2_passkey/src/oauth2/storage/store_type/tests.rs`
- `oauth2_passkey/src/passkey/storage/store_type/tests.rs`
- `oauth2_passkey/src/audit/storage/store_type/tests.rs`
- `.env_test`
- `db/mysql/docker-compose.yaml`
- `db/postgresql/docker-compose.yaml`

## Implementation Tasks

### Phase 1
- [ ] Change `from_filename_override` to `from_filename` in test_utils.rs
- [ ] Guard SQLite-specific test setup code for non-SQLite backends
- [ ] Test with PostgreSQL via Docker
- [ ] Test with MySQL via Docker
- [ ] Test with MariaDB via Docker
- [ ] Fix any backend-specific test failures
- [ ] Add `utils/test_all_backends.sh` script

### Phase 2 (develop branch only, low cost)
- [ ] Create `ci-integration.yml` with `on: push: branches: [develop]`
- [ ] Add service containers + matrix strategy (postgres, mysql, mariadb)
- [ ] Verify all backends pass in CI

## Decision Log

### 2026-03-21: Issue created from PR #274 review

- Context: PR review for MySQL/MariaDB support noted that MySQL-specific code paths are only verified by manual Docker testing. The same gap exists for PostgreSQL.
- Decision: Create issue to track multi-DB integration testing as a CI improvement. Not blocking MySQL merge since the feature was manually tested with both MySQL 8.0 and MariaDB 11.
- Reason: Building the test infrastructure once covers all current and future DB backends. More cost-effective than per-DB test efforts.

### 2026-03-23: Revised approach -- local first, CI deferred

- Context: CI matrix with 4 DB backends adds significant GitHub Actions billable minutes. Phase 1 of the approach should be local `cargo test` + Docker, with no CI cost.
- Decision: Phase 1 focuses on making `cargo test` work with any backend via env vars + Docker. Phase 2 (CI integration) deferred until Phase 1 proves insufficient.
- Reason: Most value comes from being able to run tests locally against real databases. CI can be added later if needed. Key blocker: `dotenvy::from_filename_override` in test_utils.rs must be changed to `from_filename` so env vars can override `.env_test` defaults.

### 2026-03-23: CI scope -- develop branch only

- Context: CI cost concern. Each DB backend adds ~4 min billable per run. Running on every PR doubles cost unnecessarily.
- Decision: Phase 2 CI runs only on push to `develop`, not on PRs. PRs stay SQLite-only for fast feedback.
- Reason: Multi-DB bugs are caught when merged to develop, before reaching master. Estimated ~2 hours/month billable, well within Free tier (2000 min).

## Resolution