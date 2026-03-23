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

1. Create a shared integration test suite that runs the same CRUD operations against all DB backends
2. Use Docker Compose service containers in GitHub Actions CI with a matrix strategy (`sqlite`, `postgres`, `mysql`, `mariadb`)
3. Existing `store_type` tests could serve as the basis -- they test init, CRUD, concurrent operations, and edge cases
4. Environment variables (`GENERIC_DATA_STORE_TYPE`, `GENERIC_DATA_STORE_URL`) select the backend at runtime

## Related Files

- `oauth2_passkey/src/userdb/storage/store_type/tests.rs`
- `oauth2_passkey/src/oauth2/storage/store_type/tests.rs`
- `oauth2_passkey/src/passkey/storage/store_type/tests.rs`
- `.github/workflows/` (CI configuration)
- `db/mysql/docker-compose.yaml`
- `db/postgresql/docker-compose.yaml`

## Implementation Tasks

- [ ] Design CI workflow with DB service containers (postgres, mysql, mariadb)
- [ ] Ensure existing store_type tests work with non-SQLite backends
- [ ] Add GitHub Actions matrix strategy for multi-DB testing
- [ ] Verify all 4 modules (userdb, oauth2, passkey, audit) pass on all backends

## Decision Log

### 2026-03-21: Issue created from PR #274 review

- Context: PR review for MySQL/MariaDB support noted that MySQL-specific code paths are only verified by manual Docker testing. The same gap exists for PostgreSQL.
- Decision: Create issue to track multi-DB integration testing as a CI improvement. Not blocking MySQL merge since the feature was manually tested with both MySQL 8.0 and MariaDB 11.
- Reason: Building the test infrastructure once covers all current and future DB backends. More cost-effective than per-DB test efforts.

## Resolution