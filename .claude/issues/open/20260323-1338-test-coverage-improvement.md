# Issue: Test Coverage Improvement for Non-DB Code Paths

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260323-1338

## Created: 2026-03-23

## Closed:

## Status: open

## Priority: low

## Difficulty: medium

## Description

Overall test coverage is 83.71% (lines). MySQL/PostgreSQL storage code (0%) is addressed by issue `20260321-1245` (multi-DB integration tests). This issue tracks the remaining low-coverage areas that are **not** related to DB backend switching.

### Current low-coverage areas (excluding mysql.rs/postgres.rs)

| File | Line Coverage | Gap |
|------|-------------|-----|
| `storage/schema_validation.rs` | 23.53% | Error paths in schema validation (column mismatch, missing columns) not tested |
| `oauth2/main/fedcm.rs` | 0.00% | FedCM flow requires external IdP interaction; needs mock |
| `session/main/session.rs` | ~55% | Redis cache paths untested (tests use in-memory cache only) |
| `userdb/mod.rs` | 0.00% | Small init function, dispatches to storage |
| `oauth2/main/core.rs` | ~65% | Some OAuth2 flow branches not exercised |

### Expected improvement

Addressing these areas would bring overall coverage from ~84% to ~90%+ (combined with multi-DB tests from issue `20260321-1245`).

## Related Issues

- `20260321-1245` Multi-Database Integration Tests (open) -- covers mysql.rs/postgres.rs 0% coverage
- `20260226-2025` E2E Tests (open) -- covers browser-level UI testing (separate concern)

## Approach

### 1. schema_validation.rs (~30 min)

Add unit tests for error cases: missing columns, wrong column types, extra columns. These are pure validation functions with no external dependencies.

### 2. session Redis paths (~1-2 hours)

Either:
- Use Docker Redis in tests (similar to multi-DB approach)
- Or mock the cache store trait

Lower priority since Redis paths mirror the in-memory implementation.

### 3. fedcm.rs (~2-3 hours)

Requires mock IdP server (similar to existing mock OIDC provider in axum integration tests). Medium effort, low risk since FedCM is experimental.

## Related Files

- `oauth2_passkey/src/storage/schema_validation.rs`
- `oauth2_passkey/src/oauth2/main/fedcm.rs`
- `oauth2_passkey/src/session/main/session.rs`
- `oauth2_passkey/src/oauth2/main/core.rs`

## Implementation Tasks

- [ ] Add schema_validation.rs error path tests
- [ ] Add session Redis path tests (Docker or mock)
- [ ] Add FedCM mock tests
- [ ] Verify coverage improvement

## Decision Log

### 2026-03-23: Issue created from coverage analysis

- Context: Codecov reports on PR #286/288 showed 46% patch coverage. Analysis revealed 83.71% overall, with mysql/postgres 0% (separate issue) and several non-DB areas with low coverage.
- Decision: Create single issue for remaining coverage gaps, separate from multi-DB testing and E2E testing.
- Reason: These are incremental improvements with diminishing returns. Low priority but worth tracking. schema_validation is the quickest win.

## Resolution