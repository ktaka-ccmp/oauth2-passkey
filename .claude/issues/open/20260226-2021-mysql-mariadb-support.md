# Issue: MySQL/MariaDB Database Support

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260226-2021

## Created: 2026-02-26

## Closed:

## Status: open

## Priority: medium

## Difficulty: medium

## Description

Add MySQL and MariaDB support to expand deployment options. Currently the library supports SQLite and PostgreSQL via sqlx. Adding MySQL/MariaDB would cover the majority of relational database deployments.

### Current Storage Architecture

The storage layer uses a trait-based abstraction (`DataStore`) with implementations for SQLite and PostgreSQL. The same pattern can be extended for MySQL/MariaDB.

### Considerations

- sqlx supports MySQL natively, so the infrastructure is already in place
- SQL dialect differences (e.g., `TEXT` vs `VARCHAR`, auto-increment syntax, boolean handling)
- Migration strategy for MySQL-specific schema
- Testing infrastructure (need MySQL test container or in-memory alternative)

## Related Issues

None

## Approach

1. Add `mysql` feature flag to sqlx dependency
2. Implement `DataStore` trait for MySQL/MariaDB
3. Handle SQL dialect differences in queries
4. Add MySQL-specific migrations
5. Add to CI testing matrix

## Related Files

- `oauth2_passkey/src/storage/` - Storage abstraction layer
- `oauth2_passkey/src/storage/data_store/` - DataStore implementations
- `oauth2_passkey/Cargo.toml` - Feature flags

## Implementation Tasks

- [ ] Add `mysql` feature flag to sqlx dependencies
- [ ] Implement MySQL DataStore
- [ ] Create MySQL-specific schema migrations
- [ ] Handle SQL dialect differences
- [ ] Add MySQL to CI testing
- [ ] Update documentation with MySQL configuration
- [ ] Test with MariaDB compatibility

## Decision Log

### 2026-02-26: Migrated from ToDo.md

- Context: Migrating incomplete tasks from ToDo.md to issue tracking system
- Decision: Create as medium-priority, medium-difficulty issue
- Reason: Expands deployment options; sqlx already supports MySQL so infrastructure cost is moderate

## Resolution
