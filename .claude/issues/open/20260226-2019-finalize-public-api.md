# Issue: Finalize Public API for 1.0 Release

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260226-2019

## Created: 2026-02-26

## Closed:

## Status: open

## Priority: high

## Difficulty: large

## Description

Review and document all public interfaces across both crates (`oauth2-passkey` and `oauth2-passkey-axum`) to prepare for a 1.0 stable release. A 1.0 release signals API stability, so all public types, functions, and traits must be carefully evaluated for correctness, consistency, and long-term maintainability.

### Areas to Review

- Public function signatures and return types
- Public struct/enum definitions and their fields
- Re-export structure (`pub use` in `lib.rs` / `mod.rs`)
- Feature flag boundaries
- Error types and error handling patterns
- Configuration (environment variables, defaults)
- Naming conventions and consistency

## Related Issues

- `20260226-2018` Simplify OAuth2 Account Linking API (should be resolved before 1.0)

## Approach

1. Audit all `pub` items in both crates
2. Identify items that should be made more restrictive (`pub(crate)`, `pub(super)`)
3. Ensure consistent naming and patterns
4. Document all public APIs
5. Write migration guide from 0.x to 1.0

## Related Files

- `oauth2_passkey/src/lib.rs`
- `oauth2_passkey_axum/src/lib.rs`
- All `mod.rs` files with re-exports

## Implementation Tasks

- [ ] Audit public API surface of `oauth2-passkey`
- [ ] Audit public API surface of `oauth2-passkey-axum`
- [ ] Identify breaking changes needed
- [ ] Apply visibility restrictions where appropriate
- [ ] Ensure documentation coverage for all public items
- [ ] Write 0.x to 1.0 migration guide
- [ ] Update CHANGELOG with breaking changes

## Decision Log

### 2026-02-26: Migrated from ToDo.md

- Context: Migrating incomplete tasks from ToDo.md to issue tracking system
- Decision: Create as high-priority, large-difficulty issue
- Reason: 1.0 release is a major milestone requiring thorough API review

## Resolution

