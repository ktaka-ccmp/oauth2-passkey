# Issue: Security Integration Tests Depend on Axum Handler Behavior

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260213-0145

## Created: 2026-02-13-01-45

## Closed:

## Status: open

## Priority: low

## Difficulty: medium

## Description

The security integration tests (`tests-security/`) live under the `oauth2_passkey` core library crate, but they test HTTP-level behavior (status codes, redirects) that is determined by the `oauth2_passkey_axum` handler layer.

This coupling was exposed when changing OAuth2 callback error handling from returning `400 Bad Request` to `303 See Other` (redirect to popup_close). The change was purely in `oauth2_passkey_axum/src/oauth2.rs`, yet it required updating 14 test assertions in `oauth2_passkey/tests-security/` (`oauth2_security.rs` and `cross_flow_security.rs`).

This violates the architectural boundary between the core library and the framework integration layer. Changes to handler-level behavior in the `_axum` crate should not require changes to tests in the core crate.

## Related Issues

- `2026-02-09-02` Improve OAuth2 Popup Error Handling UX (triggered discovery)
- `20260223-0027` Abstract Security Test Assertions (follow-up for approaches 2+3)

## Approach

**Move tests to `oauth2_passkey_axum`** (approach 1). The security integration tests use a `TestServer` that starts the full Axum stack and assert HTTP-level behavior (status codes, redirects), so they belong in the Axum crate.

The migration is clean:
- Only `common/mod.rs` needs path updates (6 `#[path = "..."]` references)
- All other test files (8 test modules + 2 utility files + README) are copied as-is
- Shared test utilities stay in `oauth2_passkey/tests/common/` and are referenced via `#[path]` (existing pattern)
- `test_server.rs` already depends on `oauth2_passkey_axum::oauth2_passkey_router()`

Approaches 2 (abstract assertions) and 3 (split by layer) are tracked separately in `20260223-0027`.

## Related Files

- `oauth2_passkey/tests-security/` - Source (all files to move)
- `oauth2_passkey/tests-security/common/mod.rs` - 6 `#[path]` references to update
- `oauth2_passkey/tests/common/` - Shared test utilities (stay here, referenced via `#[path]`)
- `oauth2_passkey/Cargo.toml` - Remove `[[test]]` section for "security"
- `oauth2_passkey_axum/Cargo.toml` - Add `[[test]]` section + dev-dependencies
- `oauth2_passkey_axum/tests-security/` - Destination

## Implementation Tasks

- [ ] Copy `oauth2_passkey/tests-security/` to `oauth2_passkey_axum/tests-security/`
- [ ] Update 6 `#[path]` references in `common/mod.rs`
- [ ] Add `[[test]]` section and dev-dependencies to `oauth2_passkey_axum/Cargo.toml`
- [ ] Remove `[[test]]` section from `oauth2_passkey/Cargo.toml`
- [ ] Verify security tests pass from new location
- [ ] Verify positive integration tests still pass
- [ ] Delete `oauth2_passkey/tests-security/` directory
- [ ] Run fmt, clippy, full test suite

## Decision Log

<!-- APPEND-ONLY: Do not edit or delete existing entries. Add new entries at the bottom. -->

### 2026-02-13: Issue identified during OAuth2 popup error handling work

- Context: Changed `get_authorized`/`post_authorized` handlers to redirect errors to `popup_close` instead of returning HTTP error responses. This broke 14 security test assertions in the core crate.
- Decision: Record as a separate architectural issue rather than fixing inline
- Reason: The test placement concern is orthogonal to the popup UX improvement

### 2026-02-23: Chose approach 1 (move tests to axum crate)

- Context: Evaluated 3 approaches. Approach 1 (move) fixes the crate placement with minimal effort. Approaches 2 (abstract assertions) and 3 (split by layer) address test fragility but require 3,600+ lines of rewrite.
- Decision: Proceed with approach 1 only. Track approaches 2+3 as separate issue `20260223-0027`.
- Reason: Approach 1 resolves the architectural boundary violation (the original complaint). The assertion fragility is a separate concern with lower priority — it only triggers when handler response formats change, which is infrequent.

## Resolution
