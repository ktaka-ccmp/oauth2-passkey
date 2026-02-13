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

## Approach

Possible approaches (to be decided):

1. **Move tests to `oauth2_passkey_axum`** - The security integration tests use a `TestServer` that starts the full Axum stack, so they belong in the Axum crate. This is the most straightforward fix.

2. **Abstract test assertions** - Instead of asserting specific HTTP status codes (400 vs 303), test higher-level security properties: "no session created", "authentication not established". This reduces coupling regardless of where tests live.

3. **Split tests by layer** - Core library tests verify `_core()` function error returns (unit-level). Axum tests verify HTTP-level behavior (integration-level). Each crate tests its own contract.

## Related Files

- `oauth2_passkey/tests-security/` - All security integration test files
- `oauth2_passkey/tests-security/common/security_utils.rs` - `ExpectedSecurityError` enum tied to HTTP status codes
- `oauth2_passkey/tests-security/oauth2_security.rs` - OAuth2 callback security tests
- `oauth2_passkey/tests-security/cross_flow_security.rs` - Cross-flow security tests
- `oauth2_passkey_axum/src/oauth2.rs` - Axum handlers that determine HTTP response behavior

## Implementation Tasks

- [ ] Decide on approach (move, abstract, or split)
- [ ] Implement chosen approach
- [ ] Verify all tests still pass
- [ ] Update test documentation if needed

## Decision Log

<!-- APPEND-ONLY: Do not edit or delete existing entries. Add new entries at the bottom. -->

### 2026-02-13: Issue identified during OAuth2 popup error handling work

- Context: Changed `get_authorized`/`post_authorized` handlers to redirect errors to `popup_close` instead of returning HTTP error responses. This broke 14 security test assertions in the core crate.
- Decision: Record as a separate architectural issue rather than fixing inline
- Reason: The test placement concern is orthogonal to the popup UX improvement

## Resolution

