# Issue: Abstract Security Test Assertions from HTTP Status Codes

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260223-0027

## Created: 2026-02-23-00-27

## Closed:

## Status: open

## Priority: low

## Difficulty: large

## Description

Security integration tests assert specific HTTP status codes (e.g., `400 Bad Request`, `303 See Other`) rather than higher-level security properties (e.g., "no session created", "authentication not established"). This makes the tests fragile: when handler response formats change, many test assertions break even though security behavior is unchanged.

This was exposed when changing OAuth2 callback error handling from `400 Bad Request` to `303 See Other` (redirect to popup_close), which required updating 14 test assertions despite no change in security properties.

Two complementary improvements are possible:

1. **Abstract test assertions** - Test security properties ("no session created", "proper error response") instead of specific HTTP status codes. The existing `SecurityTestResult` struct already checks `no_session_created` and `proper_error_response`, but `assert_security_failure()` still requires matching a specific `ExpectedSecurityError` variant (which maps to HTTP status codes).

2. **Split tests by layer** - Core library tests verify `_core()` function error returns (unit-level). Axum tests verify HTTP-level behavior (integration-level). Each crate tests its own contract. This requires writing new core-level tests from scratch.

## Related Issues

- `20260213-0145` Security Integration Tests Depend on Axum Handler Behavior (parent issue, handles crate placement)
- `2026-02-09-02` Improve OAuth2 Popup Error Handling UX (triggered original discovery)

## Approach

(to be decided when prioritized)

## Related Files

- `oauth2_passkey_axum/tests-security/common/security_utils.rs` - `ExpectedSecurityError` enum and `assert_security_failure()`
- `oauth2_passkey_axum/tests-security/` - All security test files that assert HTTP status codes

## Implementation Tasks

- [ ] Decide on approach (abstract only, split only, or both)
- [ ] Implement chosen approach
- [ ] Verify all tests still pass

## Decision Log

<!-- APPEND-ONLY: Do not edit or delete existing entries. Add new entries at the bottom. -->

### 2026-02-23: Issue created as follow-up from 20260213-0145

- Context: When evaluating approaches for the crate placement issue, approaches 2 (abstract assertions) and 3 (split by layer) were identified as valuable but high-effort improvements orthogonal to the placement fix.
- Decision: Track separately as low-priority/large-difficulty issue
- Reason: The assertion fragility only triggers when handler response formats change (infrequent). The crate placement fix (20260213-0145) is the immediate priority.

## Resolution
