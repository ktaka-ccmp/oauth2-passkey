# Issue: Add Core Crate Functional-Layer Tests for _core() Functions

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

After moving all HTTP integration tests to the axum crate (issue `20260213-0145`), the core crate (`oauth2_passkey`) lacks functional-layer integration tests for its `_core()` functions. These functions are the public API contract between the core library and the axum integration layer.

### Current state

The core crate has two categories of tests:

1. **Unit tests in `src/`** (40+ files with `#[cfg(test)]`) - Test individual components: storage layer, type conversions, session management, crypto, etc. Well-covered.
2. **Integration tests** - All moved to `oauth2_passkey_axum/`. These test through the full HTTP stack (TestServer + MockBrowser) and don't call `_core()` functions directly.

**Gap**: No tests directly exercise the `_core()` coordination functions with real (in-memory) storage backends. Changes to core logic are only caught by the axum crate's HTTP-level tests.

### Test coverage inventory

| Module | Function | Unit Tests | Priority |
|--------|----------|:---:|----------|
| **oauth2** | `get_authorized_core` | **0** | Critical - OAuth2 authorization flow |
| | `post_authorized_core` | **0** | Critical - OAuth2 authorization flow (POST) |
| | `list_accounts_core` | 1 | OK |
| | `delete_oauth2_account_core` | 2 | OK |
| **passkey** | `handle_start_registration_core` | 4 | OK |
| | `handle_finish_registration_core` | 2 | OK |
| | `handle_start_authentication_core` | 4 | OK |
| | `handle_finish_authentication_core` | 1 | OK |
| | `list_credentials_core` | 2 | OK |
| | `delete_passkey_credential_core` | 1 | Partial (error case only) |
| | `update_passkey_credential_core` | 3 | OK |
| **admin** | 8 functions | 2-5 each | OK |
| **user** | 2 functions | 2-4 each | OK |
| **login_history** | 4 functions | **0** | Low - query/pagination |

**2 of 11 `_core()` functions have zero unit tests** (OAuth2 authorization flows, require mock provider). All 5 passkey `_core()` functions now have functional-layer tests.

## Related Issues

- `20260213-0145` Move All HTTP Integration Tests to Axum Crate (completed, triggered this gap)

## Approach

Add `_core()` function tests directly in the existing test files within the coordination module (`oauth2_passkey/src/coordination/*/tests.rs`). These tests call `_core()` functions with real in-memory storage backends (SQLite + memory cache) without any HTTP/Axum dependency.

### Scope

Focus on the 7 untested critical functions:

1. `get_authorized_core` / `post_authorized_core` - Need mock OAuth2 provider responses
2. `handle_start_registration_core` - Test registration modes (CreateUser, AddToUser)
3. `handle_finish_registration_core` - Need constructed WebAuthn responses
4. `handle_start_authentication_core` - Test username resolution
5. `handle_finish_authentication_core` - Need constructed authenticator responses
6. `list_credentials_core` - Basic listing

### Challenges

- OAuth2 `_core()` functions require an `AuthResponse` with a valid authorization code, which normally comes from the OAuth2 provider. Tests will need to mock the JWKS/token endpoint or construct valid test tokens.
- Passkey `_core()` functions require constructed WebAuthn `RegisterCredential` / `AuthenticatorResponse` objects with valid CBOR-encoded attestation/assertion data. The existing `fixtures.rs` (now in axum crate's tests/) has this logic but would need to be accessible or duplicated.
- These are the same challenges the existing HTTP integration tests solve via `axum_mock_server.rs` and `fixtures.rs`.

## Related Files

### Existing test files (add tests here)
- `oauth2_passkey/src/coordination/oauth2/tests.rs` - 8KB, has 4 tests
- `oauth2_passkey/src/coordination/passkey/tests.rs` - 10KB, has 4 tests

### Existing test utilities
- `oauth2_passkey/src/test_utils.rs` - DB/cache initialization helpers
- `oauth2_passkey_axum/tests/common/fixtures.rs` - WebAuthn fixture generation (in axum crate)
- `oauth2_passkey_axum/tests/common/axum_mock_server.rs` - Mock OAuth2 provider (in axum crate)

### Core functions to test
- `oauth2_passkey/src/coordination/oauth2.rs` - `get_authorized_core`, `post_authorized_core`
- `oauth2_passkey/src/coordination/passkey.rs` - 5 untested `_core()` functions

## Implementation Tasks

- [x] Investigate feasibility: can `_core()` functions be tested without HTTP mock server?
- [x] Add tests for `list_credentials_core` (2 tests: with credentials, empty)
- [x] Add tests for `handle_start_registration_core` (4 tests: CreateUser, AddToUser, auth rejection for each)
- [x] Add tests for `handle_start_authentication_core` (4 tests: no username, with username, nonexistent, string body)
- [x] Add tests for `handle_finish_registration_core` (2 tests: CreateUser, AddToUser end-to-end)
- [x] Add tests for `handle_finish_authentication_core` (1 test: full end-to-end with ECDSA signing)
- [x] Verify all passkey tests pass (13 new tests, total 522 pass, 0 failures)
- [ ] Add tests for `get_authorized_core` / `post_authorized_core` (deferred - requires mock OAuth2 provider)

## Decision Log

<!-- APPEND-ONLY: Do not edit or delete existing entries. Add new entries at the bottom. -->

### 2026-02-23: Issue created as follow-up from 20260213-0145

- Context: When evaluating approaches for the crate placement issue, approaches 2 (abstract assertions) and 3 (split by layer) were identified as valuable but high-effort improvements orthogonal to the placement fix.
- Decision: Track separately as low-priority/large-difficulty issue
- Reason: The assertion fragility only triggers when handler response formats change (infrequent). The crate placement fix (20260213-0145) is the immediate priority.

### 2026-02-23: Rescoped to core crate functional-layer tests only

- Context: Investigation revealed the original approach 2 (abstract HTTP status code assertions) has low cost-effectiveness: the problem occurred once, the fix was mechanical (14 enum value replacements), and loosening assertions risks masking real bugs. Approach 3 (core-layer tests) addresses the actual gap created by moving all integration tests to the axum crate.
- Decision: Drop approach 2 (status code abstraction), focus entirely on approach 3 (add `_core()` function tests to the core crate). Approach 2 can be tracked separately if needed in the future.
- Reason: The core crate now has zero integration-level tests for its most critical public API functions (OAuth2 authorization, passkey registration/authentication). This is a real coverage gap, not a theoretical fragility concern.

### 2026-02-23: Passkey _core() tests completed (13 new tests)

- Context: Implemented functional-layer tests for all 5 untested passkey `_core()` functions in `oauth2_passkey/src/coordination/passkey/tests.rs`. Tests use real in-memory storage (SQLite + memory cache) without any HTTP/Axum dependency.
- Tests added:
  - `list_credentials_core`: 2 tests (with credentials, empty list)
  - `handle_start_registration_core`: 4 tests (CreateUser mode, AddToUser mode, auth rejection for each)
  - `handle_start_authentication_core`: 4 tests (no username, with username, nonexistent username, string body format)
  - `handle_finish_registration_core`: 2 tests (CreateUser end-to-end, AddToUser end-to-end with "none" attestation)
  - `handle_finish_authentication_core`: 1 test (full end-to-end with ECDSA P-256 signing)
- WebAuthn fixture helpers added directly in tests.rs (not a shared module):
  - `FIRST_USER_PRIVATE_KEY` - Fixed ECDSA P-256 key pair matching `test_utils.rs` public key
  - `build_auth_data_for_registration()` - Binary auth_data with COSE key
  - `build_none_registration_response()` - "none" attestation format (no signature validation)
  - `build_signed_authentication_response()` - ECDSA-signed assertion with counter management
- Key technique: `pub(super)` fields accessed via serde serialization/deserialization
- Result: 522 tests pass (was 509), 0 warnings, clean clippy + fmt
- Remaining: `get_authorized_core` / `post_authorized_core` deferred (require mock OAuth2 provider with JWKS/token endpoints)

## Resolution
