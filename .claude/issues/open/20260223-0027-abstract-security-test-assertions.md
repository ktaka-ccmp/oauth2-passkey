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
| **oauth2** | `get_authorized_core` | 4 | OK |
| | `post_authorized_core` | 1 | OK |
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

**All 11 critical `_core()` functions now have functional-layer tests.** OAuth2 authorization flows tested via mock server (HS256 JWT, PKCE, nonce correlation). Passkey flows tested via constructed WebAuthn responses (ECDSA P-256, CBOR attestation/assertion).

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
- [x] Create minimal mock OAuth2 server in core crate tests (~250 lines)
- [x] Add `drive_oauth2_flow()` test helper (~75 lines)
- [x] Add test: `get_authorized_core` login with existing account
- [x] Add test: `get_authorized_core` create new user
- [x] Add test: `get_authorized_core` login with nonexistent account (error)
- [x] Add test: `get_authorized_core` create_user_or_login mode
- [x] Add test: `post_authorized_core` wrong response mode (error)
- [x] Add test: `get_authorized_core` add_to_user with existing session
- [x] Verify all tests pass (6 new tests, total 528 pass, 0 failures)

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

### 2026-02-23: OAuth2 _core() test implementation plan

- Context: `get_authorized_core` and `post_authorized_core` internally make 3 HTTP calls (token exchange, JWKS fetch, userinfo fetch), unlike passkey functions which use local crypto only. Testing requires a mock HTTP server.
- Decision: Create a minimal mock OAuth2 server (~180 lines) directly in `coordination/oauth2/tests.rs`, add `axum` as dev-dependency, use port 19876 (distinct from axum crate's mock on 9876).
- Approach:
  - Mock server: 4 endpoints (auth, token, JWKS, userinfo), HS256 JWT signing, shared state for nonce correlation
  - Env var overrides (`OAUTH2_TOKEN_URL`, `OAUTH2_JWKS_URL`, `OAUTH2_USERINFO_URL`, `OAUTH2_EXPECTED_ISSUER`) bypass OIDC discovery entirely
  - Test flow: `prepare_oauth2_auth_request()` -> mock auth redirect -> extract code -> `get_authorized_core()`
  - 6 tests: login existing user, create new user, login nonexistent (error), create_user_or_login mode, wrong response mode (error), add_to_user with session
- Constraint: `OAUTH2_RESPONSE_MODE` is `LazyLock` set to `"query"` from `.env_test`, so POST success tests are only possible in axum integration tests
- Estimated: ~440 lines total (mock ~180, helpers ~60, tests ~200)
- Full plan: `.claude/plans/rippling-wishing-feigenbaum.md`

### 2026-02-23: OAuth2 _core() tests completed (6 new tests)

- Context: Implemented functional-layer tests for `get_authorized_core` and `post_authorized_core` in `oauth2_passkey/src/coordination/oauth2/tests.rs`. Tests use a minimal mock OAuth2 server (HS256 JWT, PKCE S256, nonce correlation) running on port 19876.
- Infrastructure added (~250 lines):
  - `MockServerState` + `MockServerHandle` with `LazyLock` lifecycle and TCP readiness polling
  - 4 mock handlers: auth (302 redirect), token (PKCE validation + JWT), JWKS (HS256 key), userinfo
  - `create_mock_jwt()` - HS256 JWT with all IdInfo fields
  - `set_mock_env_vars()` - Uses `dotenvy::from_filename_override` (avoids `#![forbid(unsafe_code)]` constraint on `std::env::set_var`)
  - `drive_oauth2_flow()` - Full flow driver: `prepare_oauth2_auth_request` -> mock auth -> extract code -> build `AuthResponse`
- Tests added (6):
  - `test_post_authorized_core_wrong_response_mode` - POST with query mode returns InvalidResponseMode
  - `test_get_authorized_core_login_existing_user` - Login with pre-existing first user succeeds
  - `test_get_authorized_core_login_nonexistent_account` - Login with unknown account returns Conflict
  - `test_get_authorized_core_create_new_user` - Creates user and OAuth2 account in DB
  - `test_get_authorized_core_create_user_or_login` - Creates when new, logs in when existing
  - `test_get_authorized_core_add_to_user` - Links new OAuth2 account to existing session user
- Key discoveries:
  - `From<IdInfo> for OAuth2Account` adds `"google_"` prefix to `sub` -> mock sub values must NOT include prefix
  - `dotenvy::from_filename_override` is a safe alternative to `std::env::set_var` (unsafe in Rust 2024 edition)
- Result: 528 tests pass (was 522), 0 warnings, clean clippy + fmt
- All implementation tasks complete. Issue ready to close.

### 2026-02-23: Review feedback addressed (6 fixes)

- Context: External review identified 9 findings (see `test_review.md`). 6 accepted for fix, 3 accepted as-is.
- Fixes applied:
  - #1: Added `MockUserGuard` RAII struct with `Drop` impl for panic-safe mock server state cleanup
  - #3: Added `extra_request_headers` parameter to `drive_oauth2_flow()`, eliminated ~50 lines of duplication in `add_to_user` test
  - #4: Deleted redundant `test_get_passkey_field_mappings_logic` (27 lines)
  - #5: Added response structure assertions to 6 start-* tests (challenge, rpId, user_handle, allowCredentials, authId, pubKeyCredParams)
  - #6: Changed `rp_id: "localhost"` to `"127.0.0.1"` to match `.env_test` origin
  - #9: Added doc comment to `insert_test_passkey_credential` explaining placeholder public key is intentional
- Accepted as-is: #2 (env var override impractical to restore), #7 (helper duplication unavoidable), #8 (fixture duplication deliberate)
- Result: 527 tests pass (was 528, minus 1 deleted redundant test), 0 failures, clean clippy + fmt

## Resolution

All critical `_core()` functions now have functional-layer tests in the core crate:
- **Passkey**: 13 new tests (5 functions) with ECDSA P-256 signing and CBOR attestation/assertion
- **OAuth2**: 6 new tests (2 functions) with mock OAuth2 server (HS256 JWT, PKCE, nonce)
- Total: 19 new tests, 527 pass (was 509 at start), 0 failures
- Review feedback: 6 of 9 findings addressed, 3 accepted as-is
