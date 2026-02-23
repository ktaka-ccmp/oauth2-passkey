# Issue: Add Core Crate Functional-Layer Tests for _core() Functions

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)
- [Code Review](#code-review)
- [Code Review 2](#code-review-2)

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

### 2026-02-23: Second review - negative security tests added (2 tests)

- Context: Second review (`test_review2.md`) identified 3 additional findings. Finding 1 (medium-high): missing negative tests for security validation. Finding 2 (low): mock server lacks graceful shutdown. Finding 3 (low): fragile mock server readiness polling.
- Disposition: Finding 1 (passkey part) addressed with 2 new tests. Finding 1 (OAuth2 part), Finding 2, and Finding 3 accepted as-is.
- Tests added:
  - `test_finish_authentication_core_tampered_signature` - Flips a byte in the ECDSA signature's r-value, asserts `CoordinationError::PasskeyError(_)`
  - `test_finish_authentication_core_challenge_mismatch` - Signs with a fabricated challenge, asserts `CoordinationError::PasskeyError(_)`
- Rationale for OAuth2 negative tests (accepted as-is): JWT signature validation belongs at `idtoken.rs` unit-test level, not coordination layer. PKCE validation is OAuth2 provider's responsibility.
- Result: 529 tests pass (was 527), 0 failures, clean clippy + fmt

## Resolution

All critical `_core()` functions now have functional-layer tests in the core crate:
- **Passkey**: 15 new tests (5 functions) with ECDSA P-256 signing and CBOR attestation/assertion, including negative security tests
- **OAuth2**: 6 new tests (2 functions) with mock OAuth2 server (HS256 JWT, PKCE, nonce)
- Total: 21 new tests, 529 pass (was 509 at start), 0 failures
- Review 1 feedback: 6 of 9 findings addressed, 3 accepted as-is
- Review 2 feedback: 1 of 3 findings addressed (partial), 2 accepted as-is

---

## Code Review

### Scope

- `oauth2_passkey/src/coordination/oauth2/tests.rs` (921 lines, 10 tests)
- `oauth2_passkey/src/coordination/passkey/tests.rs` (1240 lines, 19 tests)

### What Works Well

- **Real cryptography**: End-to-end passkey tests use actual ECDSA P-256 signing with a fixed key pair that matches the stored credential, exercising real signature verification.
- **PKCE + nonce correlation**: The OAuth2 mock server validates S256 PKCE challenges and correlates nonces through the JWT, testing the full security chain.
- **Auth boundary testing**: Each `_core()` function is tested for both success and authorization-rejection paths (unauthorized user, missing session, wrong user, etc.).
- **Deliberate isolation**: Tests run against in-memory SQLite + memory cache with no HTTP/Axum dependency (except the mock OAuth2 server).

### Issues Found

#### 1. Mock server user state is not panic-safe

`oauth2/tests.rs:289-301` -- Tests call `mock.configure_user(...)` at the start and `mock.reset_to_first_user()` at the end. If a test panics between these calls, subsequent `#[serial]` tests inherit the wrong user identity. This should use an RAII guard (reset on `Drop`) instead of manual cleanup at the end of each test.

#### 2. `set_mock_env_vars()` permanently overrides env vars, no restoration

`oauth2/tests.rs:492-508` -- This writes to `/tmp/oauth2_passkey_core_mock_env` and calls `dotenvy::from_filename_override`, which permanently overrides `OAUTH2_TOKEN_URL`, `OAUTH2_JWKS_URL`, `OAUTH2_USERINFO_URL`, `OAUTH2_EXPECTED_ISSUER` for the entire process. There is no restoration to the `.env_test` values. If any test running later in the binary happens to trigger OIDC discovery or token exchange, it would hit the mock server (port 19876) instead of the intended target (port 9876 from `.env_test`).

This is safe **today** because all such tests are `#[serial]` and self-contained, but it is a latent fragility if new tests are added that depend on the original env values.

#### 3. `test_get_authorized_core_add_to_user` duplicates `drive_oauth2_flow`

`oauth2/tests.rs:808-920` -- This test manually replicates ~60 lines of the same HTTP flow that `drive_oauth2_flow()` implements, because the helper does not accept optional session headers. A parameterized `drive_oauth2_flow_with_session(mode, session_headers)` would eliminate this duplication.

#### 4. Redundant test: `test_get_passkey_field_mappings_logic`

`passkey/tests.rs:988-1004` -- This test is nearly identical to `test_get_passkey_field_mappings_defaults` (lines 963-976). Both call `get_passkey_field_mappings()` and assert `account_field == "name"` and `label_field == "display_name"`. The "logic" test adds two `!is_empty()` assertions that are strictly weaker than the equality assertions already present. Zero additional coverage.

#### 5. Weak assertions in start_registration and start_authentication tests

Several tests only verify `result.is_ok()` without checking the response content:

- `passkey/tests.rs:556-572` `test_start_registration_core_create_user_mode` -- Does not verify the returned `RegistrationOptions` contains a challenge, user handle, or RP info.
- `passkey/tests.rs:617-646` `test_start_registration_core_add_to_user_mode` -- Same.
- `passkey/tests.rs:682-761` All 4 `start_authentication_core` tests -- Only check `is_ok()`, do not inspect `AuthenticationOptions` at all.

Contrast with the end-to-end tests (e.g., `test_finish_authentication_core_success`) which properly verify `user_handle`, `credential_ids`, and headers. The start-* tests are essentially smoke tests that only prove the function does not error -- they would not catch regressions in the response structure.

#### 6. `insert_test_passkey_credential` stores inconsistent rp_id

`passkey/tests.rs:280` -- Sets `rp_id: "localhost"`, but the test origin is `http://127.0.0.1:3000` (from `.env_test`), so the RP ID should be `127.0.0.1`. This does not affect list/update/delete tests (they do not validate RP ID), but it is a correctness gap -- if any future test tries to use these credentials for authentication, it would fail for the wrong reason.

#### 7. Duplicated `create_test_user_in_db` helper

Both `oauth2/tests.rs:78-90` and `passkey/tests.rs:247-259` have nearly identical `create_test_user_in_db()` helpers. Since these are in separate `tests` modules that cannot share code (sibling modules under `coordination`), this is somewhat unavoidable, but worth noting as maintenance surface area.

#### 8. ~500 lines of fixture infrastructure duplicated from axum crate

The WebAuthn helpers (~250 lines) and mock OAuth2 server (~250 lines) substantially duplicate code from `oauth2_passkey_axum/tests/common/`. This was a deliberate design decision (the core crate cannot depend on axum test code), and the issue documents this trade-off. However, any changes to WebAuthn response format or JWT validation need to be made in both places independently.

#### 9. `insert_test_passkey_credential` uses fake public key

`passkey/tests.rs:278` -- `public_key: "test_public_key"` -- This is not a valid base64url-encoded EC key. For list/update/delete tests this is fine, but it silently creates credentials that cannot be used for authentication. A comment should clarify this is intentional, or the helper should use the real public key from `test_utils::generate_first_user_public_key()`.

### Summary

| Category | Finding | Severity |
|----------|---------|----------|
| Correctness | Mock server state not panic-safe | Medium |
| Correctness | Env vars permanently overridden, no restore | Low (latent) |
| Coverage | Start-* tests have weak assertions (is_ok only) | Medium |
| Redundancy | `test_get_passkey_field_mappings_logic` is duplicate | Low |
| Maintenance | `add_to_user` test duplicates `drive_oauth2_flow` | Low |
| Maintenance | ~500 lines duplicated from axum test infra | Accepted trade-off |
| Consistency | `rp_id: "localhost"` vs actual `127.0.0.1` | Low |
| Consistency | `public_key: "test_public_key"` is not a real key | Low |

The test code achieves its stated goal (functional-layer coverage for `_core()` functions) with real crypto and proper authorization boundary testing. The main areas for improvement are the weak assertions on start-* tests and the fragile mock server state management.

---

### Author Response

#### Overall Assessment

The review is thorough and fair. All findings are real. Below is the disposition for each.

#### Findings to Address

| # | Finding | Disposition | Action |
|---|---------|-------------|--------|
| **1** | Mock server state not panic-safe | **Agree.** Add RAII guard that calls `reset_to_first_user()` on `Drop`. ~10 lines. | Fix |
| **3** | `add_to_user` test duplicates `drive_oauth2_flow` | **Agree.** Add optional `extra_request_headers` parameter to `drive_oauth2_flow`. Eliminates ~50 lines of duplication. | Fix |
| **4** | Redundant `test_get_passkey_field_mappings_logic` | **Agree.** The `!is_empty()` assertions are strictly weaker than the equality checks in `_defaults`. Delete the test. | Fix |
| **5** | Weak assertions in start-* tests | **Agree. Most important finding.** These tests only prove the function doesn't error, not that the response is correct. Will add assertions for: challenge presence/non-empty, user handle, RP ID, credential IDs (for authentication). | Fix |
| **6** | `rp_id: "localhost"` inconsistent with origin | **Agree.** Change to `"127.0.0.1"` to match `.env_test` origin `http://127.0.0.1:3000`. | Fix |
| **9** | `public_key: "test_public_key"` is fake | **Agree.** Use `generate_first_user_public_key()` from `test_utils` for the first user's credential. Add comment for other test credentials explaining the fake key is intentional (those tests only exercise list/update/delete paths). | Fix |

#### Findings Accepted As-Is (No Action)

| # | Finding | Rationale |
|---|---------|-----------|
| **2** | Env vars permanently overridden | The reviewer correctly notes this is safe today. Restoration is impractical: `dotenvy` has no "undo" mechanism, and key config values like `OAUTH2_RESPONSE_MODE` are `LazyLock` (evaluated once, immutable). The mock server runs for the process lifetime on a distinct port (19876 vs 9876), so the override is harmless. A comment noting this design constraint is sufficient. |
| **7** | Duplicated `create_test_user_in_db` | Unavoidable. These are `mod tests` submodules under sibling directories (`coordination/oauth2/tests.rs` and `coordination/passkey/tests.rs`). Rust's module system provides no mechanism to share code between them without promoting the helper to a crate-level `test_utils` module, which would be over-engineering for a 12-line function. The reviewer acknowledges this. |
| **8** | ~500 lines duplicated from axum crate | Deliberate design decision, documented in the issue. The core crate (`oauth2_passkey`) cannot depend on axum crate test code. The two implementations serve different purposes: core tests use minimal mock infrastructure (HS256, "none" attestation), while axum tests use a full-featured mock (RS256, packed attestation). Changes to WebAuthn/JWT formats are infrequent and affect both layers simultaneously, making independent maintenance acceptable. |

#### Fix Results

All 6 addressed findings have been implemented and verified (527 tests pass, 0 failures, clean clippy + fmt).

| # | Finding | Change |
|---|---------|--------|
| **1** | Mock server state not panic-safe | Added `MockUserGuard` struct with `Drop` impl that calls `reset_to_first_user()`. Added `configure_user_guarded()` method. 4 tests migrated from manual `configure_user` + `reset_to_first_user` to RAII guard via `_guard` binding. |
| **3** | `add_to_user` duplicates flow | Added `extra_request_headers: Option<&http::HeaderMap>` parameter to `drive_oauth2_flow()`. `add_to_user` test now passes session cookie through the helper instead of duplicating ~50 lines. All other call sites pass `None`. |
| **4** | Redundant test | Deleted `test_get_passkey_field_mappings_logic` (27 lines). |
| **5** | Weak start-* assertions | Added response structure assertions to 6 tests: `challenge` (non-empty), `rpId` (== `"127.0.0.1"`), `user.user_handle` (present), `user.name`, `user.displayName`, `rp.id`, `pubKeyCredParams`, `authId`, `allowCredentials` (empty for discoverable flow, contains expected credential for username flow, empty for nonexistent username). |
| **6** | `rp_id: "localhost"` | Changed to `"127.0.0.1"` to match `.env_test` origin `http://127.0.0.1:3000`. |
| **9** | Fake public key | Added doc comment to `insert_test_passkey_credential` explaining the placeholder key is intentional for list/update/delete tests that never verify signatures. |

---

### Reviewer Re-Review

#### Verification Method

Re-read both updated test files in full and verified each fix against the original finding.

#### Fix Verification

| # | Finding | Verdict | Notes |
|---|---------|---------|-------|
| **1** | Mock server state not panic-safe | **Resolved.** | `MockUserGuard` with `Drop` impl (lines 311-321). `configure_user_guarded()` returns the guard (lines 303-308). All 4 tests that configure non-default users now use `let _guard = mock.configure_user_guarded(...)` instead of manual `configure_user` + `reset_to_first_user`. The `_guard` binding keeps the guard alive for the test scope and resets on drop, including on panic. Clean implementation. |
| **3** | `add_to_user` duplicates flow | **Resolved.** | `drive_oauth2_flow` now takes `extra_request_headers: Option<&http::HeaderMap>` (line 538). The `add_to_user` test (lines 831-892) builds session headers and passes them via `drive_oauth2_flow("add_to_user", Some(&session_request_headers))` (line 865). Previous ~60 lines of duplicated mock-auth-endpoint logic eliminated. All other call sites pass `None`. |
| **4** | Redundant test | **Resolved.** | `test_get_passkey_field_mappings_logic` deleted. File now ends at line 1122 with only `test_get_passkey_field_mappings_defaults` remaining. |
| **5** | Weak start-* assertions | **Resolved.** | All 6 start-* tests now verify response structure beyond `is_ok()`. Specific checks added: |
|   |   |   | - `test_start_registration_core_create_user_mode` (lines 576-609): challenge non-empty, `rpId == "127.0.0.1"`, `rp.id == "127.0.0.1"`, `user.user_handle` present, `user.name` matches request, `user.displayName` matches request, `pubKeyCredParams` is array. Most thorough of the group -- good choice for the most detailed assertions. |
|   |   |   | - `test_start_registration_core_add_to_user_mode` (lines 685-699): challenge, rpId, user_handle. Appropriately lighter since the response structure is the same as CreateUser mode. |
|   |   |   | - `test_start_authentication_core_no_username` (lines 748-769): challenge, rpId, authId, `allowCredentials` empty or absent (discoverable flow). |
|   |   |   | - `test_start_authentication_core_with_username` (lines 798-826): challenge, rpId, authId, `allowCredentials` non-empty and contains `"cred_auth_start_1"`. This is the strongest authentication start test -- verifies the credential lookup actually works. |
|   |   |   | - `test_start_authentication_core_nonexistent_username` (lines 849-867): challenge, rpId, `allowCredentials` empty. Good contrast with the with_username test. |
|   |   |   | - `test_start_authentication_core_string_body` (lines 889-903): challenge, rpId, authId. |
| **6** | `rp_id: "localhost"` | **Resolved.** | Changed to `"127.0.0.1"` at line 285. Consistent with `.env_test` origin `http://127.0.0.1:3000`. |
| **9** | Fake public key | **Resolved.** | Doc comment added at lines 261-265 explaining the placeholder key is intentional. Clear guidance to use `FIRST_USER_PRIVATE_KEY` / `generate_first_user_public_key()` for authentication tests. |

#### Accepted As-Is Dispositions

All 3 "no action" decisions are reasonable:

- **#2** (env var override): The `LazyLock` constraint and `#![forbid(unsafe_code)]` make restoration impractical. Agreed.
- **#7** (duplicated helper): 12-line function across sibling test modules. Promoting to `test_utils` would be over-engineering. Agreed.
- **#8** (fixture duplication): Deliberate architecture boundary. The author's point about different purposes (HS256/"none" vs RS256/"packed") strengthens the case. Agreed.

#### New Observations

One minor observation from the re-review:

- **`test_get_authorized_core_login_existing_user`** (oauth2/tests.rs:662-688) still uses `mock.reset_to_first_user()` directly (line 666) instead of `configure_user_guarded`. This is correct -- the test uses the default first-user identity and doesn't need a guard since there's no configure-to-different-user call. No action needed, just noting for clarity.

#### Conclusion

All 6 fixes are correctly implemented. The assertions added for finding #5 are well-calibrated -- the CreateUser registration test has the most detailed assertions (7 checks), which is appropriate since it validates the full response structure, while other tests appropriately focus on the fields most relevant to their specific scenario (e.g., `allowCredentials` content for authentication tests). The RAII guard for finding #1 is clean and idiomatic Rust.

**Status: Approved.** No remaining issues.

---

## Code Review 2

### Overview

Based on the review of the newly added functional tests in `oauth2/tests.rs` and `passkey/tests.rs` and the previous feedback in `test_review.md`, I confirm that the 6 accepted findings (such as introducing `MockUserGuard` for panic-safety and strengthening assertions in `start-*` tests) have been correctly implemented. I also agree with the reasoning for keeping the 3 unaddressed points as acceptable trade-offs for integration-level testing boundaries.

However, there are a few additional areas for improvement, primarily concerning security validation testing and the robustness of the mock server.

### New Findings

#### 1. Missing Negative Tests for Security Validation (Important)

**Severity: Medium-High**

**Finding:**
The current functional tests provide excellent coverage of the "happy paths" (successful authentication/registration) and session-state assertions (e.g., trying to add to a user without an active session). However, they lack "negative paths" that specifically test the core cryptographic and security validations by intentionally providing malformed or invalid data.

**Specific Gaps:**
*   **Passkey Authentication (`handle_finish_authentication_core`):**
    There is no test verifying that the core correctly rejects an authentication attempt with an invalid signature or an mismatched challenge. Since the test infrastructure (`build_signed_authentication_response`) already exists, it is highly recommended to add tests that intentionally send a structurally valid assertion, but with a tampered signature or an incorrect challenge, and assert that it correctly results in an `Unauthorized` or `InvalidSignature` error. This guarantees the signature validation logic is actually protecting the application.
*   **OAuth2 Flow:**
    Similarly, the mock server always returns a valid, signed JWT and valid token responses. There are no tests to ensure the core correctly rejects tampering, such as:
    *   An invalid or expired JWT signature (from the JWKS endpoint).
    *   An incorrect PKCE code challenge.

#### 2. Mock Server Lacks Graceful Shutdown

**Severity: Low**

**Finding:**
In `oauth2/tests.rs`, the mock server (`MOCK_SERVER`) is spawned inside a `LazyLock` block and runs indefinitely on a detached tokio background thread until the test process exits. While this is generally acceptable for a test binary and causes no immediate harm, a cleaner approach would be to wire up `axum::serve::with_graceful_shutdown` and trigger it when the tests finish (or via a custom drop guard for the server itself), ensuring local TCP ports and resources are gracefully released.

#### 3. Fragile Mock Server Readiness Polling

**Severity: Low**

**Finding:**
The initialization logic for `MOCK_SERVER` waits for the mock server to bind and become ready by polling `std::net::TcpStream::connect` in a loop with `std::thread::sleep` (100ms intervals, up to 50 times). While functional, timeout-based polling can occasionally lead to flaky tests in heavily loaded CI environments.
A more robust approach would be to use a `tokio::sync::oneshot` channel to signal exactly when the axum server has successfully bound to the port, eliminating the need for arbitrary sleep intervals and reducing test flakiness risk.

### Summary

The tests are well-structured and provide solid coverage of the core coordination layer. The most pressing recommendation is to **add negative tests for cryptographic operations (Finding 1)** to guarantee the security boundary of the `_core` functions. The other two findings (shutdown and polling) are minor robustness improvements for the test infrastructure.

---

### Author Response

#### Overall Assessment

The review correctly identifies security validation testing as the most important gap. The passkey-side negative tests are well-scoped and actionable. The OAuth2-side suggestions and infrastructure improvements are reasonable but warrant further discussion on where these responsibilities belong.

#### Findings to Address

| # | Finding | Scope | Disposition | Action |
|---|---------|-------|-------------|--------|
| **1** (partial) | Missing negative tests for passkey authentication | Passkey | **Agree.** The existing `build_signed_authentication_response` infrastructure already supports signing with arbitrary keys and challenges, making negative tests low-cost to add. | Add 2-3 tests: (a) tampered signature rejection, (b) challenge mismatch rejection. |

#### Findings Accepted As-Is (No Action)

| # | Finding | Rationale |
|---|---------|-----------|
| **1** (OAuth2 part) | Missing negative tests for JWT signature / PKCE | **Partially disagree on scope.** JWT signature validation is performed in `oauth2/main/idtoken.rs` (`decode_and_validate_id_token`), which is a lower-level module. Negative tests for invalid/expired JWT signatures belong at that unit-test level, not the coordination layer. The coordination tests should verify end-to-end flow correctness, not re-test cryptographic primitives already covered (or coverable) by unit tests. PKCE code challenge validation is the OAuth2 provider's responsibility -- the core library *sends* the correct `code_verifier`, but the *provider* validates it. Testing PKCE rejection would require making the mock server reject valid PKCE, which tests the mock, not the core. |
| **2** | Mock server lacks graceful shutdown | **Accept as-is.** The mock server uses `LazyLock` with process-lifetime management, which is the standard pattern for test infrastructure. The OS reclaims all resources (TCP ports, threads) when the test process exits. Adding `with_graceful_shutdown` and a drop guard would add complexity (~20 lines) for no practical benefit -- the server is only used by `#[serial]` tests within a single binary, and no port conflicts can occur. |
| **3** | Fragile mock server readiness polling | **Accept as-is.** The TCP polling approach (100ms x 50 = 5s timeout) has been reliable in practice and matches the pattern used in the axum crate's test infrastructure. While a `tokio::sync::oneshot` channel would be marginally more elegant, it requires restructuring the server startup to expose the channel across the `LazyLock` + `std::thread::spawn` boundary. This is a minor improvement that does not justify dedicated effort at this time. |

#### Fix Results

The addressed finding has been implemented and verified (529 tests pass, 0 failures, clean clippy + fmt).

| # | Finding | Change |
|---|---------|--------|
| **1** (passkey) | Missing negative tests for security validation | Added 2 tests to `passkey/tests.rs`: (a) `test_finish_authentication_core_tampered_signature` -- builds a valid signed response, then flips a byte in the ECDSA signature's r-value before submitting; asserts `CoordinationError::PasskeyError(_)`. (b) `test_finish_authentication_core_challenge_mismatch` -- builds a signed response using a fabricated challenge instead of the server-issued one; asserts `CoordinationError::PasskeyError(_)`. Both tests reuse the existing `build_signed_authentication_response` infrastructure with minimal additional code (~60 lines each). |
