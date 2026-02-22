# Issue: Move All HTTP Integration Tests to Axum Crate

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

## Closed: 2026-02-23-01-34

## Status: completed

## Priority: low

## Difficulty: medium

## Description

All HTTP integration tests (`tests/` and `tests-security/`) live under the `oauth2_passkey` core library crate, but they test HTTP-level behavior through a full Axum HTTP stack. This creates a reverse dependency: the core crate depends on `oauth2-passkey-axum` as a dev-dependency.

### Investigation findings (2026-02-23)

**Every test in `oauth2_passkey/tests/` is an HTTP-level test:**
- All use `TestServer` (Axum HTTP server) + `MockBrowser` (reqwest HTTP client)
- `test_server.rs` calls `oauth2_passkey_axum::oauth2_passkey_router()` directly
- No test calls core library `_core()` functions directly (except a few admin functions that use HTTP-obtained session IDs)
- `oauth2-passkey-axum` is listed as a dev-dependency of the core crate

**The core crate already has proper unit tests** in `oauth2_passkey/src/` (40+ files with `#[cfg(test)]`):
- Business logic, cryptographic verification, session management, storage layer, type conversions
- These are pure unit tests with zero dependency on `oauth2_passkey_axum`

### Original trigger

This was exposed when changing OAuth2 callback error handling from `400 Bad Request` to `303 See Other`. The change was purely in `oauth2_passkey_axum/src/oauth2.rs`, yet it required updating 14 test assertions in `oauth2_passkey/tests-security/`.

## Related Issues

- `2026-02-09-02` Improve OAuth2 Popup Error Handling UX (triggered discovery)
- `20260223-0027` Abstract Security Test Assertions (follow-up for approaches 2+3)

## Approach

Move **all** HTTP integration tests to `oauth2_passkey_axum`:

| Source | Destination | Content |
|--------|-------------|---------|
| `oauth2_passkey/tests-security/` | `oauth2_passkey_axum/tests-security/` | Security tests (~3,600 lines) |
| `oauth2_passkey/tests/integration*` | `oauth2_passkey_axum/tests/integration*` | Positive tests (~2,100 lines) |
| `oauth2_passkey/tests/common/` | `oauth2_passkey_axum/tests/common/` | Shared utilities (~1,000+ lines) |

After moving:
- No cross-crate `#[path]` references needed (all tests and utilities in same crate)
- Security tests' `common/mod.rs` changes from `#[path]` imports to `mod common;` or local paths
- Remove `oauth2-passkey-axum`, `axum`, `reqwest` etc. from core crate's dev-dependencies
- Core crate retains only dev-dependencies needed by its unit tests (in `src/`)

Approaches 2 (abstract assertions) and 3 (split by layer) are tracked separately in `20260223-0027`.

## Related Files

### Source (all move from `oauth2_passkey/`)
- `tests/integration.rs` - Test harness
- `tests/integration/` - 4 test modules (oauth2, passkey, combined, api_client flows)
- `tests/common/` - 10 utility files (mock_browser, test_server, fixtures, etc.)
- `tests-security/` - Security test harness + 6 test modules + 2 utility files + README

### Destination (`oauth2_passkey_axum/`)
- `tests/integration.rs` - Test harness
- `tests/integration/` - Positive test modules
- `tests/common/` - Shared utilities (replaces existing minimal `tests/common/`)
- `tests-security/` - Security tests

### Config changes
- `oauth2_passkey/Cargo.toml` - Remove `[[test]]` section, remove HTTP-related dev-dependencies
- `oauth2_passkey_axum/Cargo.toml` - Add `[[test]]` sections + dev-dependencies

## Implementation Tasks

- [x] Move `tests/common/` to `oauth2_passkey_axum/tests/common/`
- [x] Move `tests/integration.rs` and `tests/integration/` to `oauth2_passkey_axum/tests/`
- [x] Move `tests-security/` to `oauth2_passkey_axum/tests-security/`
- [x] Update `tests-security/common/mod.rs`: `#[path]` unchanged (relative structure preserved)
- [x] Update `oauth2_passkey_axum/Cargo.toml`: add `[[test]]` section + 12 dev-dependencies
- [x] Update `oauth2_passkey/Cargo.toml`: remove `[[test]]` section + 7 dev-dependencies
- [x] Verify all tests pass from new location
- [x] Delete original test directories from `oauth2_passkey/`
- [x] Run fmt, clippy, full test suite

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

### 2026-02-23: Expanded scope to include all HTTP integration tests

- Context: Investigation revealed that `oauth2_passkey/tests/` (positive integration tests) have the same problem as security tests — they all use TestServer (Axum HTTP stack) + MockBrowser (reqwest). No test calls core `_core()` functions directly. The core crate has `oauth2-passkey-axum` as a dev-dependency solely for these tests.
- Decision: Move ALL HTTP integration tests (`tests/`, `tests-security/`, `tests/common/`) to `oauth2_passkey_axum`. This eliminates the reverse dev-dependency and removes the need for cross-crate `#[path]` references.
- Reason: Moving only security tests would leave the same architectural violation in the positive tests, and require ugly cross-crate `#[path]` references for shared utilities. Moving everything is cleaner and more thorough.

### 2026-02-23: Implementation findings

- Context: During implementation, two deviations from the plan were discovered.
- Decision 1: `tests-security/common/mod.rs` `#[path]` references did NOT need updating. The relative path `../../tests/common/X.rs` resolves identically in both crates because the directory structure (`tests-security/common/` -> `tests/common/`) is preserved.
- Decision 2: The axum crate needed fewer dev-dependencies than planned. `serial_test`, `proptest` are unused by HTTP tests (only by unit tests in `src/`). `axum`, `chrono`, `serde_json` are already regular dependencies of the axum crate and thus available to tests. Additional crates discovered as needed: `ciborium`, `ring`, `jsonwebtoken`, `sha2`, `uuid`, `url` (used by test fixtures and mock servers).

## Detailed Implementation Plan

### Step 1: Move common test utilities

Move `oauth2_passkey/tests/common/` to `oauth2_passkey_axum/tests/common/`.

This replaces the existing minimal `oauth2_passkey_axum/tests/common/` (currently only `mod.rs` with `TestClient`).

Files to move (all as-is, no modifications):
- `mock_browser.rs`, `test_server.rs`, `fixtures.rs`, `webauthn_helpers.rs`
- `test_setup.rs`, `axum_mock_server.rs`, `secure_auth.rs`
- `session_utils.rs`, `validation_utils.rs`, `constants.rs`
- `mod.rs` (replaces existing)

### Step 2: Move positive integration tests

Move `oauth2_passkey/tests/integration.rs` and `oauth2_passkey/tests/integration/` to `oauth2_passkey_axum/tests/`.

Files to move (all as-is, no modifications):
- `integration.rs`
- `integration/mod.rs`
- `integration/oauth2_flows.rs`
- `integration/passkey_flows.rs`
- `integration/combined_flows.rs`
- `integration/api_client_flows.rs`

### Step 3: Move security tests

Move `oauth2_passkey/tests-security/` to `oauth2_passkey_axum/tests-security/`.

Files to move:
- All files as-is EXCEPT `common/mod.rs`
- `common/mod.rs` needs update: change `#[path]` imports to local relative paths

```rust
// Before: cross-directory #[path] references
#[path = "../../tests/common/mock_browser.rs"]
pub mod mock_browser;

// After: local relative paths (common/ is now a sibling)
#[path = "../tests/common/mock_browser.rs"]
pub mod mock_browser;
```

Affected: `mock_browser`, `test_server`, `fixtures`, `webauthn_helpers`, `test_setup`, `axum_mock_server`

### Step 4: Update `oauth2_passkey_axum/Cargo.toml`

Add test sections and dev-dependencies:

```toml
[[test]]
name = "security"
path = "tests-security/lib.rs"

[dev-dependencies]
dotenvy = { workspace = true }
tokio = { workspace = true }
serial_test = { workspace = true }
proptest = { workspace = true }
axum = { workspace = true }
reqwest = { workspace = true }
base64 = { workspace = true }
chrono = { workspace = true }
tracing-subscriber = { workspace = true }
regex = { workspace = true }
```

### Step 5: Clean up `oauth2_passkey/Cargo.toml`

Remove:
- `[[test]]` section for "security"
- Dev-dependencies only needed by integration tests: `axum`, `reqwest`, `regex`, `oauth2-passkey-axum`
- Keep dev-dependencies needed by unit tests in `src/`: `serial_test`, `proptest`, `base64`, `chrono`, `tracing-subscriber`

### Step 6: Verify

```bash
# Integration tests from new location
cargo test --manifest-path oauth2_passkey_axum/Cargo.toml --test integration

# Security tests from new location
cargo test --manifest-path oauth2_passkey_axum/Cargo.toml --test security

# Core unit tests still pass
cargo test --manifest-path oauth2_passkey/Cargo.toml

# Quality checks
cargo fmt --all
cargo clippy --all-targets --all-features
```

### Step 7: Delete originals

Remove from `oauth2_passkey/`:
- `tests/` directory (entire — unit tests are in `src/`, not here)
- `tests-security/` directory

### Key notes

- `.env_test` is at workspace root. `test_server.rs` loads it via `dotenvy::from_filename(".env_test")` from CWD. No change needed.
- `test_server.rs` already uses `oauth2_passkey_axum::oauth2_passkey_router()` — now a same-crate reference.
- Security tests' `#[path]` imports become `../tests/common/` instead of cross-crate paths.
- `crate::common::*` references in integration tests continue to work (same module structure).
- Before deleting dev-deps from core Cargo.toml, verify which are actually used by unit tests in `src/`.

## Resolution

Moved all HTTP integration tests from `oauth2_passkey/` to `oauth2_passkey_axum/`:

- **27 test files** moved: 10 common utilities, 6 integration tests, 11 security tests
- **Cargo.toml**: Core crate's dev-dependencies reduced from 9 to 2 (`serial_test`, `proptest`). Reverse dependency on `oauth2-passkey-axum` eliminated. Axum crate gained 12 dev-dependencies and `[[test]]` section.
- **No code changes** to test files themselves (all paths and imports work as-is)
- **Verification**: 629 tests pass (509 unit + 10 integration + 21 security + 56 lib + 33 doc), zero clippy warnings
