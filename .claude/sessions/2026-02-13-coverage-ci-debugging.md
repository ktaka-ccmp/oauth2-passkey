# Session Snapshot: Coverage CI Debugging

## Date: 2026-02-13

## Current Task

Debugging CI Code Coverage test failures that started on 2026-02-13 18:02 (PR #214 merge).

## What Was Done This Session

### 1. Admin Deletion Safeguard Issue Completed

- Issue `20260210-1930` closed and moved to `completed/`
- All implementation tasks were already done in prior sessions
- README.md updated

### 2. Mock Tracking Race Condition Fixed (Committed: c5bca99)

**Problem**: `test_promotion_includes_exclude_credentials` failed intermittently in CI coverage.

**Root Cause**: Two test files shared a global `MOCK_LIST_CREDENTIALS_CALLED: AtomicBool`:
- `oauth2_passkey_axum/src/passkey/promotion/tests.rs`
- `oauth2_passkey_axum/src/passkey/tests.rs`

Both ran in parallel. Under `cargo-llvm-cov` LLVM instrumentation, timing changes widened the race window, causing one test's `reset_mock_calls()` to clear the flag between another test's mock call and assertion.

**Fix**: Removed redundant `reset_mock_calls()`, `was_list_credentials_called()`, and the `AtomicBool` static from `test_utils.rs`. Tests still verify mock return values directly.

### 3. Integration Test Failures in Coverage CI (Partially Fixed)

**Problem**: 8 integration test failures in CI coverage output:
- 6 port contention failures (all bind to `127.0.0.1:3000`)
- 2 AAGUID fetch errors (`test_aaguid_fetching`, `test_aaguid_real_fetch`)

**Fix Applied**: Added `-- --test-threads=1` to `.github/workflows/coverage.yml` line 39:
```yaml
cargo llvm-cov --all-features --workspace --lcov --output-path lcov.info -- --test-threads=1
```

**Local Verification**: All 10 integration tests pass with `cargo test --all-features --test integration -- --test-threads=1`.

**Status**: Needs CI verification. The fix is committed but not yet pushed/tested in CI.

## Key Investigation Findings

### Why Failures Started on 2026-02-13 18:02

- PR #214 (commit `55df3e1`) was merged to master at that time
- Coverage CI triggers on `push to master` and `pull_request to master`
- The merged code contains `bundled-tls` feature and `get_client()` changes that only exist on dev branches (NOT on master before this merge)
- Coverage CI uses `--all-features`, which enables `bundled-tls` for the first time

### The `bundled-tls` Feature Chain

1. **Feature definition** in `oauth2_passkey/Cargo.toml`:
   ```toml
   [features]
   bundled-tls = ["dep:webpki-roots", "dep:rustls"]
   ```

2. **`get_client()` function** in `oauth2_passkey/src/utils.rs`:
   ```rust
   pub(crate) fn get_client() -> reqwest::Client {
       let builder = reqwest::Client::builder()
           .timeout(std::time::Duration::from_secs(30))
           .pool_idle_timeout(std::time::Duration::from_secs(90))
           .pool_max_idle_per_host(32);

       #[cfg(feature = "bundled-tls")]
       let builder = builder.use_preconfigured_tls(rustls_config_with_webpki_roots());

       builder.build().expect("Failed to create reqwest client")
   }
   ```

3. **AAGUID fetch** in `oauth2_passkey/src/passkey/main/aaguid.rs`:
   - Changed from `reqwest::get(AAGUID_URL)` to `crate::utils::get_client().get(AAGUID_URL).send()`

4. **CI test workflow** (`ci.yml`) does NOT use `--all-features` for `oauth2_passkey`, so `bundled-tls` is never enabled in regular CI tests.

### Potential TLS Issue (Not Yet Resolved)

- When `bundled-tls` is enabled, `get_client()` calls `use_preconfigured_tls(rustls_config_with_webpki_roots())`
- This configures rustls with webpki root certificates
- But reqwest also has its own default-tls feature enabled (via default features)
- There might be a conflict between reqwest's default TLS and the preconfigured rustls TLS
- Attempted fix: Adding `reqwest/rustls-tls-manual-roots` to bundled-tls feature -- FAILED because reqwest 0.13.2 doesn't have that feature name
- The AAGUID test failures may be caused by this TLS configuration conflict, or simply by parallel execution timing

### What Needs Investigation Next

1. **Verify `--test-threads=1` fix in CI**: Push the coverage.yml change and check if CI passes
2. **If AAGUID tests still fail**: The TLS configuration under `bundled-tls` + `--all-features` may need fixing:
   - Check reqwest 0.13.2 available features: `cargo metadata` or check Cargo.lock
   - Consider disabling reqwest's default-tls when bundled-tls is active
   - Or use reqwest's native rustls feature instead of `use_preconfigured_tls`
3. **Port contention**: Should be fully resolved by `--test-threads=1`

## Uncommitted Changes

| File | Change |
|------|--------|
| `.claude/issues/README.md` | Issue table updated (admin safeguard moved to completed) |
| `.claude/issues/open/20260210-1930-admin-deletion-safeguard.md` | Deleted (moved to completed/) |
| `.claude/issues/completed/20260210-1930-admin-deletion-safeguard.md` | New file (moved from open/) |
| `.github/workflows/coverage.yml` | Added `-- --test-threads=1` to coverage command |
| `.claude/sessions/2026-02-13-coverage-ci-debugging.md` | This snapshot |

## Related Files

- `.github/workflows/coverage.yml` - Coverage CI workflow
- `.github/workflows/ci.yml` - Main CI workflow (does NOT use --all-features for oauth2_passkey)
- `oauth2_passkey/Cargo.toml` - bundled-tls feature definition
- `oauth2_passkey/src/utils.rs` - `get_client()` with `use_preconfigured_tls`
- `oauth2_passkey/src/passkey/main/aaguid.rs` - AAGUID fetch using `get_client()`
- `oauth2_passkey_axum/src/test_utils.rs` - Mock infrastructure (already fixed)
- `oauth2_passkey_axum/src/passkey/promotion/tests.rs` - Already fixed
- `oauth2_passkey_axum/src/passkey/tests.rs` - Already fixed

## Branch

`dev-20260213-admin-safeguard`

## Recent Commits on This Branch

- `c5bca99` - test: remove race-prone mock call tracking from parallel passkey tests
- `dd4153c` - docs: add admin safeguard decision log and session snapshot for PC transfer
- (earlier commits for admin safeguard implementation)
