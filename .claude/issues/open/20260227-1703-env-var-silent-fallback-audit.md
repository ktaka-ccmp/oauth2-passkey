# Issue: Audit and Improve Silent Fallback Behavior for Optional Environment Variables

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260227-1703

## Created: 2026-02-27

## Closed:

## Status: open

## Priority: low

## Difficulty: small

## Description

Optional environment variables that use `.unwrap_or()` or `.ok().and_then()` silently fall back to defaults when set to unparseable values. This hides configuration mistakes from operators.

### The Problem

Consider `SESSION_COOKIE_MAX_AGE` in `session/config.rs`:

```rust
pub static SESSION_COOKIE_MAX_AGE: LazyLock<u64> = LazyLock::new(|| {
    std::env::var("SESSION_COOKIE_MAX_AGE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(600)
});
```

If an operator sets `SESSION_COOKIE_MAX_AGE=ten_minutes`, the parse silently fails and falls back to `600`. The operator believes their configuration is active, but the library is using the default. This is different from leaving the variable unset, where the default is intentional.

### Scope

This issue covers all optional `LazyLock` variables that accept user-provided values but silently ignore invalid ones. Variables that use `.expect()` (required vars) or have no parse step (simple string defaults) are not affected.

### Known Affected Variables

From a codebase audit:

| Variable | Location | Silent Fallback |
|----------|----------|-----------------|
| `SESSION_COOKIE_MAX_AGE` | `session/config.rs` | Invalid u64 parse -> 600 |
| `AUTH_SERVER_SECRET` | `session/config.rs` | Missing -> hardcoded default (security concern) |
| `O2P_*_PREFIX` variables | various `config.rs` | Missing -> hardcoded defaults (benign) |

Note: `SESSION_CONFLICT_POLICY` already handles unknown values gracefully (falls back to `Allow` for any unrecognized string), which is acceptable because any string is a valid input -- it just may not be the one the user intended. However, a warning log would still be useful.

### Why This Matters

- **Silent misconfiguration**: Operators cannot distinguish "using default because unset" from "using default because my value was invalid"
- **Security implications**: `AUTH_SERVER_SECRET` falling back to a hardcoded default in production is dangerous but produces no warning
- **Debugging difficulty**: When session behavior is unexpected, the silent fallback to 600s (10 minutes) is not logged anywhere

## Related Issues

- `20260222-2201` Early Evaluation of OAUTH2_RESPONSE_MODE at Startup (same category: LazyLock env var handling)

## Approach

### Option A: Log warnings for invalid values (Recommended)

Add `tracing::warn!()` when a set variable fails to parse:

```rust
pub static SESSION_COOKIE_MAX_AGE: LazyLock<u64> = LazyLock::new(|| {
    match std::env::var("SESSION_COOKIE_MAX_AGE") {
        Ok(val) => match val.parse() {
            Ok(v) => v,
            Err(_) => {
                tracing::warn!(
                    "SESSION_COOKIE_MAX_AGE='{}' is not a valid u64, using default 600",
                    val
                );
                600
            }
        },
        Err(_) => 600, // Not set -- silent default is fine
    }
});
```

**Pros**: No behavior change, only adds visibility. Operators see warnings in logs.
**Cons**: More verbose code. Tracing may not be initialized when LazyLock first evaluates (but `init()` force-evaluation ensures tracing is available).

### Option B: Panic on invalid values (strict)

Treat a set-but-unparseable variable the same as a missing required variable:

```rust
.and_then(|s| s.parse().ok().or_else(|| {
    panic!("SESSION_COOKIE_MAX_AGE='{}' is not a valid u64", s)
}))
```

**Pros**: Catches mistakes immediately at startup.
**Cons**: Breaking change. A previously-working deployment with a typo would now crash.

### Option C: Early evaluation with logging

Force-evaluate optional variables in `init()` to ensure warnings appear at startup rather than on first use:

```rust
// In session::init() or wherever appropriate
let _ = *SESSION_COOKIE_MAX_AGE; // Forces evaluation, triggering any warnings
```

This complements Option A by ensuring warnings appear at startup.

### Recommendation

Implement Option B + C: panic on set-but-unparseable values AND force-evaluate in init() to catch errors at startup.

Behavior:
- Env var not set -> use default (intentional omission)
- Env var set, valid value -> use that value
- Env var set, invalid value -> panic at startup (configuration error)

## Audit Results

### Variables with silent parse errors (B targets - panic on invalid)

| Variable | File | Type | Default |
|----------|------|------|---------|
| `SESSION_COOKIE_MAX_AGE` | session/config.rs | u64 | 600 |
| `OAUTH2_CSRF_COOKIE_MAX_AGE` | oauth2/config.rs | u64 | 60 |
| `PASSKEY_TIMEOUT` | passkey/config.rs | u32 | 60 |
| `PASSKEY_CHALLENGE_TIMEOUT` | passkey/config.rs | u32 | 60 |
| `PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL` | passkey/config.rs | bool | false |
| `O2P_DEMO_MODE` | config.rs | bool | false |
| `O2P_RESPOND_WITH_X_CSRF_TOKEN` | axum/config.rs | bool | true |
| `CORS_ALLOW_CREDENTIALS` | axum/cors.rs | bool | false |

### Variables with enum match fallback (B targets - panic on invalid)

| Variable | File | Default |
|----------|------|---------|
| `SESSION_CONFLICT_POLICY` | session/config.rs | Allow |
| `PASSKEY_ATTESTATION` | passkey/config.rs | direct |
| `PASSKEY_AUTHENTICATOR_ATTACHMENT` | passkey/config.rs | platform |
| `PASSKEY_RESIDENT_KEY` | passkey/config.rs | required |
| `PASSKEY_REQUIRE_RESIDENT_KEY` | passkey/config.rs | true |
| `PASSKEY_USER_VERIFICATION` | passkey/config.rs | discouraged |
| `PASSKEY_SIGNAL_API_MODE` | config.rs | direct |
| `O2P_FEDCM` | axum/config.rs | Disabled |
| `O2P_PASSKEY_PROMOTION` | axum/config.rs | Disabled |

### Already strict (no change needed)

`OAUTH2_RESPONSE_MODE` already panics on invalid value.
Required variables (`ORIGIN`, `GENERIC_DATA_STORE_TYPE`, etc.) already use `.expect()`.

### String-only defaults (no parse step - no change needed)

`SESSION_COOKIE_NAME`, `O2P_ROUTE_PREFIX`, `DB_TABLE_PREFIX`, `OAUTH2_ISSUER_URL`, etc.
These have no parse step -- any string is a valid value.

## Related Files

- `oauth2_passkey/src/config.rs` - O2P_DEMO_MODE, PASSKEY_SIGNAL_API_MODE
- `oauth2_passkey/src/session/config.rs` - SESSION_COOKIE_MAX_AGE, SESSION_CONFLICT_POLICY, AUTH_SERVER_SECRET
- `oauth2_passkey/src/oauth2/config.rs` - OAUTH2_CSRF_COOKIE_MAX_AGE
- `oauth2_passkey/src/passkey/config.rs` - PASSKEY_TIMEOUT, PASSKEY_CHALLENGE_TIMEOUT, PASSKEY_ATTESTATION, etc.
- `oauth2_passkey_axum/src/config.rs` - O2P_RESPOND_WITH_X_CSRF_TOKEN, O2P_FEDCM, O2P_PASSKEY_PROMOTION
- `oauth2_passkey_axum/src/cors.rs` - CORS_ALLOW_CREDENTIALS
- `oauth2_passkey/src/storage/mod.rs` - existing init() with forced evaluation pattern

## Implementation Tasks

- [x] Audit all LazyLock env vars for silent fallback patterns
- [ ] Change parse-error fallback to panic for all affected variables (Option B)
- [ ] Change enum-match fallback to panic for all affected variables (Option B)
- [ ] Add early evaluation of all affected vars in init() functions (Option C)
- [ ] Address AUTH_SERVER_SECRET default value security concern
- [ ] Verify: `cargo test` passes, `cargo clippy` clean
- [ ] Test: invalid env var value causes panic at startup

## Decision Log

<!-- APPEND-ONLY: Do not edit or delete existing entries. Add new entries at the bottom. -->

### 2026-02-27: Issue created

- Context: Discussion about whether optional env vars truly do not need early evaluation, prompted by documenting the LazyLock force-evaluation rule in maintainer/development.md
- Decision: Create issue to track audit and improvement of silent fallback behavior
- Reason: Silent fallbacks can hide configuration mistakes; operators deserve visibility into whether their configuration is being used or ignored

### 2026-03-20: Switch to Option B + C (strict panic)

- Context: Revisited approach. Option A (warn + continue) still hides the problem if operators don't read logs. Option B (panic on invalid) + C (early eval in init) is stricter but consistent with how required variables work.
- Decision: Implement B + C. If an env var is explicitly set to an invalid value, panic at startup. Unset variables still silently use defaults.
- Reason: Operators who explicitly set a variable expect it to be used. Silent fallback violates that expectation. Fail-fast at startup is preferable to running with unintended configuration.

## Resolution
