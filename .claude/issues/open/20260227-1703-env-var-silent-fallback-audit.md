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

Implement Option A + C: log warnings for invalid values AND force-evaluate optional variables in init() to surface warnings early.

## Related Files

- `oauth2_passkey/src/session/config.rs` - SESSION_COOKIE_MAX_AGE, AUTH_SERVER_SECRET, SESSION_COOKIE_NAME, SESSION_COOKIE_DOMAIN, SESSION_CONFLICT_POLICY
- `oauth2_passkey/src/storage/data_store/config.rs` - GENERIC_DATA_STORE_TYPE, GENERIC_DATA_STORE_URL, DB_TABLE_PREFIX
- `oauth2_passkey/src/storage/cache_store/config.rs` - GENERIC_CACHE_STORE_TYPE, GENERIC_CACHE_STORE_URL
- `oauth2_passkey/src/oauth2/config.rs` - Various OAuth2 configuration variables
- `oauth2_passkey/src/passkey/config.rs` - Various Passkey configuration variables

## Implementation Tasks

- [ ] Audit all LazyLock env vars for silent fallback patterns
- [ ] Add tracing::warn!() for set-but-unparseable values (Option A)
- [ ] Add early evaluation of optional vars in init() functions (Option C)
- [ ] Address AUTH_SERVER_SECRET default value security concern
- [ ] Add unit tests for warning behavior
- [ ] Update documentation if new init() evaluations are added

## Decision Log

<!-- APPEND-ONLY: Do not edit or delete existing entries. Add new entries at the bottom. -->

### 2026-02-27: Issue created

- Context: Discussion about whether optional env vars truly do not need early evaluation, prompted by documenting the LazyLock force-evaluation rule in maintainer/development.md
- Decision: Create issue to track audit and improvement of silent fallback behavior
- Reason: Silent fallbacks can hide configuration mistakes; operators deserve visibility into whether their configuration is being used or ignored

## Resolution
