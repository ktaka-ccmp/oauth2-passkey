# Early Evaluation of OAUTH2_RESPONSE_MODE at Startup

- **ID**: 20260222-2201
- **Status**: open
- **Priority**: low
- **Difficulty**: easy
- **Created**: 2026-02-22

## Problem

`OAUTH2_RESPONSE_MODE` is a `LazyLock<String>` that panics if set to an invalid value (anything other than `form_post` or `query`). Because it is lazily evaluated, a typo like `OAUTH2_RESPONSE_MODE=frm_post` is not caught at startup -- it only panics when the OAuth2 login flow is first triggered at runtime.

**Location**: `oauth2_passkey/src/oauth2/config.rs:127-135`

```rust
pub(crate) static OAUTH2_RESPONSE_MODE: LazyLock<String> = LazyLock::new(|| {
    let mode = std::env::var("OAUTH2_RESPONSE_MODE").unwrap_or("form_post".to_string());
    match mode.as_str() {
        "form_post" | "query" => mode,
        _ => panic!("Invalid OAUTH2_RESPONSE_MODE '{mode}'. Must be 'form_post' or 'query'."),
    }
});
```

## Context

Discovered during issue 20260222-1315 (Make O2P_LOGIN_URL Functional). A comprehensive audit of all `LazyLock` variables with `panic!`/`expect!` found that `OAUTH2_RESPONSE_MODE` is the only lazily-evaluated variable that can panic but is NOT evaluated during `init()`.

All other panic-capable variables (`ORIGIN`, `OAUTH2_GOOGLE_CLIENT_ID`, `OAUTH2_GOOGLE_CLIENT_SECRET`, `GENERIC_DATA_STORE_TYPE`, etc.) are already evaluated during the `oauth2_passkey::init()` call chain.

## Approach

Add `let _ = &*OAUTH2_RESPONSE_MODE;` to `oauth2::init()` in the core crate, similar to how `O2P_LOGIN_URL` is force-evaluated in the axum crate's `init()` wrapper.

This is a one-line change in `oauth2_passkey/src/oauth2/mod.rs`.

## Risk Assessment

- **Low priority**: Only triggers on explicit misconfiguration (typo in env var value)
- **Default is safe**: `form_post` is used when the env var is not set
- **Impact**: Developer sees a confusing runtime panic instead of a clear startup error

## Related Issues

- `20260222-1315` Make O2P_LOGIN_URL Functional (discovered during audit)

## Decision Log

<!-- APPEND-ONLY: Do not edit or delete existing entries. Add new entries at the bottom. -->

### 2026-02-22: Issue created

- Context: Audit of all LazyLock variables during 20260222-1315 implementation
- Decision: Track separately as low-priority improvement
- Reason: Different crate (core vs axum), low risk (only on explicit misconfiguration)

## Resolution

(not yet resolved)
