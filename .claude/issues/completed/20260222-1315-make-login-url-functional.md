# Issue: Make O2P_LOGIN_URL Functional in Middleware

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260222-1315

## Created: 2026-02-22-13-15

## Closed: 2026-02-22

## Status: completed

## Priority: medium

## Difficulty: medium

## Description

`O2P_LOGIN_URL` is defined and publicly exported but not used by the library internally. Middleware and the `AuthUser` extractor redirect unauthenticated users to `O2P_DEFAULT_REDIRECT` (default: `/`) instead of `O2P_LOGIN_URL` (default: `/o2p/user/login`). This forces applications into a 2-hop redirect pattern:

```
protected route -> middleware -> "/" -> app's "/" handler -> O2P_LOGIN_URL
```

### History

`O2P_LOGIN_URL` originated as `O2P_REDIRECT_ANON` which was actively used by middleware. Commit `402cf8b` (2025-04-04) split the single variable into two: `O2P_LOGIN_URL` (login page URL constant) and a new `O2P_REDIRECT_ANON` (redirect target, default `/`). This split disconnected `O2P_LOGIN_URL` from middleware. Later, `O2P_REDIRECT_ANON` was renamed to `O2P_DEFAULT_REDIRECT` in `f907b20` (2026-01-27).

### Current Redirect Flow

| Location | File | Redirect Target |
|----------|------|----------------|
| `handle_auth_error()` (middleware) | `middleware.rs:45,53` | `O2P_DEFAULT_REDIRECT` |
| `AuthUser` extractor (`AuthRedirect`) | `session.rs:25-26` | `O2P_DEFAULT_REDIRECT` |
| Login handler (authenticated user visit) | `user/login.rs:28` | `O2P_DEFAULT_REDIRECT` |

All 3 redirect to `O2P_DEFAULT_REDIRECT`. None use `O2P_LOGIN_URL`.

## Related Issues

- `20260216-1500` Original combined issue (superseded)
- `20260222-1316` user-ui feature flag granularity (completed)
- `20260222-2201` Early evaluation of OAUTH2_RESPONSE_MODE (discovered during this issue)
- `2026-01-24-01` Documentation Improvement Planning (related to: docs accuracy)

## Approach

Change middleware and `AuthUser` extractor to redirect unauthenticated GET requests to `O2P_LOGIN_URL` instead of `O2P_DEFAULT_REDIRECT`. Keep `O2P_DEFAULT_REDIRECT` for its remaining use case (redirecting authenticated users away from login page).

After this change, each variable has a clear, distinct role:
- `O2P_LOGIN_URL`: where to send **unauthenticated** users (default: `/o2p/user/login`)
- `O2P_DEFAULT_REDIRECT`: where to send **authenticated** users away from login page, after logout, etc. (default: `/`)

This eliminates the 2-hop redirect and makes the behavior match what users expect from the variable name.

**Breaking change**: Applications that set `O2P_DEFAULT_REDIRECT` to control where unauthenticated users go would need to set `O2P_LOGIN_URL` instead.

## Related Files

- `oauth2_passkey_axum/src/config.rs` - O2P_LOGIN_URL definition (line 9)
- `oauth2_passkey_axum/src/lib.rs` - init() wrapper with O2P_LOGIN_URL early evaluation
- `oauth2_passkey_axum/src/middleware.rs` - handle_auth_error redirect (lines 45, 53)
- `oauth2_passkey_axum/src/session.rs` - AuthRedirect (lines 25-26)
- `oauth2_passkey_axum/src/user/optional.rs` - login handler redirect (line 41, keep O2P_DEFAULT_REDIRECT)
- `docs/src/integration/configuration.md` - config docs
- `dot.env.example` - env var documentation
- `demo-both/src/main.rs` - simplified to use AuthUser extractor
- `demo-live/src/main.rs` - simplified to use AuthUser extractor
- `CHANGELOG.md` - breaking change noted

## Implementation Tasks

- [x] Change `handle_auth_error()` in `middleware.rs` to redirect to `O2P_LOGIN_URL`
- [x] Change `AuthRedirect` in `session.rs` to redirect to `O2P_LOGIN_URL`
- [x] Update config.rs doc comments to clarify each variable's role
- [x] Add conditional panic when login-ui disabled and O2P_LOGIN_URL not set
- [x] Create init() wrapper in oauth2_passkey_axum for early O2P_LOGIN_URL evaluation
- [x] Update middleware.rs doc comments
- [x] Simplify demo-both (Option<AuthUser> -> AuthUser)
- [x] Simplify demo-live (Option<AuthUser> -> AuthUser)
- [x] Update documentation (configuration.md)
- [x] Update dot.env.example comments
- [x] Add cfg_attr(ignore) for tests that require login-ui feature
- [x] Run tests and verify compilation
- [x] Update CHANGELOG.md

## Decision Log

<!-- APPEND-ONLY: Do not edit or delete existing entries. Add new entries at the bottom. -->

### 2026-02-22: Issue created from split of 20260216-1500

- Context: Deep investigation completed on 20260216-1500 revealed that the env var and feature flag problems are independent concerns at different layers (runtime vs compile-time)
- Decision: Split into separate issue; approach is Option A+B from the original issue (make O2P_LOGIN_URL functional + fix docs)
- Reason: Fixing O2P_LOGIN_URL largely eliminates the urgency of the feature flag problem, so they should be tracked and prioritized independently

### 2026-02-22: Investigation - Are 2 env vars needed?

- Context: User questioned whether 2 env vars (`O2P_LOGIN_URL` + `O2P_DEFAULT_REDIRECT`) are necessary, or if 1 suffices. Concern: library users may struggle to understand the distinction.
- Investigation: Mapped all 5 usage sites of `O2P_DEFAULT_REDIRECT` and identified 3 semantic roles:
  - Role A: Redirect unauthenticated users (middleware.rs:45,53 + session.rs:25-26) -> needs login page URL
  - Role B: Redirect authenticated users away from login page (login.rs:28) -> needs app root URL
  - Role C: Logout redirect target in templates (user_account.j2:222, admin_index.j2:84) -> needs app root URL
- Finding: Roles A and B/C have different default values (`/o2p/user/login` vs `/`), so 1 env var cannot serve both.
- Finding: `customizing-templates.md` already documents the correct behavior (lines 29, 42, 446, 450) as if `O2P_LOGIN_URL` is used by middleware. The docs are ahead of the implementation.
- Decision: 2 env vars are needed. Current names are appropriate. The approach in this issue (make `O2P_LOGIN_URL` functional) is validated.
- Note: With `login-ui` feature flag (from 20260222-1316, now completed), the interaction is clean: when `login-ui` is enabled, `O2P_LOGIN_URL` default works as-is; when disabled, the user must set `O2P_LOGIN_URL` to their custom login page URL.

### 2026-02-22: login-ui disabled + O2P_LOGIN_URL unset causes redirect loop

- Context: When login-ui is disabled and O2P_LOGIN_URL not set, fallback to "/" caused ERR_TOO_MANY_REDIRECTS (/ -> AuthUser -> O2P_LOGIN_URL(/) -> / -> ...)
- Decision: panic!() in LazyLock when login-ui disabled and env var not set, plus init() wrapper for early evaluation
- Reason: Failing fast at startup is better than a confusing runtime redirect loop. The init() wrapper ensures panic happens during initialization, not on first request.

## Detailed Implementation Plan

### 1. Core: middleware.rs

- Import `O2P_LOGIN_URL` (add to line 10)
- In `handle_auth_error()` lines 44-45, 52-53: change `O2P_DEFAULT_REDIRECT` to `O2P_LOGIN_URL`
- Update doc comment on `is_authenticated_redirect` (line 98)

### 2. Core: session.rs

- Import `O2P_LOGIN_URL` (change import at line 11)
- In `AuthRedirect::into_response_with_method()` lines 25-26: change `O2P_DEFAULT_REDIRECT` to `O2P_LOGIN_URL`

### 3. config.rs doc comments

- `O2P_LOGIN_URL`: clarify middleware/AuthUser uses it for unauthenticated redirects
- `O2P_DEFAULT_REDIRECT`: clarify it's for authenticated-user redirects only (login page bounce, logout target)

### 4. Simplify demo-both

- `index()` handler: change `Option<AuthUser>` to `AuthUser` (non-optional)
- `AuthUser` extractor's `AuthRedirect` handles unauthenticated redirect automatically
- Remove `None` branch and `O2P_LOGIN_URL` import

### 5. Simplify demo-live

- Same as demo-both: change `Option<AuthUser>` to `AuthUser` in `index()`
- Requires `O2P_LOGIN_URL=/login` in `.env` (since `login-ui` is disabled)
- Remove `O2P_LOGIN_URL` import from main.rs

### 6. Documentation

- `configuration.md`: fix `O2P_DEFAULT_REDIRECT` description (remove "unauthenticated users" from its role)
- `customizing-templates.md`: already correct, minor tweaks if needed
- `dot.env.example`: update comments

### 7. CHANGELOG.md

- Note breaking change in redirect behavior

## Resolution

Implemented all changes. Middleware and AuthUser extractor now redirect unauthenticated users to `O2P_LOGIN_URL` instead of `O2P_DEFAULT_REDIRECT`. When `login-ui` feature is disabled, `O2P_LOGIN_URL` must be set explicitly via env var or the program panics at startup (via init() wrapper that forces early LazyLock evaluation). Demo apps simplified from `Option<AuthUser>` to `AuthUser`. Merged to dev branch.
