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

## Closed:

## Status: open

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
| Login handler (authenticated user visit) | `user/optional.rs:41` | `O2P_DEFAULT_REDIRECT` |

All 3 redirect to `O2P_DEFAULT_REDIRECT`. None use `O2P_LOGIN_URL`.

## Related Issues

- `20260216-1500` Original combined issue (superseded)
- `20260222-1316` user-ui feature flag granularity (deferred, separate concern)
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
- `oauth2_passkey_axum/src/lib.rs` - pub re-export (line 77)
- `oauth2_passkey_axum/src/middleware.rs` - handle_auth_error redirect (lines 45, 53)
- `oauth2_passkey_axum/src/session.rs` - AuthRedirect (lines 25-26)
- `oauth2_passkey_axum/src/user/optional.rs` - login handler redirect (line 41, keep O2P_DEFAULT_REDIRECT)
- `docs/src/integration/customizing-templates.md` - misleading docs
- `docs/src/integration/configuration.md` - config docs
- `dot.env.example` - env var documentation
- `demo-both/src/main.rs` - manual redirect to O2P_LOGIN_URL (can be simplified)
- `demo-live/src/main.rs` - same pattern
- `demo-custom-login/` - workaround pattern (can be simplified)

## Implementation Tasks

- [ ] Change `handle_auth_error()` in `middleware.rs` to redirect to `O2P_LOGIN_URL`
- [ ] Change `AuthRedirect` in `session.rs` to redirect to `O2P_LOGIN_URL`
- [ ] Update config.rs doc comments to clarify each variable's role
- [ ] Update middleware.rs doc comments
- [ ] Simplify demo-both (remove manual redirect from `/` handler)
- [ ] Simplify demo-live (same)
- [ ] Update documentation (configuration.md, customizing-templates.md)
- [ ] Update dot.env.example comments
- [ ] Run tests and verify compilation
- [ ] Update CHANGELOG.md

## Decision Log

<!-- APPEND-ONLY: Do not edit or delete existing entries. Add new entries at the bottom. -->

### 2026-02-22: Issue created from split of 20260216-1500

- Context: Deep investigation completed on 20260216-1500 revealed that the env var and feature flag problems are independent concerns at different layers (runtime vs compile-time)
- Decision: Split into separate issue; approach is Option A+B from the original issue (make O2P_LOGIN_URL functional + fix docs)
- Reason: Fixing O2P_LOGIN_URL largely eliminates the urgency of the feature flag problem, so they should be tracked and prioritized independently

## Resolution
