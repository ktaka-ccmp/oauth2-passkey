# Issue: O2P_LOGIN_URL Role Clarification and user-ui Feature Granularity

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260216-1500

## Created: 2026-02-16-15-00

## Closed: 2026-02-22

## Status: completed

## Priority: medium

## Difficulty: medium

## Description

Several issues exist around how login page customization and the `user-ui` feature flag work together:

### 1. O2P_LOGIN_URL is not used internally by the library

`O2P_LOGIN_URL` is defined in `config.rs` and re-exported as `pub`, but the library itself never reads it for routing or redirection. It is purely a convenience constant for application developers to reference manually (e.g., in their own `/` handler).

However, documentation in `customizing-templates.md` states:
> `O2P_LOGIN_URL` is **required** for custom login pages to work.

This is misleading -- the library does not use this value. Unauthenticated users are redirected to `O2P_DEFAULT_REDIRECT` (default: `/`), not `O2P_LOGIN_URL`.

### 2. user-ui feature flag is too coarse

The `user-ui` feature flag controls all 4 optional routes as a single unit:
- `/user/login` (login page)
- `/user/account` (account management page)
- `/user/account.js` (account management JS)
- `/user/o2p-base.css` (base CSS)

It is not possible to:
- Disable just the login page while keeping the account page
- Replace only the login page with a custom one (the built-in one remains accessible)

### 3. Middleware redirects to O2P_DEFAULT_REDIRECT, not O2P_LOGIN_URL

When authentication middleware (`is_authenticated_redirect`, `is_authenticated_user_redirect`) or the `AuthUser` extractor rejects an unauthenticated request, it redirects to `O2P_DEFAULT_REDIRECT` (default: `/`), not to `O2P_LOGIN_URL`. This means:
- Applications must implement their own redirect chain: middleware -> `/` -> login page
- The `demo-custom-login` pattern works around this by setting `O2P_DEFAULT_REDIRECT=/` and manually redirecting from `/` to the custom login page

## Related Issues

- `2026-01-24-01` Documentation Improvement Planning (related to: docs accuracy)

## Approach

Needs investigation and design discussion. Possible directions:

**Option A: Documentation-only fix**
- Clarify that `O2P_LOGIN_URL` is a convenience export, not used internally
- Document the actual redirect chain accurately
- Minimal code changes

**Option B: Make O2P_LOGIN_URL functional**
- Have middleware redirect to `O2P_LOGIN_URL` instead of `O2P_DEFAULT_REDIRECT` for unauthenticated GET requests
- This would make the documented behavior match reality
- Breaking change: applications that rely on current redirect-to-`/` behavior would need to update

**Option C: Split user-ui feature flag**
- Split into `login-ui` and `account-ui` (or similar)
- Allows disabling just the login page while keeping account management
- More flexible but adds feature flag complexity

**Option D: Runtime login page disable**
- Add an env var (e.g., `O2P_DISABLE_BUILTIN_LOGIN=true`) to skip registering the `/user/login` route
- Simpler than feature flag splitting, works at runtime

These options are not mutually exclusive. A combination may be appropriate.

## Related Files

- `oauth2_passkey_axum/src/config.rs` - O2P_LOGIN_URL definition (line 9)
- `oauth2_passkey_axum/src/lib.rs` - pub re-export (line 77)
- `oauth2_passkey_axum/src/middleware.rs` - redirect to O2P_DEFAULT_REDIRECT (lines 45, 53)
- `oauth2_passkey_axum/src/session.rs` - AuthUser extractor redirect (lines 25-26)
- `oauth2_passkey_axum/src/user/mod.rs` - user-ui feature gate (lines 2, 12-19)
- `oauth2_passkey_axum/src/user/optional.rs` - login + account routes (lines 23-29)
- `docs/src/integration/customizing-templates.md` - misleading O2P_LOGIN_URL docs (line 450)
- `demo-custom-login/` - workaround pattern for custom login pages

## Implementation Tasks

- [ ] Investigate impact of making O2P_LOGIN_URL functional (Option B)
- [ ] Evaluate feature flag splitting vs runtime disable (Option C vs D)
- [ ] Fix documentation to accurately describe current behavior
- [ ] Decide on approach and implement

## Decision Log

<!-- APPEND-ONLY: Do not edit or delete existing entries. Add new entries at the bottom. -->

### 2026-02-16: Issue created from code investigation

- Context: While reviewing `dot.env.example` comments and feature flags, discovered that `O2P_LOGIN_URL` is exported but unused by the library, and `user-ui` cannot be partially disabled
- Decision: Created issue to track the cleanup and design discussion
- Reason: Multiple related inconsistencies between docs, code behavior, and user expectations need coordinated resolution

### 2026-02-22: Deep investigation completed

- Context: Full code and git history investigation to understand current state and origin of issues

#### O2P_LOGIN_URL History

1. Originally existed as `O2P_REDIRECT_ANON` (pre-402cf8b) — defaulted to `{O2P_ROUTE_PREFIX}/user/login` and was **actively used by middleware** as the redirect target for unauthenticated users.
2. Commit `402cf8b` (2025-04-04, "refactor: unify demo implementations") split it into two:
   - `O2P_LOGIN_URL` — kept the old default (`/o2p/user/login`), but **removed from middleware usage**; became a convenience export only
   - New `O2P_REDIRECT_ANON` — default `/`, now used by middleware for redirects
3. Commit `f907b20` (2026-01-27) renamed `O2P_REDIRECT_ANON` to `O2P_DEFAULT_REDIRECT` for clarity.

Root cause: The split in `402cf8b` created the disconnect — `O2P_LOGIN_URL` retained the semantics of "login page URL" but lost its functional role in middleware redirects.

#### Current Redirect Flow (3 locations)

| Location | File | Redirect Target |
|----------|------|----------------|
| `handle_auth_error()` (middleware) | `middleware.rs:45,53` | `O2P_DEFAULT_REDIRECT` |
| `AuthUser` extractor (`AuthRedirect`) | `session.rs:25-26` | `O2P_DEFAULT_REDIRECT` |
| Login handler (authenticated user visit) | `user/optional.rs:41` | `O2P_DEFAULT_REDIRECT` |

All 3 redirect to `O2P_DEFAULT_REDIRECT` (default: `/`). None use `O2P_LOGIN_URL`.

#### O2P_LOGIN_URL External Usage

Only demo applications use it:
- `demo-both/src/main.rs:42` — manual redirect from `/` handler
- `demo-live/src/main.rs:65` — same pattern
- `demo-custom-login` does NOT import it (uses hardcoded `/login`)

Result: 2-hop redirect chain: protected route -> middleware -> `/` -> app's `/` handler -> `O2P_LOGIN_URL`

#### user-ui Feature Flag

- Defined in `oauth2_passkey_axum/Cargo.toml` as empty marker, default ON
- Controls 4 routes in `user/optional.rs`: `/login`, `/account`, `/account.js`, `/o2p-base.css`
- `admin-ui` follows identical pattern for admin routes
- `demo-custom-login` disables with `default-features = false` (loses BOTH user-ui and admin-ui)
- No way to disable only login page while keeping account page

#### Approach Assessment

| Option | Pros | Cons | Recommendation |
|--------|------|------|----------------|
| A: Docs only | No breaking change | Root issue remains | Minimum viable |
| B: Make O2P_LOGIN_URL functional | Eliminates 2-hop redirect, intuitive | Breaking change for apps relying on redirect-to-`/` | High impact, recommended |
| C: Split feature flags | Flexible | Adds complexity | Defer unless needed |
| D: Runtime disable | Simple, no rebuild | Overlaps with feature flags | Defer unless needed |

Recommended: A+B combination (make O2P_LOGIN_URL the middleware redirect target + fix docs).

### 2026-02-22: Issue split into two separate issues

- Context: The environment variable problem (O2P_LOGIN_URL) and the feature flag problem (user-ui granularity) are different layers (runtime vs compile-time) and should be tracked independently
- Decision: Split into `20260222-1315` (env var, open) and `20260222-1316` (feature flag, deferred)
- Reason: Fixing the env var problem (Option B) largely eliminates the urgency of the feature flag problem, so they should be prioritized separately

## Resolution

Superseded by two separate issues:
- `20260222-1315` — Make O2P_LOGIN_URL functional in middleware (env var problem)
- `20260222-1316` — user-ui feature flag granularity (deferred)
