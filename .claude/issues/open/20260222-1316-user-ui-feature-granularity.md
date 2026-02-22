# Issue: user-ui Feature Flag Granularity

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260222-1316

## Created: 2026-02-22-13-16

## Closed:

## Status: open

## Priority: low

## Difficulty: medium

## Description

The `user-ui` feature flag controls all 4 optional user routes as a single unit:
- `/user/login` (login page)
- `/user/account` (account management page)
- `/user/account.js` (account management JS)
- `/user/o2p-base.css` (base CSS)

It is not possible to:
- Disable just the login page while keeping the account page
- Replace only the login page with a custom one while keeping built-in account management

Currently, `demo-custom-login` works around this by using `default-features = false`, which disables both `user-ui` and `admin-ui`, requiring the app to reimplement all UI pages.

The `admin-ui` feature flag follows the same all-or-nothing pattern.

## Related Issues

- `20260216-1500` Original combined issue (superseded)
- `20260222-1315` Make O2P_LOGIN_URL functional (related, reduces urgency of this issue)

## Approach

Deferred. Once `20260222-1315` (O2P_LOGIN_URL functional) is resolved, the practical need for finer feature flag granularity is greatly reduced because:
- Custom login pages work by setting `O2P_LOGIN_URL` to point to the custom page
- The built-in login page remains registered but users are not redirected there
- It is harmless to have the unused built-in route available

If a need arises in the future, possible approaches include:
- **Option C**: Split `user-ui` into `login-ui` and `account-ui` feature flags
- **Option D**: Add a runtime env var (e.g., `O2P_DISABLE_BUILTIN_LOGIN=true`) to skip the `/user/login` route registration

## Related Files

- `oauth2_passkey_axum/Cargo.toml` - feature flag definition
- `oauth2_passkey_axum/src/user/mod.rs` - user-ui conditional compilation
- `oauth2_passkey_axum/src/user/optional.rs` - routes controlled by user-ui
- `oauth2_passkey_axum/src/admin/mod.rs` - admin-ui (same pattern)

## Implementation Tasks

- [ ] Evaluate need after 20260222-1315 is resolved
- [ ] If needed, choose between Option C (feature split) and Option D (runtime disable)
- [ ] Implement chosen approach

## Decision Log

<!-- APPEND-ONLY: Do not edit or delete existing entries. Add new entries at the bottom. -->

### 2026-02-22: Issue created from split of 20260216-1500, deferred

- Context: Investigation showed that fixing O2P_LOGIN_URL (20260222-1315) largely eliminates the practical need for finer feature flag granularity
- Decision: Defer this issue until a concrete need arises
- Reason: The feature flag problem is at the compile-time layer and is lower priority than the runtime redirect behavior fix

## Resolution
