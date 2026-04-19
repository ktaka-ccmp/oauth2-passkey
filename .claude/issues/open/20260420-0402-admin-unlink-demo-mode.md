# Issue: Admin unlink/delete fails in demo mode ("Invalid user ID")

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260420-0402

## Created: 2026-04-20-04-02

## Closed:

## Status: open

## Priority: medium

## Difficulty: small

## Description

In demo mode (`O2P_DEMO_MODE=true`), an admin viewing another user's
detail page and clicking **Unlink** on an OAuth2 account (or **Delete**
on a passkey credential) sees:

> Failed to unlink account: Invalid user ID: User ID contains invalid characters

Reproduced on demo-both with `O2P_DEMO_MODE=true`, viewing a target
user whose id differs from the admin's (the masking path
`Masker::for_detail` activates only in that case).

### Root cause

The admin user-detail template renders `account.user_id` /
`credential.user_id` through `masker.id()`, producing strings like
`"f47a***"` (first four chars + `***`). The page's JS helpers
`unlinkOAuth2Account` / `deletePasskeyCredential` read those masked
values out of the DOM and POST them back as `user_id` in the request
body.

The matching admin handlers in `admin/default.rs` then call
`UserId::new(payload.user_id)`, which rejects `*`, and the request
fails.

The architectural root cause is that these admin handlers call the
**user-level** coordination functions (`delete_oauth2_account_core`,
`delete_passkey_credential_core`), which need `user_id` purely to
enforce ownership ("this resource belongs to the caller"). Admin
flows don't need that check — the crate already exposes admin-level
APIs (`delete_oauth2_account_admin`, `delete_passkey_credential_admin`
in `coordination/admin.rs`) that take only the resource ID and
validate the admin session directly.

## Related Issues

- `20260220-2357` Full Masking for Email and Name in Demo Mode
  (relationship: introduced the masker used here; masking itself is
  correct — this issue is about the API call layer)

## Approach

Switch the two admin handlers to use the admin-level coordination
functions, eliminating the need to parse `user_id` out of the (masked)
request body.

High-level changes:

1. `oauth2_passkey_axum/src/admin/default.rs`
   - `delete_oauth2_account` → call `delete_oauth2_account_admin(session_id, provider_user_id)`
   - `delete_passkey_credential` → call `delete_passkey_credential_admin(session_id, credential_id)`
   - Drop `PageUserContext` body parsing; drop now-unused `Provider` /
     `UserId` usages within these two handlers.
2. `oauth2_passkey_axum/static/admin_user.js`
   - Drop the trailing `accountUserId` / `credentialUserId` args and
     request bodies.
3. `oauth2_passkey_axum/templates/admin_user_page.j2`
   - Drop the third arg from both `onclick=` handlers.

Not a security regression: the handler still runs
`auth_user.has_admin_privileges()` up-front, and the admin-level
coordination fn re-checks admin status against a fresh DB row via
`validate_admin_session`. The pre-patch `user_id` ownership check
was redundant for admin flows and actively harmful in demo mode.

Detailed plan file:
`~/.claude/plans/refactored-enchanting-pebble.md`

## Related Files

- `oauth2_passkey_axum/src/admin/default.rs`
- `oauth2_passkey_axum/static/admin_user.js`
- `oauth2_passkey_axum/templates/admin_user_page.j2`
- `oauth2_passkey/src/coordination/admin.rs` (read-only — admin fns live here)
- `oauth2_passkey_axum/src/admin/masking.rs` (read-only — masker behavior is correct)
- `oauth2_passkey_axum/src/admin/optional.rs` (read-only — where masking is applied to template data)

## Implementation Tasks

- [ ] Update `delete_oauth2_account` handler to use `delete_oauth2_account_admin`
- [ ] Update `delete_passkey_credential` handler to use `delete_passkey_credential_admin`
- [ ] Remove `PageUserContext` struct if no remaining users in the file
- [ ] Update imports in `admin/default.rs` (drop `Provider`, core fns; add admin fns)
- [ ] Update `unlinkOAuth2Account` and `deletePasskeyCredential` in `admin_user.js`
- [ ] Update both `onclick` handlers in `admin_user_page.j2`
- [ ] Update `src/admin/` tests if they cover these handlers' signatures
- [ ] `cargo fmt --all && cargo clippy --all-targets --all-features && cargo test`
- [ ] Manual verification in demo-both with `O2P_DEMO_MODE=true`
- [ ] Manual regression check with `O2P_DEMO_MODE` unset

## Decision Log

<!-- APPEND-ONLY: Do not edit or delete existing entries. Add new entries at the bottom. -->

### 2026-04-20: Use admin-level coordination fns instead of patching masking

- Context: Initial instinct was to leave the masking alone and instead
  exempt `user_id` from masking for admin forms. That would keep the
  buggy API call shape and punch a hole in demo-mode privacy.
- Decision: Switch the two admin handlers to
  `delete_oauth2_account_admin` / `delete_passkey_credential_admin`,
  which match the pattern used by the other admin handlers in the
  same file (`delete_user_account_handler`,
  `update_admin_status_handler`).
- Reason: Eliminates the `user_id` round-trip entirely, matches the
  existing "admin-level coordination fn" pattern in the crate, and
  does not compromise demo-mode masking. Security posture improves
  slightly (fresh-DB admin check in the coordination layer).

### 2026-04-20: Keep `provider` in the URL but drop it from body plumbing

- Context: `delete_oauth2_account_admin` matches on
  `provider_user_id` alone (`AccountSearchField::ProviderUserId`) and
  does not need `provider`.
- Decision: Keep the `{provider}` path segment in the route
  (`/admin/delete_oauth2_account/{provider}/{provider_user_id}`);
  bind it to `_provider` in the handler.
- Reason: URL stability for operator bookmarks; no functional
  difference.

## Resolution

<!-- To be filled in when resolved -->
