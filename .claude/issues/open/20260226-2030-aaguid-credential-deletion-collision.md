# Issue: AAGUID-Based Credential Deletion Collision with Same-Type Authenticators

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260226-2030

## Created: 2026-02-26

## Closed:

## Status: open

## Priority: low

## Difficulty: medium

## Description

During passkey re-registration, existing credentials are automatically deleted when `user_handle + user_id + aaguid` all match. This works correctly when a user re-registers the same physical authenticator, but incorrectly deletes credentials when a user has multiple authenticators of the same type.

### Problem

AAGUID identifies the authenticator *type* (e.g., "Google Password Manager", "YubiKey 5C"), not the individual *instance*. When a user has multiple instances of the same authenticator type, the code cannot distinguish between them.

### Affected Scenarios

- A user with Google Password Manager on two different Google accounts
- A user with two YubiKey 5C keys (same model = same AAGUID)
- A user with Apple Keychain on two different Apple IDs

### Current Behavior

1. User registers Passkey with Google Password Manager (Google Account A)
2. User registers Passkey with Google Password Manager (Google Account B)
3. Step 2 deletes the credential from step 1 (same AAGUID match)
4. User loses access via Google Account A's Password Manager

### Code Location

`oauth2_passkey/src/passkey/main/register.rs:369-373` has a TODO comment acknowledging this limitation:

```
// Important todo: we delete credentials for a combination of "AAGUID" and user_handle
// But we can't distinguish multiple authenticators of the same type,
// e.g. Google Password Managers for different accounts or two Yubikeys with the same model.
```

The deletion logic is at lines 395-419, enabled by default when `PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL=false`.

### Impact

Low -- most users do not have multiple instances of the same authenticator type. However, it is a correctness bug that silently deletes valid credentials.

## Related Issues

None

## Approach

**Decided: Remove AAGUID-based deletion + add `excludeCredentials` to normal registration flow.**

Two changes as a set:

1. **Remove AAGUID-based credential deletion** from `register.rs`
   - AAGUID identifies authenticator *type*, not *instance* -- server-side deletion by AAGUID is fundamentally unsafe
   - No standard WebAuthn guidance recommends server-side AAGUID-based deletion
   - Stale credentials in DB are harmless: the authenticator selects the correct credential during authentication
   - Users can manually delete unwanted credentials from the account management page

2. **Add `excludeCredentials` to normal registration flow** (core library)
   - Currently only the promotion flow (`promotion.rs`) passes `excludeCredentials`
   - Normal registration via `handle_start_registration_core()` does not
   - Without `excludeCredentials`, the same authenticator can create duplicate credentials
   - Pass all of the user's existing credential IDs -- the authenticator checks only the ones it holds
   - Cannot filter by AAGUID because the new authenticator's AAGUID is unknown at registration option generation time (it is only revealed in the attestation response after registration completes)

## Related Files

- `oauth2_passkey/src/passkey/main/register.rs` (lines 363-422) -- AAGUID-based deletion logic to remove
- `oauth2_passkey/src/passkey/config.rs` (lines 114-119, `PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL`)
- `oauth2_passkey/src/coordination/passkey.rs` -- `handle_start_registration_core()`, add `excludeCredentials`
- `oauth2_passkey_axum/src/passkey/promotion.rs` (lines 276-296) -- existing `excludeCredentials` implementation for reference

## Implementation Tasks

- [ ] Remove AAGUID-based credential deletion logic from `register.rs`
- [ ] Remove related TODO comment at lines 369-373
- [ ] Add `excludeCredentials` (all user's credential IDs) to `handle_start_registration_core()`
- [ ] Verify promotion flow's `excludeCredentials` logic can be deduplicated or remains separate
- [ ] Add unit tests for multiple same-AAGUID credential coexistence
- [ ] Update documentation

## Decision Log

### 2026-02-26: Migrated from ToDo.md

- Context: Migrating incomplete tasks from ToDo.md to issue tracking system
- Decision: Create as low-priority open issue (correctness bug, rare scenario)
- Reason: Silently deletes valid credentials in edge case; worth fixing but not urgent

### 2026-03-03: Approach decided -- remove AAGUID deletion + add excludeCredentials

Investigation findings:

1. **AAGUID-based deletion is non-standard**: No WebAuthn spec guidance or major implementation (Google, web.dev) recommends server-side credential deletion by AAGUID. The standard approach is to use `excludeCredentials` for duplicate prevention and let users manage credentials manually.

2. **Stale credentials are harmless**: When a user re-registers on the same authenticator, the old credential remains in the DB but the authenticator responds with the new one during authentication. The old entry is inert.

3. **`excludeCredentials` cannot be AAGUID-filtered**: At the time the server generates registration options, the new authenticator's AAGUID is unknown (revealed only in the attestation response after registration). So `excludeCredentials` must include all of the user's credential IDs. This is correct -- each authenticator only checks credentials it holds and ignores the rest.

4. **Normal registration flow lacks `excludeCredentials`**: Only the promotion flow (`promotion.rs`) currently passes it. The core registration flow must also include it to prevent duplicate credentials on the same authenticator.

Rejected alternatives:

- **Login-credential-aware deletion**: Only delete the credential used for the current Passkey login when re-registering with the same AAGUID. Better than deleting all same-AAGUID credentials (limits damage to one), but still fails when the device's default Password Manager differs from the one used for login (e.g., logged in via Google PM Account A, but new credential goes to Account B). Also does not apply to OAuth2 login -> Passkey registration flow (no login credential to reference).

- **Tracking Password Manager via OAuth2 account association**: Store the OAuth2 Google ID alongside passkey credentials to infer which Google account's Password Manager holds each credential. Fundamentally unreliable -- the OAuth2 login account and the device's active Password Manager are independent (user may log in with Google Account A but the device's default PM is Account B, or iCloud Keychain, or 1Password).

- Decision: Remove AAGUID-based deletion and add `excludeCredentials` to normal registration as a set
- Reason: Aligns with WebAuthn standard practices, eliminates the correctness bug. Server cannot reliably identify authenticator instances (only types via AAGUID), so any server-side deletion heuristic will have false positives.

## Resolution
