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

Possible strategies:

1. **Skip deletion entirely**: Let the WebAuthn `excludeCredentials` mechanism handle duplicates client-side instead of server-side cleanup. The authenticator itself knows which credentials it holds.
2. **Add credential_id to the match**: Instead of matching by AAGUID alone, use a more specific identifier. However, the credential_id changes on each registration, so this does not help directly.
3. **Keep all credentials**: Allow multiple credentials with the same AAGUID per user. The authenticator will present the correct one during authentication.
4. **User confirmation**: When a matching AAGUID credential exists, ask the user whether to replace it.

Needs further investigation into WebAuthn specification recommendations for this scenario.

## Related Files

- `oauth2_passkey/src/passkey/main/register.rs` (lines 363-422)
- `oauth2_passkey/src/passkey/config.rs` (lines 114-119, `PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL`)

## Implementation Tasks

- [ ] Research WebAuthn spec recommendations for same-AAGUID credential management
- [ ] Decide on approach (skip deletion, keep all, or other)
- [ ] Implement chosen approach
- [ ] Add unit tests for multiple same-type authenticator scenario
- [ ] Update documentation

## Decision Log

### 2026-02-26: Migrated from ToDo.md

- Context: Migrating incomplete tasks from ToDo.md to issue tracking system
- Decision: Create as low-priority open issue (correctness bug, rare scenario)
- Reason: Silently deletes valid credentials in edge case; worth fixing but not urgent

## Resolution

