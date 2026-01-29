# User Handle Strategy and WebAuthn Signal API

This document explains the `PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL` configuration setting in detail, and how it interacts with the WebAuthn Signal API for credential synchronization.

## Overview

Two separate but closely related mechanisms affect how passkey credentials are managed:

1. **User Handle Strategy** (`PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL`) -- Controls whether each credential gets its own unique `user_handle` or all credentials for a user share the same `user_handle`.

2. **WebAuthn Signal API** -- A set of browser APIs that allow the relying party (server) to communicate credential state changes to the authenticator (password manager, platform authenticator, security key).

The user handle strategy directly determines how effectively the Signal API can synchronize credentials between the server and the authenticator.

---

## User Handle (`user.id` / `user_handle`)

### What is a User Handle?

In the WebAuthn specification, the user handle (`user.id`) is an opaque byte sequence (0-64 bytes) that identifies a user account. It is:

- Set by the relying party during credential registration
- Stored by the authenticator alongside the credential
- Returned to the relying party during authentication (for discoverable credentials)
- Used by the authenticator to group credentials belonging to the same user

### How the Authenticator Uses User Handles

The authenticator (e.g., Google Password Manager, iCloud Keychain, YubiKey) uses the user handle to determine which credentials belong to the same user. This affects:

- **Credential display**: Credentials with the same user handle may be grouped together in the authenticator's UI
- **Credential replacement**: Some authenticators (especially password managers) overwrite existing credentials when a new one is registered with the same user handle and RP ID
- **Signal API scope**: The `signalAllAcceptedCredentials` API operates on a per-user-handle basis

### WebAuthn Specification Guidance

The WebAuthn Level 3 specification states:

> The user handle is an identifier for the user account, chosen by the Relying Party. It is not meant to be displayed to the user. Its primary purpose is to allow the Relying Party to associate a credential with a user account.

The spec does not mandate whether user handles should be unique per user or per credential. However, the design of discoverable credentials and the Signal API strongly assumes a **one-user-handle-per-user** model.

---

## `PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL`

### Configuration

```bash
# Default: true
PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL=true
```

| Value | Behavior |
|-------|----------|
| `true` (default) | Each credential gets a new random 32-character `user_handle` |
| `false` | All credentials for a user share the same `user_handle` |

### When `true` (Unique Per Credential)

Every time a user registers a new passkey, a fresh random `user_handle` is generated:

```
User "alice" registers 3 passkeys:
  Credential A: user_handle = "rNd0mStr1ng_AAAA..."  credential_id = "cred_111"
  Credential B: user_handle = "rNd0mStr2ng_BBBB..."  credential_id = "cred_222"
  Credential C: user_handle = "rNd0mStr3ng_CCCC..."  credential_id = "cred_333"
```

From the authenticator's perspective, these appear as **three different users** because each has a different `user_handle`.

**Behavior details**:

- No credential cleanup during registration (each credential is independent)
- The user can register unlimited credentials from the same authenticator type
- Password managers that enforce "one credential per user per RP" will store all credentials independently
- Discoverable credential selection shows each credential as a separate entry

**Source**: `oauth2_passkey/src/passkey/main/register.rs` lines 64-71

```rust
if *PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL {
    let new_handle = gen_random_string(32)?;
    tracing::debug!(
        "Using unique user handle for every credential: {}",
        new_handle
    );
    return Ok(new_handle);
}
```

### When `false` (Shared Per User)

All credentials for the same user reuse the same `user_handle`:

```
User "alice" registers 3 passkeys:
  Credential A: user_handle = "aliceHandle123..."  credential_id = "cred_111"
  Credential B: user_handle = "aliceHandle123..."  credential_id = "cred_222"
  Credential C: user_handle = "aliceHandle123..."  credential_id = "cred_333"
```

From the authenticator's perspective, these all belong to **the same user**.

**Behavior details**:

- During registration, existing credentials with the same `user_handle`, `user_id`, and `aaguid` are deleted (one credential per authenticator type per user)
- Password managers may overwrite an existing credential with the same user handle on re-registration
- The authenticator can group all credentials under one user identity
- For already-logged-in users, the user_handle is retrieved from the first existing credential

**Source**: `oauth2_passkey/src/passkey/main/register.rs` lines 73-110

```rust
// Otherwise, follow the normal logic of reusing handles for logged-in users
if let Some(user) = session_user {
    let existing_credentials =
        PasskeyStore::get_credentials_by(CredentialSearchField::UserId(user_id)).await?;

    if !existing_credentials.is_empty() {
        // Reuse the existing user_handle from the first credential
        let existing_handle = existing_credentials[0].user.user_handle.clone();
        Ok(existing_handle)
    } else {
        let new_handle = gen_random_string(32)?;
        Ok(new_handle)
    }
}
```

### Credential Cleanup During Registration

When `false`, the library performs cleanup during registration to enforce the one-credential-per-authenticator-type policy:

**Source**: `oauth2_passkey/src/passkey/main/register.rs` lines 345-422

```rust
if !*PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL {
    // Find credentials with matching user_handle
    let credentials_with_matching_handle =
        PasskeyStore::get_credentials_by(
            CredentialSearchField::UserHandle(user_handle)
        ).await?;

    // Delete credentials that match user_handle + user_id + aaguid
    for cred in credentials_with_matching_handle {
        if cred.aaguid == aaguid && cred.user_id == user_id.as_str() {
            PasskeyStore::delete_credential_by(
                CredentialSearchField::CredentialId(credential_id)
            ).await?;
        }
    }
}
```

When `true`, this cleanup is skipped entirely because each credential has a unique `user_handle`, so there are no pre-existing credentials with the same handle.

### Database State Comparison

| Scenario | `true` | `false` |
|----------|--------|---------|
| Alice registers 1st passkey (Google Password Manager) | 1 credential, unique handle | 1 credential, handle H1 |
| Alice registers 2nd passkey (Google Password Manager) | 2 credentials, different handles | Old credential deleted, new credential with handle H1 |
| Alice registers 3rd passkey (YubiKey) | 3 credentials, all different handles | 2 credentials (1 GPM + 1 YubiKey), both with handle H1 |

---

## WebAuthn Signal API

### What is the Signal API?

The WebAuthn Signal API (part of CTAP 2.1 and WebAuthn Level 3) provides three functions for the relying party to communicate credential state to the authenticator:

| API | Purpose | Scope |
|-----|---------|-------|
| `signalAllAcceptedCredentials` | Tell the authenticator which credentials are still valid for a user | Per `userId` (user_handle) |
| `signalCurrentUserDetails` | Update user metadata (name, display name) in the authenticator | Per `userId` (user_handle) |
| `signalUnknownCredential` | Tell the authenticator that a specific credential is not recognized | Per `credentialId` |

### Browser Support

| Browser | Support |
|---------|---------|
| Chrome 132+ | Yes |
| Edge 132+ | Yes |
| Safari 26+ (macOS/iOS) | Yes |
| Firefox | Not supported |

All Signal API calls are **non-critical** and use feature detection:

```javascript
if (
    window.PublicKeyCredential &&
    typeof window.PublicKeyCredential.signalAllAcceptedCredentials === "function"
) {
    // API available
}
```

### `signalAllAcceptedCredentials`

```javascript
await PublicKeyCredential.signalAllAcceptedCredentials({
    rpId: "example.com",
    userId: base64urlEncodedUserHandle,
    allAcceptedCredentialIds: ["cred_111", "cred_222", "cred_333"],
});
```

**How the authenticator processes this**:

1. Find all stored credentials matching `rpId` AND `userId`
2. For each stored credential: if its `credentialId` is NOT in the `allAcceptedCredentialIds` list, mark it as removed/invalid
3. Credentials with a different `userId` are NOT affected

**Key point**: This API is scoped by `userId` (user_handle). It can only affect credentials that share the same user handle.

### `signalCurrentUserDetails`

```javascript
await PublicKeyCredential.signalCurrentUserDetails({
    rpId: "example.com",
    userId: base64urlEncodedUserHandle,
    name: "alice@example.com",
    displayName: "Alice",
});
```

Updates the display name and username for all credentials matching `rpId` AND `userId`.

### `signalUnknownCredential`

```javascript
await PublicKeyCredential.signalUnknownCredential({
    rpId: "example.com",
    credentialId: "cred_111",
});
```

**How the authenticator processes this**:

1. Find the stored credential matching `rpId` AND `credentialId`
2. Mark that credential as unknown/removed

**Key point**: This API is scoped by `credentialId` only. It does NOT depend on `userId` (user_handle).

---

## Signal API Behavior by User Handle Strategy

### When `false` (Shared User Handle) -- Signal API Works Correctly

All credentials share the same `user_handle`, so the authenticator correctly groups them as belonging to one user.

#### Credential Deletion

After deleting credential A from the server:

```javascript
// userId matches all remaining credentials
signalAllAcceptedCredentials({
    rpId: "example.com",
    userId: encode("aliceHandle123"),         // Shared handle
    allAcceptedCredentialIds: ["cred_222", "cred_333"],  // Remaining credentials
});
```

The authenticator:
1. Finds all credentials with `userId = aliceHandle123` -> credentials A, B, C
2. Credential A (`cred_111`) is NOT in the accepted list -> **removed**
3. Credentials B and C are in the list -> **kept**

**Result**: Correct. Deleted credential is removed, remaining credentials are confirmed.

#### Login Success

```javascript
signalAllAcceptedCredentials({
    rpId: "example.com",
    userId: encode("aliceHandle123"),
    allAcceptedCredentialIds: ["cred_111", "cred_222", "cred_333"],
});
```

**Result**: Correct. All credentials are confirmed as valid.

#### Login Failure

```javascript
signalUnknownCredential({
    rpId: "example.com",
    credentialId: "cred_111",
});
```

**Result**: Correct. The specific unrecognized credential is removed from the authenticator.

### When `true` (Unique User Handle) -- Signal API Is Largely Ineffective

Each credential has a different `user_handle`, so the authenticator sees them as separate users.

#### Credential Deletion

After deleting credential A (user_handle = `handle_aaa`) from the server:

```javascript
signalAllAcceptedCredentials({
    rpId: "example.com",
    userId: encode("handle_aaa"),             // Deleted credential's handle
    allAcceptedCredentialIds: ["cred_222", "cred_333"],  // Remaining credentials
});
```

The authenticator:
1. Finds credentials with `userId = handle_aaa` -> **only credential A**
2. Credential A (`cred_111`) is NOT in the accepted list -> **removed** (correct)
3. `cred_222` and `cred_333` have different `userId` values -> **not matched, ignored**

**Result**: The deleted credential itself may be removed (its `credentialId` is absent from the list), but the remaining credential IDs in the list are meaningless noise. The authenticator cannot verify or act on credentials that don't match the given `userId`.

Using `signalUnknownCredential` is simpler and more direct for this case:

```javascript
// More appropriate for unique-per-credential mode
signalUnknownCredential({
    rpId: "example.com",
    credentialId: "cred_111",  // Directly targets the deleted credential
});
```

#### Login Success

After authenticating with credential B (user_handle = `handle_bbb`):

```javascript
signalAllAcceptedCredentials({
    rpId: "example.com",
    userId: encode("handle_bbb"),             // Authenticated credential's handle
    allAcceptedCredentialIds: ["cred_111", "cred_222", "cred_333"],
});
```

The authenticator:
1. Finds credentials with `userId = handle_bbb` -> **only credential B**
2. Credential B (`cred_222`) IS in the list -> **confirmed** (trivially)
3. `cred_111` and `cred_333` have different `userId` values -> **ignored**

**Result**: Only confirms the credential that was just used for login. Cannot synchronize other credentials.

#### Login Failure

```javascript
signalUnknownCredential({
    rpId: "example.com",
    credentialId: "cred_111",
});
```

**Result**: Correct. Works by `credentialId`, independent of user handle strategy.

### Summary Table

| Signal API | `true` (unique) | `false` (shared) |
|------------|-----------------|-------------------|
| `signalAllAcceptedCredentials` (deletion) | Only removes the deleted credential; remaining IDs are noise | Correctly removes deleted credential and confirms remaining ones |
| `signalAllAcceptedCredentials` (login) | Only confirms the one authenticated credential | Confirms all credentials for the user |
| `signalCurrentUserDetails` (name update) | Updates only one credential's display info | Updates all credentials' display info |
| `signalUnknownCredential` (login failure) | Works correctly | Works correctly |

---

## Implementation Strategy

### Key Insight: API Effectiveness by Mode

From the analysis above, we can summarize which APIs work in which mode:

| API                            | `true` (unique handle)               | `false` (shared handle)               |
|--------------------------------|--------------------------------------|---------------------------------------|
| `signalUnknownCredential`      | Works (scoped by credentialId)       | Works (scoped by credentialId)        |
| `signalAllAcceptedCredentials` | Limited (only affects one credential)| Works (affects all user's credentials)|

This leads to a simple conclusion: **call both APIs** for credential deletion. Since the APIs are independent, idempotent, and non-conflicting, calling both ensures correct behavior regardless of the user handle strategy:

```javascript
// After successful credential deletion:
// IMPORTANT: These calls are fire-and-forget (no await) to avoid blocking page reload.
// The deletion has already succeeded on the server; Signal API is non-critical.

// 1. signalUnknownCredential: directly target the deleted credential
//    - Works correctly in BOTH modes (true and false)
//    - Scoped by credentialId, independent of user_handle
signalUnknownCredential({
    rpId: "example.com",
    credentialId: deletedCredentialId,
});

// 2. signalAllAcceptedCredentials: sync remaining credentials
//    - Fully effective when false (shared user_handle)
//    - Harmless but redundant when true (unique user_handle)
signalAllAcceptedCredentials({
    rpId: "example.com",
    userId: encode(userHandle),
    allAcceptedCredentialIds: remainingCredentialIds,
});
```

#### Result by Mode

| Mode    | `signalUnknownCredential`  | `signalAllAcceptedCredentials`         | Combined                           |
|---------|----------------------------|----------------------------------------|------------------------------------|
| `true`  | Removes deleted credential | Harmless (no-op for other credentials) | Deleted credential removed         |
| `false` | Removes deleted credential | Confirms remaining credentials         | Deleted credential removed + full sync |

#### Ordering

`signalUnknownCredential` is called first. This ensures the deleted credential is flagged immediately, even if the subsequent call fails.

### Login Flow

The login flow uses:

| Event | APIs Used | Notes |
|-------|-----------|-------|
| Login success | `signalAllAcceptedCredentials` | Effective for `false`; harmless for `true` |
| Login failure | `signalUnknownCredential` | Effective for both modes |

No dual approach is needed for login because:

- On success, there is no specific credential to signal as unknown
- On failure, `signalUnknownCredential` already works correctly for both modes

### Current Implementation

The implementation uses the dual approach for credential deletion:

- `account.js`: `deletePasskeyCredential()` calls both `synchronizeCredentialsWithSignalUnknown(credentialId)` and `synchronizeCredentials(userHandle, remainingCredentialIds)`
- `passkey.js`: Login success calls `signalAllAcceptedCredentials` via `signalAfterLogin()`; login failure calls `signalUnknownCredential`
- `conditional_ui.js`: Same as `passkey.js`

All Signal API calls are fire-and-forget (no await on success paths) to avoid blocking page navigation.

---

## Choosing the Right Strategy

### Use `true` (Unique Per Credential) When:

- Users need multiple passkeys from the same authenticator type (e.g., multiple Google Password Manager credentials)
- The application prioritizes maximum credential accumulation
- Signal API-based credential synchronization is not a priority
- The deployment primarily uses hardware security keys (which handle credential management independently)

### Use `false` (Shared Per User) When:

- Credential synchronization via Signal API is important
- The deployment targets modern browsers with Signal API support (Chrome 132+, Edge 132+, Safari 26+)
- Users typically have one credential per authenticator type
- Password manager compatibility is desired (many password managers enforce one credential per user handle per RP)
- The application wants the authenticator to display credentials grouped by user

### Migration Considerations

Switching from `true` to `false` requires consideration:

- **Existing credentials**: Credentials already registered with unique user handles will retain their individual handles. Only newly registered credentials will use the shared handle.
- **Mixed state**: During the transition period, the user may have some credentials with unique handles and some with the shared handle. Signal API will only synchronize credentials sharing the same handle.
- **Database migration**: No schema changes are required. The `user_handle` column remains the same; only the values stored change.
- **No backward compatibility issues**: Authentication works regardless of user handle strategy, since credential lookup is by `credential_id`, not by `user_handle`.

---

## Technical Reference

### Server-Side Data Flow

#### Authentication Response

After successful authentication, the server returns:

```json
{
  "name": "alice",
  "user_handle": "handle_of_authenticated_credential",
  "credential_ids": ["cred_111", "cred_222", "cred_333"]
}
```

- `user_handle`: From the specific credential used for authentication
- `credential_ids`: All credential IDs for this user (queried by `user_id`, not by `user_handle`)

**Source**: `oauth2_passkey/src/coordination/passkey.rs`

```rust
pub struct AuthenticationResponse {
    pub name: String,
    pub user_handle: String,
    pub credential_ids: Vec<String>,
}
```

#### Credential Deletion Response

After deleting a credential, the server returns:

```json
{
  "remaining_credential_ids": ["cred_222", "cred_333"],
  "user_handle": "handle_of_deleted_credential"
}
```

- `user_handle`: From the deleted credential (important: this is the deleted credential's handle, not the remaining credentials' handle)
- `remaining_credential_ids`: All credential IDs still registered for this user

**Source**: `oauth2_passkey/src/coordination/passkey.rs`

```rust
pub struct DeleteCredentialResponse {
    pub remaining_credential_ids: Vec<String>,
    pub user_handle: String,
}
```

### Client-Side Signal API Calls

#### After Successful Login (`passkey.js`, `conditional_ui.js`)

Signal API calls are fire-and-forget (no await) to avoid blocking page navigation:

```javascript
// IMPORTANT: This call is fire-and-forget to avoid blocking page reload.
// The login has already succeeded on the server; Signal API is non-critical.

const userIdBytes = new TextEncoder().encode(data.user_handle);
const userIdBase64Url = arrayBufferToBase64URL(userIdBytes.buffer);

// signalAllAcceptedCredentials: Tell authenticator which credentials are valid
PublicKeyCredential.signalAllAcceptedCredentials({
    rpId: window.location.hostname,
    userId: userIdBase64Url,
    allAcceptedCredentialIds: data.credential_ids,
});
```

#### After Login Failure (`passkey.js`, `conditional_ui.js`)

```javascript
await PublicKeyCredential.signalUnknownCredential({
    rpId: window.location.hostname,
    credentialId: credential.id,
});
```

#### After Credential Deletion (`account.js`)

Uses a dual approach for maximum compatibility across both user handle modes.
Signal API calls are fire-and-forget (no await) to avoid blocking page reload:

```javascript
const data = await response.json();

// IMPORTANT: These calls are fire-and-forget to avoid blocking page reload.
// The deletion has already succeeded on the server; Signal API is non-critical.

// Step 1: Signal the specific deleted credential as unknown
PublicKeyCredential.signalUnknownCredential({
    rpId: window.location.hostname,
    credentialId: deletedCredentialId,
});

// Step 2: Signal remaining accepted credentials
const userIdBytes = new TextEncoder().encode(data.user_handle);
const userIdBase64Url = arrayBufferToBase64URL(userIdBytes.buffer);
PublicKeyCredential.signalAllAcceptedCredentials({
    rpId: window.location.hostname,
    userId: userIdBase64Url,
    allAcceptedCredentialIds: data.remaining_credential_ids,
});
```

### Encoding Note

The user handle is stored as a UTF-8 string in the database. When passed to the Signal API, it must be encoded to base64url:

```javascript
const userIdBytes = new TextEncoder().encode(userHandle);  // String -> Uint8Array
const userIdBase64Url = arrayBufferToBase64URL(userIdBytes.buffer);  // Uint8Array -> base64url
```

This matches how the user handle is encoded during credential registration (`user.id` is set to `base64URLToUint8Array(userHandle)`).

---

## References

- [WebAuthn Level 3 Specification](https://www.w3.org/TR/webauthn-3/)
- [WebAuthn Signal API Explainer](https://github.com/nicognaW/nicognaw.github.io/blob/main/nicognaw-webauthn-signal-explainer.md)
- [Chrome Developers: Signal API](https://developer.chrome.com/docs/identity/passkeys/passkey-management)
- [CTAP 2.1 Specification](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html)
