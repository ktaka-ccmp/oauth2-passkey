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

This library provides an option to generate a unique user handle for each credential. This allows a single user to register multiple credentials from the same authenticator type (e.g., multiple passkeys in Google Password Manager), which would otherwise be prevented by password managers that enforce "one credential per user per RP".

---

## `PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL`

### Configuration

```bash
# Default: true
PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL=true
```

| Value            | `user_handle`         | Credentials per authenticator |
|------------------|-----------------------|-------------------------------|
| `true` (default) | Unique per credential | Unlimited                     |
| `false`          | Shared per user       | One                           |

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

> **Note**: In the deletion rule above, `user_id` refers to the application's internal user identifier (database primary key), not the WebAuthn `user_handle`.

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

The WebAuthn Signal API (part of CTAP 2.1 and WebAuthn Level 3) provides functions for the relying party to communicate credential state to the authenticator (password manager, platform authenticator).

### Current Reality (2026-01)

> **Important**: Testing with Chrome + Google Password Manager shows that **only `signalUnknownCredential` actually works** for credential removal. `signalAllAcceptedCredentials` has no visible effect.

| API | Purpose | Status |
|-----|---------|--------|
| `signalUnknownCredential` | Remove a specific credential from authenticator | ✅ **Works** |
| `signalCurrentUserDetails` | Update user metadata (name, display name) | ✅ Works |
| `signalAllAcceptedCredentials` | Sync valid credential list | ❌ No effect |

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
    typeof window.PublicKeyCredential.signalUnknownCredential === "function"
) {
    // API available
}
```

### `signalUnknownCredential` (Primary API)

The **only working API** for credential removal with Google Password Manager.

```javascript
await PublicKeyCredential.signalUnknownCredential({
    rpId: "example.com",
    credentialId: "cred_111",
});
```

**How the authenticator processes this**:

1. Find the stored credential matching `rpId` AND `credentialId`
2. Remove that credential from the authenticator

**Key advantages**:

- Scoped by `credentialId` only -- works regardless of `user_handle` strategy
- Simple and direct -- targets exactly one credential
- Actually works with current browsers and password managers

### `signalCurrentUserDetails`

```javascript
await PublicKeyCredential.signalCurrentUserDetails({
    rpId: "example.com",
    userId: base64urlEncodedUserHandle,
    name: "alice@example.com",
    displayName: "Alice",
});
```

Updates the display name and username for credentials matching `rpId` AND `userId`. This API works correctly.

### `signalAllAcceptedCredentials` (Currently Ineffective)

> **Note**: This API currently has **no visible effect** on Google Password Manager. It is kept in the codebase for future compatibility.

```javascript
await PublicKeyCredential.signalAllAcceptedCredentials({
    rpId: "example.com",
    userId: base64urlEncodedUserHandle,
    allAcceptedCredentialIds: ["cred_111", "cred_222", "cred_333"],
});
```

**Theoretical behavior** (per WebAuthn spec):

1. Find all stored credentials matching `rpId` AND `userId`
2. For each stored credential: if its `credentialId` is NOT in the list, mark it as removed
3. Credentials with a different `userId` are NOT affected

**Actual behavior** (Chrome + GPM, 2026-01):

- API call succeeds without error
- No credentials are removed or hidden
- No visible change in passkey selection dialog

This API may work in future browser updates or with different authenticators.

> **Terminology note**: The Signal API uses `userId` as the parameter name. This is the same value as `user.id` (registration), `userHandle` (authentication response), and `user_handle` (this library's database field).

---

## Signal API Behavior by User Handle Strategy

### `signalUnknownCredential` -- Works in Both Modes

The key advantage of `signalUnknownCredential` is that it works **regardless of user handle strategy**. It targets credentials by `credentialId`, not by `user_handle`.

#### Credential Deletion (Both Modes)

```javascript
// Works identically in both true and false modes
signalUnknownCredential({
    rpId: "example.com",
    credentialId: "cred_111",  // Directly targets the deleted credential
});
```

**Result**: The deleted credential is removed from the authenticator. Simple and direct.

#### Login Failure (Both Modes)

When authentication fails because the server doesn't recognize a credential:

```javascript
signalUnknownCredential({
    rpId: "example.com",
    credentialId: credential.id,  // The unrecognized credential
});
```

**Result**: The orphaned credential is removed from the authenticator.

### `signalAllAcceptedCredentials` -- Theoretical Differences by Mode

> **Note**: This API currently has no effect on Google Password Manager. The following describes theoretical behavior per the WebAuthn spec.

#### When `false` (Shared User Handle)

All credentials share the same `user_handle`, so the API can theoretically affect all credentials:

```javascript
signalAllAcceptedCredentials({
    rpId: "example.com",
    userId: encode("aliceHandle123"),         // Shared handle
    allAcceptedCredentialIds: ["cred_222", "cred_333"],  // Remaining credentials
});
```

**Theoretical result**: Credential `cred_111` (not in list) would be removed.

#### When `true` (Unique User Handle)

Each credential has a different `user_handle`, so the API only affects one credential at a time:

```javascript
signalAllAcceptedCredentials({
    rpId: "example.com",
    userId: encode("handle_aaa"),             // Only matches credential A
    allAcceptedCredentialIds: [],             // Empty list
});
```

**Theoretical result**: Only the credential with matching `user_handle` would be affected.

### Summary Table

| Signal API | `true` (unique) | `false` (shared) | Actual Status |
|------------|-----------------|-------------------|---------------|
| `signalUnknownCredential` | ✅ Works | ✅ Works | **Use this** |
| `signalCurrentUserDetails` | Updates one credential | Updates all credentials | Works |
| `signalAllAcceptedCredentials` | Limited scope | Full scope | ❌ No effect |

---

## Implementation Strategy

### Primary Approach: `signalUnknownCredential`

The library uses `signalUnknownCredential` as the **primary and default** method for credential synchronization because:

1. **It actually works** - the only API that removes credentials from Google Password Manager
2. **No user_handle dependency** - works identically regardless of `PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL` setting
3. **Simple and direct** - targets exactly the credential that was deleted

### Signal API Mode Configuration

The `PASSKEY_SIGNAL_API_MODE` environment variable controls which Signal APIs are called:

```bash
# Default: 'direct'
PASSKEY_SIGNAL_API_MODE=direct
```

| Value | APIs Called | Use Case |
|-------|-------------|----------|
| `direct` (default) | `signalUnknownCredential` only | **Production** - use this |
| `sync` | `signalAllAcceptedCredentials` only | Testing `signalAllAcceptedCredentials` in isolation |
| `direct+sync` | Both APIs | Future compatibility testing |

**Important**: This is a **server-side only** configuration. The client-side behavior is controlled entirely by the server response content:

- Server always includes `signal_api_mode` in responses
- When mode includes `direct`: Client calls `signalUnknownCredential`
- When mode includes `sync`: Server also includes `credential_ids` and `user_handle`, client calls `signalAllAcceptedCredentials`

This design means **custom page developers do not need to configure Signal API behavior** -- it's handled automatically by the library.

**Pure `sync` mode**: When set to `sync` (without `direct`), only `signalAllAcceptedCredentials` is called. This is useful for testing whether `signalAllAcceptedCredentials` alone can properly synchronize credentials with the authenticator, without `signalUnknownCredential` interference.

### Credential Deletion Flow

When a credential is deleted from the server:

```javascript
// Fire-and-forget (no await) to avoid blocking page reload
signalUnknownCredential({
    rpId: "example.com",
    credentialId: deletedCredentialId,
});
```

**Result**: The deleted credential is immediately removed from the authenticator.

### Login Failure Flow

When authentication fails because the server doesn't recognize a credential:

```javascript
signalUnknownCredential({
    rpId: "example.com",
    credentialId: credential.id,
});
```

**Result**: The orphaned credential is removed, preventing future failed attempts.

### Optional: `signalAllAcceptedCredentials` (Future Compatibility)

When `PASSKEY_SIGNAL_API_MODE` includes `sync`, the server includes `credential_ids` and `user_handle` in responses. The client then calls `signalAllAcceptedCredentials`:

```javascript
// Only called if server returns credential_ids in response
// Currently has no effect on Chrome + GPM, kept for future compatibility
if (data.credential_ids && data.user_handle) {
    signalAllAcceptedCredentials({
        rpId: "example.com",
        userId: encode(data.user_handle),
        allAcceptedCredentialIds: data.credential_ids,
    });
}
```

This approach eliminates the need for client-side configuration -- the server controls the behavior via response content. This may work in future browser updates or with different authenticators (iCloud Keychain, etc.).

---

## Choosing the Right Strategy

> **Note**: Since `signalUnknownCredential` works regardless of user handle strategy, Signal API behavior is no longer a primary consideration when choosing between modes.

### Use `true` (Unique Per Credential) When:

- Users need multiple passkeys from the same authenticator type (e.g., multiple Google Password Manager credentials)
- The application prioritizes maximum credential accumulation
- The deployment primarily uses hardware security keys
- You want each credential to appear as a separate entry in the passkey selection dialog

### Use `false` (Shared Per User) When:

- Users typically have one credential per authenticator type
- Password manager compatibility is desired (many password managers enforce one credential per user handle per RP)
- The application wants the authenticator to display credentials grouped by user
- You prefer automatic cleanup of old credentials during re-registration

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
// When PASSKEY_SIGNAL_API_MODE includes 'sync':
{
  "name": "alice",
  "signal_api_mode": "direct+sync",
  "user_handle": "handle_of_authenticated_credential",
  "credential_ids": ["cred_111", "cred_222", "cred_333"]
}

// When PASSKEY_SIGNAL_API_MODE is 'direct' (default):
{
  "name": "alice",
  "signal_api_mode": "direct"
}
```

- `name`: Always included
- `signal_api_mode`: Always included (controls whether client calls `signalUnknownCredential`)
- `user_handle`: Only included when mode includes 'sync'
- `credential_ids`: Only included when mode includes 'sync' (all credential IDs for this user, queried by `user_id`, not by `user_handle`)

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
// When PASSKEY_SIGNAL_API_MODE includes 'sync':
{
  "signal_api_mode": "direct+sync",
  "remaining_credential_ids": ["cred_222", "cred_333"],
  "user_handle": "handle_of_deleted_credential"
}

// When PASSKEY_SIGNAL_API_MODE is 'direct' (default):
{
  "signal_api_mode": "direct"
}
```

- `signal_api_mode`: Always included (controls whether client calls `signalUnknownCredential`)
- `user_handle`: Only included when mode includes 'sync' (from the deleted credential)
- `remaining_credential_ids`: Only included when mode includes 'sync' (credential IDs with the same `user_handle` as the deleted credential, filtered for `signalAllAcceptedCredentials` which is scoped by userId)

**Source**: `oauth2_passkey/src/coordination/passkey.rs`

```rust
pub struct DeleteCredentialResponse {
    pub remaining_credential_ids: Vec<String>,
    pub user_handle: String,
}
```

### Client-Side Signal API Calls

All Signal API calls are **fire-and-forget** (no await) to avoid blocking page navigation. The authentication/deletion has already succeeded on the server; Signal API is non-critical.

#### After Login Failure (`passkey.js`, `conditional_ui.js`)

Remove the unrecognized credential from the authenticator:

```javascript
// Fire-and-forget - don't block error handling
PublicKeyCredential.signalUnknownCredential({
    rpId: window.location.hostname,
    credentialId: credential.id,
});
```

#### After Credential Deletion (`account.js`)

Remove the deleted credential from the authenticator. The server controls which APIs are called via `signal_api_mode`:

```javascript
const data = await response.json();
const mode = data.signal_api_mode || "direct";

// signalUnknownCredential - only if mode includes 'direct'
// Works with any user_handle strategy
if (mode.includes("direct")) {
    signalUnknownCredential({
        rpId: window.location.hostname,
        credentialId: deletedCredentialId,
    });
}

// signalAllAcceptedCredentials - only if server returns remaining_credential_ids
// Server includes these fields when mode includes 'sync'
if (data.remaining_credential_ids && data.user_handle) {
    signalAllAcceptedCredentials({
        rpId: window.location.hostname,
        userId: encode(data.user_handle),
        allAcceptedCredentialIds: data.remaining_credential_ids,
    });
}
```

#### After Successful Login (Optional)

When `PASSKEY_SIGNAL_API_MODE` includes `sync`, the server includes `credential_ids` and `user_handle` in the authentication response. The client detects this and calls `signalAllAcceptedCredentials`:

```javascript
// Server controls whether this is called by including credential_ids in response
// No client-side configuration needed
// Currently has no effect on Chrome + GPM
if (data.credential_ids && data.user_handle) {
    const userIdBytes = new TextEncoder().encode(data.user_handle);
    const userIdBase64Url = arrayBufferToBase64URL(userIdBytes.buffer);

    PublicKeyCredential.signalAllAcceptedCredentials({
        rpId: window.location.hostname,
        userId: userIdBase64Url,
        allAcceptedCredentialIds: data.credential_ids,
    });
}
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
