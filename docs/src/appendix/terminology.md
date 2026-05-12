# Terminology and Glossary

This document clarifies the terminology used in WebAuthn, OAuth2, and this library. Many identifier terms can be confusing because the same concept has different names in different contexts.

## User Identifiers

### Quick Reference

| Term | Context | Description |
|------|---------|-------------|
| `user_id` | This library (database) | Application's internal user identifier (database primary key) |
| `user_handle` | This library (database) | WebAuthn user identifier stored with credentials |
| `user.id` | WebAuthn registration | User identifier in `PublicKeyCredentialUserEntity` |
| `userHandle` | WebAuthn authentication | Returned in `AuthenticatorAssertionResponse` |
| `userId` | Signal API | Parameter name for user identifier |

### Key Distinction

**`user_id` is different from `user_handle`/`user.id`/`userHandle`/`userId`.**

- `user_id`: The application's internal database identifier for the user account
- `user_handle`: The WebAuthn-specific identifier that the authenticator stores and returns

The terms `user_handle`, `user.id`, `userHandle`, and `userId` all refer to the **same value** - just in different contexts:

- **Registration**: `user.id` in `PublicKeyCredentialUserEntity`
- **Authentication**: `userHandle` in `AuthenticatorAssertionResponse`
- **Signal API**: `userId` parameter
- **This library's database**: `user_handle` column

### Database Relationship

```
Application Database:
+---------------------------------------------+
| users table                                 |
|   user_id (PK) ------------------+          |
|   account, label                 |          |
+----------------------------------|---------+
                                   v
+---------------------------------------------+
| passkey_credentials table                   |
|   credential_id (PK)                        |
|   user_id (FK) <----------------|          |
|   user_handle --------> WebAuthn user.id    |
|   public_key, aaguid                        |
+---------------------------------------------+

WebAuthn Term Aliases:
  Registration:   user.id --------+
  Authentication: userHandle -----+---> Same value
  Signal API:     userId ---------+
  This library:   user_handle ----+
```

## Credential Identifiers

| Term | Context | Description |
|------|---------|-------------|
| `credential_id` | This library (database) | Base64URL-encoded credential identifier |
| `credentialId` | WebAuthn/Signal API | Raw credential identifier (Uint8Array or Base64URL) |
| `id` | `PublicKeyCredential` | Same as credentialId, Base64URL-encoded |
| `rawId` | `PublicKeyCredential` | Same as credentialId, ArrayBuffer format |

### Encoding Note

In JavaScript, credential IDs come in two formats from `PublicKeyCredential`:
- `id`: Base64URL-encoded string
- `rawId`: Raw `ArrayBuffer`

This library stores credential IDs as Base64URL-encoded strings in the database.

## Session Identifiers

| Term | Context | Description |
|------|---------|-------------|
| `session_id` | This library | Internal session identifier stored in cache |
| `session_cookie` | HTTP | Cookie value sent to the client |
| `SessionId` | Type wrapper | Type-safe wrapper for session identifiers |
| `SessionCookie` | Type wrapper | Type-safe wrapper for session cookie values |

## OAuth2 Identifiers

| Term | Context | Description |
|------|---------|-------------|
| `provider` | This library | OAuth2 provider name (e.g., "google") |
| `provider_user_id` | This library | User ID from the OAuth2 provider |
| `sub` | OIDC | Subject identifier in ID token (same as provider_user_id) |

## Type-Safe Wrappers

This library uses type-safe wrappers to prevent identifier confusion at compile time. See [Type-Safe Validation](type-safe.md) for details.

| Type | Wraps | Description |
|------|-------|-------------|
| `UserId` | `String` | Database user identifier |
| `CredentialId` | `String` | Passkey credential identifier |
| `SessionId` | `String` | Session identifier |
| `SessionCookie` | `String` | Session cookie value |
| `UserHandle` | `String` | WebAuthn user handle |
| `Provider` | `String` | OAuth2 provider name |
| `ProviderUserId` | `String` | OAuth2 provider's user ID |

## Common Confusion Points

### 1. user_id vs user_handle

```rust,ignore
// WRONG: These are different!
let user_id = "db_user_123";      // Database primary key
let user_handle = "webauthn_abc"; // WebAuthn identifier

// They relate to different concepts:
// - user_id: Identifies the user in YOUR application
// - user_handle: Identifies the user to the AUTHENTICATOR
```

### 2. Multiple credentials, one user

A single user (`user_id`) can have multiple passkey credentials, each with its own `credential_id`. Depending on configuration, they may share the same `user_handle` or each have a unique one.

| Configuration | user_handle per credential |
|--------------|---------------------------|
| `PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL=false` (default) | Shared |
| `PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL=true` | Unique |

### 3. Signal API userId parameter

The Signal API uses `userId` as the parameter name, but this is the **WebAuthn user handle**, not the application's `user_id`:

```javascript
// CORRECT: userId here is the user_handle value
PublicKeyCredential.signalAllAcceptedCredentials({
    rpId: "example.com",
    userId: base64urlEncode(user_handle),  // NOT user_id!
    allAcceptedCredentialIds: [...]
});
```

## See Also

- [User Handle and Signal API](../webauthn/user-handle-and-signal-api.md) - Detailed explanation of user handle strategies
- [Type-Safe Validation](type-safe.md) - Compile-time type safety for identifiers
