# Type-Safe Validation

## What Is Type-Safe Validation?

In authentication code, many values are plain strings: user IDs, session IDs, credential IDs, email addresses, and so on. When functions accept raw `String` parameters, the compiler cannot tell them apart. This leads to a class of bugs where values are accidentally swapped:

```rust,ignore
// Both parameters are String — the compiler accepts this without complaint
fn delete_credential(session_id: String, credential_id: String) { /* ... */ }

// Bug: arguments are swapped, but the code compiles and runs
delete_credential(credential_id, session_id);
```

This is especially dangerous in authentication systems where such a mix-up can cause privilege escalation or silent data corruption.

**Type-safe validation** solves this by wrapping each string in a dedicated type (the "newtype pattern" in Rust):

```rust,ignore
// Each type is a thin wrapper around String
pub struct SessionId(String);
pub struct CredentialId(String);

// Now the function signature enforces correct usage
fn delete_credential(session_id: SessionId, credential_id: CredentialId) { /* ... */ }

// Bug caught at compile time — this will not compile
delete_credential(credential_id, session_id);
//                ^^^^^^^^^^^^^ expected `SessionId`, found `CredentialId`
```

The wrapper types also validate their contents on construction (e.g., checking length, allowed characters), so invalid values are rejected immediately rather than causing errors deep in the system.

## Why This Library Uses It

Authentication code handles many different string identifiers (session IDs, user IDs, credential IDs, cache keys, etc.) that pass through multiple layers. Without type-safe wrappers, two categories of bugs can occur:

1. **Parameter Confusion**: Raw string parameters can be silently swapped. For example, passing a `credential_id` where a `session_id` is expected compiles and runs, but produces incorrect behavior. In authentication code, this can lead to privilege escalation or data corruption.
2. **Unvalidated Input**: Raw strings carry no guarantee about their contents. Malformed, empty, or overly long values can propagate deep into the system before causing failures. Cache keys could contain characters that trigger Redis command injection.

By wrapping each identifier in its own type, these issues are caught at the point of entry: the compiler rejects type mix-ups, and the constructor rejects invalid input.

## Core Benefits

- **Compile-time safety**: Impossible to mix up parameter types (compiler rejects it)
- **Input validation at the boundary**: Invalid values are rejected at construction, never propagated
- **Single validation point**: Validate once at construction, never again
- **Consistent behavior**: Same validation rules regardless of backend/deployment
- **Performance**: Zero runtime overhead after construction (just a `String` wrapper)
- **Maintainability**: Centralized validation logic per type

## Available Types

All types follow the same newtype pattern. Here is the full implementation of `SessionId` as a representative example:

```rust,ignore
pub struct SessionId(String);  // Private inner field -- cannot be constructed directly

impl SessionId {
    pub fn new(id: String) -> Result<Self, SessionError> {
        // Must not be empty
        if id.is_empty() { return Err(SessionError::Validation("...".into())); }
        // Session IDs need sufficient entropy
        if id.len() < 10 { return Err(SessionError::Validation("...".into())); }
        if id.len() > 256 { return Err(SessionError::Validation("...".into())); }
        // URL-safe characters only (no whitespace)
        if !id.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~')) {
            return Err(SessionError::Validation("...".into()));
        }
        Ok(SessionId(id))
    }

    pub fn as_str(&self) -> &str { &self.0 }
}
```

Every type below works the same way: `new()` validates and returns `Result`, `as_str()` returns the inner string. The differences are in what each type accepts.

### Session & User Management

```rust,ignore
// SessionId: session identifiers for coordination layer functions
// Length: 10-256 | Chars: a-zA-Z0-9 - _ . ~ | Error: SessionError
pub struct SessionId(String);

// UserId: user identifiers (database IDs)
// Length: 1-255 | Chars: a-zA-Z0-9 - _ . @ + ( ) | Rejects: .. -- __ | Error: SessionError
pub struct UserId(String);

// SessionCookie: HTTP session cookie values
// Length: 10-1024 | Chars: a-zA-Z0-9 - _ = . + / | Error: SessionError
pub struct SessionCookie(String);
```

Usage:
```rust,ignore
let session_id = SessionId::new("session_abc123".to_string())?;
let user_id = UserId::new("user_123".to_string())?;
let user = get_user(session_id, user_id).await?;

let cookie = SessionCookie::new(cookie_value.to_string())?;
let user = get_user_from_session(&cookie).await?;
```

### WebAuthn/Passkey Types

```rust,ignore
// CredentialId: passkey credential identifiers (base64url-encoded)
// Length: 10-1024 | Chars: a-zA-Z0-9 - _ . ~ = + / | Error: PasskeyError
pub struct CredentialId(String);

// UserHandle: WebAuthn user handles
// NO VALIDATION -- accepts any string, returns Self (not Result)
// WebAuthn user handles can be arbitrary binary data (base64-encoded)
pub struct UserHandle(String);

// UserName: usernames for WebAuthn registration
// Length: 1-64 | Rejects: .. -- __ and whitespace-only | Error: PasskeyError
pub struct UserName(String);

// ChallengeType: identifies the WebAuthn operation kind
// Length: 1-64 | Chars: a-zA-Z0-9 _ | Error: PasskeyError
// Convenience constructors: ChallengeType::registration(), ChallengeType::authentication()
pub struct ChallengeType(String);

// ChallengeId: unique identifier for a specific challenge instance
// Length: 8-256 | Chars: a-zA-Z0-9 - _ . + | Error: PasskeyError
pub struct ChallengeId(String);
```

Usage:
```rust,ignore
let cred_id = CredentialId::new("credential_abc123".to_string())?;
delete_credential(session_id, cred_id).await?;

let handle = UserHandle::new("user_handle_123".to_string()); // no ? -- always succeeds

let challenge_type = ChallengeType::registration(); // convenience constructor, no validation needed
```

### OAuth2 Types

```rust,ignore
// OAuth2State: OAuth2 state parameter carrying CSRF protection data
// Length: 10-8192 | Error: OAuth2Error
// Multi-layer validation: base64url decode -> UTF-8 check -> JSON parse as StateParams
// This is the most heavily validated type in the library.
pub struct OAuth2State(String);

// AccountId: database identifiers for OAuth2 accounts
// Length: 1-255 | Chars: a-zA-Z0-9 - _ . @ + | Rejects: .. -- __ | Error: OAuth2Error
pub struct AccountId(String);

// Provider: OAuth2 provider names (e.g., "google", "github")
// Length: 1-50 | Chars: a-zA-Z0-9 - _ . | Cannot start with - _ . | Error: OAuth2Error
pub struct Provider(String);

// ProviderUserId: external user IDs from OAuth2 providers
// Length: 1-512 | Chars: a-zA-Z0-9 - _ . @ + = ( ) | Rejects: .. -- __ | Error: OAuth2Error
pub struct ProviderUserId(String);

// DisplayName: user display names from OAuth2 providers
// Length: 1-100 | Rejects: .. -- __ and whitespace-only | Error: OAuth2Error
pub struct DisplayName(String);

// Email: email addresses from OAuth2 providers
// Length: 3-254 (RFC 5321) | Must have exactly one @ with non-empty local/domain | Error: OAuth2Error
pub struct Email(String);
```

Usage:
```rust,ignore
let state = OAuth2State::new(state_param.to_string())?; // validates base64url -> UTF-8 -> JSON
let decoded = decode_state(&state)?;

let provider = Provider::new("google".to_string())?;
let email = Email::new("alice@example.com".to_string())?;
```

### Cache & Storage Types

```rust,ignore
// CachePrefix and CacheKey share identical validation logic.
// Both are designed to prevent Redis command injection.
//
// Length: max 250 bytes
// Rejected chars: \n \r space \t
// Rejected keywords: SET, GET, DEL, FLUSHDB, FLUSHALL, EVAL, SCRIPT,
//                    SHUTDOWN, CONFIG, CLIENT, DEBUG, MONITOR, SYNC
// Error: StorageError
pub struct CachePrefix(String);
pub struct CacheKey(String);

// CachePrefix provides convenience constructors for common prefixes.
// These bypass validation since they are known-good compile-time constants:
//   CachePrefix::session(), CachePrefix::csrf(), CachePrefix::jwks(),
//   CachePrefix::pkce(), CachePrefix::nonce(), CachePrefix::aaguid(), ...
```

Usage:
```rust,ignore
// From string (with validation)
let prefix = CachePrefix::new("custom_prefix".to_string())?;

// Convenience constructors (known-good values, no validation overhead)
let session_prefix = CachePrefix::session();
let csrf_prefix = CachePrefix::csrf();
```

## Search Field Enums

Database queries often need to search by different fields. Without type safety, you might write:

```rust,ignore
// Dangerous: which field does this string refer to? A user ID? An email? A credential ID?
fn get_credentials(field_name: &str, value: &str) -> Vec<Credential> { /* ... */ }
```

Search field enums combine the field selection and the typed value into a single type, so the compiler ensures you cannot pass an `Email` when searching by `CredentialId`:

```rust,ignore
// Passkey credential searches
pub enum CredentialSearchField {
    CredentialId(CredentialId),  // find by credential ID
    UserId(UserId),             // find all credentials for a user
    UserHandle(UserHandle),     // find by WebAuthn user handle
    UserName(UserName),         // find by username
}

// OAuth2 account searches
pub enum AccountSearchField {
    Id(AccountId),              // find by account ID
    UserId(UserId),             // find all accounts for a user
    Provider(Provider),         // find by provider name
    ProviderUserId(ProviderUserId), // find by provider-specific user ID
    Name(DisplayName),          // find by display name
    Email(Email),               // find by email address
}
```

Usage:
```rust,ignore
// Each variant carries a validated typed value -- no raw strings anywhere
let user_id = UserId::new("user_123".to_string())?;
let credentials = PasskeyStore::get_credentials_by(
    CredentialSearchField::UserId(user_id)  // compiler ensures UserId goes into UserId variant
).await?;

let email = Email::new("alice@example.com".to_string())?;
let accounts = OAuth2Store::get_accounts_by(
    AccountSearchField::Email(email)  // cannot accidentally pass a Provider here
).await?;
```

## Security Guarantees

### Compile-Time Safety
- **Parameter Confusion Prevention**: Cannot pass `UserId` where `CredentialId` expected
- **Type Mixing Protection**: Compiler enforces correct parameter types
- **API Consistency**: All functions use consistent typed interfaces

### Runtime Validation
- **Input Validation**: All types validate their input during construction
- **Cache Security**: Prevents Redis command injection across all backends
- **Length Limits**: Enforces reasonable bounds on all identifiers

### Storage Backend Consistency
- **Unified Validation**: Same security guarantees regardless of storage backend
- **Memory vs Redis**: No deployment-specific vulnerabilities
- **Centralized Logic**: Single validation point per type for easier maintenance

## Security vs Performance Tradeoff

The type-safe validation system is designed for **zero runtime overhead**:

- **Validation occurs once** at type construction
- **No repeated validation** during function calls
- **Compile-time guarantees** eliminate runtime checks
- **Memory overhead** is minimal (single String wrapper per type)

This approach provides maximum security with optimal performance for authentication-critical code paths.

## Usage Patterns

### Coordination Layer Functions
All coordination functions require typed parameters:

```rust,ignore
// Admin functions
get_all_users(session_id: SessionId) -> Result<Vec<User>, CoordinationError>
get_user(session_id: SessionId, user_id: UserId) -> Result<Option<User>, CoordinationError>
delete_credential(session_id: SessionId, credential_id: CredentialId) -> Result<(), CoordinationError>

// User functions
get_user_credentials(session_id: SessionId, user_id: UserId) -> Result<Vec<PasskeyCredential>, CoordinationError>
```

### Session Management
```rust,ignore
// Session validation
get_user_from_session(session_cookie: &SessionCookie) -> Result<SessionUser, SessionError>

// CSRF token handling uses typed SessionId internally
get_csrf_token_from_session(session_cookie: &str) -> Result<CsrfToken, SessionError>
```

### OAuth2 Operations
```rust,ignore
// State parameter handling
encode_state(params: StateParams) -> Result<OAuth2State, OAuth2Error>
decode_state(state: &OAuth2State) -> Result<StateParams, OAuth2Error>

// Account search with typed enums
OAuth2Store::get_accounts_by(search_field: AccountSearchField) -> Result<Vec<OAuth2Account>, OAuth2Error>
```

### Cache Operations
```rust,ignore
// Unified cache operations with type safety
store_cache_auto(prefix: CachePrefix, data: T, ttl: u64) -> Result<String, E>
store_cache_keyed(prefix: CachePrefix, key: CacheKey, data: T, ttl: u64) -> Result<(), E>
get_data(prefix: CachePrefix, key: CacheKey) -> Result<Option<T>, E>
```

## Error Handling

All typed constructors can fail with validation errors:

```rust,ignore
// Handle validation errors
match SessionCookie::new(cookie_value.to_string()) {
    Ok(cookie) => {
        let user = get_user_from_session(&cookie).await?;
        // Use validated cookie
    }
    Err(SessionError::Cookie(msg)) => {
        // Handle invalid cookie format
    }
}

match OAuth2State::new(state_param.to_string()) {
    Ok(state) => {
        let params = decode_state(&state)?;
        // Use validated state
    }
    Err(OAuth2Error::DecodeState(msg)) => {
        // Handle invalid state format
    }
}
```

## Benefits for Developers

### IDE Support
- **Auto-completion**: IDEs show exactly what types are expected
- **Type Checking**: Immediate feedback on parameter mistakes
- **Refactoring Safety**: Compiler catches all places needing updates

### Code Clarity
- **Self-Documenting**: Function signatures show validation requirements
- **Intent Clear**: Type names indicate the purpose of each parameter
- **Consistent APIs**: Same patterns across all modules

### Security by Default
- **No Bypass**: Impossible to accidentally use raw strings
- **Validation Required**: Must construct types with proper validation
- **Defense in Depth**: Multiple layers of protection

## Migration from Raw Strings

When migrating existing code from raw strings to typed wrappers, the change is straightforward. The key difference is that the typed version catches invalid input immediately and prevents parameter mix-ups at compile time:

```rust,ignore
// Before: raw String — no validation, no type safety
// A malicious or malformed user_id passes through silently.
// Swapping user_id with another String parameter compiles without error.
let credentials = PasskeyStore::get_credentials_by(
    CredentialSearchField::UserId(user_id.to_string())
);

// After: typed wrapper — validated on construction, type-checked by compiler
// UserId::new() rejects empty strings, overly long values, and dangerous characters.
// Passing a CredentialId where UserId is expected is a compile error.
let user_id = UserId::new(user_id_string.to_string())?;
let credentials = PasskeyStore::get_credentials_by(
    CredentialSearchField::UserId(user_id)
);
```
