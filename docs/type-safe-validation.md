# Type-Safe Validation

The oauth2-passkey library implements comprehensive type-safe validation throughout the codebase to prevent authentication vulnerabilities and provide compile-time safety guarantees.

## Problem Statement

The type-safe validation system was implemented to address critical security and consistency issues:

1. **Security Vulnerabilities**: Functions were trusting session data without database validation, enabling privilege escalation attacks
2. **Backend Inconsistency**: Redis deployments had validation while Memory deployments didn't, creating deployment-specific vulnerabilities  
3. **Parameter Confusion**: Raw string parameters could be mixed up, leading to authentication logic errors

## Core Benefits

- ✅ **Compile-time safety**: Impossible to construct invalid values or mix up parameter types
- ✅ **Single validation point**: Validate once at construction, never again  
- ✅ **Consistent behavior**: Same validation rules regardless of backend/deployment
- ✅ **Defense-in-depth**: Multiple layers of validation protection
- ✅ **Performance**: Zero runtime overhead after construction
- ✅ **Maintainability**: Centralized validation logic

## Available Types

### Session & User Management

#### `SessionId`
Type-safe wrapper for session identifiers used in coordination layer functions.

```rust
use oauth2_passkey::SessionId;

// Create from string
let session_id = SessionId::new("session_abc123".to_string());

// Use in coordination functions
let users = get_all_users(session_id).await?;
```

#### `UserId` 
Type-safe wrapper for user identifiers to prevent mixing up with other ID types.

```rust
use oauth2_passkey::UserId;

let user_id = UserId::new("user_123".to_string());
let user = get_user(session_id, user_id).await?;
```

#### `SessionCookie`
Type-safe wrapper for HTTP session cookies with validation.

```rust
use oauth2_passkey::SessionCookie;

// Validates length (10-1024 chars) and safe characters
let cookie = SessionCookie::new(cookie_value.to_string())?;
let user = get_user_from_session(&cookie).await?;
```

### WebAuthn/Passkey Types

#### `CredentialId`
Type-safe wrapper for passkey credential identifiers.

```rust
use oauth2_passkey::CredentialId;

let cred_id = CredentialId::new("credential_abc".to_string());
let result = delete_credential(session_id, cred_id).await?;
```

#### `UserHandle` 
Type-safe wrapper for WebAuthn user handles.

```rust
use oauth2_passkey::UserHandle;

let handle = UserHandle::new("user_handle_123".to_string());
```

#### `UserName`
Type-safe wrapper for usernames.

```rust
use oauth2_passkey::UserName;

let username = UserName::new("alice".to_string());
```

#### `ChallengeType`
Type-safe wrapper for WebAuthn challenge types with validation.

```rust
use oauth2_passkey::ChallengeType;

// Validates against known challenge types
let challenge_type = ChallengeType::new("registration".to_string())?;

// Or use convenience constructors
let reg_challenge = ChallengeType::registration();
let auth_challenge = ChallengeType::authentication();
```

#### `ChallengeId`
Type-safe wrapper for challenge identifiers.

```rust
use oauth2_passkey::ChallengeId;

let challenge_id = ChallengeId::new("challenge_xyz".to_string())?;
```

### OAuth2 Types

#### `OAuth2State`
Type-safe wrapper for OAuth2 state parameters with comprehensive validation.

```rust
use oauth2_passkey::OAuth2State;

// Validates base64url encoding, JSON structure, length limits
let state = OAuth2State::new(state_param.to_string())?;
let decoded = decode_state(&state)?;
```

#### `AccountId`
Type-safe wrapper for OAuth2 account identifiers.

```rust
use oauth2_passkey::AccountId;

let account_id = AccountId::new("account_123".to_string());
```

#### `Provider`
Type-safe wrapper for OAuth2 provider names.

```rust
use oauth2_passkey::Provider;

let provider = Provider::new("google".to_string());
```

#### `ProviderUserId`
Type-safe wrapper for provider-specific user identifiers.

```rust
use oauth2_passkey::ProviderUserId;

let provider_user_id = ProviderUserId::new("google_123456".to_string());
```

#### `DisplayName`
Type-safe wrapper for user display names.

```rust
use oauth2_passkey::DisplayName;

let name = DisplayName::new("Alice Smith".to_string());
```

#### `Email`
Type-safe wrapper for email addresses.

```rust
use oauth2_passkey::Email;

let email = Email::new("alice@example.com".to_string());
```

### Cache & Storage Types

#### `CachePrefix`
Type-safe wrapper for cache namespace prefixes with validation.

```rust
use oauth2_passkey::CachePrefix;

// Validates length, safe characters, prevents Redis injection
let prefix = CachePrefix::new("session".to_string())?;

// Or use convenience constructors
let session_prefix = CachePrefix::session();
let oauth2_prefix = CachePrefix::oauth2();
```

#### `CacheKey`
Type-safe wrapper for cache entry keys with validation.

```rust
use oauth2_passkey::CacheKey;

// Same validation as CachePrefix
let key = CacheKey::new("user_123_token".to_string())?;
```

## Search Field Enums

### `CredentialSearchField`
Type-safe search operations for passkey credentials.

```rust
use oauth2_passkey::{CredentialSearchField, CredentialId, UserId, UserHandle, UserName};

// Search by different field types - compile-time type safety
let by_cred_id = CredentialSearchField::CredentialId(credential_id);
let by_user_id = CredentialSearchField::UserId(user_id);  
let by_handle = CredentialSearchField::UserHandle(user_handle);
let by_name = CredentialSearchField::UserName(user_name);

let credentials = PasskeyStore::get_credentials_by(by_user_id).await?;
```

### `AccountSearchField` 
Type-safe search operations for OAuth2 accounts.

```rust
use oauth2_passkey::{AccountSearchField, AccountId, UserId, Provider, Email};

let by_account_id = AccountSearchField::Id(account_id);
let by_user_id = AccountSearchField::UserId(user_id);
let by_provider = AccountSearchField::Provider(provider);
let by_email = AccountSearchField::Email(email);

let accounts = OAuth2Store::get_accounts_by(by_email).await?;
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

```rust
// Admin functions
get_all_users(session_id: SessionId) -> Result<Vec<User>, CoordinationError>
get_user(session_id: SessionId, user_id: UserId) -> Result<Option<User>, CoordinationError>
delete_credential(session_id: SessionId, credential_id: CredentialId) -> Result<(), CoordinationError>

// User functions  
get_user_credentials(session_id: SessionId, user_id: UserId) -> Result<Vec<PasskeyCredential>, CoordinationError>
```

### Session Management
```rust
// Session validation
get_user_from_session(session_cookie: &SessionCookie) -> Result<SessionUser, SessionError>

// CSRF token handling uses typed SessionId internally
get_csrf_token_from_session(session_cookie: &str) -> Result<CsrfToken, SessionError>
```

### OAuth2 Operations
```rust
// State parameter handling
encode_state(params: StateParams) -> Result<OAuth2State, OAuth2Error>
decode_state(state: &OAuth2State) -> Result<StateParams, OAuth2Error>

// Account search with typed enums
OAuth2Store::get_accounts_by(search_field: AccountSearchField) -> Result<Vec<OAuth2Account>, OAuth2Error>
```

### Cache Operations
```rust
// Unified cache operations with type safety
store_cache_auto(prefix: CachePrefix, data: T, ttl: u64) -> Result<String, E>
store_cache_keyed(prefix: CachePrefix, key: CacheKey, data: T, ttl: u64) -> Result<(), E>
get_data(prefix: CachePrefix, key: CacheKey) -> Result<Option<T>, E>
```

## Error Handling

All typed constructors can fail with validation errors:

```rust
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

When updating code that uses raw strings:

```rust
// Before (vulnerable to parameter confusion)
let credentials = PasskeyStore::get_credentials_by(
    CredentialSearchField::UserId(user_id.to_string())
);

// After (type-safe)
let user_id = UserId::new(user_id_string.to_string());
let credentials = PasskeyStore::get_credentials_by(
    CredentialSearchField::UserId(user_id)
);
```

## Benefits Summary

### Security Impact
- **Eliminates privilege escalation attacks** through session validation
- **Prevents parameter confusion vulnerabilities** 
- **Provides consistent security** across all deployment configurations
- **Defense-in-depth validation** at multiple architectural layers

### Development Benefits  
- **Compile-time error detection** for authentication logic mistakes
- **Self-documenting APIs** through descriptive type names
- **IDE assistance** with auto-completion and type checking
- **Refactoring safety** with compiler-verified updates

### Operational Benefits
- **Predictable behavior** regardless of storage backend choice
- **Centralized validation** logic for easier security auditing
- **Future-proof architecture** for extending validation rules
- **Professional-grade** authentication suitable for production systems

The type system prevents mixing up parameters and ensures consistent validation across the entire codebase, providing robust security guarantees for authentication-critical operations.