# Type-Safe Validation Strategy

## Overview

This document provides a comprehensive strategy for implementing type-safe validation throughout the oauth2-passkey codebase. The approach eliminates validation inconsistencies, prevents security vulnerabilities, and provides compile-time guarantees for all data validation.

## Problem Statement

Current implementation has validation gaps across multiple layers:

1. **Security Vulnerabilities**: Functions trust session data without database validation (coordination layer)
2. **Backend Inconsistency**: Redis validates while Memory doesn't, causing different behavior (storage layer)
3. **Validation Gaps**: Many functions accept raw strings without format validation (comprehensive coverage)

## Core Benefits

- ✅ **Compile-time safety**: Impossible to construct invalid values
- ✅ **Single validation point**: Validate once at construction, never again
- ✅ **Consistent behavior**: Same validation rules regardless of backend/deployment
- ✅ **Defense-in-depth**: Multiple layers of validation protection
- ✅ **Performance**: Zero runtime overhead after construction
- ✅ **Maintainability**: Centralized validation logic

## Implementation Phases

### Phase 1: Coordination Layer (High Priority - Security Critical)

**Problem**: Authentication functions trust session data without validating against database, enabling privilege escalation attacks.

**Current Vulnerability** (documented in authorization_security_tests.rs:321-333):
```rust
// Functions trust SessionUser data without DB validation
pub async fn update_user_admin_status(
    admin_user: &SessionUser,  // ❌ Could be tampered session data
    user_id: &str,            // ❌ Raw string
    is_admin: bool,
) -> Result<User, CoordinationError>
```

**Secure Implementation**:
```rust
// Validate session + fetch fresh user data from database
pub async fn update_user_admin_status(
    session_id: SessionId,     // ✅ Validated session identifier
    user_id: UserId,          // ✅ Validated user identifier
    is_admin: bool,
) -> Result<User, CoordinationError> {
    let _admin_user = validate_admin_session(session_id).await?;  // Fresh DB lookup
    // ... function logic
}
```

**Helper Functions Approach** (Recommended):
```rust
// Simple one-liners for common authorization patterns
pub async fn validate_admin_session(session_id: SessionId) -> Result<User, CoordinationError> {
    let session = validate_session(session_id.as_str()).await?;
    let user = UserStore::get_user(&session.user_id).await?.ok_or(NotFound)?;
    if !user.is_admin { return Err(Unauthorized); }
    Ok(user)
}

pub async fn validate_owner_session(session_id: SessionId, resource_user_id: UserId) -> Result<User, CoordinationError> {
    let session = validate_session(session_id.as_str()).await?;
    let user = UserStore::get_user(&session.user_id).await?.ok_or(NotFound)?;
    if user.id != resource_user_id.as_str() { return Err(Unauthorized); }
    Ok(user)
}
```

**Functions to Update**:
- **Admin Functions** (oauth2_passkey/src/coordination/admin.rs):
  - `delete_passkey_credential_admin(user: &SessionUser, credential_id: &str)` :97
  - `delete_oauth2_account_admin(user: &SessionUser, provider_user_id: &str)` :166
  - `update_user_admin_status(admin_user: &SessionUser, user_id: &str, is_admin: bool)` :273
  - `get_all_users()` :30 (add session validation)
  - `get_user(user_id: &str)` :64 (add session validation)
  - `delete_user_account_admin(user_id: &str)` :220 (add session validation)
- **User Functions** (oauth2_passkey/src/coordination/user.rs):
  - `update_user_account(user_id: &str, account: Option<String>, label: Option<String>)` :8
  - `delete_user_account(user_id: &str)` :38

### Phase 2: Storage Layer (Medium Priority - Consistency)

**Problem**: Storage implementations have different validation approaches, causing inconsistent behavior across deployment configurations.

**Cache Store Inconsistency**:
```rust
// Redis - validates every call
impl RedisCacheStore {
    fn make_key(prefix: &str, key: &str) -> Result<String, StorageError> {
        Self::validate_key_component(prefix, "prefix")?;  // Length, chars, commands
        Self::validate_key_component(key, "key")?;        // Runtime validation
        Ok(format!("{CACHE_PREFIX}:{prefix}:{key}"))
    }
}

// Memory - no validation at all
impl InMemoryCacheStore {
    fn make_key(prefix: &str, key: &str) -> String {
        format!("{CACHE_PREFIX}:{prefix}:{key}")  // ❌ Inconsistent behavior
    }
}
```

**Unified Solution**:
```rust
// Both implementations use same validated types
trait CacheStore {
    async fn put(&mut self, prefix: CachePrefix, key: CacheKey, value: CacheData) -> Result<(), StorageError>;
    async fn get(&self, prefix: CachePrefix, key: CacheKey) -> Result<Option<CacheData>, StorageError>;
    // ... other methods
}

// No validation needed in implementations - types guarantee validity
impl RedisCacheStore {
    fn make_key(prefix: CachePrefix, key: CacheKey) -> String {
        format!("{CACHE_PREFIX}:{}:{}", prefix.as_str(), key.as_str())
    }
}

impl InMemoryCacheStore {
    fn make_key(prefix: CachePrefix, key: CacheKey) -> String {
        format!("{CACHE_PREFIX}:{}:{}", prefix.as_str(), key.as_str())
    }
}
```

### Phase 3: Comprehensive Coverage (Medium Priority - Completeness)

**Problem**: Many functions throughout the codebase accept raw strings without validation, creating gaps in the validation strategy.

**Critical Gap: Search Field Enums**:
```rust
// Current: Unvalidated strings in database operations
pub enum UserSearchField {
    Id(String),              // ❌ No validation
    SequenceNumber(i64),     // ✅ Already type-safe
}

pub enum CredentialSearchField {
    CredentialId(String),    // ❌ Could be malformed
    UserId(String),          // ❌ Could be empty/oversized
    UserHandle(String),      // ❌ No WebAuthn format validation
}

// Better: Validated enum variants
pub enum UserSearchField {
    Id(UserId),              // ✅ Validated user identifier
    SequenceNumber(i64),
}

pub enum CredentialSearchField {
    CredentialId(CredentialId),  // ✅ Base64url validated
    UserId(UserId),             // ✅ Consistent validation
    UserHandle(UserHandle),     // ✅ WebAuthn format validation
}
```

**Additional Categories**:

- **Session Management**: `get_user_from_session(session_cookie: &str)` → `get_user_from_session(session_cookie: SessionCookie)`
- **WebAuthn Challenges**: `remove_options(challenge_type: &str, id: &str)` → `remove_options(challenge_type: ChallengeType, id: ChallengeId)`
- **OAuth2 Parameters**: `decode_state(state: &str)` → `decode_state(state: OAuth2State)`
- **Cache Operations**: `get_from_cache(category: &str, key: &str)` → `get_from_cache(category: CacheCategory, key: CacheKey)`

## Type Implementations

### Phase 1 Types (High Priority)

```rust
// Session and User Identifiers
const MAX_SESSION_ID_LENGTH: usize = 64;
const MAX_USER_ID_LENGTH: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionId(String);

impl SessionId {
    pub fn new(id: String) -> Result<Self, CoordinationError> {
        if id.is_empty() {
            return Err(CoordinationError::InvalidInput("Session ID cannot be empty".to_string()));
        }

        if id.len() > MAX_SESSION_ID_LENGTH {
            return Err(CoordinationError::InvalidInput(
                format!("Session ID too long: {} bytes (max: {})", id.len(), MAX_SESSION_ID_LENGTH)
            ));
        }

        // Validate character set (alphanumeric + hyphens for UUIDs)
        if !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(CoordinationError::InvalidInput("Invalid characters in session ID".to_string()));
        }

        Ok(SessionId(id))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserId(String);

impl UserId {
    pub fn new(id: String) -> Result<Self, CoordinationError> {
        if id.is_empty() {
            return Err(CoordinationError::InvalidInput("User ID cannot be empty".to_string()));
        }

        if id.len() > MAX_USER_ID_LENGTH {
            return Err(CoordinationError::InvalidInput(
                format!("User ID too long: {} bytes (max: {})", id.len(), MAX_USER_ID_LENGTH)
            ));
        }

        Ok(UserId(id))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// Additional Phase 1 types: CredentialId, CsrfToken, ProviderUserId
```

### Phase 2 Types (Storage Layer)

```rust
// Cache Types
const MAX_CACHE_PREFIX_LENGTH: usize = 50;
const MAX_CACHE_KEY_LENGTH: usize = 200;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachePrefix(String);

impl CachePrefix {
    pub fn new(prefix: String) -> Result<Self, StorageError> {
        if prefix.is_empty() {
            return Err(StorageError::InvalidInput("Cache prefix cannot be empty".to_string()));
        }

        if prefix.len() > MAX_CACHE_PREFIX_LENGTH {
            return Err(StorageError::InvalidInput(
                format!("Cache prefix too long: {} bytes (max: {})", prefix.len(), MAX_CACHE_PREFIX_LENGTH)
            ));
        }

        // Validate characters safe for all cache backends (Redis + Memory)
        let dangerous_chars = ['\n', '\r', ' ', '\t', ':', '*'];
        if prefix.chars().any(|c| dangerous_chars.contains(&c)) {
            return Err(StorageError::InvalidInput("Cache prefix contains unsafe characters".to_string()));
        }

        Ok(CachePrefix(prefix))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheKey(String);

impl CacheKey {
    pub fn new(key: String) -> Result<Self, StorageError> {
        if key.is_empty() {
            return Err(StorageError::InvalidInput("Cache key cannot be empty".to_string()));
        }

        if key.len() > MAX_CACHE_KEY_LENGTH {
            return Err(StorageError::InvalidInput(
                format!("Cache key too long: {} bytes (max: {})", key.len(), MAX_CACHE_KEY_LENGTH)
            ));
        }

        // Combined validation for all cache backends
        let dangerous_chars = ['\n', '\r', ' ', '\t'];
        if key.chars().any(|c| dangerous_chars.contains(&c)) {
            return Err(StorageError::InvalidInput("Cache key contains unsafe characters".to_string()));
        }

        // Check for Redis command keywords
        let key_upper = key.to_uppercase();
        let redis_commands = ["SET", "GET", "DEL", "FLUSHDB", "FLUSHALL", "EVAL", "SCRIPT"];
        for cmd in &redis_commands {
            if key_upper.contains(cmd) {
                return Err(StorageError::InvalidInput(
                    format!("Cache key contains dangerous command keyword: '{}'", key)
                ));
            }
        }

        Ok(CacheKey(key))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}
```

### Phase 3 Types (Comprehensive Coverage)

```rust
// Session Types
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionCookie(String);

impl SessionCookie {
    pub fn new(cookie: String) -> Result<Self, SessionError> {
        if cookie.is_empty() {
            return Err(SessionError::InvalidInput("Session cookie cannot be empty".to_string()));
        }

        if cookie.len() > 512 {
            return Err(SessionError::InvalidInput(
                format!("Session cookie too long: {} bytes (max: 512)", cookie.len())
            ));
        }

        // Validate cookie format (base64url or similar)
        if !cookie.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
            return Err(SessionError::InvalidInput("Invalid characters in session cookie".to_string()));
        }

        Ok(SessionCookie(cookie))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// WebAuthn Types
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge(String);

impl Challenge {
    pub fn new(challenge: String) -> Result<Self, PasskeyError> {
        if challenge.is_empty() {
            return Err(PasskeyError::InvalidInput("Challenge cannot be empty".to_string()));
        }

        if challenge.len() > 512 {
            return Err(PasskeyError::InvalidInput(
                format!("Challenge too long: {} bytes (max: 512)", challenge.len())
            ));
        }

        // Validate base64url encoding
        if !is_valid_base64url(&challenge) {
            return Err(PasskeyError::InvalidInput("Challenge must be valid base64url".to_string()));
        }

        Ok(Challenge(challenge))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserHandle(String);

impl UserHandle {
    pub fn new(handle: String) -> Result<Self, PasskeyError> {
        if handle.is_empty() {
            return Err(PasskeyError::InvalidInput("User handle cannot be empty".to_string()));
        }

        if handle.len() > 128 {
            return Err(PasskeyError::InvalidInput(
                format!("User handle too long: {} bytes (max: 128)", handle.len())
            ));
        }

        // WebAuthn user handles are typically base64url encoded
        if !is_valid_base64url(&handle) {
            return Err(PasskeyError::InvalidInput("User handle must be valid base64url".to_string()));
        }

        Ok(UserHandle(handle))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeType(String);

impl ChallengeType {
    pub fn new(challenge_type: String) -> Result<Self, PasskeyError> {
        // WebAuthn challenge types are specific values
        match challenge_type.as_str() {
            "webauthn.create" | "webauthn.get" => Ok(ChallengeType(challenge_type)),
            _ => Err(PasskeyError::InvalidInput(
                format!("Invalid challenge type: {}", challenge_type)
            ))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn create() -> Self {
        ChallengeType("webauthn.create".to_string())
    }

    pub fn get() -> Self {
        ChallengeType("webauthn.get".to_string())
    }
}

// OAuth2 Types
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuth2State(String);

impl OAuth2State {
    pub fn new(state: String) -> Result<Self, OAuth2Error> {
        if state.is_empty() {
            return Err(OAuth2Error::InvalidInput("OAuth2 state cannot be empty".to_string()));
        }

        if state.len() > 256 {
            return Err(OAuth2Error::InvalidInput(
                format!("OAuth2 state too long: {} bytes (max: 256)", state.len())
            ));
        }

        // OAuth2 state is typically base64url encoded
        if !is_valid_base64url(&state) {
            return Err(OAuth2Error::InvalidInput("OAuth2 state must be valid base64url".to_string()));
        }

        Ok(OAuth2State(state))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthProvider(String);

impl OAuthProvider {
    pub fn new(provider: String) -> Result<Self, OAuth2Error> {
        // Only allow known OAuth2 providers
        match provider.as_str() {
            "google" | "github" | "apple" | "microsoft" => Ok(OAuthProvider(provider)),
            _ => Err(OAuth2Error::InvalidInput(
                format!("Unknown OAuth2 provider: {}", provider)
            ))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn google() -> Self {
        OAuthProvider("google".to_string())
    }
}

// Cache Types
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheCategory(String);

impl CacheCategory {
    pub fn new(category: String) -> Result<Self, PasskeyError> {
        // Cache categories should be predefined
        match category.as_str() {
            "challenge" | "session" | "jwks" | "user" | "credential" => {
                Ok(CacheCategory(category))
            }
            _ => Err(PasskeyError::InvalidInput(
                format!("Unknown cache category: {}", category)
            ))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn challenge() -> Self {
        CacheCategory("challenge".to_string())
    }
}
```

## Security vs Performance Tradeoff

The type-safe validation approach adds database lookups for session validation but this is acceptable because:

- **User operations are infrequent**: Admin/user attribute modifications happen much less than simple page authentication
- **Interactive context**: These operations involve user forms/interactions where milliseconds don't impact UX
- **Security priority**: Correctness trumps micro-optimizations for critical authentication functions
- **Defense-in-depth**: Multiple validation layers provide robust security

## Usage Examples

### Phase 1: Secure Function Implementation
```rust
// Before: Trusts session data
pub async fn update_user_admin_status(
    admin_user: &SessionUser,
    user_id: &str,
    is_admin: bool,
) -> Result<User, CoordinationError> {
    if !admin_user.is_admin {  // ❌ Trusts session data
        return Err(Unauthorized);
    }
    // ...
}

// After: Validates against database
pub async fn update_user_admin_status(
    session_id: SessionId,
    user_id: UserId,
    is_admin: bool,
) -> Result<User, CoordinationError> {
    let _admin_user = validate_admin_session(session_id).await?;  // ✅ Fresh DB lookup
    // ...
}
```

### Phase 2: Consistent Storage Interface
```rust
// Usage at API boundary
let cache_prefix = CachePrefix::new("session".to_string())?;
let cache_key = CacheKey::new(session_id.to_string())?;
store.put(cache_prefix, cache_key, session_data).await?;  // Safe for all backends
```

### Phase 3: Complete Type Safety
```rust
// Search operations with validated enums
let search_field = CredentialSearchField::UserId(user_id);  // user_id is already UserId type
let credentials = PasskeyStore::get_credentials_by(search_field).await?;

// OAuth2 operations with validated parameters
let oauth_state = OAuth2State::new(raw_state_string)?;
let state_params = decode_state(oauth_state)?;
```

## Migration Strategy

### Cross-Phase Coordination
1. **Define common types first**: SessionId, UserId, etc. used across multiple phases
2. **Implement phases incrementally**: Can work on multiple phases in parallel
3. **Maintain backwards compatibility**: Add new functions alongside old ones initially
4. **Update callers systematically**: One module at a time within each phase
5. **Remove deprecated functions**: After all callers updated in that phase

### Testing Strategy
- **Unit tests for all type constructors**: Verify validation logic
- **Integration tests**: Ensure no regressions in end-to-end flows
- **Security tests**: Verify attack scenarios are properly blocked
- **Performance tests**: Ensure no significant performance regression

### Backwards Compatibility
- **Non-breaking additions**: Add typed versions alongside string versions
- **Deprecation warnings**: Mark old functions as deprecated with migration guidance
- **Documentation**: Clear migration examples for each affected function
- **Version planning**: Remove deprecated functions in next major version

## Benefits Summary

### Security Impact
- **Eliminates privilege escalation**: Fresh database validation prevents session tampering attacks
- **Prevents injection attacks**: Format validation blocks malicious input at construction
- **Defense-in-depth**: Multiple validation layers throughout the stack
- **Consistent protection**: Same security guarantees regardless of deployment configuration

### Development Benefits
- **Compile-time safety**: Invalid data cannot be constructed or passed to functions
- **Clear contracts**: Function signatures explicitly show validation requirements
- **Refactoring safety**: Compiler catches all places needing updates during changes
- **Reduced bugs**: Centralized validation eliminates scattered validation logic

### Operational Benefits
- **Predictable behavior**: Same validation everywhere, regardless of storage backend
- **Performance**: Single validation point, zero overhead after construction
- **Maintainability**: Changes to validation logic only need to happen in one place
- **Debuggability**: Clear error messages from validation failures at construction time

This comprehensive type-safe validation strategy provides a robust foundation for secure, maintainable, and performant authentication throughout the oauth2-passkey library.
