# Type-Safe Input Validation

## Problem

String parameters throughout the codebase lack validation at compile time, leading to:
- Runtime validation scattered across multiple functions
- Potential for bypassing validation by accident
- DoS vulnerabilities from oversized inputs (e.g., 1MB session IDs in tests)
- Repeated validation overhead for the same data

## Solution: Validated Newtypes

Replace string parameters with validated wrapper types that enforce constraints at construction time.

## Implementation Pattern

```rust
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeName(String);

impl TypeName {
    pub fn new(value: String) -> Result<Self, CoordinationError> {
        // Validation logic here
        if value.is_empty() {
            return Err(CoordinationError::InvalidInput("Value cannot be empty".to_string()));
        }
        
        if value.len() > MAX_LENGTH {
            return Err(CoordinationError::InvalidInput(
                format!("Value too long: {} bytes (max: {})", value.len(), MAX_LENGTH)
            ));
        }
        
        // Additional format validation
        if !value.chars().all(|c| /* validation condition */) {
            return Err(CoordinationError::InvalidInput("Invalid format".to_string()));
        }
        
        Ok(TypeName(value))
    }
    
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TypeName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// Optional: TryFrom for convenience
impl TryFrom<String> for TypeName {
    type Error = CoordinationError;
    
    fn try_from(value: String) -> Result<Self, Self::Error> {
        TypeName::new(value)
    }
}

impl TryFrom<&str> for TypeName {
    type Error = CoordinationError;
    
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        TypeName::new(value.to_string())
    }
}
```

## High Priority Implementations

### SessionId

```rust
const MAX_SESSION_ID_LENGTH: usize = 64;

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
```

### UserId

```rust
const MAX_USER_ID_LENGTH: usize = 128;

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
        
        // Optional: Add UUID format validation if using UUIDs
        // if !is_valid_uuid(&id) {
        //     return Err(CoordinationError::InvalidInput("Invalid UUID format".to_string()));
        // }
        
        Ok(UserId(id))
    }
    
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
```

### CredentialId

```rust
const MAX_CREDENTIAL_ID_LENGTH: usize = 256; // WebAuthn credential IDs can be longer

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialId(String);

impl CredentialId {
    pub fn new(id: String) -> Result<Self, CoordinationError> {
        if id.is_empty() {
            return Err(CoordinationError::InvalidInput("Credential ID cannot be empty".to_string()));
        }
        
        if id.len() > MAX_CREDENTIAL_ID_LENGTH {
            return Err(CoordinationError::InvalidInput(
                format!("Credential ID too long: {} bytes (max: {})", id.len(), MAX_CREDENTIAL_ID_LENGTH)
            ));
        }
        
        // Optional: Validate base64url encoding if credentials are base64url encoded
        // if !is_valid_base64url(&id) {
        //     return Err(CoordinationError::InvalidInput("Invalid base64url format".to_string()));
        // }
        
        Ok(CredentialId(id))
    }
    
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
```

### CsrfToken

```rust
const CSRF_TOKEN_LENGTH: usize = 32; // Assuming fixed-length tokens

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CsrfToken(String);

impl CsrfToken {
    pub fn new(token: String) -> Result<Self, CoordinationError> {
        if token.len() != CSRF_TOKEN_LENGTH {
            return Err(CoordinationError::InvalidInput(
                format!("CSRF token must be exactly {} characters", CSRF_TOKEN_LENGTH)
            ));
        }
        
        if !token.chars().all(|c| c.is_ascii_alphanumeric()) {
            return Err(CoordinationError::InvalidInput("CSRF token contains invalid characters".to_string()));
        }
        
        Ok(CsrfToken(token))
    }
    
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
```

## Updated Function Signatures

```rust
// Before: String parameters, runtime validation scattered
pub async fn update_user_admin_status(
    session_id: &str,           // ❌ No compile-time validation
    user_id: &str,             // ❌ Could be empty, oversized, malformed
    is_admin: bool,
) -> Result<User, CoordinationError>

// After: Validated types, impossible to construct invalid values
pub async fn update_user_admin_status(
    session_id: SessionId,      // ✅ Guaranteed valid at compile time
    user_id: UserId,           // ✅ Validated once at construction
    is_admin: bool,
) -> Result<User, CoordinationError> {
    let _admin_user = validate_admin_session(session_id).await?;
    // ... function logic (no need to re-validate IDs)
}
```

## Usage at API Boundaries

```rust
// In HTTP handlers or other entry points
async fn handle_admin_update(
    raw_session_id: String,
    raw_user_id: String,
    is_admin: bool
) -> Result<User, CoordinationError> {
    // Validate once at the boundary
    let session_id = SessionId::new(raw_session_id)?;
    let user_id = UserId::new(raw_user_id)?;
    
    // Pass validated types to business logic
    update_user_admin_status(session_id, user_id, is_admin).await
}

// Or with TryFrom for convenience
async fn handle_admin_update_v2(
    raw_session_id: String,
    raw_user_id: String,
    is_admin: bool
) -> Result<User, CoordinationError> {
    let session_id: SessionId = raw_session_id.try_into()?;
    let user_id: UserId = raw_user_id.try_into()?;
    
    update_user_admin_status(session_id, user_id, is_admin).await
}
```

## Benefits

### Compile-Time Safety
- ✅ **Impossible to construct invalid values**: Type system prevents creation of malformed identifiers
- ✅ **Clear function contracts**: Signatures show exactly what validation is required
- ✅ **Refactoring safety**: Compiler catches all places that need updating

### Performance
- ✅ **Single validation**: Validate once at construction, never again
- ✅ **Zero runtime overhead**: After construction, just memory access
- ✅ **No repeated checks**: Eliminates validation in every function that uses the value

### Security
- ✅ **DoS prevention**: Cannot create oversized identifiers that consume memory/bandwidth
- ✅ **Format validation**: Ensures consistent format throughout the application
- ✅ **Impossible to bypass**: Type system enforces validation, no way to accidentally skip it

### Developer Experience
- ✅ **Early error detection**: Validation failures happen at API boundaries, not deep in business logic
- ✅ **Clear error messages**: Validation errors are specific and actionable
- ✅ **Documentation**: Types serve as executable documentation of constraints

## Implementation Priority

1. **Start with SessionId**: Most security-critical and frequently used
2. **Add UserId**: Second most common identifier in the codebase
3. **Implement CredentialId**: Important for WebAuthn security
4. **Add CsrfToken**: Critical for CSRF protection
5. **Consider others**: OAuth2State, ContextToken, etc. as needed

## Migration Strategy

1. **Create the newtype**: Add the validated wrapper type
2. **Update core functions**: Change signatures to accept the newtype
3. **Update callers**: Add validation at API boundaries
4. **Remove old validation**: Clean up redundant runtime checks
5. **Test thoroughly**: Ensure no regressions in validation logic

The type system approach provides the strongest possible validation - it's impossible to bypass and has zero runtime cost after construction.