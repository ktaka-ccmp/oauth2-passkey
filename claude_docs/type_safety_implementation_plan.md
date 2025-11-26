# Type Safety Implementation Plan

## Overview

This document outlines the plan to implement comprehensive type-safe validation for ID constructors across the oauth2-passkey library. Based on previous attempts recorded in `git-diff-cached.log` and `git-diff-cached.log2`, the main logic changes can now be successfully applied since the test code has been separated into dedicated test files.

## Background

### Previous Attempts
- **git-diff-cached.log**: First attempt to implement type safety with validation
- **git-diff-cached.log2**: Refined attempt with improved validation logic
- **Issue**: Both attempts failed due to compilation errors in mixed main logic + test code files
- **Resolution**: Recent refactoring separated tests into dedicated files, removing the compilation blocker

### Key Changes Required
1. **Constructor Signatures**: Change from `pub fn new(x: String) -> Self` to `pub fn new(x: String) -> Result<Self, Error>`
2. **Validation Logic**: Add comprehensive validation for each ID type
3. **Call Site Updates**: Add proper error handling (`.expect()` or `?` operator)
4. **Test Updates**: Update tests to work with validated constructors

## Implementation Strategy

### Order: Module → Call Sites → Tests → Next Module

For each module, follow this sequence:
1. **Update Core Types** - Add validation to constructors
2. **Update Call Sites** - Add proper error handling  
3. **Update Tests** - Ensure tests work with validated constructors
4. **Verify** - Run tests to confirm everything works before proceeding

This approach ensures immediate validation and prevents compounding issues.

## Phase 1: Session Module

### Files to Update
- **Core Types**: `oauth2_passkey/src/session/types.rs`
- **Call Sites**: All files using `SessionId::new()` and `UserId::new()`
- **Tests**: `oauth2_passkey/src/session/*/tests.rs`

### Types to Update

#### SessionId
**Current:**
```rust
pub fn new(id: String) -> Self {
    Self(id)
}
```

**Updated:**
```rust
/// Creates a new SessionId from a string with validation.
///
/// # Arguments
/// * `id` - The session ID string
///
/// # Returns
/// * `Ok(SessionId)` - If the ID is valid
/// * `Err(SessionError)` - If the ID is invalid
///
/// # Validation Rules
/// * Must not be empty
/// * Must contain only safe characters (alphanumeric + URL-safe symbols)
/// * Must not contain control characters or whitespace
pub fn new(id: String) -> Result<Self, crate::session::SessionError> {
    use crate::session::SessionError;

    // Validate ID is not empty
    if id.is_empty() {
        return Err(SessionError::Validation(
            "Session ID cannot be empty".to_string(),
        ));
    }

    // Validate ID length (session IDs need sufficient entropy)
    if id.len() < 10 {
        return Err(SessionError::Validation("Session ID too short".to_string()));
    }

    if id.len() > 256 {
        return Err(SessionError::Validation("Session ID too long".to_string()));
    }

    // Validate ID contains only URL-safe characters (no whitespace)
    if !id.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~')) {
        return Err(SessionError::Validation(
            "Session ID contains invalid characters".to_string(),
        ));
    }

    Ok(SessionId(id))
}
```

#### UserId
**Current:**
```rust
pub fn new(id: String) -> Self {
    Self(id)
}
```

**Updated:**
```rust
/// Creates a new UserId from a string with validation.
///
/// # Arguments
/// * `id` - The user ID string
///
/// # Returns
/// * `Ok(UserId)` - If the ID is valid
/// * `Err(SessionError)` - If the ID is invalid
///
/// # Validation Rules
/// * Must not be empty
/// * Must contain only safe characters (alphanumeric + basic symbols)
/// * Must not contain control characters or dangerous sequences
pub fn new(id: String) -> Result<Self, crate::session::SessionError> {
    use crate::session::SessionError;

    // Validate ID is not empty
    if id.is_empty() {
        return Err(SessionError::Validation(
            "User ID cannot be empty".to_string(),
        ));
    }

    // Validate ID length (reasonable bounds)
    if id.len() < 1 {
        return Err(SessionError::Validation("User ID too short".to_string()));
    }

    if id.len() > 255 {
        return Err(SessionError::Validation("User ID too long".to_string()));
    }

    // Validate ID contains only safe characters
    if !id.chars().all(|c| {
        c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@' | '+')
    }) {
        return Err(SessionError::Validation(
            "User ID contains invalid characters".to_string(),
        ));
    }

    // Check for dangerous sequences
    if id.contains("..") || id.contains("--") || id.contains("__") {
        return Err(SessionError::Validation(
            "User ID contains dangerous character sequences".to_string(),
        ));
    }

    Ok(UserId(id))
}
```

### Call Site Update Pattern
**Before:**
```rust
SessionId::new(session_id.to_string())
UserId::new(user_id.to_string())
```

**After:**
```rust
SessionId::new(session_id.to_string()).expect("Valid session ID")
UserId::new(user_id.to_string()).expect("Valid user ID")
```

### Error Handling Strategy
- **In Tests**: Use `.expect("Valid ID")` for known-good test data
- **In Main Logic**: Use `?` operator where possible, `.expect()` for internal/trusted data
- **User Input**: Proper error handling with informative error messages

## Phase 2: Passkey Module

### Files to Update
- **Core Types**: `oauth2_passkey/src/passkey/types.rs`
- **Call Sites**: All files using passkey types
- **Tests**: `oauth2_passkey/src/passkey/*/tests.rs`

### Types to Update
- `CredentialId`
- `UserName`
- Any other unvalidated ID types in the passkey module

### Validation Rules
- **CredentialId**: URL-safe characters, sufficient length for entropy
- **UserName**: Safe characters, reasonable length bounds, no dangerous sequences

## Phase 3: OAuth2 Module

### Files to Update
- **Core Types**: `oauth2_passkey/src/oauth2/types.rs`
- **Call Sites**: All files using OAuth2 types
- **Tests**: `oauth2_passkey/src/oauth2/*/tests.rs`

### Types to Update
- `AccountId`
- `Provider`  
- `ProviderUserId`
- `DisplayName`
- `Email`

### Validation Rules
- **AccountId/ProviderUserId**: Safe characters, reasonable length
- **Provider**: Alphanumeric + basic symbols, no leading special chars
- **DisplayName**: UTF-8 safe, length limits, whitespace handling
- **Email**: Basic email format validation, length limits

## Implementation Verification

### After Each Phase
1. **Compile Check**: `cargo check`
2. **Format Code**: `cargo fmt --all`
3. **Lint Check**: `cargo clippy --all-targets --all-features`
4. **Run Tests**: `cargo test --manifest-path oauth2_passkey/Cargo.toml`
5. **Integration Tests**: Run demo applications to verify functionality

### Success Criteria
- All tests pass
- No clippy warnings related to the changes
- Demo applications continue to work
- Error messages are informative and appropriate

## Security Benefits

### Input Validation
- Prevents empty/malformed IDs from entering the system
- Validates character sets to prevent injection attacks
- Enforces reasonable length bounds to prevent resource exhaustion

### Type Safety
- Compile-time prevention of ID type confusion
- Clear error messages for invalid input
- Consistent validation across the entire codebase

### Defensive Programming
- Fail-fast on invalid input rather than silent corruption
- Explicit error handling makes failure modes visible
- Validation logic centralized in constructors

## Rollback Plan

If issues arise during implementation:
1. **Module-Level Rollback**: Revert changes for the current module only
2. **Keep Completed Phases**: Previous successful phases remain implemented
3. **Incremental Recovery**: Address issues and resume from the problematic phase

## Notes

- This implementation leverages the recent refactoring that separated test files
- The validation logic is based on the proven approaches from previous attempts
- Each phase can be completed independently, allowing for flexible implementation timing
- All validation rules prioritize security while maintaining usability