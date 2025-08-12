# Authorization Security Patterns

## Problem

Current authentication functions trust session data without validating against the database, creating security vulnerabilities where tampered sessions could bypass authorization checks (documented in authorization_security_tests.rs:321-333).

## Security vs Performance Tradeoff

The fix involves adding verification logic: `session_id -> session check -> database user attribute check`. This eliminates the security flaw but increases database lookups.

**Performance Impact**: The additional database lookup penalty is generally acceptable because:
- User attribute operations (showing/modifying) are much less frequent than simple page authentication
- The security benefit outweighs the minimal performance cost
- These operations typically involve user interaction (forms, admin panels) where a few milliseconds don't matter
- Critical security functions should prioritize correctness over micro-optimizations

## Solutions

There are three approaches to fix this security issue, from most robust to most convenient:

### 1. Direct Function Modification (Most Robust)

Modify functions to receive `session_id` and validate session + fetch fresh user data directly in each function.

### 2. Helper Functions (Recommended - Best Balance)

Use helper functions at the top of each function that need security validation. Simple one-liners that do all the validation work.

### 3. Middleware Pattern (Most Convenient)

Use middleware that wraps function logic, but adds complexity with closures.

## Implementation

### Helper Functions (Recommended)

```rust
// Helper functions for common authorization patterns
pub async fn validate_admin_session(session_id: &str) -> Result<User, CoordinationError> {
    let session = validate_session(session_id).await?;
    let user = UserStore::get_user(&session.user_id).await?.ok_or(NotFound)?;
    if !user.is_admin {
        return Err(CoordinationError::Unauthorized.log());
    }
    Ok(user)
}

pub async fn validate_owner_session(session_id: &str, resource_user_id: &str) -> Result<User, CoordinationError> {
    let session = validate_session(session_id).await?;
    let user = UserStore::get_user(&session.user_id).await?.ok_or(NotFound)?;
    if user.id != resource_user_id {
        return Err(CoordinationError::Unauthorized.log());
    }
    Ok(user)
}

pub async fn validate_admin_or_owner_session(session_id: &str, resource_user_id: &str) -> Result<User, CoordinationError> {
    let session = validate_session(session_id).await?;
    let user = UserStore::get_user(&session.user_id).await?.ok_or(NotFound)?;
    if !user.is_admin && user.id != resource_user_id {
        return Err(CoordinationError::Unauthorized.log());
    }
    Ok(user)
}
```

### Middleware Pattern (Alternative)

```rust
// Admin authorization middleware
pub async fn with_admin_auth<F, R>(session_id: &str, operation: F) -> Result<R, CoordinationError>
where F: FnOnce(&User) -> Result<R, CoordinationError>
{
    let session = validate_session(session_id).await?;
    let user = get_fresh_user(&session.user_id).await?;
    if !user.is_admin { return Err(Unauthorized); }
    operation(&user)
}

// Owner authorization middleware
pub async fn with_owner_auth<F, R>(session_id: &str, resource_user_id: &str, operation: F) -> Result<R, CoordinationError>
where F: FnOnce(&User) -> Result<R, CoordinationError>
{
    let session = validate_session(session_id).await?;
    let user = get_fresh_user(&session.user_id).await?;
    if user.id != resource_user_id { return Err(Unauthorized); }
    operation(&user)
}

// Admin OR owner authorization middleware
pub async fn with_admin_or_owner_auth<F, R>(session_id: &str, resource_user_id: &str, operation: F) -> Result<R, CoordinationError>
where F: FnOnce(&User) -> Result<R, CoordinationError>
{
    let session = validate_session(session_id).await?;
    let user = get_fresh_user(&session.user_id).await?;
    if !user.is_admin && user.id != resource_user_id {
        return Err(Unauthorized);
    }
    operation(&user)
}
```

## Usage Examples

### Helper Functions (Simple One-Liners)

```rust
// Admin-only function
pub async fn update_user_admin_status(
    session_id: &str,
    user_id: &str,
    is_admin: bool,
) -> Result<User, CoordinationError> {
    // Simple one-liner at the top
    let _admin_user = validate_admin_session(session_id).await?;

    // Original function logic continues...
    let user = UserStore::get_user(user_id).await?.ok_or(NotFound)?;
    if user.sequence_number == Some(1) {
        return Err(CoordinationError::Coordination("Cannot change admin status of first user".to_string()));
    }
    let updated_user = User { is_admin, ..user };
    UserStore::upsert_user(updated_user).await
}

// Owner-only function
pub async fn update_user_account(
    session_id: &str,
    user_id: &str,
    account: Option<String>,
    label: Option<String>,
) -> Result<User, CoordinationError> {
    // One-liner owner validation
    let _owner_user = validate_owner_session(session_id, user_id).await?;

    // Original function logic...
    let user = UserStore::get_user(user_id).await?.ok_or(NotFound)?;
    let updated_user = User {
        account: account.unwrap_or(user.account),
        label: label.unwrap_or(user.label),
        ..user
    };
    UserStore::upsert_user(updated_user).await
}

// Admin OR owner function
pub async fn delete_user_account(session_id: &str, user_id: &str) -> Result<Vec<String>, CoordinationError> {
    // One-liner validation
    let _user = validate_admin_or_owner_session(session_id, user_id).await?;

    // Original function logic...
    let user = UserStore::get_user(user_id).await?.ok_or(NotFound)?;
    // ... rest of delete logic
    Ok(credential_ids)
}
```

### Middleware Pattern (Alternative)

```rust
// Admin-only function
pub async fn delete_user_account_admin(session_id: &str, user_id: &str) -> Result<(), CoordinationError> {
    with_admin_auth(session_id, |_admin_user| {
        // Original function logic here
        UserStore::delete_user(user_id)
    }).await
}

// Owner-only function
pub async fn update_user_account(session_id: &str, user_id: &str, account: Option<String>, label: Option<String>) -> Result<User, CoordinationError> {
    with_owner_auth(session_id, user_id, |_owner_user| {
        // Original function logic here
        let user = UserStore::get_user(user_id).await?.ok_or(NotFound)?;
        let updated_user = User {
            account: account.unwrap_or(user.account),
            label: label.unwrap_or(user.label),
            ..user
        };
        UserStore::upsert_user(updated_user)
    }).await
}

// Admin OR owner function
pub async fn delete_user_account(session_id: &str, user_id: &str) -> Result<Vec<String>, CoordinationError> {
    with_admin_or_owner_auth(session_id, user_id, |_user| {
        // Original function logic here
        // ... delete logic
    }).await
}
```

## Benefits

### Helper Functions
- ✅ **Simple to use**: Just one line at the top of each function
- ✅ **Clear and readable**: Obvious what security check is happening
- ✅ **No complex middleware**: Straightforward function calls
- ✅ **Easy to modify**: Can add logging, metrics, etc. in helpers
- ✅ **Consistent security**: Same validation logic everywhere
- ✅ **Testable**: Can unit test helpers independently

### Both Approaches
- ✅ Works for admin, owner, and admin-or-owner authorization patterns
- ✅ Always validates session freshness against database
- ✅ Always fetches fresh user data from database
- ✅ Centralizes authorization logic for consistency and maintainability
- ✅ Prevents privilege escalation vulnerabilities from tampered session data
- ✅ DRY principle - write authorization logic once, use everywhere
- ✅ Easily testable authorization logic in isolation

## Security Impact

This pattern eliminates the vulnerability where functions trust `SessionUser.is_admin` without database validation, preventing attacks where tampered session data could bypass authorization checks.

## Alternative Approaches Considered

1. **Direct function modification**: Add session_id parameter to each function - requires changing many signatures
2. **Capability-based security**: Use capability tokens - more complex, requires new infrastructure
3. **Database-first authorization**: Always query DB in each function - repetitive, error-prone
4. **Session validation helper**: Centralized validation function - still requires modifying each function

The middleware pattern provides the best balance of security, maintainability, and implementation simplicity.
