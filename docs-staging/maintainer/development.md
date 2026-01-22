# Chapter 22: Development

This chapter covers the development practices, project organization, and testing strategies for the OAuth2-Passkey library.

## Project Structure

The OAuth2-Passkey workspace is organized as a multi-crate Rust project with clear separation of concerns.

### Crate Organization

```
oauth2-passkey/
├── oauth2_passkey/           # Core library
│   ├── src/
│   │   ├── config/           # Configuration handling
│   │   ├── coordination/     # Central orchestration of auth flows
│   │   ├── oauth2/           # OAuth2 implementation
│   │   │   ├── main/         # Core OAuth2 logic
│   │   │   └── storage/      # OAuth2 data persistence
│   │   ├── passkey/          # WebAuthn/Passkey implementation
│   │   │   ├── main/         # Core passkey logic
│   │   │   └── storage/      # Passkey data persistence
│   │   ├── session/          # Session management
│   │   ├── storage/          # Database and cache abstraction
│   │   │   ├── data_store/   # PostgreSQL/SQLite backends
│   │   │   └── cache_store/  # Redis/Memory backends
│   │   ├── userdb/           # User account management
│   │   ├── test_utils/       # Test utilities module
│   │   └── utils/            # Common utilities
│   └── tests/                # Integration tests
│       ├── common/           # Shared test utilities
│       └── integration/      # Integration test modules
│
├── oauth2_passkey_axum/      # Axum web framework integration
│   └── src/
│       ├── assets/           # Static assets (JS/CSS)
│       └── templates/        # HTML templates
│
└── demo-*/                   # Demo applications
```

### Key Design Principles

1. **Layered Architecture**: Clear separation between core logic and web framework
2. **Coordination Layer**: All authentication flows route through the coordination module
3. **Flexible Storage**: Supports both development (SQLite, in-memory) and production (PostgreSQL, Redis) setups
4. **Security First**: Built-in CSRF protection, secure sessions, and page session tokens

## Testing Strategy

The project follows a bottom-up testing approach, starting with fundamental modules and building toward integration testing.

### Testing Principles

1. **Simplicity First**
   - Prefer simple, focused tests
   - One assertion per test when practical
   - Clear, descriptive test names

2. **Minimal Dependencies**
   - Avoid test-only dependencies when possible
   - Prefer standard library solutions
   - Document required test setup clearly

3. **Test Organization**
   - Unit tests in the same file as the code under test
   - Integration tests in `/tests/` directory
   - Documentation tests in module docs when helpful

### Module Testing Order

The testing strategy follows a bottom-up approach based on module dependencies:

1. **Core Utilities** (`src/utils.rs`) - Foundation functions
2. **Configuration** (`src/config.rs`) - Configuration validation
3. **Storage Layer** (`src/storage/`) - Data and cache operations
4. **OAuth2 Module** (`src/oauth2/`) - OAuth2 flows and token handling
5. **Passkey Module** (`src/passkey/`) - WebAuthn operations
6. **Session Management** (`src/session/`) - Session handling
7. **User Database** (`src/userdb/`) - User management
8. **Coordination Layer** (`src/coordination/`) - Business workflows

## Unit Test Patterns

Unit tests are placed inline with the code they test, within a `tests` submodule.

### Basic Test Structure

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_function_returns_expected_value() {
        // Arrange
        let input = "test_input";

        // Act
        let result = function_under_test(input);

        // Assert
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected_value);
    }
}
```

### Pure Function Testing

For pure functions without side effects, tests are straightforward:

```rust
#[test]
fn test_base64url_encode_decode() {
    // Test with simple string
    let original = b"hello world";
    let encoded = base64url_encode(original.to_vec()).expect("Failed to encode");
    let decoded = base64url_decode(&encoded).expect("Failed to decode");
    assert_eq!(decoded, original);

    // Test with empty input
    let empty_encoded = base64url_encode(vec![]).expect("Failed to encode empty");
    let empty_decoded = base64url_decode(&empty_encoded).expect("Failed to decode empty");
    assert!(empty_decoded.is_empty());
}

#[test]
fn test_base64url_decode_invalid() {
    // Test with invalid base64url string
    let invalid_base64 = "This is not base64url!";
    let result = base64url_decode(invalid_base64);
    assert!(matches!(result, Err(UtilError::Format(_))));
}
```

### Testing with Dependencies

For tests requiring HTTP headers or other framework types:

```rust
// Helper function to create test fixtures
fn create_header_map_with_cookie(cookie_name: &str, cookie_value: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    let cookie_str = format!("{cookie_name}={cookie_value}");
    headers.insert(COOKIE, HeaderValue::from_str(&cookie_str).unwrap());
    headers
}

/// Test session ID extraction from HTTP headers
#[test]
fn test_get_session_id_from_headers() {
    // Given a header map with a session cookie
    let cookie_name = SESSION_COOKIE_NAME.to_string();
    let session_id = "test_session_id";
    let headers = create_header_map_with_cookie(&cookie_name, session_id);

    // When getting the session ID
    let result = get_session_id_from_headers(&headers);

    // Then it should return the session ID
    assert!(result.is_ok());
    let session_id_opt = result.unwrap();
    assert!(session_id_opt.is_some());
    assert_eq!(session_id_opt.unwrap(), session_id);
}
```

### Async Test Patterns

For async functions requiring database access:

```rust
use crate::test_utils::init_test_environment;

#[tokio::test]
async fn test_user_creation() {
    // Initialize test environment (loads .env_test, sets up databases)
    init_test_environment().await;

    // Arrange
    let user = User::new(
        "test-user".to_string(),
        "test@example.com".to_string(),
        "Test User".to_string(),
    );

    // Act
    let result = UserStore::upsert_user(user).await;

    // Assert
    assert!(result.is_ok());
    let created_user = result.unwrap();
    assert_eq!(created_user.email, "test@example.com");
}
```

## Integration Test Patterns

Integration tests verify complete authentication flows and are organized in the `/tests/` directory.

### Test Organization

```
oauth2_passkey/tests/
├── integration.rs            # Test module entry point
├── common/                   # Shared test utilities
│   ├── mod.rs
│   ├── fixtures.rs          # Test data and constants
│   └── mock_browser.rs      # HTTP client simulation
└── integration/
    ├── oauth2_flows.rs      # OAuth2 flow tests
    ├── passkey_flows.rs     # Passkey flow tests
    ├── combined_flows.rs    # Multi-method auth tests
    └── api_client_flows.rs  # API client tests
```

### Integration Test Structure

```rust
/// Integration tests for oauth2-passkey library
///
/// These tests verify complete authentication flows in an isolated test environment
/// with mocked external services and in-memory databases.
mod common;

mod integration {
    pub mod api_client_flows;
    pub mod combined_flows;
    pub mod oauth2_flows;
    pub mod passkey_flows;
}
```

### Flow Testing Example

```rust
use crate::common::{MockBrowser, TestSetup, TestUsers};

#[tokio::test]
async fn test_oauth2_login_flow() {
    // Setup test environment
    let setup = TestSetup::new().await;
    let browser = MockBrowser::new(&setup);

    // Start OAuth2 authorization
    let auth_url = browser.start_oauth2_login().await
        .expect("Should initiate OAuth2 flow");

    // Complete authorization (mock provider response)
    let (auth_code, state) = complete_oauth2_authorization(&auth_url).await
        .expect("Should complete authorization");

    // Handle callback
    let response = browser.oauth2_callback(&auth_code, &state).await
        .expect("Callback should succeed");

    // Verify session created
    assert!(response.headers().contains_key("set-cookie"));
}
```

## Test Utilities

The `test_utils` module provides centralized test setup functionality for consistent test environments.

### Initialization

```rust
use crate::test_utils::init_test_environment;

#[tokio::test]
async fn my_test() {
    // Initialize test environment once per test run
    init_test_environment().await;

    // Test code that requires database access
}
```

### What `init_test_environment()` Does

1. **Environment Setup** (runs once):
   - Loads `.env_test` file with test configuration
   - Falls back to `.env` if test file not found
   - Cleans up any existing test database file

2. **Database Initialization**:
   - Initializes UserStore, OAuth2Store, and PasskeyStore
   - Creates a first test user if none exists
   - Sets up test OAuth2 accounts and Passkey credentials

### Test Origin Helper

```rust
use crate::test_utils::get_test_origin;

#[test]
fn test_with_origin() {
    let origin = get_test_origin();
    // Returns ORIGIN from environment or defaults to "http://127.0.0.1:3000"
}
```

### First User Test Data

The test utilities automatically create a first user with:
- **User ID**: `first-user`
- **Email**: `first-user@example.com`
- **OAuth2 Account**: Google provider with test ID
- **Passkey Credential**: Valid ECDSA P-256 credential for signature verification

This enables integration tests to perform authentic authentication flows.

## Running Tests

```bash
# Run all tests
cargo test

# Run tests for specific crate
cargo test --manifest-path oauth2_passkey/Cargo.toml
cargo test --manifest-path oauth2_passkey_axum/Cargo.toml --all-features

# Run specific test module
cargo test module_name::tests::

# Run with logging output
RUST_LOG=debug cargo test -- --nocapture

# Run ignored (slow) tests
cargo test -- --ignored
```

## Best Practices

### Error Handling in Tests

- Prefer `expect()` with descriptive messages over `unwrap()`
- Test error cases explicitly
- Use pattern matching to verify error types

```rust
#[test]
fn test_invalid_input_returns_error() {
    let result = process_input("invalid");
    assert!(matches!(result, Err(MyError::InvalidInput(_))));
}
```

### Test Isolation

- Each test should be independent
- Use unique identifiers for test data
- Clean up test data when necessary
- Use test fixtures for complex setup

### Performance

- Keep individual tests fast (under 100ms for unit tests)
- Use in-memory databases for testing when possible
- Mark slow tests with `#[ignore]`
- Run slow tests separately in CI

```rust
#[test]
#[ignore]  // Run with: cargo test -- --ignored
fn slow_integration_test() {
    // Test that requires external services or significant time
}
```

### Documentation

- Document test requirements in comments
- Explain complex test scenarios
- Note any external dependencies
- Use doc comments for test helper functions

## Code Quality Commands

After making code changes, always verify quality:

```bash
# Format code
cargo fmt --all

# Check for issues
cargo clippy --all-targets --all-features

# Run tests
cargo test
```

All clippy warnings should be addressed before committing code.