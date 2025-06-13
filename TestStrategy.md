# OAuth2-Passkey Testing Strategy

This document outlines the testing strategy for the OAuth2-Passkey project, focusing on simplicity, maintainability, and minimal dependencies.

## Testing Principles

1. **Simplicity First**
   - Prefer simple, focused tests
   - One assertion per test when possible
   - Clear, descriptive test names

2. **Minimal Dependencies**
   - Avoid test-only dependencies when possible
   - Prefer standard library solutions
   - Document required test setup clearly

3. **Test Organization**
   - Unit tests in the same file as the code under test
   - Integration tests in `/tests/` directory
   - Documentation tests in module docs when helpful

## Module Testing Strategy

We'll follow a bottom-up testing approach, starting with the most fundamental modules:

### 1. Core Utilities (`src/utils.rs`)
- **Why Start Here**: Foundation used throughout the codebase
- **Testing Focus**:
  - Pure function behavior
  - Helper functions
  - Edge cases
- **Example Tests**:
  - Input validation
  - Output correctness
  - Error conditions

### 2. Configuration (`src/config.rs`)
- **Why Next**: Early validation of configuration
- **Testing Focus**:
  - Config loading
  - Validation rules
  - Environment variable handling
- **Testing Approach**:
  - Test with different config scenarios
  - Verify environment variable overrides
  - Test default values

### 3. Storage Layer (`src/storage/`)
- **Components**:
  - `cache_store/`
  - `data_store/`
- **Testing Focus**:
  - Data persistence
  - Cache behavior
  - Transaction handling
- **Testing Approach**:
  - Use in-memory SQLite for fast tests
  - Test against both SQLite and PostgreSQL in CI
  - Verify error handling

### 4. OAuth2 Module (`src/oauth2/`)
- **Components**:
  - `main/` - Core OAuth2 logic
  - `storage/` - OAuth2 data persistence
- **Testing Focus**:
  - OAuth2 flows
  - Token handling
  - Security validations
- **Testing Approach**:
  - Unit test core logic
  - Integration test with storage
  - Mock external services

### 5. Passkey Module (`src/passkey/`)
- **Components**:
  - `main/` - Core passkey logic
  - `storage/` - Passkey data persistence
- **Testing Focus**:
  - WebAuthn operations
  - Credential management
  - Security validations
- **Testing Approach**:
  - Test with mock authenticators
  - Verify cryptographic operations
  - Test edge cases

### 6. Session Management (`src/session/`)
- **Components**:
  - `main/` - Session handling
- **Testing Focus**:
  - Session creation/validation
  - Expiration handling
  - Security properties
- **Testing Approach**:
  - Unit test session logic
  - Test session storage
  - Verify security properties

### 7. User Database (`src/userdb/`)
- **Components**:
  - `storage/` - User data persistence
- **Testing Focus**:
  - User management
  - Authentication flows
  - Permission handling
- **Testing Approach**:
  - Test CRUD operations
  - Verify authentication flows
  - Test permission checks

### 8. Coordination Layer (`src/coordination/`)
- **Dependencies**: All previous modules
- **Testing Focus**:
  - Business workflows
  - Module integration
  - Error handling
- **Testing Approach**:
  - Test complete flows
  - Verify error recovery
  - Test edge cases

## Test Structure

### Unit Tests
```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_function_behavior() {
        // Arrange
        let input = ...;
        
        // Act
        let result = function_under_test(input);
        
        // Assert
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected_value);
    }
}
```

### Integration Tests
- Place in `/tests/` directory
- Test component interactions
- May require external services
- Document setup requirements

## Handling Dependencies

For modules requiring external services:
1. Document test setup requirements
2. Use feature flags if needed
3. Consider integration tests instead of unit tests
4. Provide test helpers when appropriate

## Running Tests

```bash
# Run all tests
cargo test

# Run specific test module
cargo test module_name::tests::

# Run with logging
RUST_LOG=debug cargo test -- --nocapture
```

## Best Practices

1. **No Unwraps**
   - Avoid `unwrap()` in tests
   - Use `expect()` with descriptive messages
   - Test error cases explicitly

2. **Test Documentation**
   - Document test requirements
   - Explain complex test scenarios
   - Note any test dependencies

3. **Test Isolation**
   - Each test should be independent
   - Clean up test data
   - Use test fixtures when helpful

4. **Performance**
   - Keep tests fast
   - Use in-memory databases for testing when possible
   - Mark slow tests with `#[ignore]`

## Future Considerations

- Property-based testing for critical paths
- Fuzz testing for security-sensitive code
- Benchmarking for performance-critical sections

---

Last Updated: 2025-06-04

## Configuration Testing

### Current Configuration Options

- `O2P_ROUTE_PREFIX`: Sets the route prefix for all oauth2_passkey endpoints (default: `/o2p`)

### Manual Testing Approach

Configuration can be tested manually using the demo01 example:

```bash
# Test with default prefix
cargo run --example demo01
# Then verify http://localhost:8080/o2p/auth works

# Test with custom prefix
O2P_ROUTE_PREFIX=/custom cargo run --example demo01
# Then verify http://localhost:8080/custom/auth works
```

### Future Automated Testing Considerations

In the future, a dedicated test application could be created to automate testing of configuration options:

1. **Minimal Test Application**
   - Similar to demo01 but focused specifically on testing configuration
   - Include endpoints that don't require complex authentication flows
   - Designed for automated testing with clear success/failure criteria

2. **Test Cases to Cover**
   - Default route prefix works correctly (`/o2p`)
   - Custom route prefix from environment variable works correctly
   - Routes are properly mounted under the configured prefix
   - Any future configuration options

3. **Implementation Options**
   - Integration tests that spawn the test application with different configurations
   - Shell script that runs the application with different configurations and tests endpoints
   - Dedicated test runner that manages the application lifecycle and runs tests

### Implementation Priority

This testing plan is considered low priority since:
1. The configuration system is relatively simple
2. Manual testing is currently sufficient
3. The focus should be on core functionality and user-facing features

The plan should be revisited when:
1. More configuration options are added
2. The configuration system becomes more complex
3. There's a need for more comprehensive automated testing

---

Do we have anything that needs unit tests here?


I'd like you to identify the functions for which writing unit tests a more appropriate than leaving it to integration tests, first. 


What do you think about unit tests in this module? Aren't there any meaningless tests that should be removed? Is there room for improvement?

Now that we can use in-memory GENERIC_DATA_STORE and in-memory GENERIC_CACHE_STORE, that are dedicated for unit testing, can you assess the unit tests in this module to see if there is a room for improvement?