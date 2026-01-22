# Testing OIDC Discovery with Axum Mock Server

## Overview

This document explains how OIDC Discovery testing works with the new persistent Axum mock server architecture in the oauth2-passkey library.

## Architecture Changes

The testing infrastructure has been completely refactored:

- **Persistent Axum Mock Server**: Runs on fixed port 9876 throughout all tests
- **Thread-based Lifecycle**: Uses `std::thread::spawn` with dedicated tokio runtime
- **OIDC Discovery Support**: Full `.well-known/openid-configuration` endpoint implementation
- **Eliminated httpmock Dependency**: Replaced with native Axum-based mock OIDC provider

## Testing OIDC Discovery

### Current Test Architecture

All integration tests now work seamlessly with OIDC Discovery:

```bash
# Run all integration tests (includes OIDC Discovery)
cargo test --manifest-path oauth2_passkey/Cargo.toml --test integration
```

**Key improvements:**
- ✅ **Fixed port 9876**: No more random port conflicts or LazyLock issues
- ✅ **Persistent server**: Runs throughout entire test suite for consistency
- ✅ **OIDC Discovery endpoint**: Always available at `http://127.0.0.1:9876/.well-known/openid-configuration`
- ✅ **Nonce-aware JWT generation**: Proper OpenID Connect compliance

### Specific OIDC Discovery Tests

```bash
# Test OIDC Discovery endpoint specifically
cargo test test_oidc_discovery_endpoint -- --nocapture

# Test OAuth2 flow with OIDC Discovery
cargo test a_test_oauth2_uses_oidc_discovery -- --nocapture
```

## Integration with Full Test Suite

The new architecture eliminates previous LazyLock issues:

```bash
# All tests run reliably with serial execution
cargo test --manifest-path oauth2_passkey/Cargo.toml --test integration -- --test-threads=1
```

**Benefits:**
- ✅ **No initialization order issues**: Persistent server is always ready
- ✅ **Consistent OIDC Discovery**: Same endpoints used across all tests
- ✅ **Reliable test execution**: No flaky failures due to port conflicts

## Production Verification

In production, OIDC Discovery works correctly because:

1. **Single initialization**: The application initializes once at startup
2. **Consistent environment**: Production uses real Google OAuth2 endpoints
3. **No test conflicts**: No competing mock servers or test configurations

## Implementation Details

### Unified Test Configuration

The new architecture uses a single `.env_test` file for all test types:

```bash
# Unified test configuration in .env_test
OAUTH2_ISSUER_URL='http://127.0.0.1:9876'  # Persistent Axum mock server
# Individual URLs discovered dynamically from OIDC Discovery
```

### Test Infrastructure Components

1. **Production-Grade Mock Server** (`tests/common/axum_mock_server.rs`):
   - Runs on fixed port 9876 throughout all tests
   - Provides complete OIDC Discovery endpoint
   - Implements full OAuth2/OIDC specification compliance
   - Authorization code flow with UUID-based unique codes
   - PKCE S256 validation for enhanced security
   - Support for both form_post and query response modes
   - Automatic authorization code expiration and cleanup
   - Thread-based lifecycle with dedicated tokio runtime

2. **Unit Tests**:
   - Use dependency injection to avoid HTTP requests
   - Test behavior rather than hardcoded URLs
   - Maintain fast execution without external dependencies

3. **Integration Tests**:
   - Use OIDC Discovery for dynamic endpoint resolution
   - Test complete OAuth2 flows with production-grade mock server
   - Extract authorization codes from both response modes
   - Validate comprehensive success criteria including sessions and redirects
   - Verify OAuth2/OIDC compliance including PKCE and nonce verification

## Troubleshooting

### Mock Server Connection Issues

If you see connection refused errors:

```bash
# Check if the mock server is running on the expected port
netstat -an | grep 9876
```

**Solutions:**
- The persistent mock server starts automatically during test execution
- Server initialization includes a readiness check with 50 retry attempts
- Thread-based architecture ensures server persistence across tests

### Port Already in Use

If port 9876 is occupied:

```bash
# Find what's using the port
lsof -i :9876

# Kill the process if needed
kill $(lsof -t -i :9876)
```

The test server will handle port conflicts gracefully and report initialization status.

## Conclusion

The enhanced Axum mock server provides comprehensive OAuth2/OIDC testing capabilities:

- ✅ **Production-Grade Implementation**: Complete OAuth2/OIDC specification compliance
- ✅ **Authorization Code Flow**: UUID-based unique codes with proper expiration
- ✅ **PKCE Security**: S256 code challenge validation for enhanced security
- ✅ **Response Mode Support**: Both form_post and query modes fully implemented
- ✅ **Parameter Validation**: Comprehensive OAuth2 parameter validation matching production servers
- ✅ **OIDC Discovery**: Full `.well-known/openid-configuration` endpoint with dynamic URL resolution
- ✅ **Enhanced Testing**: Proper auth code extraction and comprehensive success validation
- ✅ **Automatic Cleanup**: Background task manages authorization code expiration
- ✅ **Test Reliability**: Thread-based persistence with tracing support for debugging

The mock server now provides production-equivalent OAuth2/OIDC testing while maintaining the reliability and performance benefits of the persistent architecture.
