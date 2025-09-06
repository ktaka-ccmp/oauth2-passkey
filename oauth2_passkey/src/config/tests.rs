use super::*;

/// Test that O2P_ROUTE_PREFIX configuration works correctly
///
/// This test verifies that the O2P_ROUTE_PREFIX static value is properly initialized
/// based on environment variables or defaults to "/o2p" when not set. It tests the
/// LazyLock initialization behavior.
///
#[test]
fn test_route_prefix_default_value() {
    // Test that the default route prefix is correct when env var is not set
    let prefix = &*O2P_ROUTE_PREFIX;

    // This test verifies the current state - either default or env value
    match std::env::var("O2P_ROUTE_PREFIX") {
        Err(_) => assert_eq!(prefix, "/o2p"),
        Ok(env_value) => assert_eq!(prefix, &env_value),
    }
}

/// Test that O2P_ROUTE_PREFIX meets validation criteria
///
/// This test verifies that the route prefix follows expected formatting rules:
/// starts with a forward slash, is not empty, and doesn't end with a slash
/// (unless it's just "/").
///
#[test]
fn test_route_prefix_validation() {
    let prefix = &*O2P_ROUTE_PREFIX;

    // Route prefix should start with forward slash
    assert!(
        prefix.starts_with('/'),
        "Route prefix should start with '/'"
    );

    // Route prefix should not be empty
    assert!(!prefix.is_empty(), "Route prefix should not be empty");

    // Route prefix should not end with slash (unless it's just "/")
    if prefix.len() > 1 {
        assert!(
            !prefix.ends_with('/'),
            "Route prefix should not end with '/' unless it's root"
        );
    }
}
