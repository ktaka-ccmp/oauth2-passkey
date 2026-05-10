use super::*;
use crate::test_utils::{run_child_with_env as run_child, run_child_without_env};

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

// --- Env var validation tests (Option B) ---
// Each test serves double duty: as parent (spawns child) and as child (evaluates the variable).
// The __TEST_ENV_VAR_CHILD env var distinguishes the two roles.

#[test]
fn test_demo_mode_rejects_invalid() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        let _ = *O2P_DEMO_MODE;
        return;
    }
    let output = run_child(
        "config::tests::test_demo_mode_rejects_invalid",
        "O2P_DEMO_MODE",
        "invalid",
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("O2P_DEMO_MODE"));
}

#[test]
fn test_demo_mode_accepts_true() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        assert!(*O2P_DEMO_MODE);
        return;
    }
    let output = run_child(
        "config::tests::test_demo_mode_accepts_true",
        "O2P_DEMO_MODE",
        "true",
    );
    assert!(output.status.success(), "Should accept O2P_DEMO_MODE=true");
}

#[test]
fn test_demo_mode_accepts_false() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        assert!(!(*O2P_DEMO_MODE));
        return;
    }
    let output = run_child(
        "config::tests::test_demo_mode_accepts_false",
        "O2P_DEMO_MODE",
        "false",
    );
    assert!(output.status.success(), "Should accept O2P_DEMO_MODE=false");
}

#[test]
fn test_signal_api_mode_rejects_invalid() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        let _ = *PASSKEY_SIGNAL_API_MODE;
        return;
    }
    let output = run_child(
        "config::tests::test_signal_api_mode_rejects_invalid",
        "PASSKEY_SIGNAL_API_MODE",
        "invalid_mode",
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("PASSKEY_SIGNAL_API_MODE"));
}

#[test]
fn test_signal_api_mode_accepts_valid() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        assert_eq!(*PASSKEY_SIGNAL_API_MODE, "direct+sync");
        return;
    }
    let output = run_child(
        "config::tests::test_signal_api_mode_accepts_valid",
        "PASSKEY_SIGNAL_API_MODE",
        "direct+sync",
    );
    assert!(
        output.status.success(),
        "Should accept PASSKEY_SIGNAL_API_MODE=direct+sync"
    );
}

#[test]
fn test_demo_mode_defaults_to_false() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        assert!(!(*O2P_DEMO_MODE));
        return;
    }
    let output = run_child_without_env(
        "config::tests::test_demo_mode_defaults_to_false",
        "O2P_DEMO_MODE",
    );
    assert!(output.status.success());
}

#[test]
fn test_signal_api_mode_defaults_to_direct() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        assert_eq!(*PASSKEY_SIGNAL_API_MODE, "direct");
        return;
    }
    let output = run_child_without_env(
        "config::tests::test_signal_api_mode_defaults_to_direct",
        "PASSKEY_SIGNAL_API_MODE",
    );
    assert!(output.status.success());
}
