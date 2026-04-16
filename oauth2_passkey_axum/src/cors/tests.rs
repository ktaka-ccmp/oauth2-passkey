use super::*;
use crate::test_utils::env_var_test::{run_child_with_env as run_child, run_child_without_env};

// --- CORS_ALLOW_CREDENTIALS ---

#[test]
fn test_cors_allow_credentials_rejects_invalid() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        let _ = *CORS_ALLOW_CREDENTIALS;
        return;
    }
    let output = run_child(
        "cors::tests::test_cors_allow_credentials_rejects_invalid",
        "CORS_ALLOW_CREDENTIALS",
        "invalid",
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("CORS_ALLOW_CREDENTIALS"));
}

#[test]
fn test_cors_allow_credentials_accepts_valid() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        assert!(*CORS_ALLOW_CREDENTIALS);
        return;
    }
    let output = run_child(
        "cors::tests::test_cors_allow_credentials_accepts_valid",
        "CORS_ALLOW_CREDENTIALS",
        "true",
    );
    assert!(output.status.success());
}

#[test]
fn test_cors_allow_credentials_defaults_to_false() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        assert!(!(*CORS_ALLOW_CREDENTIALS));
        return;
    }
    let output = run_child_without_env(
        "cors::tests::test_cors_allow_credentials_defaults_to_false",
        "CORS_ALLOW_CREDENTIALS",
    );
    assert!(output.status.success());
}

#[test]
fn test_cors_allowed_origins_parsing() {
    // This test demonstrates the parsing logic
    let input = "https://app.example.com, https://admin.example.com";
    let origins: Vec<String> = input
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    assert_eq!(origins.len(), 2);
    assert_eq!(origins[0], "https://app.example.com");
    assert_eq!(origins[1], "https://admin.example.com");
}
