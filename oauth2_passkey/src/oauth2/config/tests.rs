use super::*;
use crate::test_utils::{run_child_with_env as run_child, run_child_without_env};

// --- OAUTH2_CSRF_COOKIE_NAME ---

#[test]
fn test_oauth2_csrf_cookie_name_defaults_to_host_prefix() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        assert_eq!(OAUTH2_CSRF_COOKIE_NAME.as_str(), "__Host-CsrfId");
        return;
    }
    let output = run_child_without_env(
        "oauth2::config::tests::test_oauth2_csrf_cookie_name_defaults_to_host_prefix",
        "OAUTH2_CSRF_COOKIE_NAME",
    );
    assert!(output.status.success());
}

#[test]
fn test_oauth2_csrf_cookie_name_accepts_custom_value() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        assert_eq!(OAUTH2_CSRF_COOKIE_NAME.as_str(), "MyCsrfCookie");
        return;
    }
    let output = run_child(
        "oauth2::config::tests::test_oauth2_csrf_cookie_name_accepts_custom_value",
        "OAUTH2_CSRF_COOKIE_NAME",
        "MyCsrfCookie",
    );
    assert!(output.status.success());
}

// --- OAUTH2_CSRF_COOKIE_MAX_AGE ---

#[test]
fn test_oauth2_csrf_cookie_max_age_rejects_invalid() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        let _ = *OAUTH2_CSRF_COOKIE_MAX_AGE;
        return;
    }
    let output = run_child(
        "oauth2::config::tests::test_oauth2_csrf_cookie_max_age_rejects_invalid",
        "OAUTH2_CSRF_COOKIE_MAX_AGE",
        "abc",
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("OAUTH2_CSRF_COOKIE_MAX_AGE"));
}

#[test]
fn test_oauth2_csrf_cookie_max_age_accepts_valid() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        assert_eq!(*OAUTH2_CSRF_COOKIE_MAX_AGE, 120);
        return;
    }
    let output = run_child(
        "oauth2::config::tests::test_oauth2_csrf_cookie_max_age_accepts_valid",
        "OAUTH2_CSRF_COOKIE_MAX_AGE",
        "120",
    );
    assert!(output.status.success());
}

#[test]
fn test_oauth2_csrf_cookie_max_age_defaults_to_60() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        assert_eq!(*OAUTH2_CSRF_COOKIE_MAX_AGE, 60);
        return;
    }
    let output = run_child_without_env(
        "oauth2::config::tests::test_oauth2_csrf_cookie_max_age_defaults_to_60",
        "OAUTH2_CSRF_COOKIE_MAX_AGE",
    );
    assert!(output.status.success());
}
