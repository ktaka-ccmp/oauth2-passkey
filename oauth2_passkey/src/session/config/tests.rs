use super::*;
use crate::test_utils::{run_child_with_env as run_child, run_child_without_env};

// --- SESSION_COOKIE_MAX_AGE ---

#[test]
fn test_session_cookie_max_age_rejects_invalid() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        let _ = *SESSION_COOKIE_MAX_AGE;
        return;
    }
    let output = run_child(
        "session::config::tests::test_session_cookie_max_age_rejects_invalid",
        "SESSION_COOKIE_MAX_AGE",
        "abc",
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("SESSION_COOKIE_MAX_AGE"));
}

#[test]
fn test_session_cookie_max_age_accepts_valid() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        assert_eq!(*SESSION_COOKIE_MAX_AGE, 300);
        return;
    }
    let output = run_child(
        "session::config::tests::test_session_cookie_max_age_accepts_valid",
        "SESSION_COOKIE_MAX_AGE",
        "300",
    );
    assert!(output.status.success());
}

// --- SESSION_CONFLICT_POLICY ---

#[test]
fn test_session_conflict_policy_rejects_invalid() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        let _ = *SESSION_CONFLICT_POLICY;
        return;
    }
    let output = run_child(
        "session::config::tests::test_session_conflict_policy_rejects_invalid",
        "SESSION_CONFLICT_POLICY",
        "invalid",
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("SESSION_CONFLICT_POLICY"));
}

#[test]
fn test_session_conflict_policy_accepts_replace() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        assert_eq!(*SESSION_CONFLICT_POLICY, SessionConflictPolicy::Replace);
        return;
    }
    let output = run_child(
        "session::config::tests::test_session_conflict_policy_accepts_replace",
        "SESSION_CONFLICT_POLICY",
        "replace",
    );
    assert!(output.status.success());
}

// --- AUTH_SERVER_SECRET ---

#[test]
fn test_auth_server_secret_uses_env_value() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        assert_eq!(*AUTH_SERVER_SECRET, b"my_test_secret");
        return;
    }
    let output = run_child(
        "session::config::tests::test_auth_server_secret_uses_env_value",
        "AUTH_SERVER_SECRET",
        "my_test_secret",
    );
    assert!(output.status.success());
}

#[test]
fn test_auth_server_secret_generates_random_when_unset() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        let secret = &*AUTH_SERVER_SECRET;
        assert_eq!(secret.len(), 32, "Random secret should be 32 bytes");
        assert!(
            !secret.iter().all(|&b| b == 0),
            "Random secret should not be all zeros"
        );
        return;
    }
    let output = run_child_without_env(
        "session::config::tests::test_auth_server_secret_generates_random_when_unset",
        "AUTH_SERVER_SECRET",
    );
    assert!(output.status.success());
}

// --- Default value tests ---

#[test]
fn test_session_cookie_max_age_defaults_to_600() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        assert_eq!(*SESSION_COOKIE_MAX_AGE, 600);
        return;
    }
    let output = run_child_without_env(
        "session::config::tests::test_session_cookie_max_age_defaults_to_600",
        "SESSION_COOKIE_MAX_AGE",
    );
    assert!(output.status.success());
}

#[test]
fn test_session_conflict_policy_defaults_to_allow() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        assert_eq!(*SESSION_CONFLICT_POLICY, SessionConflictPolicy::Allow);
        return;
    }
    let output = run_child_without_env(
        "session::config::tests::test_session_conflict_policy_defaults_to_allow",
        "SESSION_CONFLICT_POLICY",
    );
    assert!(output.status.success());
}
