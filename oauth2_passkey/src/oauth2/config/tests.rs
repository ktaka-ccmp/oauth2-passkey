use super::*;
use std::process::Command;

fn run_child(test_name: &str, env_name: &str, env_value: &str) -> std::process::Output {
    Command::new(std::env::current_exe().unwrap())
        .args([test_name, "--exact", "--nocapture"])
        .env("__TEST_ENV_VAR_CHILD", "1")
        .env(env_name, env_value)
        .output()
        .expect("Failed to spawn child process")
}

fn run_child_without_env(test_name: &str, env_name: &str) -> std::process::Output {
    Command::new(std::env::current_exe().unwrap())
        .args([test_name, "--exact", "--nocapture"])
        .env("__TEST_ENV_VAR_CHILD", "1")
        .env_remove(env_name)
        .output()
        .expect("Failed to spawn child process")
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
