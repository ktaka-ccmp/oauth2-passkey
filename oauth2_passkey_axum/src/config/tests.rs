use super::*;
use crate::test_utils::env_var_test::{run_child_with_env as run_child, run_child_without_env};

// --- O2P_RESPOND_WITH_X_CSRF_TOKEN ---

#[test]
fn test_respond_with_x_csrf_token_rejects_invalid() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        let _ = *O2P_RESPOND_WITH_X_CSRF_TOKEN;
        return;
    }
    let output = run_child(
        "config::tests::test_respond_with_x_csrf_token_rejects_invalid",
        "O2P_RESPOND_WITH_X_CSRF_TOKEN",
        "invalid",
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("O2P_RESPOND_WITH_X_CSRF_TOKEN"));
}

#[test]
fn test_respond_with_x_csrf_token_accepts_valid() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        assert_eq!(*O2P_RESPOND_WITH_X_CSRF_TOKEN, false);
        return;
    }
    let output = run_child(
        "config::tests::test_respond_with_x_csrf_token_accepts_valid",
        "O2P_RESPOND_WITH_X_CSRF_TOKEN",
        "false",
    );
    assert!(output.status.success());
}

// --- O2P_FEDCM ---

#[test]
fn test_fedcm_rejects_invalid() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        let _ = *O2P_FEDCM;
        return;
    }
    let output = run_child(
        "config::tests::test_fedcm_rejects_invalid",
        "O2P_FEDCM",
        "invalid",
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("O2P_FEDCM"));
}

#[test]
fn test_fedcm_accepts_enabled() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        assert!(O2P_FEDCM.is_enabled());
        return;
    }
    let output = run_child(
        "config::tests::test_fedcm_accepts_enabled",
        "O2P_FEDCM",
        "enabled",
    );
    assert!(output.status.success());
}

// --- O2P_PASSKEY_PROMOTION ---

#[test]
fn test_passkey_promotion_rejects_invalid() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        let _ = *O2P_PASSKEY_PROMOTION;
        return;
    }
    let output = run_child(
        "config::tests::test_passkey_promotion_rejects_invalid",
        "O2P_PASSKEY_PROMOTION",
        "invalid",
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("O2P_PASSKEY_PROMOTION"));
}

#[test]
fn test_passkey_promotion_accepts_ask() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        assert_eq!(*O2P_PASSKEY_PROMOTION, PasskeyPromotionMode::Ask);
        return;
    }
    let output = run_child(
        "config::tests::test_passkey_promotion_accepts_ask",
        "O2P_PASSKEY_PROMOTION",
        "ask",
    );
    assert!(output.status.success());
}

// --- Default value tests ---

#[test]
fn test_respond_with_x_csrf_token_defaults_to_true() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        assert_eq!(*O2P_RESPOND_WITH_X_CSRF_TOKEN, true);
        return;
    }
    let output = run_child_without_env(
        "config::tests::test_respond_with_x_csrf_token_defaults_to_true",
        "O2P_RESPOND_WITH_X_CSRF_TOKEN",
    );
    assert!(output.status.success());
}

#[test]
fn test_fedcm_defaults_to_disabled() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        assert!(!O2P_FEDCM.is_enabled());
        return;
    }
    let output = run_child_without_env(
        "config::tests::test_fedcm_defaults_to_disabled",
        "O2P_FEDCM",
    );
    assert!(output.status.success());
}

#[test]
fn test_passkey_promotion_defaults_to_disabled() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        assert_eq!(*O2P_PASSKEY_PROMOTION, PasskeyPromotionMode::Disabled);
        return;
    }
    let output = run_child_without_env(
        "config::tests::test_passkey_promotion_defaults_to_disabled",
        "O2P_PASSKEY_PROMOTION",
    );
    assert!(output.status.success());
}
