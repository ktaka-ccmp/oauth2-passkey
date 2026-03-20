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

// --- PASSKEY_TIMEOUT ---

#[test]
fn test_passkey_timeout_rejects_invalid() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        let _ = *PASSKEY_TIMEOUT;
        return;
    }
    let output = run_child(
        "passkey::config::tests::test_passkey_timeout_rejects_invalid",
        "PASSKEY_TIMEOUT",
        "abc",
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("PASSKEY_TIMEOUT"));
}

#[test]
fn test_passkey_timeout_accepts_valid() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        assert_eq!(*PASSKEY_TIMEOUT, 120);
        return;
    }
    let output = run_child(
        "passkey::config::tests::test_passkey_timeout_accepts_valid",
        "PASSKEY_TIMEOUT",
        "120",
    );
    assert!(output.status.success());
}

// --- PASSKEY_CHALLENGE_TIMEOUT ---

#[test]
fn test_passkey_challenge_timeout_rejects_invalid() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        let _ = *PASSKEY_CHALLENGE_TIMEOUT;
        return;
    }
    let output = run_child(
        "passkey::config::tests::test_passkey_challenge_timeout_rejects_invalid",
        "PASSKEY_CHALLENGE_TIMEOUT",
        "xyz",
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("PASSKEY_CHALLENGE_TIMEOUT"));
}

#[test]
fn test_passkey_challenge_timeout_accepts_valid() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        assert_eq!(*PASSKEY_CHALLENGE_TIMEOUT, 90);
        return;
    }
    let output = run_child(
        "passkey::config::tests::test_passkey_challenge_timeout_accepts_valid",
        "PASSKEY_CHALLENGE_TIMEOUT",
        "90",
    );
    assert!(output.status.success());
}

// --- PASSKEY_ATTESTATION ---

#[test]
fn test_passkey_attestation_rejects_invalid() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        let _ = &*PASSKEY_ATTESTATION;
        return;
    }
    let output = run_child(
        "passkey::config::tests::test_passkey_attestation_rejects_invalid",
        "PASSKEY_ATTESTATION",
        "invalid",
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("PASSKEY_ATTESTATION"));
}

#[test]
fn test_passkey_attestation_accepts_valid() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        assert_eq!(*PASSKEY_ATTESTATION, "enterprise");
        return;
    }
    let output = run_child(
        "passkey::config::tests::test_passkey_attestation_accepts_valid",
        "PASSKEY_ATTESTATION",
        "enterprise",
    );
    assert!(output.status.success());
}

// --- PASSKEY_AUTHENTICATOR_ATTACHMENT ---

#[test]
fn test_passkey_authenticator_attachment_rejects_invalid() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        let _ = &*PASSKEY_AUTHENTICATOR_ATTACHMENT;
        return;
    }
    let output = run_child(
        "passkey::config::tests::test_passkey_authenticator_attachment_rejects_invalid",
        "PASSKEY_AUTHENTICATOR_ATTACHMENT",
        "invalid",
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("PASSKEY_AUTHENTICATOR_ATTACHMENT"));
}

#[test]
fn test_passkey_authenticator_attachment_accepts_valid() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        assert_eq!(*PASSKEY_AUTHENTICATOR_ATTACHMENT, "cross-platform");
        return;
    }
    let output = run_child(
        "passkey::config::tests::test_passkey_authenticator_attachment_accepts_valid",
        "PASSKEY_AUTHENTICATOR_ATTACHMENT",
        "cross-platform",
    );
    assert!(output.status.success());
}

// --- PASSKEY_RESIDENT_KEY ---

#[test]
fn test_passkey_resident_key_rejects_invalid() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        let _ = &*PASSKEY_RESIDENT_KEY;
        return;
    }
    let output = run_child(
        "passkey::config::tests::test_passkey_resident_key_rejects_invalid",
        "PASSKEY_RESIDENT_KEY",
        "invalid",
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("PASSKEY_RESIDENT_KEY"));
}

#[test]
fn test_passkey_resident_key_accepts_valid() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        assert_eq!(*PASSKEY_RESIDENT_KEY, "preferred");
        return;
    }
    let output = run_child(
        "passkey::config::tests::test_passkey_resident_key_accepts_valid",
        "PASSKEY_RESIDENT_KEY",
        "preferred",
    );
    assert!(output.status.success());
}

// --- PASSKEY_REQUIRE_RESIDENT_KEY ---

#[test]
fn test_passkey_require_resident_key_rejects_invalid() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        let _ = *PASSKEY_REQUIRE_RESIDENT_KEY;
        return;
    }
    let output = run_child(
        "passkey::config::tests::test_passkey_require_resident_key_rejects_invalid",
        "PASSKEY_REQUIRE_RESIDENT_KEY",
        "invalid",
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("PASSKEY_REQUIRE_RESIDENT_KEY"));
}

#[test]
fn test_passkey_require_resident_key_accepts_valid() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        assert_eq!(*PASSKEY_REQUIRE_RESIDENT_KEY, false);
        return;
    }
    let output = run_child(
        "passkey::config::tests::test_passkey_require_resident_key_accepts_valid",
        "PASSKEY_REQUIRE_RESIDENT_KEY",
        "false",
    );
    assert!(output.status.success());
}

// --- PASSKEY_USER_VERIFICATION ---

#[test]
fn test_passkey_user_verification_rejects_invalid() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        let _ = &*PASSKEY_USER_VERIFICATION;
        return;
    }
    let output = run_child(
        "passkey::config::tests::test_passkey_user_verification_rejects_invalid",
        "PASSKEY_USER_VERIFICATION",
        "invalid",
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("PASSKEY_USER_VERIFICATION"));
}

#[test]
fn test_passkey_user_verification_accepts_valid() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        assert_eq!(*PASSKEY_USER_VERIFICATION, "required");
        return;
    }
    let output = run_child(
        "passkey::config::tests::test_passkey_user_verification_accepts_valid",
        "PASSKEY_USER_VERIFICATION",
        "required",
    );
    assert!(output.status.success());
}

// --- PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL ---

#[test]
fn test_passkey_user_handle_unique_rejects_invalid() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        let _ = *PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL;
        return;
    }
    let output = run_child(
        "passkey::config::tests::test_passkey_user_handle_unique_rejects_invalid",
        "PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL",
        "invalid",
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL"));
}

#[test]
fn test_passkey_user_handle_unique_accepts_valid() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        assert_eq!(*PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL, true);
        return;
    }
    let output = run_child(
        "passkey::config::tests::test_passkey_user_handle_unique_accepts_valid",
        "PASSKEY_USER_HANDLE_UNIQUE_FOR_EVERY_CREDENTIAL",
        "true",
    );
    assert!(output.status.success());
}
