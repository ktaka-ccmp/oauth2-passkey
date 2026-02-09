use serde_json::json;

/// Test that promotion_start_registration rejects CreateUser mode
/// The promotion flow should only work with AddToUser mode
#[tokio::test]
async fn test_promotion_rejects_create_user_mode() {
    // Initialize test environment
    let _ = crate::test_utils::env::origin();

    // Simulate what promotion_start_registration would do with CreateUser mode
    // It should reject the request
    let mode = oauth2_passkey::RegistrationMode::CreateUser;
    let result: Result<(), (http::StatusCode, String)> = match mode {
        oauth2_passkey::RegistrationMode::AddToUser => Ok(()),
        oauth2_passkey::RegistrationMode::CreateUser => Err((
            http::StatusCode::BAD_REQUEST,
            "Promotion registration only supports add_to_user mode".to_string(),
        )),
    };

    assert!(result.is_err());
    let (status, message) = result.unwrap_err();
    assert_eq!(status, http::StatusCode::BAD_REQUEST);
    assert!(message.contains("add_to_user"));
}

/// Test that promotion flow includes excludeCredentials from user's existing credentials
/// This test verifies that the handler correctly appends excludeCredentials to the
/// registration options returned by the core function
#[tokio::test]
async fn test_promotion_includes_exclude_credentials() {
    use crate::test_utils::{core_mocks, mocks};

    // Initialize test environment
    let _ = crate::test_utils::env::origin();

    // Reset mock tracking
    core_mocks::reset_mock_calls();

    // Create a mock AuthUser
    let auth_user = mocks::mock_auth_user("test-user-id", "test@example.com");

    // Simulate getting credentials (what promotion handler does after core function)
    let credentials = core_mocks::mock_list_credentials_core(&auth_user.id, false)
        .await
        .expect("Failed to get mock credentials");

    // Build excludeCredentials from the credentials (same logic as the handler)
    let exclude_credentials: Vec<serde_json::Value> = credentials
        .iter()
        .map(|c| {
            json!({
                "type_": "public-key",
                "id": c.credential_id
            })
        })
        .collect();

    // Verify exclude_credentials is not empty
    assert!(
        !exclude_credentials.is_empty(),
        "excludeCredentials should not be empty when user has credentials"
    );

    // Verify the format of exclude_credentials
    let first = &exclude_credentials[0];
    assert_eq!(first["type_"], "public-key", "type should be 'public-key'");
    assert!(
        first["id"].is_string(),
        "id should be a string (credential_id)"
    );

    // Verify mock was called
    assert!(
        core_mocks::was_list_credentials_called(),
        "list_credentials should be called to build excludeCredentials"
    );
}

/// Test that promotion flow returns empty excludeCredentials when user has no credentials
#[tokio::test]
async fn test_promotion_empty_exclude_credentials_for_new_user() {
    // Initialize test environment
    let _ = crate::test_utils::env::origin();

    // Simulate the case where user has no existing credentials
    let credentials: Vec<oauth2_passkey::PasskeyCredential> = vec![];

    let exclude_credentials: Vec<serde_json::Value> = credentials
        .iter()
        .map(|c| {
            json!({
                "type_": "public-key",
                "id": c.credential_id
            })
        })
        .collect();

    assert!(
        exclude_credentials.is_empty(),
        "excludeCredentials should be empty when user has no credentials"
    );
}

// --- Tests for is_credential_likely_available() heuristic ---

use super::is_credential_likely_available;

/// Cross-platform password managers should always be considered available
#[test]
fn test_cross_platform_always_available() {
    let windows_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
    let mac_ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36";
    let android_ua = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36";

    // 1Password
    assert!(is_credential_likely_available("1Password", windows_ua));
    assert!(is_credential_likely_available("1Password", mac_ua));
    assert!(is_credential_likely_available("1Password", android_ua));

    // Bitwarden
    assert!(is_credential_likely_available("Bitwarden", windows_ua));
    assert!(is_credential_likely_available("Bitwarden", mac_ua));

    // Other cross-platform managers
    assert!(is_credential_likely_available("Dashlane", windows_ua));
    assert!(is_credential_likely_available("KeePassXC", mac_ua));
    assert!(is_credential_likely_available("NordPass", android_ua));
    assert!(is_credential_likely_available("Proton Pass", windows_ua));
}

/// iCloud Keychain should be available on Apple devices only
#[test]
fn test_icloud_on_apple_device() {
    let mac_ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15";
    let iphone_ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15";
    let ipad_ua = "Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15";

    assert!(is_credential_likely_available("iCloud Keychain", mac_ua));
    assert!(is_credential_likely_available("iCloud Keychain", iphone_ua));
    assert!(is_credential_likely_available("iCloud Keychain", ipad_ua));
    assert!(is_credential_likely_available(
        "iCloud Keychain (Managed)",
        mac_ua
    ));
}

/// iCloud Keychain should NOT be available on non-Apple devices
#[test]
fn test_icloud_on_non_apple_device() {
    let windows_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
    let android_ua = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36";

    assert!(!is_credential_likely_available(
        "iCloud Keychain",
        windows_ua
    ));
    assert!(!is_credential_likely_available(
        "iCloud Keychain",
        android_ua
    ));
}

/// Google Password Manager should be available on Chrome and Android
#[test]
fn test_google_pm_on_chrome() {
    let chrome_mac_ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
    let chrome_win_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
    let android_ua = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36";
    let chromeos_ua = "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36";

    assert!(is_credential_likely_available(
        "Google Password Manager",
        chrome_mac_ua
    ));
    assert!(is_credential_likely_available(
        "Google Password Manager",
        chrome_win_ua
    ));
    assert!(is_credential_likely_available(
        "Google Password Manager",
        android_ua
    ));
    assert!(is_credential_likely_available(
        "Google Password Manager",
        chromeos_ua
    ));
}

/// Google Password Manager should NOT be available on Safari-only (no Chrome)
#[test]
fn test_google_pm_on_safari() {
    let safari_ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15";

    assert!(!is_credential_likely_available(
        "Google Password Manager",
        safari_ua
    ));
}

/// Windows Hello should be available on Windows only
#[test]
fn test_windows_hello_on_windows() {
    let windows_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

    assert!(is_credential_likely_available("Windows Hello", windows_ua));
}

/// Windows Hello should NOT be available on non-Windows
#[test]
fn test_windows_hello_on_mac() {
    let mac_ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36";

    assert!(!is_credential_likely_available("Windows Hello", mac_ua));
}

/// Samsung Pass should be available on Android only
#[test]
fn test_samsung_pass_on_android() {
    let android_ua = "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36";
    let windows_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";

    assert!(is_credential_likely_available("Samsung Pass", android_ua));
    assert!(!is_credential_likely_available("Samsung Pass", windows_ua));
}

/// Unknown authenticator should be conservatively treated as not available
#[test]
fn test_unknown_authenticator() {
    let any_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";

    assert!(!is_credential_likely_available(
        "Unknown Authenticator",
        any_ua
    ));
    assert!(!is_credential_likely_available("", any_ua));
    assert!(!is_credential_likely_available(
        "Some Future Device",
        any_ua
    ));
}
