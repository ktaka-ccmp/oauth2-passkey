use super::*;
use chrono::{Duration, Utc};
use serde_json::json;

/// Test conversion from OidcUserInfo to OAuth2Account via free function
///
/// This test verifies that a OidcUserInfo struct can be correctly converted into
/// an OAuth2Account using `oauth2_account_from_userinfo`. It creates a OidcUserInfo
/// object in memory with sample data and validates that all fields are properly
/// mapped to the resulting OAuth2Account structure.
///
#[test]
fn test_from_google_user_info() {
    let google_user = OidcUserInfo {
        sub: "12345".to_string(),
        family_name: Some("Doe".to_string()),
        name: "John Doe".to_string(),
        picture: Some("https://example.com/pic.jpg".to_string()),
        email: "john@example.com".to_string(),
        given_name: Some("John".to_string()),
        hd: Some("example.com".to_string()),
        email_verified: Some(true),
    };

    let account = oauth2_account_from_userinfo(&google_user, "google");

    // Check that fields are correctly mapped
    assert_eq!(account.name, "John Doe");
    assert_eq!(account.email, "john@example.com");
    assert_eq!(
        account.picture,
        Some("https://example.com/pic.jpg".to_string())
    );
    assert_eq!(account.provider, "google");
    assert_eq!(account.provider_user_id, "google_12345");

    // Check metadata
    let metadata = account.metadata.as_object().unwrap();
    assert_eq!(metadata["family_name"], json!("Doe"));
    assert_eq!(metadata["given_name"], json!("John"));
    assert_eq!(metadata["hd"], json!("example.com"));
    assert_eq!(metadata["email_verified"], json!(true));
}

/// Test conversion from OidcIdInfo to OAuth2Account via free function
///
/// This test verifies that a OidcIdInfo struct can be correctly converted into
/// an OAuth2Account using `oauth2_account_from_idinfo`. It creates a OidcIdInfo
/// object in memory with ID token claims and validates that all fields are properly
/// mapped to the resulting OAuth2Account structure.
///
#[test]
fn test_from_google_id_info() {
    // Create a mock OidcIdInfo
    let id_info = OidcIdInfo {
        iss: "https://accounts.google.com".to_string(),
        azp: Some("client_id".to_string()),
        aud: "client_id".to_string(),
        sub: "12345".to_string(),
        email: "john@example.com".to_string(),
        email_verified: Some(true),
        at_hash: Some("hash".to_string()),
        name: "John Doe".to_string(),
        picture: Some("https://example.com/pic.jpg".to_string()),
        given_name: Some("John".to_string()),
        family_name: Some("Doe".to_string()),
        locale: Some("en".to_string()),
        iat: 0,
        exp: 0,
        nbf: Some(0),
        jti: Some("jti_value".to_string()),
        nonce: Some("nonce_value".to_string()),
        hd: Some("example.com".to_string()),
    };

    let account = oauth2_account_from_idinfo(&id_info, "google");

    // Check that fields are correctly mapped
    assert_eq!(account.name, "John Doe");
    assert_eq!(account.email, "john@example.com");
    assert_eq!(
        account.picture,
        Some("https://example.com/pic.jpg".to_string())
    );
    assert_eq!(account.provider, "google");
    assert_eq!(account.provider_user_id, "google_12345");

    // Check metadata
    let metadata = account.metadata.as_object().unwrap();
    assert_eq!(metadata["family_name"], json!("Doe"));
    assert_eq!(metadata["given_name"], json!("John"));
    assert_eq!(metadata["hd"], json!("example.com"));
    assert_eq!(metadata["verified_email"], json!(true));
}

/// Test StoredToken to CacheData conversion roundtrip
///
/// This test verifies that StoredToken can be converted to CacheData and back while
/// preserving all field values. It creates a StoredToken in memory, converts it to
/// CacheData, then back to StoredToken, and validates that all fields including
/// timestamps are preserved correctly through the conversion process.
///
#[test]
fn test_stored_token_cache_data_conversion() {
    // Create a StoredToken
    let now = Utc::now();
    let expires_at = now + Duration::seconds(3600);
    let stored_token = StoredToken {
        token: "test_token".to_string(),
        expires_at,
        user_agent: Some("test_agent".to_string()),
        ttl: 3600,
    };

    // Convert to CacheData
    let cache_data = CacheData::from(stored_token.clone());

    // Convert back to StoredToken
    let recovered_token = StoredToken::try_from(cache_data).unwrap();

    // Verify all fields match
    assert_eq!(recovered_token.token, stored_token.token);
    assert_eq!(
        recovered_token.expires_at.timestamp(),
        stored_token.expires_at.timestamp()
    );
    assert_eq!(recovered_token.user_agent, stored_token.user_agent);
    assert_eq!(recovered_token.ttl, stored_token.ttl);
}
