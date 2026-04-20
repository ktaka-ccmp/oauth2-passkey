use super::*;
use chrono::{Duration, Utc};
use serde_json::json;

/// Test conversion from OidcUserInfo to OAuth2Account via free function
#[test]
fn test_from_google_user_info() {
    let google_user = OidcUserInfo {
        sub: "12345".to_string(),
        family_name: Some("Doe".to_string()),
        name: Some("John Doe".to_string()),
        picture: Some("https://example.com/pic.jpg".to_string()),
        email: Some("john@example.com".to_string()),
        given_name: Some("John".to_string()),
        hd: Some("example.com".to_string()),
        email_verified: Some(true),
        preferred_username: None,
    };

    let account = oauth2_account_from_userinfo(&google_user, "google").unwrap();

    assert_eq!(account.name, "John Doe");
    assert_eq!(account.email, "john@example.com");
    assert_eq!(
        account.picture,
        Some("https://example.com/pic.jpg".to_string())
    );
    assert_eq!(account.provider, "google");
    assert_eq!(account.provider_user_id, "google_12345");

    let metadata = account.metadata.as_object().unwrap();
    assert_eq!(metadata["family_name"], json!("Doe"));
    assert_eq!(metadata["given_name"], json!("John"));
    assert_eq!(metadata["hd"], json!("example.com"));
    assert_eq!(metadata["email_verified"], json!(true));
}

/// Test conversion from OidcIdInfo to OAuth2Account via free function
#[test]
fn test_from_google_id_info() {
    let id_info = OidcIdInfo {
        iss: "https://accounts.google.com".to_string(),
        azp: Some("client_id".to_string()),
        aud: "client_id".to_string(),
        sub: "12345".to_string(),
        email: Some("john@example.com".to_string()),
        email_verified: Some(true),
        at_hash: Some("hash".to_string()),
        name: Some("John Doe".to_string()),
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
        preferred_username: None,
    };

    let account = oauth2_account_from_idinfo(&id_info, "google").unwrap();

    assert_eq!(account.name, "John Doe");
    assert_eq!(account.email, "john@example.com");
    assert_eq!(
        account.picture,
        Some("https://example.com/pic.jpg".to_string())
    );
    assert_eq!(account.provider, "google");
    assert_eq!(account.provider_user_id, "google_12345");

    let metadata = account.metadata.as_object().unwrap();
    assert_eq!(metadata["family_name"], json!("Doe"));
    assert_eq!(metadata["given_name"], json!("John"));
    assert_eq!(metadata["hd"], json!("example.com"));
    assert_eq!(metadata["verified_email"], json!(true));
}

/// preferred_username is used when email claim is absent (Entra personal account case)
#[test]
fn test_userinfo_preferred_username_fallback() {
    let userinfo = OidcUserInfo {
        sub: "msa_42".to_string(),
        email: None,
        preferred_username: Some("alice@live.com".to_string()),
        name: Some("Alice".to_string()),
        picture: None,
        family_name: None,
        given_name: None,
        hd: None,
        email_verified: None,
    };

    let account = oauth2_account_from_userinfo(&userinfo, "entra").unwrap();
    assert_eq!(account.email, "alice@live.com");
    assert_eq!(account.name, "Alice");
}

/// Error is returned when both email and preferred_username are absent
#[test]
fn test_userinfo_missing_email_and_preferred_username_errors() {
    let userinfo = OidcUserInfo {
        sub: "sub_xyz".to_string(),
        email: None,
        preferred_username: None,
        name: Some("Bob".to_string()),
        picture: None,
        family_name: None,
        given_name: None,
        hd: None,
        email_verified: None,
    };

    let result = oauth2_account_from_userinfo(&userinfo, "entra");
    assert!(result.is_err());
    let msg = result.unwrap_err().to_string();
    assert!(msg.contains("email") && msg.contains("preferred_username"));
}

/// Name falls back to email when name claim is absent
#[test]
fn test_userinfo_name_falls_back_to_email() {
    let userinfo = OidcUserInfo {
        sub: "sub_noname".to_string(),
        email: Some("carol@example.com".to_string()),
        preferred_username: None,
        name: None,
        picture: None,
        family_name: None,
        given_name: None,
        hd: None,
        email_verified: None,
    };

    let account = oauth2_account_from_userinfo(&userinfo, "entra").unwrap();
    assert_eq!(account.name, "carol@example.com");
    assert_eq!(account.email, "carol@example.com");
}

/// preferred_username fallback works for idinfo path too
#[test]
fn test_idinfo_preferred_username_fallback() {
    let id_info = OidcIdInfo {
        iss: "https://login.microsoftonline.com/tenant/v2.0".to_string(),
        sub: "msa_99".to_string(),
        azp: None,
        aud: "client".to_string(),
        email: None,
        preferred_username: Some("dave@hotmail.com".to_string()),
        email_verified: None,
        name: Some("Dave".to_string()),
        picture: None,
        given_name: None,
        family_name: None,
        locale: None,
        iat: 0,
        exp: 0,
        nbf: None,
        jti: None,
        nonce: None,
        hd: None,
        at_hash: None,
    };

    let account = oauth2_account_from_idinfo(&id_info, "entra").unwrap();
    assert_eq!(account.email, "dave@hotmail.com");
    assert_eq!(account.name, "Dave");
}

/// Test StoredToken to CacheData conversion roundtrip
#[test]
fn test_stored_token_cache_data_conversion() {
    let now = Utc::now();
    let expires_at = now + Duration::seconds(3600);
    let stored_token = StoredToken {
        token: "test_token".to_string(),
        expires_at,
        user_agent: Some("test_agent".to_string()),
        ttl: 3600,
    };

    let cache_data = CacheData::from(stored_token.clone());
    let recovered_token = StoredToken::try_from(cache_data).unwrap();

    assert_eq!(recovered_token.token, stored_token.token);
    assert_eq!(
        recovered_token.expires_at.timestamp(),
        stored_token.expires_at.timestamp()
    );
    assert_eq!(recovered_token.user_agent, stored_token.user_agent);
    assert_eq!(recovered_token.ttl, stored_token.ttl);
}
