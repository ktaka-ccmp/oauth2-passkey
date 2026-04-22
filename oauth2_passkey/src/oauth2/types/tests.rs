use super::*;
use chrono::{Duration, Utc};
use serde_json::json;

/// Build a skeleton `OidcIdInfo` with every optional claim set to `None` — the
/// profile fields that the merged builder cares about stay unset so the
/// userinfo side of the merge is the sole source unless a test overrides it.
fn empty_idinfo(sub: &str) -> OidcIdInfo {
    OidcIdInfo {
        iss: "https://idp.example.com".to_string(),
        sub: sub.to_string(),
        azp: None,
        aud: vec!["client_id".to_string()],
        email: None,
        email_verified: None,
        name: None,
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
        preferred_username: None,
    }
}

/// Merged builder takes profile fields from the id_token — the signed source.
#[test]
fn test_merged_takes_profile_from_idinfo() {
    let idinfo = OidcIdInfo {
        email: Some("john@example.com".to_string()),
        email_verified: Some(true),
        name: Some("John Doe".to_string()),
        picture: Some("https://example.com/pic.jpg".to_string()),
        given_name: Some("John".to_string()),
        family_name: Some("Doe".to_string()),
        hd: Some("example.com".to_string()),
        ..empty_idinfo("12345")
    };
    let userinfo = OidcUserInfo {
        sub: "12345".to_string(),
        email: None,
        preferred_username: None,
        name: None,
        picture: None,
        family_name: None,
        given_name: None,
        hd: None,
        email_verified: None,
    };

    let account = oauth2_account_from_idinfo_and_userinfo(&idinfo, &userinfo, "google").unwrap();

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

/// Merged builder falls back to /userinfo when the id_token omits a claim.
/// This is the Zitadel-shape fix — providers that only assert profile claims
/// in /userinfo (not in the ID token) must still succeed through the main
/// callback.
#[test]
fn test_merged_falls_back_to_userinfo_when_idinfo_omits_fields() {
    let idinfo = empty_idinfo("sub-zit");
    let userinfo = OidcUserInfo {
        sub: "sub-zit".to_string(),
        email: Some("zit@example.com".to_string()),
        preferred_username: None,
        name: Some("Zitadel User".to_string()),
        picture: Some("https://example.com/zit.jpg".to_string()),
        family_name: Some("User".to_string()),
        given_name: Some("Zitadel".to_string()),
        hd: Some("example.com".to_string()),
        email_verified: Some(true),
    };

    let account = oauth2_account_from_idinfo_and_userinfo(&idinfo, &userinfo, "zitadel").unwrap();

    assert_eq!(account.email, "zit@example.com");
    assert_eq!(account.name, "Zitadel User");
    assert_eq!(
        account.picture,
        Some("https://example.com/zit.jpg".to_string())
    );
    assert_eq!(account.provider_user_id, "zitadel_sub-zit");

    let metadata = account.metadata.as_object().unwrap();
    assert_eq!(metadata["family_name"], json!("User"));
    assert_eq!(metadata["given_name"], json!("Zitadel"));
    assert_eq!(metadata["hd"], json!("example.com"));
    assert_eq!(metadata["email_verified"], json!(true));
}

/// The id_token wins per-field when both sources populate it — the signed
/// source is authoritative, and any /userinfo value is silently ignored.
#[test]
fn test_merged_idinfo_wins_per_field() {
    let idinfo = OidcIdInfo {
        email: Some("signed@example.com".to_string()),
        name: Some("Signed Name".to_string()),
        ..empty_idinfo("sub-1")
    };
    let userinfo = OidcUserInfo {
        sub: "sub-1".to_string(),
        email: Some("unsigned@example.com".to_string()),
        name: Some("Unsigned Name".to_string()),
        preferred_username: None,
        picture: None,
        family_name: None,
        given_name: None,
        hd: None,
        email_verified: None,
    };

    let account = oauth2_account_from_idinfo_and_userinfo(&idinfo, &userinfo, "zitadel").unwrap();
    assert_eq!(account.email, "signed@example.com");
    assert_eq!(account.name, "Signed Name");
}

/// Test conversion from OidcIdInfo to OAuth2Account via free function
#[test]
fn test_from_google_id_info() {
    let id_info = OidcIdInfo {
        iss: "https://accounts.google.com".to_string(),
        azp: Some("client_id".to_string()),
        aud: vec!["client_id".to_string()],
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
fn test_merged_userinfo_preferred_username_fallback() {
    let idinfo = empty_idinfo("msa_42");
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

    let account = oauth2_account_from_idinfo_and_userinfo(&idinfo, &userinfo, "entra").unwrap();
    assert_eq!(account.email, "alice@live.com");
    assert_eq!(account.name, "Alice");
}

/// Error is returned when email / preferred_username are absent in both sources.
#[test]
fn test_merged_missing_email_everywhere_errors() {
    let idinfo = empty_idinfo("sub_xyz");
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

    let result = oauth2_account_from_idinfo_and_userinfo(&idinfo, &userinfo, "entra");
    assert!(result.is_err());
    let msg = result.unwrap_err().to_string();
    assert!(msg.contains("email") && msg.contains("preferred_username"));
}

/// Merged view succeeds when email is present only in the id_token and not
/// in /userinfo — the case that was regressing under userinfo-only.
#[test]
fn test_merged_email_only_in_idinfo_succeeds() {
    let idinfo = OidcIdInfo {
        email: Some("frank@example.com".to_string()),
        ..empty_idinfo("sub-frank")
    };
    let userinfo = OidcUserInfo {
        sub: "sub-frank".to_string(),
        email: None,
        preferred_username: None,
        name: None,
        picture: None,
        family_name: None,
        given_name: None,
        hd: None,
        email_verified: None,
    };

    let account = oauth2_account_from_idinfo_and_userinfo(&idinfo, &userinfo, "entra").unwrap();
    assert_eq!(account.email, "frank@example.com");
    assert_eq!(account.name, "frank@example.com");
}

/// Name falls back to email when both sources omit the `name` claim.
#[test]
fn test_merged_name_falls_back_to_email() {
    let idinfo = empty_idinfo("sub_noname");
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

    let account = oauth2_account_from_idinfo_and_userinfo(&idinfo, &userinfo, "entra").unwrap();
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
        aud: vec!["client".to_string()],
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
