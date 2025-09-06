use super::*;
use serde_json::json;

/// Test successful OIDC discovery document deserialization
#[test]
fn test_oidc_discovery_document_deserialization() {
    let json_data = json!({
        "issuer": "https://accounts.google.com",
        "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_endpoint": "https://oauth2.googleapis.com/token",
        "userinfo_endpoint": "https://openidconnect.googleapis.com/v1/userinfo",
        "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
        "scopes_supported": ["openid", "email", "profile"],
        "response_types_supported": ["code", "token", "id_token"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"]
    });

    let json_str = serde_json::to_string(&json_data).unwrap();
    let document: Result<OidcDiscoveryDocument, _> = serde_json::from_str(&json_str);

    assert!(document.is_ok());
    let doc = document.unwrap();
    assert_eq!(doc.issuer, "https://accounts.google.com");
    assert_eq!(
        doc.authorization_endpoint,
        "https://accounts.google.com/o/oauth2/v2/auth"
    );
    assert_eq!(doc.token_endpoint, "https://oauth2.googleapis.com/token");
    assert_eq!(doc.jwks_uri, "https://www.googleapis.com/oauth2/v3/certs");
}

/// Test OIDC discovery document with minimal required fields
#[test]
fn test_oidc_discovery_document_minimal() {
    let json_data = json!({
        "issuer": "https://example.com",
        "authorization_endpoint": "https://example.com/auth",
        "token_endpoint": "https://example.com/token",
        "userinfo_endpoint": "https://example.com/userinfo",
        "jwks_uri": "https://example.com/jwks"
    });

    let json_str = serde_json::to_string(&json_data).unwrap();
    let document: Result<OidcDiscoveryDocument, _> = serde_json::from_str(&json_str);

    assert!(document.is_ok());
    let doc = document.unwrap();
    assert_eq!(doc.issuer, "https://example.com");
    assert!(doc.scopes_supported.is_none());
    assert!(doc.response_types_supported.is_none());
}

/// Test OIDC discovery document deserialization with missing required fields
#[test]
fn test_oidc_discovery_document_missing_fields() {
    let json_data = json!({
        "issuer": "https://example.com",
        // Missing required endpoints
        "scopes_supported": ["openid"]
    });

    let json_str = serde_json::to_string(&json_data).unwrap();
    let document: Result<OidcDiscoveryDocument, _> = serde_json::from_str(&json_str);

    assert!(document.is_err());
}

/// Test error display formatting
#[test]
fn test_oidc_discovery_error_display() {
    let error = OidcDiscoveryError::IssuerMismatch(
        "https://actual.com".to_string(),
        "https://expected.com".to_string(),
    );
    assert_eq!(
        error.to_string(),
        "Issuer mismatch: discovered=https://actual.com, expected=https://expected.com"
    );

    let error = OidcDiscoveryError::InvalidUrl("invalid-url".to_string());
    assert_eq!(error.to_string(), "Invalid discovery URL: invalid-url");
}
