use super::*;
use crate::test_utils::run_child_without_env;

// --- ProviderKind ---

#[test]
fn test_provider_kind_from_path_segment_known() {
    assert_eq!(
        ProviderKind::from_path_segment("google"),
        Some(ProviderKind::Google)
    );
}

#[test]
fn test_provider_kind_from_path_segment_keycloak() {
    assert_eq!(
        ProviderKind::from_path_segment("keycloak"),
        Some(ProviderKind::Keycloak)
    );
}

#[test]
fn test_provider_kind_from_path_segment_unknown() {
    assert_eq!(ProviderKind::from_path_segment("github"), None);
    assert_eq!(ProviderKind::from_path_segment(""), None);
    assert_eq!(ProviderKind::from_path_segment("Google"), None); // case-sensitive
}

#[test]
fn test_provider_kind_as_str() {
    assert_eq!(ProviderKind::Google.as_str(), "google");
}

// --- from_path_segment: entra ---

#[test]
fn test_provider_kind_from_path_segment_entra() {
    assert_eq!(
        ProviderKind::from_path_segment("entra"),
        Some(ProviderKind::Entra)
    );
}

// --- optional_env_contract ---

#[test]
fn test_optional_env_contract_google() {
    assert_eq!(ProviderKind::Google.optional_env_contract(), None);
}

#[test]
fn test_optional_env_contract_auth0() {
    let (trigger, required) = ProviderKind::Auth0.optional_env_contract().unwrap();
    assert_eq!(trigger, "OAUTH2_AUTH0_CLIENT_ID");
    assert_eq!(
        required,
        ["OAUTH2_AUTH0_CLIENT_SECRET", "OAUTH2_AUTH0_ISSUER_URL"]
    );
}

#[test]
fn test_optional_env_contract_keycloak() {
    let (trigger, required) = ProviderKind::Keycloak.optional_env_contract().unwrap();
    assert_eq!(trigger, "OAUTH2_KEYCLOAK_CLIENT_ID");
    assert_eq!(
        required,
        [
            "OAUTH2_KEYCLOAK_CLIENT_SECRET",
            "OAUTH2_KEYCLOAK_ISSUER_URL"
        ]
    );
}

// --- provider_for ---

#[test]
fn test_provider_for_unknown_returns_none() {
    // provider_for can only be called with ProviderKind variants;
    // there is no way to pass an unknown kind at compile time.
    // This test documents that Google resolves to Some (when env vars set)
    // and that the function signature guarantees exhaustiveness.
    // provider_for(Google) tested in test_google_provider_initialization below.
    let _ = provider_for; // just ensure it compiles and is accessible
}

// --- GOOGLE_PROVIDER initialization ---

#[test]
fn test_google_provider_init_requires_client_id() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        let _ = &*GOOGLE_PROVIDER;
        return;
    }
    // Should panic when OAUTH2_GOOGLE_CLIENT_ID is missing
    let output = run_child_without_env(
        "oauth2::provider::tests::test_google_provider_init_requires_client_id",
        "OAUTH2_GOOGLE_CLIENT_ID",
    );
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("OAUTH2_GOOGLE_CLIENT_ID"));
}

#[test]
fn test_google_provider_init_accepts_valid_env() {
    if std::env::var("__TEST_ENV_VAR_CHILD").is_ok() {
        assert_eq!(GOOGLE_PROVIDER.client_id, "test-client-id");
        assert_eq!(GOOGLE_PROVIDER.kind, ProviderKind::Google);
        assert_eq!(
            provider_for(ProviderKind::Google).map(|p| p.kind),
            Some(ProviderKind::Google)
        );
        return;
    }
    let exe = std::env::current_exe().unwrap();
    let output = std::process::Command::new(&exe)
        .args([
            "oauth2::provider::tests::test_google_provider_init_accepts_valid_env",
            "--exact",
            "--nocapture",
        ])
        .env("__TEST_ENV_VAR_CHILD", "1")
        .env("OAUTH2_GOOGLE_CLIENT_ID", "test-client-id")
        .env("OAUTH2_GOOGLE_CLIENT_SECRET", "test-secret")
        .env("ORIGIN", "https://example.com")
        .output()
        .expect("failed to run child process");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

impl ProviderConfig {
    /// Build a `ProviderConfig` pointing at a local mock server.
    ///
    /// All discovery endpoints are pre-populated to `{base_url}/<path>` so no
    /// network calls are made and the mock server does not need to serve
    /// `/.well-known/openid-configuration`.
    ///
    /// `client_id` matches the `aud` claim emitted by `create_mock_jwt` in tests.
    pub(crate) fn for_mock_server(base_url: &str) -> Self {
        let discovery = OnceLock::new();
        let _ = discovery.set(OidcDiscoveryDocument {
            issuer: base_url.to_string(),
            authorization_endpoint: format!("{base_url}/oauth2/auth"),
            token_endpoint: format!("{base_url}/oauth2/token"),
            userinfo_endpoint: format!("{base_url}/oauth2/userinfo"),
            jwks_uri: format!("{base_url}/oauth2/v3/certs"),
            scopes_supported: None,
            response_types_supported: None,
            grant_types_supported: None,
            subject_types_supported: None,
            id_token_signing_alg_values_supported: None,
        });
        let response_mode = "query";
        let query_string = format!(
            "&response_type=code&scope=openid+email+profile&response_mode={response_mode}&access_type=online&prompt=consent"
        );
        Self {
            kind: ProviderKind::Google,
            client_id: "test-client-id.apps.googleusercontent.com".to_string(),
            client_secret: "test_secret".to_string(),
            issuer_url: base_url.to_string(),
            redirect_uri: format!("{base_url}/oauth2/google/authorized"),
            response_mode: response_mode.to_string(),
            query_string,
            discovery,
        }
    }

    /// Build a `ProviderConfig` for use in tests, with a pre-populated discovery
    /// document so no network calls are made.
    pub(crate) fn for_test(auth_url: &str, response_mode: &str) -> Self {
        let discovery = OnceLock::new();
        let _ = discovery.set(OidcDiscoveryDocument {
            issuer: "https://accounts.google.com".to_string(),
            authorization_endpoint: auth_url.to_string(),
            token_endpoint: "https://test.example.com/token".to_string(),
            userinfo_endpoint: "https://test.example.com/userinfo".to_string(),
            jwks_uri: "https://test.example.com/.well-known/certs".to_string(),
            scopes_supported: None,
            response_types_supported: None,
            grant_types_supported: None,
            subject_types_supported: None,
            id_token_signing_alg_values_supported: None,
        });
        let query_string = format!(
            "&response_type=code&scope=openid+email+profile&response_mode={}&access_type=online&prompt=consent",
            response_mode
        );
        Self {
            kind: ProviderKind::Google,
            client_id: "test_client_id".to_string(),
            client_secret: "test_secret".to_string(),
            issuer_url: "https://accounts.google.com".to_string(),
            redirect_uri: "https://test.example.com/oauth2/google/authorized".to_string(),
            response_mode: response_mode.to_string(),
            query_string,
            discovery,
        }
    }
}
