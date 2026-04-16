use super::*;

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
