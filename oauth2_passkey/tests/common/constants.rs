/// OAuth2 authentication constants
pub mod oauth2 {
    /// Default OAuth2 response mode for tests
    pub const DEFAULT_RESPONSE_MODE: &str = "form_post";

    /// OAuth2 flow modes
    pub const ADD_TO_USER_MODE: &str = "add_to_user";

    /// Default OAuth2 issuer URL for tests
    pub const DEFAULT_ISSUER_URL: &str = "http://127.0.0.1:9876";
}

/// Passkey authentication constants
pub mod passkey {
    /// Default WebAuthn attestation format for successful tests
    pub const DEFAULT_ATTESTATION_FORMAT: &str = "packed";

    /// Fallback credential ID for mock credentials
    pub const FALLBACK_CREDENTIAL_ID: &str = "mock_credential_id_123";
}
