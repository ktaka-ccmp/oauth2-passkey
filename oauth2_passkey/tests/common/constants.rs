/// OAuth2 authentication constants
pub mod oauth2 {
    /// Default OAuth2 response mode for tests
    pub const DEFAULT_RESPONSE_MODE: &str = "form_post";

    /// OAuth2 provider name
    pub const PROVIDER: &str = "google";

    /// OAuth2 flow modes
    pub const CREATE_USER_MODE: &str = "create_user_or_login";
    pub const LOGIN_MODE: &str = "login";
    pub const ADD_TO_USER_MODE: &str = "add_to_user";

    /// Expected success messages in OAuth2 responses
    pub const NEW_USER_MESSAGE: &str = "Created%20new%20user";
    pub const EXISTING_USER_MESSAGE: &str = "Signing%20in%20as";
    pub const LINKED_ACCOUNT_MESSAGE: &str = "Successfully%20linked%20to";

    /// Default OAuth2 issuer URL for tests
    pub const DEFAULT_ISSUER_URL: &str = "http://127.0.0.1:9876";
}

/// Passkey authentication constants
pub mod passkey {
    /// Default WebAuthn attestation format for successful tests
    pub const DEFAULT_ATTESTATION_FORMAT: &str = "packed";

    /// Fallback credential ID for mock credentials
    pub const FALLBACK_CREDENTIAL_ID: &str = "mock_credential_id_123";

    /// Additional credential display name suffix
    pub const ADDITIONAL_CREDENTIAL_SUFFIX: &str = "#2";

    /// WebAuthn attestation formats for testing
    pub const ATTESTATION_FORMAT_NONE: &str = "none";
    pub const ATTESTATION_FORMAT_PACKED: &str = "packed";
    pub const ATTESTATION_FORMAT_TPM: &str = "tpm";
}

/// Common authentication constants
pub mod common {
    /// Default test origin URL
    pub const DEFAULT_ORIGIN: &str = "http://127.0.0.1:3000";

    /// Session cookie names
    pub const SESSION_COOKIE_HOST: &str = "__Host-SessionId";
    pub const SESSION_COOKIE_TEST: &str = "SessionId-Test";

    /// CSRF cookie name
    pub const CSRF_COOKIE_NAME: &str = "__Host-CsrfId";

    /// Common API endpoints
    pub const USER_INFO_ENDPOINT: &str = "/auth/user/info";
    pub const USER_LOGOUT_ENDPOINT: &str = "/auth/user/logout";
    pub const CSRF_TOKEN_ENDPOINT: &str = "/auth/user/csrf_token";
    pub const USER_SUMMARY_ENDPOINT: &str = "/auth/user/summary";
}
