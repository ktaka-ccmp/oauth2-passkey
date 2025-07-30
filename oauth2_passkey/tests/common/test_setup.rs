use super::{MockBrowser, TestServer, TestUsers};

/// Generic test environment setup for authentication tests
///
/// This structure provides a common foundation for both OAuth2 and passkey tests,
/// managing the test server, browser, and test user lifecycle.
pub struct AuthTestSetup {
    pub server: TestServer,
    pub browser: MockBrowser,
    pub test_user: crate::common::fixtures::TestUser,
}

impl AuthTestSetup {
    /// Create a new test environment with default OAuth2 user
    pub async fn new_oauth2() -> Result<Self, Box<dyn std::error::Error>> {
        let server = TestServer::start().await?;
        let browser = MockBrowser::new(&server.base_url, true);
        let test_user = TestUsers::oauth2_user();
        Ok(Self {
            server,
            browser,
            test_user,
        })
    }

    /// Create a new test environment with default passkey user
    pub async fn new_passkey() -> Result<Self, Box<dyn std::error::Error>> {
        let server = TestServer::start().await?;
        let browser = MockBrowser::new(&server.base_url, true);
        let test_user = TestUsers::passkey_user();
        Ok(Self {
            server,
            browser,
            test_user,
        })
    }

    /// Create a new test environment with a specific test user
    pub async fn with_user(
        test_user: crate::common::fixtures::TestUser,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let server = TestServer::start().await?;
        let browser = MockBrowser::new(&server.base_url, true);
        Ok(Self {
            server,
            browser,
            test_user,
        })
    }

    /// Get the base URL for the test server
    pub fn base_url(&self) -> &str {
        &self.server.base_url
    }

    /// Shutdown the test server
    pub async fn shutdown(self) -> Result<(), Box<dyn std::error::Error>> {
        self.server.shutdown().await;
        Ok(())
    }
}

/// OAuth2-specific configuration and utilities
pub struct OAuth2Config {
    pub default_response_mode: String,
    pub provider: String,
    pub issuer_url: String,
}

impl OAuth2Config {
    pub fn new() -> Self {
        Self {
            default_response_mode: std::env::var("OAUTH2_RESPONSE_MODE")
                .unwrap_or_else(|_| "form_post".to_string()),
            provider: "google".to_string(),
            issuer_url: std::env::var("OAUTH2_ISSUER_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:9876".to_string()),
        }
    }

    pub fn response_mode(&self) -> &str {
        &self.default_response_mode
    }

    pub fn issuer_url(&self) -> &str {
        &self.issuer_url
    }
}

impl Default for OAuth2Config {
    fn default() -> Self {
        Self::new()
    }
}

/// Passkey-specific configuration and utilities
pub struct PasskeyConfig {
    pub default_attestation_format: String,
    pub fallback_credential_id: String,
}

impl PasskeyConfig {
    pub fn new() -> Self {
        Self {
            default_attestation_format: "packed".to_string(),
            fallback_credential_id: "mock_credential_id_123".to_string(),
        }
    }

    pub fn attestation_format(&self) -> &str {
        &self.default_attestation_format
    }

    pub fn fallback_credential_id(&self) -> &str {
        &self.fallback_credential_id
    }
}

impl Default for PasskeyConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Combined test setup for tests that use both OAuth2 and passkey authentication
pub struct CombinedAuthSetup {
    pub base: AuthTestSetup,
    pub oauth2_config: OAuth2Config,
    pub passkey_config: PasskeyConfig,
}

impl CombinedAuthSetup {
    /// Create a new combined authentication test environment
    pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let base = AuthTestSetup::new_oauth2().await?; // Default to OAuth2 user for combined tests
        let oauth2_config = OAuth2Config::new();
        let passkey_config = PasskeyConfig::new();

        Ok(Self {
            base,
            oauth2_config,
            passkey_config,
        })
    }

    /// Get the base URL for the test server
    pub fn base_url(&self) -> &str {
        self.base.base_url()
    }

    /// Shutdown the test server
    pub async fn shutdown(self) -> Result<(), Box<dyn std::error::Error>> {
        self.base.shutdown().await
    }
}
