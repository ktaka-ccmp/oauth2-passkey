use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::FromRow;

use super::errors::OAuth2Error;
use super::main::IdInfo as GoogleIdInfo;

use crate::session::UserId;
use crate::storage::CacheData;

/// Represents an OAuth2 account linked to a user
///
/// This struct contains information about an OAuth2 account that has been
/// authenticated and linked to a user in the system. It stores both
/// the provider-specific information and internal tracking data.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct OAuth2Account {
    /// Unique identifier for this OAuth2 account in our system
    pub id: String,
    /// Internal user ID this OAuth2 account is linked to
    pub user_id: String,
    /// OAuth2 provider name (e.g., "google")
    pub provider: String,
    /// User identifier from the OAuth2 provider
    pub provider_user_id: String,
    /// User's display name from the OAuth2 provider
    pub name: String,
    /// User's email address from the OAuth2 provider
    pub email: String,
    /// Optional URL to user's profile picture
    pub picture: Option<String>,
    /// Additional provider-specific metadata as JSON
    pub metadata: Value,
    /// When this OAuth2 account was first linked
    pub created_at: DateTime<Utc>,
    /// When this OAuth2 account was last updated
    pub updated_at: DateTime<Utc>,
}

impl Default for OAuth2Account {
    fn default() -> Self {
        Self {
            id: String::new(),
            user_id: String::new(),
            provider: String::new(),
            provider_user_id: String::new(),
            name: String::new(),
            email: String::new(),
            picture: None,
            metadata: Value::Null,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }
}

// The user data we'll get back from Google
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct GoogleUserInfo {
    pub(crate) sub: String,
    pub(crate) family_name: String,
    pub name: String,
    pub picture: Option<String>,
    pub(crate) email: String,
    pub(crate) given_name: String,
    pub(crate) hd: Option<String>,
    pub(crate) email_verified: bool,
}

// Add these implementations
impl From<GoogleUserInfo> for OAuth2Account {
    fn from(google_user: GoogleUserInfo) -> Self {
        Self {
            id: String::new(),      // Will be set during storage
            user_id: String::new(), // Will be set during upsert process
            name: google_user.name,
            email: google_user.email,
            picture: google_user.picture,
            provider: "google".to_string(),
            provider_user_id: format!("google_{}", google_user.sub),
            metadata: json!({
                "family_name": google_user.family_name,
                "given_name": google_user.given_name,
                "hd": google_user.hd,
                "email_verified": google_user.email_verified,
            }),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }
}

impl From<GoogleIdInfo> for OAuth2Account {
    fn from(idinfo: GoogleIdInfo) -> Self {
        Self {
            id: String::new(),      // Will be set during storage
            user_id: String::new(), // Will be set during upsert process
            name: idinfo.name,
            email: idinfo.email,
            picture: idinfo.picture,
            provider: "google".to_string(),
            provider_user_id: format!("google_{}", idinfo.sub),
            metadata: json!({
                "family_name": idinfo.family_name,
                "given_name": idinfo.given_name,
                "hd": idinfo.hd,
                "verified_email": idinfo.email_verified,
            }),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct StateParams {
    pub(crate) csrf_id: String,
    pub(crate) nonce_id: String,
    pub(crate) pkce_id: String,
    pub(crate) misc_id: Option<String>,
    pub(crate) mode_id: Option<String>,
}

#[derive(Serialize, Clone, Deserialize, Debug)]
pub(crate) struct StoredToken {
    pub(crate) token: String,
    pub(crate) expires_at: DateTime<Utc>,
    pub(crate) user_agent: Option<String>,
    pub(crate) ttl: u64,
}

/// Response from an OAuth2 authorization request
///
/// This struct represents the data received from an OAuth2 provider's
/// authorization endpoint. It contains the authorization code and state
/// parameter needed to complete the OAuth2 flow.
#[derive(Debug, Deserialize)]
pub struct AuthResponse {
    /// Authorization code from the OAuth2 provider
    pub(crate) code: String,
    /// State parameter that was included in the original request
    pub state: String,
    /// Optional ID token if provided directly by the authorization endpoint
    _id_token: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(super) struct OidcTokenResponse {
    pub(super) access_token: String,
    token_type: String,
    expires_in: u64,
    refresh_token: Option<String>,
    scope: String,
    pub(super) id_token: Option<String>,
}

impl From<StoredToken> for CacheData {
    fn from(data: StoredToken) -> Self {
        Self {
            value: serde_json::to_string(&data).expect("Failed to serialize StoredToken"),
            expires_at: data.expires_at,
        }
    }
}

impl TryFrom<CacheData> for StoredToken {
    type Error = OAuth2Error;

    fn try_from(data: CacheData) -> Result<Self, Self::Error> {
        serde_json::from_str(&data.value).map_err(|e| OAuth2Error::Storage(e.to_string()))
    }
}

/// Search field options for credential lookup
#[allow(dead_code)]
#[derive(Debug, PartialEq)]
pub(crate) enum AccountSearchField {
    /// Search by ID (type-safe)
    Id(AccountId),
    /// Search by user ID (database ID, type-safe)
    UserId(UserId),
    /// Search by provider (type-safe)
    Provider(Provider),
    /// Search by provider user ID (type-safe)
    ProviderUserId(ProviderUserId),
    /// Search by name (type-safe)
    Name(DisplayName),
    /// Search by email (type-safe)
    Email(Email),
}

/// Mode of OAuth2 operation to explicitly indicate user intent.
///
/// This enum defines the available modes for OAuth2 authentication, determining
/// the behavior when a user authenticates with an OAuth2 provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OAuth2Mode {
    /// Add an OAuth2 account to an existing user.
    ///
    /// This mode is used when an authenticated user wants to link an additional
    /// OAuth2 provider account to their existing account.
    AddToUser,

    /// Create a new user account from the OAuth2 provider data.
    ///
    /// This mode is used specifically for new user registration using OAuth2.
    CreateUser,

    /// Login with an existing OAuth2 account.
    ///
    /// This mode is used when a user wants to authenticate using a previously
    /// linked OAuth2 provider account.
    Login,

    /// Create a new user if no matching account exists, otherwise login.
    ///
    /// This flexible mode attempts to login with an existing account if one matches
    /// the OAuth2 provider data, or creates a new user account if none is found.
    CreateUserOrLogin,
}

impl OAuth2Mode {
    /// Converts the OAuth2Mode enum variant to its string representation.
    ///
    /// This method returns a static string representing the mode, which can be
    /// used in URLs, API responses, or for logging purposes.
    ///
    /// # Returns
    ///
    /// * A string representation of the OAuth2Mode
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AddToUser => "add_to_user",
            Self::CreateUser => "create_user",
            Self::Login => "login",
            Self::CreateUserOrLogin => "create_user_or_login",
        }
    }
}

impl std::str::FromStr for OAuth2Mode {
    type Err = OAuth2Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "add_to_user" => Ok(Self::AddToUser),
            "create_user" => Ok(Self::CreateUser),
            "login" => Ok(Self::Login),
            "create_user_or_login" => Ok(Self::CreateUserOrLogin),
            _ => Err(OAuth2Error::InvalidMode(s.to_string())),
        }
    }
}

/// Type-safe wrapper for OAuth2 account identifiers.
///
/// This provides compile-time safety to prevent mixing up account IDs with other string types.
/// Account IDs are database-specific identifiers for OAuth2 accounts.
#[derive(Debug, Clone, PartialEq)]
pub struct AccountId(String);

impl AccountId {
    /// Creates a new AccountId from a string with validation.
    ///
    /// # Arguments
    /// * `id` - The account ID string
    ///
    /// # Returns
    /// * `Ok(AccountId)` - If the ID is valid
    /// * `Err(OAuth2Error)` - If the ID is invalid
    ///
    /// # Validation Rules
    /// * Must not be empty
    /// * Must contain only safe characters (alphanumeric + basic symbols)
    /// * Must not contain control characters or dangerous sequences
    pub fn new(id: String) -> Result<Self, crate::oauth2::OAuth2Error> {
        use crate::oauth2::OAuth2Error;

        // Validate ID is not empty
        if id.is_empty() {
            return Err(OAuth2Error::Validation(
                "Account ID cannot be empty".to_string(),
            ));
        }

        // Validate ID length (reasonable bounds)
        if id.len() > 255 {
            return Err(OAuth2Error::Validation("Account ID too long".to_string()));
        }

        // Validate ID contains only safe characters
        if !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@' | '+'))
        {
            return Err(OAuth2Error::Validation(
                "Account ID contains invalid characters".to_string(),
            ));
        }

        // Check for dangerous sequences
        if id.contains("..") || id.contains("--") || id.contains("__") {
            return Err(OAuth2Error::Validation(
                "Account ID contains dangerous character sequences".to_string(),
            ));
        }

        Ok(AccountId(id))
    }

    /// Returns the account ID as a string slice.
    ///
    /// # Returns
    /// * A string slice containing the account ID
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Type-safe wrapper for OAuth2 provider names.
///
/// This provides compile-time safety to prevent mixing up provider names with other string types.
/// Provider names identify the OAuth2 service (e.g., "google", "github").
#[derive(Debug, Clone, PartialEq)]
pub struct Provider(String);

impl Provider {
    /// Creates a new Provider from a string with validation.
    ///
    /// # Arguments
    /// * `provider` - The provider name string
    ///
    /// # Returns
    /// * `Ok(Provider)` - If the provider name is valid
    /// * `Err(OAuth2Error)` - If the provider name is invalid
    ///
    /// # Validation Rules
    /// * Must not be empty
    /// * Must contain only safe characters (alphanumeric, hyphens, underscores, periods)
    /// * Must not start with special characters
    pub fn new(provider: String) -> Result<Self, crate::oauth2::OAuth2Error> {
        use crate::oauth2::OAuth2Error;

        // Validate provider is not empty
        if provider.is_empty() {
            return Err(OAuth2Error::Validation(
                "Provider name cannot be empty".to_string(),
            ));
        }

        // Validate provider length (reasonable bounds for provider names)
        if provider.len() > 50 {
            return Err(OAuth2Error::Validation(
                "Provider name too long".to_string(),
            ));
        }

        // Validate provider contains only safe characters (alphanumeric, hyphens, underscores, periods)
        // Must not start with special characters
        if !provider
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        {
            return Err(OAuth2Error::Validation(
                "Provider name contains invalid characters".to_string(),
            ));
        }

        if provider.starts_with('-') || provider.starts_with('_') || provider.starts_with('.') {
            return Err(OAuth2Error::Validation(
                "Provider name cannot start with special characters".to_string(),
            ));
        }

        Ok(Provider(provider))
    }

    /// Returns the provider name as a string slice.
    ///
    /// # Returns
    /// * A string slice containing the provider name
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Type-safe wrapper for provider-specific user identifiers.
///
/// This provides compile-time safety to prevent mixing up provider user IDs with database user IDs.
/// Provider user IDs are external identifiers from OAuth2 providers (e.g., Google user ID).
#[derive(Debug, Clone, PartialEq)]
pub struct ProviderUserId(String);

impl ProviderUserId {
    /// Creates a new ProviderUserId from a string with validation.
    ///
    /// # Arguments
    /// * `id` - The provider user ID string
    ///
    /// # Returns
    /// * `Ok(ProviderUserId)` - If the ID is valid
    /// * `Err(OAuth2Error)` - If the ID is invalid
    ///
    /// # Validation Rules
    /// * Must not be empty
    /// * Must contain only safe characters (alphanumeric + basic symbols)
    /// * Must not contain control characters or dangerous sequences
    pub fn new(id: String) -> Result<Self, crate::oauth2::OAuth2Error> {
        use crate::oauth2::OAuth2Error;

        // Validate ID is not empty
        if id.is_empty() {
            return Err(OAuth2Error::Validation(
                "Provider user ID cannot be empty".to_string(),
            ));
        }

        // Validate ID length (provider IDs can be long but reasonable bounds)
        if id.len() > 512 {
            return Err(OAuth2Error::Validation(
                "Provider user ID too long".to_string(),
            ));
        }

        // Validate ID contains only safe characters
        if !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@' | '+' | '='))
        {
            return Err(OAuth2Error::Validation(
                "Provider user ID contains invalid characters".to_string(),
            ));
        }

        // Check for dangerous sequences
        if id.contains("..") || id.contains("--") || id.contains("__") {
            return Err(OAuth2Error::Validation(
                "Provider user ID contains dangerous character sequences".to_string(),
            ));
        }

        Ok(ProviderUserId(id))
    }

    /// Returns the provider user ID as a string slice.
    ///
    /// # Returns
    /// * A string slice containing the provider user ID
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Type-safe wrapper for user display names.
///
/// This provides compile-time safety to prevent mixing up display names with other string types.
/// Display names are user-facing names from OAuth2 providers.
#[derive(Debug, Clone, PartialEq)]
pub struct DisplayName(String);

impl DisplayName {
    /// Creates a new DisplayName from a string with validation.
    ///
    /// This constructor is part of the public type-safe search API and is used
    /// internally by the AccountSearchField enum for database queries.
    ///
    /// # Arguments
    /// * `name` - The display name string
    ///
    /// # Returns
    /// * `Ok(DisplayName)` - If the name is valid
    /// * `Err(OAuth2Error)` - If the name is invalid
    ///
    /// # Validation Rules
    /// * Must not be empty
    /// * Must not consist only of whitespace
    /// * Must not contain dangerous sequences
    #[allow(dead_code)] // Part of type-safe search API, used in tests but not by library's public interface
    pub fn new(name: String) -> Result<Self, crate::oauth2::OAuth2Error> {
        use crate::oauth2::OAuth2Error;

        // Validate name is not empty
        if name.is_empty() {
            return Err(OAuth2Error::Validation(
                "Display name cannot be empty".to_string(),
            ));
        }

        // Validate name length (reasonable bounds for display names)
        if name.len() > 100 {
            return Err(OAuth2Error::Validation("Display name too long".to_string()));
        }

        // Validate name doesn't consist only of whitespace
        if name.trim().is_empty() {
            return Err(OAuth2Error::Validation(
                "Display name cannot consist only of whitespace".to_string(),
            ));
        }

        // Check for dangerous sequences
        if name.contains("..") || name.contains("--") || name.contains("__") {
            return Err(OAuth2Error::Validation(
                "Display name contains dangerous character sequences".to_string(),
            ));
        }

        Ok(DisplayName(name))
    }

    /// Returns the display name as a string slice.
    ///
    /// # Returns
    /// * A string slice containing the display name
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Type-safe wrapper for email addresses.
///
/// This provides compile-time safety to prevent mixing up email addresses with other string types.
/// Email addresses are provided by OAuth2 providers for user identification.
#[derive(Debug, Clone, PartialEq)]
pub struct Email(String);

impl Email {
    /// Creates a new Email from a string with validation.
    ///
    /// This constructor is part of the public type-safe search API and is used
    /// internally by the AccountSearchField enum for database queries.
    ///
    /// # Arguments
    /// * `email` - The email address string
    ///
    /// # Returns
    /// * `Ok(Email)` - If the email is valid
    /// * `Err(OAuth2Error)` - If the email is invalid
    ///
    /// # Validation Rules
    /// * Must not be empty
    /// * Must contain @ symbol
    /// * Must have reasonable length
    #[allow(dead_code)] // Part of type-safe search API, used in tests but not by library's public interface
    pub fn new(email: String) -> Result<Self, crate::oauth2::OAuth2Error> {
        use crate::oauth2::OAuth2Error;

        // Validate email is not empty
        if email.is_empty() {
            return Err(OAuth2Error::Validation("Email cannot be empty".to_string()));
        }

        // Validate email length (RFC 5321 limits: maximum 254 characters)
        if email.len() < 3 {
            return Err(OAuth2Error::Validation("Email too short".to_string()));
        }

        if email.len() > 254 {
            return Err(OAuth2Error::Validation("Email too long".to_string()));
        }

        // Basic email format validation (must contain @ and reasonable structure)
        if !email.contains('@') {
            return Err(OAuth2Error::Validation(
                "Email must contain @ symbol".to_string(),
            ));
        }

        let parts: Vec<&str> = email.split('@').collect();
        if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
            return Err(OAuth2Error::Validation(
                "Email format is invalid".to_string(),
            ));
        }

        Ok(Email(email))
    }

    /// Returns the email address as a string slice.
    ///
    /// # Returns
    /// * A string slice containing the email address
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Type-safe wrapper for OAuth2 state parameters.
///
/// This provides compile-time safety to prevent mixing up OAuth2 state strings with other string types.
/// OAuth2 state parameters are base64url-encoded JSON that carries CSRF protection and flow parameters
/// between authorization requests and callbacks. Proper validation is critical for security.
#[derive(Debug, Clone, PartialEq)]
pub struct OAuth2State(String);

impl std::fmt::Display for OAuth2State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl OAuth2State {
    /// Creates a new OAuth2State from a string with validation.
    ///
    /// This constructor validates the OAuth2 state format to ensure it meets
    /// security requirements for CSRF protection and parameter integrity.
    ///
    /// # Arguments
    /// * `state` - The OAuth2 state string (should be base64url-encoded)
    ///
    /// # Returns
    /// * `Ok(OAuth2State)` - If the state is valid
    /// * `Err(OAuth2Error)` - If the state is invalid
    ///
    /// # Validation Rules
    /// * Must not be empty
    /// * Must be valid base64url encoding
    /// * Must contain valid JSON when decoded
    /// * Must be reasonable length
    pub fn new(state: String) -> Result<Self, super::errors::OAuth2Error> {
        use super::errors::OAuth2Error;
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

        // Validate state is not empty
        if state.is_empty() {
            return Err(OAuth2Error::DecodeState(
                "OAuth2 state cannot be empty".to_string(),
            ));
        }

        // Validate state length (reasonable bounds)
        if state.len() < 10 {
            return Err(OAuth2Error::DecodeState(
                "OAuth2 state too short".to_string(),
            ));
        }

        if state.len() > 8192 {
            return Err(OAuth2Error::DecodeState(
                "OAuth2 state too long".to_string(),
            ));
        }

        // Validate state is valid base64url
        let decoded_bytes = URL_SAFE_NO_PAD
            .decode(&state)
            .map_err(|e| OAuth2Error::DecodeState(format!("Invalid base64url encoding: {e}")))?;

        // Validate decoded content is valid UTF-8
        let decoded_string = String::from_utf8(decoded_bytes).map_err(|e| {
            OAuth2Error::DecodeState(format!("Invalid UTF-8 in decoded state: {e}"))
        })?;

        // Validate decoded content is valid JSON
        let _: StateParams = serde_json::from_str(&decoded_string)
            .map_err(|e| OAuth2Error::DecodeState(format!("Invalid JSON in decoded state: {e}")))?;

        Ok(OAuth2State(state))
    }

    /// Returns the OAuth2 state as a string slice.
    ///
    /// # Returns
    /// * A string slice containing the OAuth2 state
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Checks if the state contains a substring.
    ///
    /// # Arguments
    /// * `needle` - The substring to search for
    ///
    /// # Returns
    /// * `true` if the substring is found, `false` otherwise
    pub fn contains(&self, needle: char) -> bool {
        self.0.contains(needle)
    }
}

/// Type-safe wrapper for OAuth2 token types.
///
/// This enum provides compile-time safety to prevent mixing up different types of OAuth2 tokens.
/// It ensures that token types are clearly defined and prevents typos in token type strings.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TokenType {
    /// CSRF protection token for OAuth2 authorization flow
    Csrf,
    /// Nonce token for OpenID Connect
    Nonce,
    /// PKCE (Proof Key for Code Exchange) verifier token
    Pkce,
}

impl std::fmt::Display for TokenType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl TokenType {
    /// Returns the token type as a string slice.
    ///
    /// # Returns
    /// * A string slice containing the token type name
    pub fn as_str(&self) -> &str {
        match self {
            TokenType::Csrf => "csrf",
            TokenType::Nonce => "nonce",
            TokenType::Pkce => "pkce",
        }
    }
}

#[cfg(test)]
mod tests;
