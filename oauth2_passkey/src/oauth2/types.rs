use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::FromRow;

use super::errors::OAuth2Error;
use super::main::IdInfo as GoogleIdInfo;

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
    /// Search by ID
    Id(String),
    /// Search by user ID (database ID)
    UserId(String),
    /// Search by provider
    Provider(String),
    /// Search by provider user ID
    ProviderUserId(String),
    /// Search by name
    Name(String),
    /// Search by email
    Email(String),
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use serde_json::json;

    /// Test conversion from GoogleUserInfo to OAuth2Account
    ///
    /// This test verifies that a GoogleUserInfo struct can be correctly converted into
    /// an OAuth2Account using the From trait implementation. It creates a GoogleUserInfo
    /// object in memory with sample data and validates that all fields are properly
    /// mapped to the resulting OAuth2Account structure.
    ///
    #[test]
    fn test_from_google_user_info() {
        let google_user = GoogleUserInfo {
            sub: "12345".to_string(),
            family_name: "Doe".to_string(),
            name: "John Doe".to_string(),
            picture: Some("https://example.com/pic.jpg".to_string()),
            email: "john@example.com".to_string(),
            given_name: "John".to_string(),
            hd: Some("example.com".to_string()),
            email_verified: true,
        };

        let account = OAuth2Account::from(google_user.clone());

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

    /// Test conversion from GoogleIdInfo to OAuth2Account
    ///
    /// This test verifies that a GoogleIdInfo struct can be correctly converted into
    /// an OAuth2Account using the From trait implementation. It creates a GoogleIdInfo
    /// object in memory with ID token claims and validates that all fields are properly
    /// mapped to the resulting OAuth2Account structure.
    ///
    #[test]
    fn test_from_google_id_info() {
        // Create a mock GoogleIdInfo
        let id_info = GoogleIdInfo {
            iss: "https://accounts.google.com".to_string(),
            azp: "client_id".to_string(),
            aud: "client_id".to_string(),
            sub: "12345".to_string(),
            email: "john@example.com".to_string(),
            email_verified: true,
            at_hash: Some("hash".to_string()),
            name: "John Doe".to_string(),
            picture: Some("https://example.com/pic.jpg".to_string()),
            given_name: "John".to_string(),
            family_name: "Doe".to_string(),
            locale: Some("en".to_string()),
            iat: 0,
            exp: 0,
            nbf: Some(0),
            jti: Some("jti_value".to_string()),
            nonce: Some("nonce_value".to_string()),
            hd: Some("example.com".to_string()),
        };

        let account = OAuth2Account::from(id_info.clone());

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
}
