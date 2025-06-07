use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::FromRow;

use super::errors::OAuth2Error;
use super::main::IdInfo as GoogleIdInfo;

use crate::storage::CacheData;

/// Represents an OAuth2 account linked to a user
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct OAuth2Account {
    pub id: String,
    pub user_id: String,
    pub provider: String,
    pub provider_user_id: String,
    pub name: String,
    pub email: String,
    pub picture: Option<String>,
    pub metadata: Value,
    pub created_at: DateTime<Utc>,
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
    pub(crate) id: String,
    pub(crate) family_name: String,
    pub name: String,
    pub picture: Option<String>,
    pub(crate) email: String,
    pub(crate) given_name: String,
    pub(crate) hd: Option<String>,
    pub(crate) verified_email: bool,
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
            provider_user_id: format!("google_{}", google_user.id),
            metadata: json!({
                "family_name": google_user.family_name,
                "given_name": google_user.given_name,
                "hd": google_user.hd,
                "verified_email": google_user.verified_email,
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

#[derive(Debug, Deserialize)]
pub struct AuthResponse {
    pub(crate) code: String,
    pub state: String,
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

/// Mode of OAuth2 operation to explicitly indicate user intent
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OAuth2Mode {
    AddToUser,
    CreateUser,
    Login,
    CreateUserOrLogin,
}

impl OAuth2Mode {
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

    #[test]
    fn test_oauth2_mode_serde() {
        let mode = OAuth2Mode::AddToUser;
        let serialized = serde_json::to_string(&mode).unwrap();
        assert_eq!(serialized, "\"add_to_user\"");
        let deserialized: OAuth2Mode = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, OAuth2Mode::AddToUser);

        let mode = OAuth2Mode::CreateUser;
        let serialized = serde_json::to_string(&mode).unwrap();
        assert_eq!(serialized, "\"create_user\"");
        let deserialized: OAuth2Mode = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, OAuth2Mode::CreateUser);
    }

    #[test]
    fn test_oauth2_mode_from_str() {
        use std::str::FromStr;

        // Test valid modes
        let mode = OAuth2Mode::from_str("add_to_user").unwrap();
        assert_eq!(mode, OAuth2Mode::AddToUser);

        let mode = OAuth2Mode::from_str("create_user").unwrap();
        assert_eq!(mode, OAuth2Mode::CreateUser);

        let mode = OAuth2Mode::from_str("login").unwrap();
        assert_eq!(mode, OAuth2Mode::Login);

        let mode = OAuth2Mode::from_str("create_user_or_login").unwrap();
        assert_eq!(mode, OAuth2Mode::CreateUserOrLogin);

        // Test with unknown string - should return an error
        let result = OAuth2Mode::from_str("unknown_mode");
        assert!(result.is_err());
    }

    #[test]
    fn test_oauth2_mode_as_str() {
        assert_eq!(OAuth2Mode::AddToUser.as_str(), "add_to_user");
        assert_eq!(OAuth2Mode::CreateUser.as_str(), "create_user");
        assert_eq!(OAuth2Mode::Login.as_str(), "login");
        assert_eq!(
            OAuth2Mode::CreateUserOrLogin.as_str(),
            "create_user_or_login"
        );
    }

    #[test]
    fn test_from_google_user_info() {
        let google_user = GoogleUserInfo {
            id: "12345".to_string(),
            family_name: "Doe".to_string(),
            name: "John Doe".to_string(),
            picture: Some("https://example.com/pic.jpg".to_string()),
            email: "john@example.com".to_string(),
            given_name: "John".to_string(),
            hd: Some("example.com".to_string()),
            verified_email: true,
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

    #[test]
    fn test_stored_token_invalid_cache_data() {
        // Create invalid cache data
        let invalid_data = CacheData {
            value: "not valid json".to_string(),
        };

        // Try to convert to StoredToken
        let result = StoredToken::try_from(invalid_data);

        // Should fail
        assert!(result.is_err());
        match result {
            Err(OAuth2Error::Storage(_)) => {}
            Ok(_) => {
                assert!(false, "Expected Storage error but got Ok");
            }
            Err(err) => {
                assert!(false, "Expected Storage error, got {:?}", err);
            }
        }
    }

    #[test]
    fn test_state_params_serialization() {
        let state_params = StateParams {
            csrf_id: "csrf123".to_string(),
            nonce_id: "nonce456".to_string(),
            pkce_id: "pkce789".to_string(),
            misc_id: Some("misc012".to_string()),
            mode_id: Some("mode345".to_string()),
        };

        // Test serialization
        let serialized = serde_json::to_string(&state_params).unwrap();
        let deserialized: StateParams = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized.csrf_id, state_params.csrf_id);
        assert_eq!(deserialized.nonce_id, state_params.nonce_id);
        assert_eq!(deserialized.pkce_id, state_params.pkce_id);
        assert_eq!(deserialized.misc_id, state_params.misc_id);
        assert_eq!(deserialized.mode_id, state_params.mode_id);
    }

    #[test]
    fn test_state_params_with_none_values() {
        let state_params = StateParams {
            csrf_id: "csrf123".to_string(),
            nonce_id: "nonce456".to_string(),
            pkce_id: "pkce789".to_string(),
            misc_id: None,
            mode_id: None,
        };

        let serialized = serde_json::to_string(&state_params).unwrap();
        let deserialized: StateParams = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized.csrf_id, state_params.csrf_id);
        assert_eq!(deserialized.nonce_id, state_params.nonce_id);
        assert_eq!(deserialized.pkce_id, state_params.pkce_id);
        assert!(deserialized.misc_id.is_none());
        assert!(deserialized.mode_id.is_none());
    }

    #[test]
    fn test_auth_response_deserialization() {
        let json_str = r#"{"code": "auth_code_123", "state": "state_456"}"#;
        let auth_response: AuthResponse = serde_json::from_str(json_str).unwrap();

        assert_eq!(auth_response.code, "auth_code_123");
        assert_eq!(auth_response.state, "state_456");
    }

    #[test]
    fn test_auth_response_with_id_token() {
        let json_str =
            r#"{"code": "auth_code_123", "state": "state_456", "id_token": "token_789"}"#;
        let auth_response: AuthResponse = serde_json::from_str(json_str).unwrap();

        assert_eq!(auth_response.code, "auth_code_123");
        assert_eq!(auth_response.state, "state_456");
        // Note: _id_token is private, but we can test that deserialization works
    }

    #[test]
    fn test_oidc_token_response_serialization() {
        let token_response = OidcTokenResponse {
            access_token: "access_123".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: 3600,
            refresh_token: Some("refresh_456".to_string()),
            scope: "openid email profile".to_string(),
            id_token: Some("id_token_789".to_string()),
        };

        let serialized = serde_json::to_string(&token_response).unwrap();
        let deserialized: OidcTokenResponse = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized.access_token, token_response.access_token);
        assert_eq!(deserialized.token_type, token_response.token_type);
        assert_eq!(deserialized.expires_in, token_response.expires_in);
        assert_eq!(deserialized.refresh_token, token_response.refresh_token);
        assert_eq!(deserialized.scope, token_response.scope);
        assert_eq!(deserialized.id_token, token_response.id_token);
    }

    #[test]
    fn test_oauth2_account_default() {
        let account = OAuth2Account::default();

        assert!(account.id.is_empty());
        assert!(account.user_id.is_empty());
        assert!(account.provider.is_empty());
        assert!(account.provider_user_id.is_empty());
        assert!(account.name.is_empty());
        assert!(account.email.is_empty());
        assert!(account.picture.is_none());
        assert_eq!(account.metadata, Value::Null);
        // created_at and updated_at should be recent (within last second)
        let now = Utc::now();
        assert!((now - account.created_at).num_seconds() < 1);
        assert!((now - account.updated_at).num_seconds() < 1);
    }

    #[test]
    fn test_oauth2_account_serialization() {
        let account = OAuth2Account {
            id: "acc123".to_string(),
            user_id: "user456".to_string(),
            provider: "google".to_string(),
            provider_user_id: "google_789".to_string(),
            name: "John Doe".to_string(),
            email: "john@example.com".to_string(),
            picture: Some("https://example.com/pic.jpg".to_string()),
            metadata: json!({"verified": true}),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let serialized = serde_json::to_string(&account).unwrap();
        let deserialized: OAuth2Account = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized.id, account.id);
        assert_eq!(deserialized.user_id, account.user_id);
        assert_eq!(deserialized.provider, account.provider);
        assert_eq!(deserialized.provider_user_id, account.provider_user_id);
        assert_eq!(deserialized.name, account.name);
        assert_eq!(deserialized.email, account.email);
        assert_eq!(deserialized.picture, account.picture);
        assert_eq!(deserialized.metadata, account.metadata);
    }

    #[test]
    fn test_google_user_info_serialization() {
        let google_user = GoogleUserInfo {
            id: "123456".to_string(),
            family_name: "Doe".to_string(),
            name: "John Doe".to_string(),
            picture: Some("https://example.com/pic.jpg".to_string()),
            email: "john@example.com".to_string(),
            given_name: "John".to_string(),
            hd: Some("example.com".to_string()),
            verified_email: true,
        };

        let serialized = serde_json::to_string(&google_user).unwrap();
        let deserialized: GoogleUserInfo = serde_json::from_str(&serialized).unwrap();

        assert_eq!(deserialized.id, google_user.id);
        assert_eq!(deserialized.family_name, google_user.family_name);
        assert_eq!(deserialized.name, google_user.name);
        assert_eq!(deserialized.picture, google_user.picture);
        assert_eq!(deserialized.email, google_user.email);
        assert_eq!(deserialized.given_name, google_user.given_name);
        assert_eq!(deserialized.hd, google_user.hd);
        assert_eq!(deserialized.verified_email, google_user.verified_email);
    }

    #[test]
    fn test_stored_token_ttl_consistency() {
        let now = Utc::now();
        let ttl_seconds = 3600u64;
        let expires_at = now + Duration::seconds(ttl_seconds as i64);

        let stored_token = StoredToken {
            token: "test_token".to_string(),
            expires_at,
            user_agent: Some("Mozilla/5.0".to_string()),
            ttl: ttl_seconds,
        };

        // Verify that ttl and expires_at are consistent
        let calculated_expires = now + Duration::seconds(stored_token.ttl as i64);
        let diff = (stored_token.expires_at - calculated_expires)
            .num_seconds()
            .abs();
        assert!(
            diff <= 1,
            "TTL and expires_at should be consistent within 1 second"
        );
    }

    #[test]
    fn test_account_search_field_variants() {
        // Test that all variants can be created and compared
        let id_field = AccountSearchField::Id("id123".to_string());
        let user_id_field = AccountSearchField::UserId("user456".to_string());
        let provider_field = AccountSearchField::Provider("google".to_string());
        let provider_user_id_field = AccountSearchField::ProviderUserId("google_789".to_string());
        let name_field = AccountSearchField::Name("John Doe".to_string());
        let email_field = AccountSearchField::Email("john@example.com".to_string());

        // Test equality
        assert_eq!(id_field, AccountSearchField::Id("id123".to_string()));
        assert_ne!(id_field, user_id_field);
        assert_ne!(user_id_field, provider_field);
        assert_ne!(provider_field, provider_user_id_field);
        assert_ne!(provider_user_id_field, name_field);
        assert_ne!(name_field, email_field);
    }

    #[test]
    fn test_oauth2_mode_all_variants() {
        // Test all variants exist and work correctly
        let modes = vec![
            OAuth2Mode::AddToUser,
            OAuth2Mode::CreateUser,
            OAuth2Mode::Login,
            OAuth2Mode::CreateUserOrLogin,
        ];

        for mode in &modes {
            // Test as_str
            let str_repr = mode.as_str();
            assert!(!str_repr.is_empty());

            // Test from_str roundtrip
            let parsed_mode = std::str::FromStr::from_str(str_repr).unwrap();
            assert_eq!(*mode, parsed_mode);

            // Test serde roundtrip
            let serialized = serde_json::to_string(mode).unwrap();
            let deserialized: OAuth2Mode = serde_json::from_str(&serialized).unwrap();
            assert_eq!(*mode, deserialized);
        }
    }

    #[test]
    fn test_oauth2_mode_invalid_string() {
        use std::str::FromStr;

        let invalid_strings = vec![
            "invalid_mode",
            "",
            "ADD_TO_USER", // wrong case
            "add-to-user", // wrong separator
            "add_user",    // missing "to"
            "loginuser",   // missing separator
        ];

        for invalid_str in invalid_strings {
            let result = OAuth2Mode::from_str(invalid_str);
            assert!(result.is_err(), "Should fail to parse: {}", invalid_str);

            match result {
                Err(OAuth2Error::InvalidMode(msg)) => {
                    assert_eq!(msg, invalid_str);
                }
                _ => panic!("Expected InvalidMode error for: {}", invalid_str),
            }
        }
    }
}
