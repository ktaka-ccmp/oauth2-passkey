use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::errors::PasskeyError;
use crate::session::UserId;
use crate::storage::CacheData;

#[derive(Clone, Serialize, Deserialize, Debug, Default)]
pub struct PublicKeyCredentialUserEntity {
    pub user_handle: String,
    pub name: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub(super) struct StoredOptions {
    pub(super) challenge: String,
    pub(super) user: PublicKeyCredentialUserEntity,
    pub(super) timestamp: u64,
    pub(super) ttl: u64,
}

/// Stored credential information for a WebAuthn/Passkey.
///
/// This struct represents a stored passkey credential that can be used for authentication.
/// It contains all the necessary information to verify subsequent authentications using
/// the same credential, including the public key, credential ID, and counter value.
///
/// The credential is associated with a specific user and includes metadata about when
/// it was created, updated, and last used.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct PasskeyCredential {
    /// Raw credential ID bytes
    pub credential_id: String,
    /// User ID associated with this credential (database ID)
    pub user_id: String,
    /// Public key bytes for the credential
    pub public_key: String,
    /// AAGUID of the authenticator
    pub aaguid: String,
    /// Counter value for the credential (used to prevent replay attacks)
    pub counter: u32,
    /// User entity information
    pub user: PublicKeyCredentialUserEntity,
    /// When the credential was created
    pub created_at: DateTime<Utc>,
    /// When the credential was last updated
    pub updated_at: DateTime<Utc>,
    /// When the credential was last used
    pub last_used_at: DateTime<Utc>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub(super) struct UserIdCredentialIdStr {
    pub(super) user_id: String,
    pub(super) credential_id: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub(super) struct SessionInfo {
    pub(super) user: crate::session::User,
}

/// Search field options for credential lookup.
///
/// This enum provides various ways to search for passkey credentials in storage,
/// supporting different lookup strategies based on the available identifier.
/// Each variant represents a different search parameter type with compile-time type safety.
#[allow(dead_code)]
#[derive(Debug)]
pub enum CredentialSearchField {
    /// Search by credential ID (type-safe)
    CredentialId(CredentialId),
    /// Search by user ID (database ID, type-safe)
    UserId(UserId),
    /// Search by user handle (WebAuthn user handle, type-safe)
    UserHandle(UserHandle),
    /// Search by username (type-safe)
    UserName(UserName),
}

/// Helper functions for cache store operations to improve code reuse and maintainability
impl From<SessionInfo> for CacheData {
    fn from(data: SessionInfo) -> Self {
        Self {
            value: serde_json::to_string(&data).expect("Failed to serialize SessionInfo"),
            expires_at: chrono::Utc::now() + chrono::Duration::hours(24), // SessionInfo expires in 24 hours
        }
    }
}

impl TryFrom<CacheData> for SessionInfo {
    type Error = PasskeyError;

    fn try_from(data: CacheData) -> Result<Self, Self::Error> {
        serde_json::from_str(&data.value).map_err(|e| PasskeyError::Storage(e.to_string()))
    }
}

impl From<StoredOptions> for CacheData {
    fn from(data: StoredOptions) -> Self {
        Self {
            value: serde_json::to_string(&data).expect("Failed to serialize StoredOptions"),
            expires_at: chrono::Utc::now() + chrono::Duration::seconds(data.ttl as i64),
        }
    }
}

impl TryFrom<CacheData> for StoredOptions {
    type Error = PasskeyError;

    fn try_from(data: CacheData) -> Result<Self, Self::Error> {
        serde_json::from_str(&data.value).map_err(|e| PasskeyError::Storage(e.to_string()))
    }
}

/// Type-safe wrapper for credential identifiers.
///
/// This provides compile-time safety to prevent mixing up credential IDs with other string types.
/// It's used in passkey coordination functions to ensure type safety when passing credential identifiers.
#[derive(Debug, Clone, PartialEq)]
pub struct CredentialId(String);

impl CredentialId {
    /// Creates a new CredentialId from a string.
    ///
    /// # Arguments
    /// * `id` - The credential ID string
    ///
    /// # Returns
    /// * A new CredentialId instance
    pub fn new(id: String) -> Self {
        Self(id)
    }

    /// Returns the credential ID as a string slice.
    ///
    /// # Returns
    /// * A string slice containing the credential ID
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Type-safe wrapper for WebAuthn user handles.
///
/// This provides compile-time safety to prevent mixing up user handles with other string types.
/// User handles are WebAuthn-specific identifiers that may differ from usernames or display names.
#[derive(Debug, Clone, PartialEq)]
pub struct UserHandle(String);

impl UserHandle {
    /// Creates a new UserHandle from a string.
    ///
    /// # Arguments
    /// * `handle` - The user handle string
    ///
    /// # Returns
    /// * A new UserHandle instance
    pub fn new(handle: String) -> Self {
        Self(handle)
    }

    /// Returns the user handle as a string slice.
    ///
    /// # Returns
    /// * A string slice containing the user handle
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Type-safe wrapper for usernames.
///
/// This provides compile-time safety to prevent mixing up usernames with other string types.
/// Usernames are user-facing identifiers that may be used for display or authentication.
#[derive(Debug, Clone, PartialEq)]
pub struct UserName(String);

impl UserName {
    /// Creates a new UserName from a string.
    ///
    /// # Arguments
    /// * `name` - The username string
    ///
    /// # Returns
    /// * A new UserName instance
    pub fn new(name: String) -> Self {
        Self(name)
    }

    /// Returns the username as a string slice.
    ///
    /// # Returns
    /// * A string slice containing the username
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Type-safe wrapper for WebAuthn challenge types.
///
/// This provides compile-time safety to prevent mixing up challenge types with other string types.
/// Challenge types identify the kind of WebAuthn operation (registration, authentication) and are
/// used as cache prefixes for storing challenge data.
#[derive(Debug, Clone, PartialEq)]
pub struct ChallengeType(String);

impl ChallengeType {
    /// Creates a new ChallengeType from a string with validation.
    ///
    /// This constructor validates the challenge type to ensure it meets
    /// requirements for cache operations and WebAuthn flow identification.
    ///
    /// # Arguments
    /// * `challenge_type` - The challenge type string
    ///
    /// # Returns
    /// * `Ok(ChallengeType)` - If the challenge type is valid
    /// * `Err(PasskeyError)` - If the challenge type is invalid
    ///
    /// # Validation Rules
    /// * Must not be empty
    /// * Must contain only alphanumeric characters and underscores
    /// * Must be reasonable length
    pub fn new(challenge_type: String) -> Result<Self, super::errors::PasskeyError> {
        use super::errors::PasskeyError;

        // Validate challenge type is not empty
        if challenge_type.is_empty() {
            return Err(PasskeyError::Challenge(
                "Challenge type cannot be empty".to_string(),
            ));
        }

        // Validate challenge type length (reasonable bounds)
        if challenge_type.len() > 64 {
            return Err(PasskeyError::Challenge(
                "Challenge type too long".to_string(),
            ));
        }

        // Validate challenge type contains only safe characters for cache prefixes
        if !challenge_type
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            return Err(PasskeyError::Challenge(
                "Challenge type contains invalid characters".to_string(),
            ));
        }

        Ok(ChallengeType(challenge_type))
    }

    /// Returns the challenge type as a string slice.
    ///
    /// # Returns
    /// * A string slice containing the challenge type
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Creates a registration challenge type.
    ///
    /// # Returns
    /// * A ChallengeType for registration operations
    pub fn registration() -> Self {
        ChallengeType("registration".to_string())
    }

    /// Creates an authentication challenge type.
    ///
    /// # Returns
    /// * A ChallengeType for authentication operations
    pub fn authentication() -> Self {
        ChallengeType("authentication".to_string())
    }
}

/// Type-safe wrapper for WebAuthn challenge identifiers.
///
/// This provides compile-time safety to prevent mixing up challenge IDs with other string types.
/// Challenge IDs are unique identifiers for specific WebAuthn challenge instances and are used
/// as cache keys for storing and retrieving challenge data.
#[derive(Debug, Clone, PartialEq)]
pub struct ChallengeId(String);

impl ChallengeId {
    /// Creates a new ChallengeId from a string with validation.
    ///
    /// This constructor validates the challenge ID to ensure it meets
    /// requirements for cache operations and uniqueness.
    ///
    /// # Arguments
    /// * `id` - The challenge ID string
    ///
    /// # Returns
    /// * `Ok(ChallengeId)` - If the challenge ID is valid
    /// * `Err(PasskeyError)` - If the challenge ID is invalid
    ///
    /// # Validation Rules
    /// * Must not be empty
    /// * Must contain only safe characters for cache keys
    /// * Must be reasonable length
    pub fn new(id: String) -> Result<Self, super::errors::PasskeyError> {
        use super::errors::PasskeyError;

        // Validate ID is not empty
        if id.is_empty() {
            return Err(PasskeyError::Challenge(
                "Challenge ID cannot be empty".to_string(),
            ));
        }

        // Validate ID length (reasonable bounds)
        if id.len() < 8 {
            return Err(PasskeyError::Challenge(
                "Challenge ID too short".to_string(),
            ));
        }

        if id.len() > 256 {
            return Err(PasskeyError::Challenge("Challenge ID too long".to_string()));
        }

        // Validate ID contains only safe characters for cache keys
        if !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '+'))
        {
            return Err(PasskeyError::Challenge(
                "Challenge ID contains invalid characters".to_string(),
            ));
        }

        Ok(ChallengeId(id))
    }

    /// Returns the challenge ID as a string slice.
    ///
    /// # Returns
    /// * A string slice containing the challenge ID
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
