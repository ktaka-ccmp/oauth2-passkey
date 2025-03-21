use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::errors::PasskeyError;
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

#[derive(Clone, Serialize, Deserialize, Debug)]
/// Stored credential information for a passkey
pub struct StoredCredential {
    /// Raw credential ID bytes
    pub credential_id: String,
    /// User ID associated with this credential (database ID)
    pub user_id: String,
    /// Public key bytes for the credential
    pub public_key: String,
    /// Counter value for the credential (used to prevent replay attacks)
    pub counter: u32,
    /// User entity information
    pub user: PublicKeyCredentialUserEntity,
    /// When the credential was created
    pub created_at: DateTime<Utc>,
    /// When the credential was last updated
    pub updated_at: DateTime<Utc>,
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

/// Search field options for credential lookup
#[allow(dead_code)]
#[derive(Debug)]
pub enum CredentialSearchField {
    /// Search by credential ID
    // CredentialId(Vec<u8>),
    CredentialId(String),
    /// Search by user ID (database ID)
    UserId(String),
    /// Search by user handle (WebAuthn user handle)
    UserHandle(String),
    /// Search by username
    UserName(String),
}

/// Helper functions for cache store operations to improve code reuse and maintainability
impl From<SessionInfo> for CacheData {
    fn from(data: SessionInfo) -> Self {
        Self {
            value: serde_json::to_string(&data).expect("Failed to serialize SessionInfo"),
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
        }
    }
}

impl TryFrom<CacheData> for StoredOptions {
    type Error = PasskeyError;

    fn try_from(data: CacheData) -> Result<Self, Self::Error> {
        serde_json::from_str(&data.value).map_err(|e| PasskeyError::Storage(e.to_string()))
    }
}
