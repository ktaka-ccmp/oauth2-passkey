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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn test_session_info_conversion() {
        // Create a SessionInfo instance
        let user = crate::session::User {
            id: "test_user_id".to_string(),
            account: "test_account".to_string(),
            label: "test_label".to_string(),
            is_admin: false,
            sequence_number: 1,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        let session_info = SessionInfo { user };

        // Convert to CacheData
        let cache_data: CacheData = session_info.clone().into();

        // Verify the conversion worked by checking the JSON structure
        let json_value: serde_json::Value = serde_json::from_str(&cache_data.value).unwrap();
        assert_eq!(json_value["user"]["id"], "test_user_id");
        assert_eq!(json_value["user"]["account"], "test_account");
        assert_eq!(json_value["user"]["label"], "test_label");
        assert_eq!(json_value["user"]["is_admin"], false);
        assert_eq!(json_value["user"]["sequence_number"], 1);

        // Convert back to SessionInfo
        let converted_session_info: SessionInfo = cache_data.try_into().unwrap();

        // Verify the round-trip conversion preserved all data
        assert_eq!(converted_session_info.user.id, session_info.user.id);
        assert_eq!(
            converted_session_info.user.account,
            session_info.user.account
        );
        assert_eq!(converted_session_info.user.label, session_info.user.label);
        assert_eq!(
            converted_session_info.user.is_admin,
            session_info.user.is_admin
        );
        assert_eq!(
            converted_session_info.user.sequence_number,
            session_info.user.sequence_number
        );
    }

    #[test]
    fn test_stored_options_conversion() {
        // Create a StoredOptions instance
        let user = PublicKeyCredentialUserEntity {
            user_handle: "test_user_handle".to_string(),
            name: "test_user".to_string(),
            display_name: "Test User".to_string(),
        };

        let stored_options = StoredOptions {
            challenge: "test_challenge".to_string(),
            user,
            timestamp: 1622505600, // June 1, 2021
            ttl: 300,              // 5 minutes
        };

        // Convert to CacheData
        let cache_data: CacheData = stored_options.clone().into();

        // Verify the conversion worked by checking the JSON structure
        let json_value: serde_json::Value = serde_json::from_str(&cache_data.value).unwrap();
        assert_eq!(json_value["challenge"], "test_challenge");
        assert_eq!(json_value["user"]["user_handle"], "test_user_handle");
        assert_eq!(json_value["user"]["name"], "test_user");
        assert_eq!(json_value["user"]["displayName"], "Test User");
        assert_eq!(json_value["timestamp"], 1622505600);
        assert_eq!(json_value["ttl"], 300);

        // Convert back to StoredOptions
        let converted_stored_options: StoredOptions = cache_data.try_into().unwrap();

        // Verify the round-trip conversion preserved all data
        assert_eq!(converted_stored_options.challenge, stored_options.challenge);
        assert_eq!(
            converted_stored_options.user.user_handle,
            stored_options.user.user_handle
        );
        assert_eq!(converted_stored_options.user.name, stored_options.user.name);
        assert_eq!(
            converted_stored_options.user.display_name,
            stored_options.user.display_name
        );
        assert_eq!(converted_stored_options.timestamp, stored_options.timestamp);
        assert_eq!(converted_stored_options.ttl, stored_options.ttl);
    }

    #[test]
    fn test_invalid_cache_data_conversion() {
        // Test with invalid JSON data
        let invalid_cache_data = CacheData {
            value: "{invalid json}".to_string(),
        };

        // Attempt to convert to SessionInfo
        let session_info_result: Result<SessionInfo, PasskeyError> =
            invalid_cache_data.clone().try_into();
        assert!(session_info_result.is_err());

        // Verify the error is a Storage error
        match session_info_result {
            Err(PasskeyError::Storage(_)) => {} // Expected error type
            _ => panic!("Expected a Storage error"),
        }

        // Attempt to convert to StoredOptions
        let stored_options_result: Result<StoredOptions, PasskeyError> =
            invalid_cache_data.try_into();
        assert!(stored_options_result.is_err());

        // Verify the error is a Storage error
        match stored_options_result {
            Err(PasskeyError::Storage(_)) => {} // Expected error type
            _ => panic!("Expected a Storage error"),
        }
    }

    #[test]
    fn test_passkey_credential_fields() {
        // Test creating a PasskeyCredential and verifying its fields
        let credential_id = "test_credential_id".to_string();
        let user_id = "test_user_id".to_string();
        let public_key = "test_public_key".to_string();
        let aaguid = "test_aaguid".to_string();
        let counter = 42;
        let user = PublicKeyCredentialUserEntity {
            user_handle: "test_user_handle".to_string(),
            name: "test_user".to_string(),
            display_name: "Test User".to_string(),
        };
        let created_at = Utc.with_ymd_and_hms(2023, 1, 1, 0, 0, 0).unwrap();
        let updated_at = Utc.with_ymd_and_hms(2023, 1, 2, 0, 0, 0).unwrap();
        let last_used_at = Utc.with_ymd_and_hms(2023, 1, 3, 0, 0, 0).unwrap();

        let credential = PasskeyCredential {
            credential_id: credential_id.clone(),
            user_id: user_id.clone(),
            public_key: public_key.clone(),
            aaguid: aaguid.clone(),
            counter,
            user: user.clone(),
            created_at,
            updated_at,
            last_used_at,
        };

        // Verify all fields
        assert_eq!(credential.credential_id, credential_id);
        assert_eq!(credential.user_id, user_id);
        assert_eq!(credential.public_key, public_key);
        assert_eq!(credential.aaguid, aaguid);
        assert_eq!(credential.counter, counter);
        assert_eq!(credential.user.user_handle, user.user_handle);
        assert_eq!(credential.user.name, user.name);
        assert_eq!(credential.user.display_name, user.display_name);
        assert_eq!(credential.created_at, created_at);
        assert_eq!(credential.updated_at, updated_at);
        assert_eq!(credential.last_used_at, last_used_at);
    }
}
