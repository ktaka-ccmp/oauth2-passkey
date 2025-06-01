use crate::storage::{CacheData, GENERIC_CACHE_STORE};

use crate::passkey::PasskeyError;
use crate::passkey::PasskeyStore;
use crate::passkey::{CredentialSearchField, types::UserIdCredentialIdStr};

async fn get_credential_id_strs_by(
    field: CredentialSearchField,
) -> Result<Vec<UserIdCredentialIdStr>, PasskeyError> {
    let stored_credentials = PasskeyStore::get_credentials_by(field).await?;

    let credential_id_strs = stored_credentials
        .into_iter()
        .map(|cred| UserIdCredentialIdStr {
            user_id: cred.user_id,
            credential_id: cred.credential_id,
        })
        .collect();

    Ok(credential_id_strs)
}

pub(super) async fn name2cid_str_vec(
    name: &str,
) -> Result<Vec<UserIdCredentialIdStr>, PasskeyError> {
    get_credential_id_strs_by(CredentialSearchField::UserName(name.to_string())).await
}

/// Helper function to store data in the cache
pub(super) async fn store_in_cache<T>(
    category: &str,
    key: &str,
    data: T,
    ttl: usize,
) -> Result<(), PasskeyError>
where
    T: Into<CacheData>,
{
    GENERIC_CACHE_STORE
        .lock()
        .await
        .put_with_ttl(category, key, data.into(), ttl)
        .await
        .map_err(|e| PasskeyError::Storage(e.to_string()))
}

/// Helper function to retrieve data from the cache
pub(super) async fn get_from_cache<T>(category: &str, key: &str) -> Result<Option<T>, PasskeyError>
where
    T: TryFrom<CacheData, Error = PasskeyError>,
{
    let data = GENERIC_CACHE_STORE
        .lock()
        .await
        .get(category, key)
        .await
        .map_err(|e| PasskeyError::Storage(e.to_string()))?;

    match data {
        Some(value) => Ok(Some(value.try_into()?)),
        None => Ok(None),
    }
}

/// Helper function to remove data from the cache
pub(super) async fn remove_from_cache(category: &str, key: &str) -> Result<(), PasskeyError> {
    GENERIC_CACHE_STORE
        .lock()
        .await
        .remove(category, key)
        .await
        .map_err(|e| PasskeyError::Storage(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::passkey::types::PasskeyCredential;
    use crate::passkey::types::PublicKeyCredentialUserEntity;
    use crate::passkey::types::StoredOptions;

    // Test the mapping from credential to UserIdCredentialIdStr
    #[test]
    fn test_map_credential_to_id_str() {
        // Create a test credential
        let cred = crate::passkey::types::PasskeyCredential {
            credential_id: "test_cred_id".to_string(),
            user_id: "test_user_id".to_string(),
            public_key: "test_public_key".to_string(),
            aaguid: "test_aaguid".to_string(),
            counter: 1,
            user: PublicKeyCredentialUserEntity {
                user_handle: "test_user_handle".to_string(),
                name: "test_user".to_string(),
                display_name: "Test User".to_string(),
            },
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            last_used_at: chrono::Utc::now(),
        };

        // Map the credential to UserIdCredentialIdStr
        let id_str = UserIdCredentialIdStr {
            user_id: cred.user_id.clone(),
            credential_id: cred.credential_id.clone(),
        };

        // Verify the mapping
        assert_eq!(id_str.user_id, "test_user_id");
        assert_eq!(id_str.credential_id, "test_cred_id");
    }

    // Test the CacheData conversion for StoredOptions
    #[test]
    fn test_stored_options_cache_data_conversion() {
        // Create a test StoredOptions
        let options = StoredOptions {
            challenge: "test_challenge".to_string(),
            user: PublicKeyCredentialUserEntity {
                user_handle: "test_user_handle".to_string(),
                name: "test_user".to_string(),
                display_name: "Test User".to_string(),
            },
            timestamp: 1622505600, // June 1, 2021
            ttl: 300,              // 5 minutes
        };

        // Convert to CacheData
        let cache_data: CacheData = options.clone().into();

        // Verify the conversion worked
        assert!(!cache_data.value.is_empty());
        assert!(cache_data.value.contains("test_challenge"));
        assert!(cache_data.value.contains("test_user_handle"));

        // Convert back to StoredOptions
        let converted_options: Result<StoredOptions, _> = cache_data.try_into();
        assert!(converted_options.is_ok());

        let converted = converted_options.unwrap();
        assert_eq!(converted.challenge, options.challenge);
        assert_eq!(converted.user.user_handle, options.user.user_handle);
        assert_eq!(converted.timestamp, options.timestamp);
        assert_eq!(converted.ttl, options.ttl);
    }

    // Test error handling for cache operations
    #[test]
    fn test_passkey_error_from_string() {
        // Create a storage error
        let error_message = "Test storage error";
        let error = PasskeyError::Storage(error_message.to_string());

        // Verify the error message
        match error {
            PasskeyError::Storage(msg) => assert_eq!(msg, error_message),
            _ => panic!("Expected a Storage error"),
        }
    }
}
