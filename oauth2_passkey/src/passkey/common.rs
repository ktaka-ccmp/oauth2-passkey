use crate::storage::{CacheData, GENERIC_CACHE_STORE};

use super::errors::PasskeyError;
use super::storage::PasskeyStore;
use super::types::{CredentialSearchField, SessionInfo, StoredOptions, UserIdCredentialIdStr};

pub async fn init() -> Result<(), PasskeyError> {
    // Validate required environment variables early
    let _ = *super::config::PASSKEY_RP_ID;

    crate::storage::init()
        .await
        .map_err(|e| PasskeyError::Storage(e.to_string()))?;

    PasskeyStore::init().await?;

    Ok(())
}

pub(crate) async fn get_credential_id_strs_by(
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

pub(crate) async fn name2cid_str_vec(
    name: &str,
) -> Result<Vec<UserIdCredentialIdStr>, PasskeyError> {
    get_credential_id_strs_by(CredentialSearchField::UserName(name.to_string())).await
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

/// Helper function to store data in the cache
pub(crate) async fn store_in_cache<T>(
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
pub(crate) async fn get_from_cache<T>(category: &str, key: &str) -> Result<Option<T>, PasskeyError>
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
pub(crate) async fn remove_from_cache(category: &str, key: &str) -> Result<(), PasskeyError> {
    GENERIC_CACHE_STORE
        .lock()
        .await
        .remove(category, key)
        .await
        .map_err(|e| PasskeyError::Storage(e.to_string()))
}
