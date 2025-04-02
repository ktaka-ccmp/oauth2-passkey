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
