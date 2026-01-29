use crate::session::config::USER_SESSIONS_MAPPING_TTL;
use crate::session::errors::SessionError;
use crate::storage::{CacheData, CacheErrorConversion, CacheKey, CachePrefix, GENERIC_CACHE_STORE};

/// Retrieve all session IDs associated with a user from the cache mapping.
///
/// Returns an empty Vec if no mapping exists for the user.
pub(super) async fn get_user_session_ids(user_id: &str) -> Result<Vec<String>, SessionError> {
    let cache_key =
        CacheKey::new(user_id.to_string()).map_err(SessionError::convert_storage_error)?;

    let result = GENERIC_CACHE_STORE
        .lock()
        .await
        .get(CachePrefix::user_sessions(), cache_key)
        .await
        .map_err(SessionError::convert_storage_error)?;

    match result {
        Some(cache_data) => {
            let session_ids: Vec<String> = serde_json::from_str(&cache_data.value)
                .map_err(|e| SessionError::Storage(format!("Failed to parse session IDs: {e}")))?;
            Ok(session_ids)
        }
        None => Ok(Vec::new()),
    }
}

/// Write the session ID list for a user to the cache.
///
/// If the list is empty, the mapping is removed from the cache.
async fn set_user_session_ids(user_id: &str, session_ids: &[String]) -> Result<(), SessionError> {
    let cache_key =
        CacheKey::new(user_id.to_string()).map_err(SessionError::convert_storage_error)?;

    if session_ids.is_empty() {
        // Remove the mapping entirely when no sessions remain
        GENERIC_CACHE_STORE
            .lock()
            .await
            .remove(CachePrefix::user_sessions(), cache_key)
            .await
            .map_err(SessionError::convert_storage_error)?;
    } else {
        let value = serde_json::to_string(session_ids)
            .map_err(|e| SessionError::Storage(format!("Failed to serialize session IDs: {e}")))?;
        let cache_data = CacheData { value };

        GENERIC_CACHE_STORE
            .lock()
            .await
            .put_with_ttl(
                CachePrefix::user_sessions(),
                cache_key,
                cache_data,
                USER_SESSIONS_MAPPING_TTL as usize,
            )
            .await
            .map_err(SessionError::convert_storage_error)?;
    }

    Ok(())
}

/// Add a session ID to the user's session mapping.
pub(super) async fn add_session_to_user_mapping(
    user_id: &str,
    session_id: &str,
) -> Result<(), SessionError> {
    let mut session_ids = get_user_session_ids(user_id).await?;

    // Avoid duplicates
    if !session_ids.iter().any(|id| id == session_id) {
        session_ids.push(session_id.to_string());
    }

    set_user_session_ids(user_id, &session_ids).await
}

/// Remove a session ID from the user's session mapping.
pub(super) async fn remove_session_from_user_mapping(
    user_id: &str,
    session_id: &str,
) -> Result<(), SessionError> {
    let mut session_ids = get_user_session_ids(user_id).await?;
    session_ids.retain(|id| id != session_id);
    set_user_session_ids(user_id, &session_ids).await
}

/// Perform lazy cleanup of stale sessions from the user's mapping.
///
/// Checks each session ID in the mapping to see if it still exists in the cache.
/// Removes any that no longer exist (expired via TTL or explicitly deleted).
///
/// Returns the list of session IDs that are still valid.
pub(super) async fn cleanup_stale_sessions(user_id: &str) -> Result<Vec<String>, SessionError> {
    let session_ids = get_user_session_ids(user_id).await?;

    if session_ids.is_empty() {
        return Ok(Vec::new());
    }

    let mut valid_ids = Vec::new();

    for session_id in &session_ids {
        let cache_key =
            CacheKey::new(session_id.clone()).map_err(SessionError::convert_storage_error)?;

        let exists = GENERIC_CACHE_STORE
            .lock()
            .await
            .get(CachePrefix::session(), cache_key)
            .await
            .map_err(SessionError::convert_storage_error)?
            .is_some();

        if exists {
            valid_ids.push(session_id.clone());
        } else {
            tracing::debug!(
                "Removing stale session {} from user {} mapping",
                session_id,
                user_id
            );
        }
    }

    // Only write back if we actually removed stale entries
    if valid_ids.len() != session_ids.len() {
        set_user_session_ids(user_id, &valid_ids).await?;
    }

    Ok(valid_ids)
}

#[cfg(test)]
mod tests;
