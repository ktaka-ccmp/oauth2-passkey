//! Test utilities for session module tests

use super::user_sessions::add_session_to_user_mapping;
use crate::session::errors::SessionError;
use crate::session::types::{SessionId, StoredSession, UserId};
use crate::storage::{CacheData, CacheErrorConversion, CacheKey, CachePrefix, GENERIC_CACHE_STORE};
use crate::userdb::User;
use crate::userdb::UserStore;
use chrono::{Duration, Utc};

/// Insert a test user in the database for testing
#[cfg(test)]
pub(crate) async fn insert_test_user(
    user_id: UserId,
    account: &str,
    label: &str,
    is_admin: bool,
) -> Result<User, SessionError> {
    let user = User {
        sequence_number: None,
        id: user_id.as_str().to_string(),
        account: account.to_string(),
        label: label.to_string(),
        is_admin,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    UserStore::upsert_user(user)
        .await
        .map_err(|e| SessionError::Storage(e.to_string()))
}

/// Insert a test session in the cache for testing
#[cfg(test)]
pub(crate) async fn insert_test_session(
    session_id: SessionId,
    user_id: UserId,
    csrf_token: &str,
    ttl: u64,
) -> Result<(), SessionError> {
    let expires_at = Utc::now() + Duration::seconds(ttl as i64);

    let stored_session = StoredSession {
        user_id: user_id.as_str().to_string(),
        csrf_token: csrf_token.to_string(),
        expires_at,
        ttl,
    };

    let cache_data = CacheData {
        value: serde_json::to_string(&stored_session)
            .map_err(|e| SessionError::Storage(e.to_string()))?,
    };

    let cache_key = CacheKey::new(session_id.as_str().to_string())
        .map_err(SessionError::convert_storage_error)?;

    GENERIC_CACHE_STORE
        .lock()
        .await
        .put_with_ttl(CachePrefix::session(), cache_key, cache_data, ttl as usize)
        .await
        .map_err(SessionError::convert_storage_error)?;

    // Also update the user_sessions mapping for session count tracking
    add_session_to_user_mapping(user_id.as_str(), session_id.as_str()).await?;

    Ok(())
}

/// Create a test user and session for testing
#[cfg(test)]
pub(crate) async fn create_test_user_and_session(
    user_id: UserId,
    account: &str,
    label: &str,
    is_admin: bool,
    session_id: SessionId,
    csrf_token: &str,
    ttl: u64,
) -> Result<(User, ()), SessionError> {
    let user = insert_test_user(user_id.clone(), account, label, is_admin).await?;
    insert_test_session(session_id, user_id, csrf_token, ttl).await?;
    Ok((user, ()))
}

/// Delete a test session from cache for cleanup
#[cfg(test)]
pub(crate) async fn delete_test_session(session_id: SessionId) -> Result<(), SessionError> {
    let cache_key = CacheKey::new(session_id.as_str().to_string())
        .map_err(SessionError::convert_storage_error)?;

    GENERIC_CACHE_STORE
        .lock()
        .await
        .remove(CachePrefix::session(), cache_key)
        .await
        .map_err(SessionError::convert_storage_error)?;
    Ok(())
}

/// Delete a test user from database for cleanup
#[cfg(test)]
pub(crate) async fn delete_test_user(user_id: UserId) -> Result<(), SessionError> {
    UserStore::delete_user(user_id)
        .await
        .map_err(|e| SessionError::Storage(e.to_string()))?;
    Ok(())
}

/// Clean up test resources (user and session) for testing
#[cfg(test)]
pub(crate) async fn cleanup_test_resources(
    user_id: UserId,
    session_id: SessionId,
) -> Result<(), SessionError> {
    // Delete session first, then user (order matters for referential integrity)
    delete_test_session(session_id).await.ok(); // Ignore errors since session might not exist
    delete_test_user(user_id).await.ok(); // Ignore errors since user might not exist
    Ok(())
}
