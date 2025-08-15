//! Test utilities for session module tests

use crate::session::errors::SessionError;
use crate::session::types::StoredSession;
use crate::storage::{CacheData, CacheErrorConversion, CacheKey, CachePrefix, GENERIC_CACHE_STORE};
use crate::userdb::User;
use crate::userdb::UserStore;
use chrono::{Duration, Utc};

/// Insert a test user in the database for testing
#[cfg(test)]
pub(crate) async fn insert_test_user(
    user_id: &str,
    account: &str,
    label: &str,
    is_admin: bool,
) -> Result<User, SessionError> {
    let user = User {
        sequence_number: None,
        id: user_id.to_string(),
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
    session_id: &str,
    user_id: &str,
    csrf_token: &str,
    ttl: u64,
) -> Result<(), SessionError> {
    let expires_at = Utc::now() + Duration::seconds(ttl as i64);

    let stored_session = StoredSession {
        user_id: user_id.to_string(),
        csrf_token: csrf_token.to_string(),
        expires_at,
        ttl,
    };

    let cache_data = CacheData {
        value: serde_json::to_string(&stored_session)
            .map_err(|e| SessionError::Storage(e.to_string()))?,
        expires_at: chrono::Utc::now() + chrono::Duration::seconds(ttl as i64),
    };

    let cache_key =
        CacheKey::new(session_id.to_string()).map_err(SessionError::convert_storage_error)?;

    GENERIC_CACHE_STORE
        .lock()
        .await
        .put_with_ttl(CachePrefix::session(), cache_key, cache_data, ttl as usize)
        .await
        .map_err(SessionError::convert_storage_error)?;

    Ok(())
}

/// Create a test user and session for testing
#[cfg(test)]
pub(crate) async fn create_test_user_and_session(
    user_id: &str,
    account: &str,
    label: &str,
    is_admin: bool,
    session_id: &str,
    csrf_token: &str,
    ttl: u64,
) -> Result<(User, ()), SessionError> {
    let user = insert_test_user(user_id, account, label, is_admin).await?;
    insert_test_session(session_id, user_id, csrf_token, ttl).await?;
    Ok((user, ()))
}

/// Delete a test session from cache for cleanup
#[cfg(test)]
pub(crate) async fn delete_test_session(session_id: &str) -> Result<(), SessionError> {
    let cache_key =
        CacheKey::new(session_id.to_string()).map_err(SessionError::convert_storage_error)?;

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
pub(crate) async fn delete_test_user(user_id: &str) -> Result<(), SessionError> {
    UserStore::delete_user(user_id)
        .await
        .map_err(|e| SessionError::Storage(e.to_string()))?;
    Ok(())
}

/// Clean up test resources (user and session) for testing
#[cfg(test)]
pub(crate) async fn cleanup_test_resources(
    user_id: &str,
    session_id: &str,
) -> Result<(), SessionError> {
    // Delete session first, then user (order matters for referential integrity)
    delete_test_session(session_id).await.ok(); // Ignore errors since session might not exist
    delete_test_user(user_id).await.ok(); // Ignore errors since user might not exist
    Ok(())
}
