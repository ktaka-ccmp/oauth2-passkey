//! Test utilities for session module tests

use crate::session::errors::SessionError;
use crate::session::types::StoredSession;
use crate::storage::{CacheData, GENERIC_CACHE_STORE};
use crate::userdb::User;
use crate::userdb::UserStore;
use chrono::{Duration, Utc};

/// Insert a test user in the database for testing
pub async fn insert_test_user(
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
pub async fn insert_test_session(
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
    };

    GENERIC_CACHE_STORE
        .lock()
        .await
        .put_with_ttl("session", session_id, cache_data, ttl as usize)
        .await
        .map_err(|e| SessionError::Storage(e.to_string()))?;

    Ok(())
}

/// Create a test user and session in one go
pub async fn create_test_user_and_session(
    user_id: &str,
    account: &str,
    label: &str,
    is_admin: bool,
    session_id: &str,
    csrf_token: &str,
    ttl: u64,
) -> Result<User, SessionError> {
    // Insert the user
    let user = insert_test_user(user_id, account, label, is_admin).await?;

    // Create the session
    insert_test_session(session_id, user_id, csrf_token, ttl).await?;

    Ok(user)
}

/// Delete a test session
pub async fn delete_test_session(session_id: &str) -> Result<(), SessionError> {
    GENERIC_CACHE_STORE
        .lock()
        .await
        .remove("session", session_id)
        .await
        .map_err(|e| SessionError::Storage(e.to_string()))?;

    Ok(())
}

/// Delete a test user
pub async fn delete_test_user(user_id: &str) -> Result<(), SessionError> {
    UserStore::delete_user(user_id)
        .await
        .map_err(|e| SessionError::Storage(e.to_string()))
}

/// Clean up test resources - delete both user and session
pub async fn cleanup_test_resources(user_id: &str, session_id: &str) -> Result<(), SessionError> {
    // Delete session first
    let _ = delete_test_session(session_id).await;

    // Then delete user
    let _ = delete_test_user(user_id).await;

    Ok(())
}
