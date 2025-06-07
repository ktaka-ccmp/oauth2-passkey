//! Test utilities for passkey module tests
//!
//! This module provides helper functions for setting up and tearing down test data
//! for passkey-related tests. It leverages the in-memory GENERIC_DATA_STORE and
//! GENERIC_CACHE_STORE to create isolated test environments.

use crate::passkey::errors::PasskeyError;
use crate::passkey::types::{PublicKeyCredentialUserEntity, StoredOptions};
use crate::passkey::{PasskeyCredential, PasskeyStore};
use crate::storage::{CacheData, GENERIC_CACHE_STORE};
use crate::userdb::{User, UserStore};
use chrono::Utc;
use std::time::SystemTime;

// Use the existing types for tests, don't create new ones

/// Insert a test user in the database for testing
pub async fn insert_test_user(
    user_id: &str,
    account: &str,
    label: &str,
    is_admin: bool,
) -> Result<User, PasskeyError> {
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
        .map_err(|e| PasskeyError::Storage(e.to_string()))
}

/// Insert a test passkey credential in the database
pub async fn insert_test_credential(
    credential_id: &str,
    user_id: &str,
    user_handle: &str,
    name: &str,
    display_name: &str,
    public_key: &str,
    aaguid: &str,
    counter: u32,
) -> Result<(), PasskeyError> {
    let now = Utc::now();

    let credential = PasskeyCredential {
        credential_id: credential_id.to_string(),
        user_id: user_id.to_string(),
        public_key: public_key.to_string(),
        aaguid: aaguid.to_string(),
        counter,
        user: PublicKeyCredentialUserEntity {
            user_handle: user_handle.to_string(),
            name: name.to_string(),
            display_name: display_name.to_string(),
        },
        created_at: now,
        updated_at: now,
        last_used_at: now,
    };

    PasskeyStore::store_credential(credential_id.to_string(), credential).await
}

/// Insert a test user and then a test passkey credential
/// This ensures the foreign key constraint is satisfied
pub async fn insert_test_user_and_credential(
    credential_id: &str,
    user_id: &str,
    user_handle: &str,
    name: &str,
    display_name: &str,
    public_key: &str,
    aaguid: &str,
    counter: u32,
) -> Result<(), PasskeyError> {
    // First create the user
    insert_test_user(user_id, name, display_name, false)
        .await
        .map_err(|e| PasskeyError::Storage(e.to_string()))?;

    // Then create the credential
    insert_test_credential(
        credential_id,
        user_id,
        user_handle,
        name,
        display_name,
        public_key,
        aaguid,
        counter,
    )
    .await
}

/// Delete a test credential by its ID
pub async fn delete_test_credential(credential_id: &str) -> Result<(), PasskeyError> {
    PasskeyStore::delete_credential_by(crate::passkey::CredentialSearchField::CredentialId(
        credential_id.to_string(),
    ))
    .await
}

/// Remove a key from the cache store
pub async fn remove_from_cache(category: &str, key: &str) -> Result<(), PasskeyError> {
    GENERIC_CACHE_STORE
        .lock()
        .await
        .remove(category, key)
        .await
        .map_err(|e| PasskeyError::Storage(e.to_string()))
}

/// Clean up test credential data
pub async fn cleanup_test_credential(credential_id: &str) -> Result<(), PasskeyError> {
    delete_test_credential(credential_id).await
}

/// Create a test challenge in the cache store
pub async fn create_test_challenge(
    challenge_type: &str,
    id: &str,
    challenge: &str,
    user_handle: &str,
    name: &str,
    display_name: &str,
    ttl: u64,
) -> Result<(), PasskeyError> {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let stored_options = StoredOptions {
        challenge: challenge.to_string(),
        user: PublicKeyCredentialUserEntity {
            user_handle: user_handle.to_string(),
            name: name.to_string(),
            display_name: display_name.to_string(),
        },
        timestamp: now,
        ttl,
    };

    let cache_data = CacheData {
        value: serde_json::to_string(&stored_options)
            .map_err(|e| PasskeyError::Storage(e.to_string()))?,
    };

    GENERIC_CACHE_STORE
        .lock()
        .await
        .put_with_ttl(challenge_type, id, cache_data, ttl as usize)
        .await
        .map_err(|e| PasskeyError::Storage(e.to_string()))
}

/// Check cache store for a specific key
pub async fn check_cache_exists(category: &str, key: &str) -> bool {
    match GENERIC_CACHE_STORE.lock().await.get(category, key).await {
        Ok(Some(_)) => true,
        _ => false,
    }
}
