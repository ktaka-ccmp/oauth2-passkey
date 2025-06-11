use chrono::{DateTime, Utc};

use crate::passkey::PasskeyCredential;
use crate::storage::GENERIC_DATA_STORE;

use crate::passkey::errors::PasskeyError;
use crate::passkey::types::CredentialSearchField;

use super::postgres::*;
use super::sqlite::*;

pub struct PasskeyStore;

impl PasskeyStore {
    pub(crate) async fn init() -> Result<(), PasskeyError> {
        let store = GENERIC_DATA_STORE.lock().await;

        match (store.as_sqlite(), store.as_postgres()) {
            (Some(pool), _) => {
                create_tables_sqlite(pool).await?;
                validate_passkey_tables_sqlite(pool).await?;
                Ok(())
            }
            (_, Some(pool)) => {
                create_tables_postgres(pool).await?;
                validate_passkey_tables_postgres(pool).await?;
                Ok(())
            }
            _ => Err(PasskeyError::Storage(
                "Unsupported database type".to_string(),
            )),
        }
    }

    pub(crate) async fn store_credential(
        credential_id: String,
        credential: PasskeyCredential,
    ) -> Result<(), PasskeyError> {
        let store = GENERIC_DATA_STORE.lock().await;

        if let Some(pool) = store.as_sqlite() {
            store_credential_sqlite(pool, &credential_id, &credential).await
        } else if let Some(pool) = store.as_postgres() {
            store_credential_postgres(pool, &credential_id, &credential).await
        } else {
            Err(PasskeyError::Storage("Unsupported database type".into()))
        }
    }

    pub(crate) async fn get_credential(
        credential_id: &str,
    ) -> Result<Option<PasskeyCredential>, PasskeyError> {
        let store = GENERIC_DATA_STORE.lock().await;

        if let Some(pool) = store.as_sqlite() {
            get_credential_sqlite(pool, credential_id).await
        } else if let Some(pool) = store.as_postgres() {
            get_credential_postgres(pool, credential_id).await
        } else {
            Err(PasskeyError::Storage("Unsupported database type".into()))
        }
    }

    pub(crate) async fn get_credentials_by(
        field: CredentialSearchField,
    ) -> Result<Vec<PasskeyCredential>, PasskeyError> {
        let store = GENERIC_DATA_STORE.lock().await;

        if let Some(pool) = store.as_sqlite() {
            get_credentials_by_field_sqlite(pool, &field).await
        } else if let Some(pool) = store.as_postgres() {
            get_credentials_by_field_postgres(pool, &field).await
        } else {
            Err(PasskeyError::Storage("Unsupported database type".into()))
        }
    }

    pub(crate) async fn update_credential_counter(
        credential_id: &str,
        counter: u32,
    ) -> Result<(), PasskeyError> {
        let store = GENERIC_DATA_STORE.lock().await;

        if let Some(pool) = store.as_sqlite() {
            update_credential_counter_sqlite(pool, credential_id, counter).await
        } else if let Some(pool) = store.as_postgres() {
            update_credential_counter_postgres(pool, credential_id, counter).await
        } else {
            Err(PasskeyError::Storage("Unsupported database type".into()))
        }
    }

    pub(crate) async fn delete_credential_by(
        field: CredentialSearchField,
    ) -> Result<(), PasskeyError> {
        let store = GENERIC_DATA_STORE.lock().await;

        if let Some(pool) = store.as_sqlite() {
            delete_credential_by_field_sqlite(pool, &field).await
        } else if let Some(pool) = store.as_postgres() {
            delete_credential_by_field_postgres(pool, &field).await
        } else {
            Err(PasskeyError::Storage("Unsupported database type".into()))
        }
    }

    pub(crate) async fn update_credential(
        credential_id: &str,
        name: &str,
        display_name: &str,
    ) -> Result<(), PasskeyError> {
        let store = GENERIC_DATA_STORE.lock().await;

        if let Some(pool) = store.as_sqlite() {
            update_credential_user_details_sqlite(pool, credential_id, name, display_name).await
        } else if let Some(pool) = store.as_postgres() {
            update_credential_user_details_postgres(pool, credential_id, name, display_name).await
        } else {
            Err(PasskeyError::Storage("Unsupported database type".into()))
        }
    }

    pub(crate) async fn update_credential_last_used_at(
        credential_id: &str,
        last_used_at: DateTime<Utc>,
    ) -> Result<(), PasskeyError> {
        let store = GENERIC_DATA_STORE.lock().await;

        if let Some(pool) = store.as_sqlite() {
            update_credential_last_used_at_sqlite(pool, credential_id, last_used_at).await
        } else if let Some(pool) = store.as_postgres() {
            update_credential_last_used_at_postgres(pool, credential_id, last_used_at).await
        } else {
            Err(PasskeyError::Storage("Unsupported database type".into()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::passkey::types::PublicKeyCredentialUserEntity;
    use crate::test_utils::init_test_environment;
    use crate::userdb::{User, UserStore};
    use chrono::Utc;
    use serial_test::serial;

    /// Helper function to create a test PasskeyCredential
    fn create_test_credential(
        credential_id: &str,
        user_id: &str,
        user_handle: &str,
    ) -> PasskeyCredential {
        let now = Utc::now();
        PasskeyCredential {
            credential_id: credential_id.to_string(),
            user_id: user_id.to_string(),
            public_key: format!("test_public_key_for_{}", credential_id),
            aaguid: "test-aaguid-1234-5678".to_string(),
            counter: 1,
            user: PublicKeyCredentialUserEntity {
                user_handle: user_handle.to_string(),
                name: format!("test_user_{}", user_id),
                display_name: format!("Test User {}", user_id),
            },
            created_at: now,
            updated_at: now,
            last_used_at: now,
        }
    }

    /// Helper function to create a test user
    async fn create_test_user(user_id: &str) -> Result<User, Box<dyn std::error::Error>> {
        let user = User {
            sequence_number: None,
            id: user_id.to_string(),
            account: format!("{}@example.com", user_id),
            label: format!("Test User {}", user_id),
            is_admin: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let created_user = UserStore::upsert_user(user).await?;
        Ok(created_user)
    }

    #[tokio::test]
    #[serial]
    async fn test_passkey_store_init() {
        init_test_environment().await;

        let result = PasskeyStore::init().await;
        assert!(result.is_ok(), "PasskeyStore initialization should succeed");
    }

    #[tokio::test]
    #[serial]
    async fn test_store_and_get_credential() {
        init_test_environment().await;
        let _ = PasskeyStore::init().await;
        let _ = UserStore::init().await;

        let credential_id = "test_cred_001";
        let user_id = "test_user_001";
        let user_handle = "test_handle_001";

        // Create user first
        let _ = create_test_user(user_id)
            .await
            .expect("Failed to create test user");

        let credential = create_test_credential(credential_id, user_id, user_handle);

        // Store credential
        let store_result =
            PasskeyStore::store_credential(credential_id.to_string(), credential.clone()).await;
        assert!(
            store_result.is_ok(),
            "Failed to store credential: {:?}",
            store_result.err()
        );

        // Get credential
        let get_result = PasskeyStore::get_credential(credential_id).await;
        assert!(
            get_result.is_ok(),
            "Failed to get credential: {:?}",
            get_result.err()
        );

        let retrieved_credential = get_result.unwrap();
        assert!(retrieved_credential.is_some(), "Credential should exist");

        let retrieved = retrieved_credential.unwrap();
        assert_eq!(retrieved.credential_id, credential.credential_id);
        assert_eq!(retrieved.user_id, credential.user_id);
        assert_eq!(retrieved.public_key, credential.public_key);
        assert_eq!(retrieved.user.user_handle, credential.user.user_handle);
        assert_eq!(retrieved.counter, credential.counter);

        // Cleanup
        let _ = PasskeyStore::delete_credential_by(CredentialSearchField::CredentialId(
            credential_id.to_string(),
        ))
        .await;
        let _ = UserStore::delete_user(user_id).await;
    }

    #[tokio::test]
    #[serial]
    async fn test_get_nonexistent_credential() {
        init_test_environment().await;
        let _ = PasskeyStore::init().await;

        let result = PasskeyStore::get_credential("nonexistent_credential").await;
        assert!(
            result.is_ok(),
            "Getting nonexistent credential should not error"
        );
        assert!(
            result.unwrap().is_none(),
            "Nonexistent credential should return None"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_get_credentials_by_user_id() {
        init_test_environment().await;
        let _ = PasskeyStore::init().await;
        let _ = UserStore::init().await;

        let user_id = "test_user_multi";
        let credential1 = create_test_credential("cred_001", user_id, "handle_001");
        let credential2 = create_test_credential("cred_002", user_id, "handle_002");

        // Create user first
        let _ = create_test_user(user_id)
            .await
            .expect("Failed to create test user");

        // Store multiple credentials for same user
        let _ = PasskeyStore::store_credential("cred_001".to_string(), credential1).await;
        let _ = PasskeyStore::store_credential("cred_002".to_string(), credential2).await;

        // Get credentials by user ID
        let result =
            PasskeyStore::get_credentials_by(CredentialSearchField::UserId(user_id.to_string()))
                .await;
        assert!(
            result.is_ok(),
            "Failed to get credentials by user ID: {:?}",
            result.err()
        );

        let credentials = result.unwrap();
        assert_eq!(
            credentials.len(),
            2,
            "Should find exactly 2 credentials for user"
        );

        let credential_ids: Vec<String> = credentials
            .iter()
            .map(|c| c.credential_id.clone())
            .collect();
        assert!(credential_ids.contains(&"cred_001".to_string()));
        assert!(credential_ids.contains(&"cred_002".to_string()));

        // Cleanup
        let _ =
            PasskeyStore::delete_credential_by(CredentialSearchField::UserId(user_id.to_string()))
                .await;
        let _ = UserStore::delete_user(user_id).await;
    }

    #[tokio::test]
    #[serial]
    async fn test_get_credentials_by_user_handle() {
        init_test_environment().await;
        let _ = PasskeyStore::init().await;
        let _ = UserStore::init().await;

        let user_id = "user_123";
        let user_handle = "unique_handle_123";
        let credential = create_test_credential("cred_handle_test", user_id, user_handle);

        // Create user first
        let _ = create_test_user(user_id)
            .await
            .expect("Failed to create test user");

        // Store credential
        let _ = PasskeyStore::store_credential("cred_handle_test".to_string(), credential.clone())
            .await;

        // Get by user handle
        let result = PasskeyStore::get_credentials_by(CredentialSearchField::UserHandle(
            user_handle.to_string(),
        ))
        .await;
        assert!(
            result.is_ok(),
            "Failed to get credentials by user handle: {:?}",
            result.err()
        );

        let credentials = result.unwrap();
        assert_eq!(
            credentials.len(),
            1,
            "Should find exactly 1 credential for user handle"
        );
        assert_eq!(credentials[0].user.user_handle, user_handle);

        // Cleanup
        let _ = PasskeyStore::delete_credential_by(CredentialSearchField::CredentialId(
            "cred_handle_test".to_string(),
        ))
        .await;
        let _ = UserStore::delete_user(user_id).await;
    }

    #[tokio::test]
    #[serial]
    async fn test_get_credentials_by_username() {
        init_test_environment().await;
        let _ = PasskeyStore::init().await;
        let _ = UserStore::init().await;

        let username = "test_username_search";
        let user_id = "user_username";
        let mut credential =
            create_test_credential("cred_username_test", user_id, "handle_username");
        credential.user.name = username.to_string();

        // Create user first
        let _ = create_test_user(user_id)
            .await
            .expect("Failed to create test user");

        // Store credential
        let _ =
            PasskeyStore::store_credential("cred_username_test".to_string(), credential.clone())
                .await;

        // Get by username
        let result =
            PasskeyStore::get_credentials_by(CredentialSearchField::UserName(username.to_string()))
                .await;
        assert!(
            result.is_ok(),
            "Failed to get credentials by username: {:?}",
            result.err()
        );

        let credentials = result.unwrap();
        assert_eq!(
            credentials.len(),
            1,
            "Should find exactly 1 credential for username"
        );
        assert_eq!(credentials[0].user.name, username);

        // Cleanup
        let _ = PasskeyStore::delete_credential_by(CredentialSearchField::CredentialId(
            "cred_username_test".to_string(),
        ))
        .await;
        let _ = UserStore::delete_user(user_id).await;
    }

    #[tokio::test]
    #[serial]
    async fn test_update_credential_counter() {
        init_test_environment().await;
        let _ = PasskeyStore::init().await;
        let _ = UserStore::init().await;

        let credential_id = "cred_counter_test";
        let user_id = "user_counter";
        let credential = create_test_credential(credential_id, user_id, "handle_counter");

        // Create user first
        let _ = create_test_user(user_id)
            .await
            .expect("Failed to create test user");

        // Store credential with initial counter = 1
        let _ = PasskeyStore::store_credential(credential_id.to_string(), credential).await;

        // Update counter
        let new_counter = 42;
        let update_result =
            PasskeyStore::update_credential_counter(credential_id, new_counter).await;
        assert!(
            update_result.is_ok(),
            "Failed to update counter: {:?}",
            update_result.err()
        );

        // Verify counter was updated
        let get_result = PasskeyStore::get_credential(credential_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            get_result.counter, new_counter,
            "Counter should be updated to new value"
        );

        // Cleanup
        let _ = PasskeyStore::delete_credential_by(CredentialSearchField::CredentialId(
            credential_id.to_string(),
        ))
        .await;
        let _ = UserStore::delete_user(user_id).await;
    }

    #[tokio::test]
    #[serial]
    async fn test_update_credential_user_details() {
        init_test_environment().await;
        let _ = PasskeyStore::init().await;
        let _ = UserStore::init().await;

        let credential_id = "cred_update_test";
        let user_id = "user_update";
        let credential = create_test_credential(credential_id, user_id, "handle_update");

        // Create user first
        let _ = create_test_user(user_id)
            .await
            .expect("Failed to create test user");

        // Store credential
        let _ = PasskeyStore::store_credential(credential_id.to_string(), credential).await;

        // Update user details
        let new_name = "updated_name";
        let new_display_name = "Updated Display Name";
        let update_result =
            PasskeyStore::update_credential(credential_id, new_name, new_display_name).await;
        assert!(
            update_result.is_ok(),
            "Failed to update credential: {:?}",
            update_result.err()
        );

        // Verify details were updated
        let get_result = PasskeyStore::get_credential(credential_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(get_result.user.name, new_name);
        assert_eq!(get_result.user.display_name, new_display_name);

        // Cleanup
        let _ = PasskeyStore::delete_credential_by(CredentialSearchField::CredentialId(
            credential_id.to_string(),
        ))
        .await;
        let _ = UserStore::delete_user(user_id).await;
    }

    #[tokio::test]
    #[serial]
    async fn test_update_credential_last_used_at() {
        init_test_environment().await;
        let _ = PasskeyStore::init().await;
        let _ = UserStore::init().await;

        let credential_id = "cred_last_used_test";
        let user_id = "user_last_used";
        let credential = create_test_credential(credential_id, user_id, "handle_last_used");
        let original_last_used = credential.last_used_at;

        // Create user first
        let _ = create_test_user(user_id)
            .await
            .expect("Failed to create test user");

        // Store credential
        let _ = PasskeyStore::store_credential(credential_id.to_string(), credential).await;

        // Wait a moment then update last_used_at
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        let new_last_used = Utc::now();
        let update_result =
            PasskeyStore::update_credential_last_used_at(credential_id, new_last_used).await;
        assert!(
            update_result.is_ok(),
            "Failed to update last_used_at: {:?}",
            update_result.err()
        );

        // Verify timestamp was updated
        let get_result = PasskeyStore::get_credential(credential_id)
            .await
            .unwrap()
            .unwrap();
        assert_ne!(
            get_result.last_used_at, original_last_used,
            "last_used_at should be different"
        );
        // Allow some tolerance for timestamp comparison (within 1 second)
        let diff = (get_result.last_used_at - new_last_used)
            .num_milliseconds()
            .abs();
        assert!(diff < 1000, "last_used_at should be close to expected time");

        // Cleanup
        let _ = PasskeyStore::delete_credential_by(CredentialSearchField::CredentialId(
            credential_id.to_string(),
        ))
        .await;
        let _ = UserStore::delete_user(user_id).await;
    }

    #[tokio::test]
    #[serial]
    async fn test_delete_credential_by_credential_id() {
        init_test_environment().await;
        let _ = PasskeyStore::init().await;
        let _ = UserStore::init().await;

        let credential_id = "cred_delete_test";
        let user_id = "user_delete";
        let credential = create_test_credential(credential_id, user_id, "handle_delete");

        // Create user first
        let _ = create_test_user(user_id)
            .await
            .expect("Failed to create test user");

        // Store credential
        let _ = PasskeyStore::store_credential(credential_id.to_string(), credential).await;

        // Verify it exists
        let get_result = PasskeyStore::get_credential(credential_id).await.unwrap();
        assert!(
            get_result.is_some(),
            "Credential should exist before deletion"
        );

        // Delete credential
        let delete_result = PasskeyStore::delete_credential_by(
            CredentialSearchField::CredentialId(credential_id.to_string()),
        )
        .await;
        assert!(
            delete_result.is_ok(),
            "Failed to delete credential: {:?}",
            delete_result.err()
        );

        // Verify it's gone
        let get_result_after = PasskeyStore::get_credential(credential_id).await.unwrap();
        assert!(
            get_result_after.is_none(),
            "Credential should not exist after deletion"
        );

        // Cleanup user
        let _ = UserStore::delete_user(user_id).await;
    }

    #[tokio::test]
    #[serial]
    async fn test_delete_credentials_by_user_id() {
        init_test_environment().await;
        let _ = PasskeyStore::init().await;
        let _ = UserStore::init().await;

        let user_id = "user_delete_multi";
        let credential1 = create_test_credential("cred_del_001", user_id, "handle_del_001");
        let credential2 = create_test_credential("cred_del_002", user_id, "handle_del_002");

        // Create user first
        let _ = create_test_user(user_id)
            .await
            .expect("Failed to create test user");

        // Store multiple credentials for same user
        let _ = PasskeyStore::store_credential("cred_del_001".to_string(), credential1).await;
        let _ = PasskeyStore::store_credential("cred_del_002".to_string(), credential2).await;

        // Verify they exist
        let get_result =
            PasskeyStore::get_credentials_by(CredentialSearchField::UserId(user_id.to_string()))
                .await
                .unwrap();
        assert_eq!(
            get_result.len(),
            2,
            "Should have 2 credentials before deletion"
        );

        // Delete all credentials for user
        let delete_result =
            PasskeyStore::delete_credential_by(CredentialSearchField::UserId(user_id.to_string()))
                .await;
        assert!(
            delete_result.is_ok(),
            "Failed to delete credentials by user ID: {:?}",
            delete_result.err()
        );

        // Verify they're gone
        let get_result_after =
            PasskeyStore::get_credentials_by(CredentialSearchField::UserId(user_id.to_string()))
                .await
                .unwrap();
        assert_eq!(
            get_result_after.len(),
            0,
            "Should have 0 credentials after deletion"
        );

        // Cleanup user
        let _ = UserStore::delete_user(user_id).await;
    }

    #[tokio::test]
    #[serial]
    async fn test_credential_isolation() {
        init_test_environment().await;
        let _ = PasskeyStore::init().await;
        let _ = UserStore::init().await;

        let user_id_1 = "user_iso_001";
        let user_id_2 = "user_iso_002";
        let credential1 = create_test_credential("cred_iso_001", user_id_1, "handle_iso_001");
        let credential2 = create_test_credential("cred_iso_002", user_id_2, "handle_iso_002");

        // Create users first
        let _ = create_test_user(user_id_1)
            .await
            .expect("Failed to create test user 1");
        let _ = create_test_user(user_id_2)
            .await
            .expect("Failed to create test user 2");

        // Store credentials for different users
        let _ = PasskeyStore::store_credential("cred_iso_001".to_string(), credential1).await;
        let _ = PasskeyStore::store_credential("cred_iso_002".to_string(), credential2).await;

        // Get credentials by different search fields
        let creds_user1 =
            PasskeyStore::get_credentials_by(CredentialSearchField::UserId(user_id_1.to_string()))
                .await
                .unwrap();
        let creds_user2 =
            PasskeyStore::get_credentials_by(CredentialSearchField::UserId(user_id_2.to_string()))
                .await
                .unwrap();

        // Verify isolation
        assert_eq!(
            creds_user1.len(),
            1,
            "User 1 should have exactly 1 credential"
        );
        assert_eq!(
            creds_user2.len(),
            1,
            "User 2 should have exactly 1 credential"
        );
        assert_eq!(creds_user1[0].credential_id, "cred_iso_001");
        assert_eq!(creds_user2[0].credential_id, "cred_iso_002");

        // Cleanup
        let _ = PasskeyStore::delete_credential_by(CredentialSearchField::CredentialId(
            "cred_iso_001".to_string(),
        ))
        .await;
        let _ = PasskeyStore::delete_credential_by(CredentialSearchField::CredentialId(
            "cred_iso_002".to_string(),
        ))
        .await;
        let _ = UserStore::delete_user(user_id_1).await;
        let _ = UserStore::delete_user(user_id_2).await;
    }

    #[tokio::test]
    #[serial]
    async fn test_concurrent_operations() {
        init_test_environment().await;
        let _ = PasskeyStore::init().await;
        let _ = UserStore::init().await;

        // Test concurrent credential operations
        let handles = (0..5)
            .map(|i| {
                let credential_id = format!("cred_concurrent_{}", i);
                let user_id = format!("user_concurrent_{}", i);
                let user_handle = format!("handle_concurrent_{}", i);

                tokio::spawn(async move {
                    // Create user first
                    let _ = create_test_user(&user_id)
                        .await
                        .expect("Failed to create test user");

                    let credential = create_test_credential(&credential_id, &user_id, &user_handle);

                    // Store credential
                    let store_result =
                        PasskeyStore::store_credential(credential_id.clone(), credential).await;
                    assert!(store_result.is_ok(), "Concurrent store should succeed");

                    // Get credential
                    let get_result = PasskeyStore::get_credential(&credential_id).await;
                    assert!(
                        get_result.is_ok() && get_result.unwrap().is_some(),
                        "Concurrent get should succeed"
                    );

                    // Clean up
                    let _ = PasskeyStore::delete_credential_by(
                        CredentialSearchField::CredentialId(credential_id),
                    )
                    .await;
                    let _ = UserStore::delete_user(&user_id).await;
                })
            })
            .collect::<Vec<_>>();

        // Wait for all operations to complete
        for handle in handles {
            handle
                .await
                .expect("Concurrent task should complete successfully");
        }
    }
}
