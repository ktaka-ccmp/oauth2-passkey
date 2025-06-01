use crate::oauth2::{AccountSearchField, OAuth2Store};
use crate::passkey::{CredentialSearchField, PasskeyStore};
use crate::userdb::{User, UserStore};

use super::errors::CoordinationError;

/// Update a user's account and label
pub async fn update_user_account(
    user_id: &str,
    account: Option<String>,
    label: Option<String>,
) -> Result<User, CoordinationError> {
    // Get the current user
    let user = UserStore::get_user(user_id).await?.ok_or_else(|| {
        CoordinationError::ResourceNotFound {
            resource_type: "User".to_string(),
            resource_id: user_id.to_string(),
        }
        .log()
    })?;

    // Update the user with the new values
    let updated_user = User {
        account: account.unwrap_or(user.account),
        label: label.unwrap_or(user.label),
        ..user
    };

    // Save the updated user
    let user = UserStore::upsert_user(updated_user).await?;

    Ok(user)
}

/// Delete a user account and all associated OAuth2 accounts and Passkey credentials
///
/// Returns a list of deleted passkey credential IDs for client-side notification
pub async fn delete_user_account(user_id: &str) -> Result<Vec<String>, CoordinationError> {
    // Check if the user exists
    let user = UserStore::get_user(user_id).await?.ok_or_else(|| {
        CoordinationError::ResourceNotFound {
            resource_type: "User".to_string(),
            resource_id: user_id.to_string(),
        }
        .log()
    })?;

    tracing::debug!("Deleting user account: {:#?}", user);

    // Get all Passkey credentials for this user before deleting them
    let credentials =
        PasskeyStore::get_credentials_by(CredentialSearchField::UserId(user_id.to_string()))
            .await?;
    let credential_ids: Vec<String> = credentials
        .iter()
        .map(|c| c.credential_id.clone())
        .collect();

    // Delete all OAuth2 accounts for this user
    OAuth2Store::delete_oauth2_accounts_by(AccountSearchField::UserId(user_id.to_string())).await?;

    // Delete all Passkey credentials for this user
    PasskeyStore::delete_credential_by(CredentialSearchField::UserId(user_id.to_string())).await?;

    // Finally, delete the user account
    UserStore::delete_user(user_id).await?;

    Ok(credential_ids)
}

// generate a unique user ID, with built-in collision detection
pub(super) async fn gen_new_user_id() -> Result<String, CoordinationError> {
    // Try up to 3 times to generate a unique ID
    for _ in 0..3 {
        let id = uuid::Uuid::new_v4().to_string();
        // let id = crate::utils::gen_random_string(32)?;

        // Check if a user with this ID already exists
        match UserStore::get_user(&id).await {
            Ok(None) => return Ok(id), // ID is unique, return it
            Ok(Some(_)) => continue,   // ID exists, try again
            Err(e) => {
                return Err(
                    CoordinationError::Database(format!("Failed to check user ID: {}", e)).log(),
                );
            }
        }
    }

    // If we get here, we failed to generate a unique ID after multiple attempts
    // This is extremely unlikely with UUID v4, but we handle it anyway
    Err(CoordinationError::Coordination(
        "Failed to generate a unique user ID after multiple attempts".to_string(),
    )
    .log())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::env; // Assuming you'll add `serial_test` to dev-dependencies

    use crate::oauth2::OAuth2Store;
    use crate::passkey::{PasskeyCredential, PasskeyStore};
    use crate::userdb::{User, UserStore};

    // Helper function to create a test user
    fn create_test_user(id: &str, account: &str, label: &str) -> User {
        User {
            id: id.to_string(),
            account: account.to_string(),
            label: label.to_string(),
            is_admin: false,
            sequence_number: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    // Helper function to create a minimal test PasskeyCredential for testing
    // We only need the credential_id field for our tests
    fn create_test_credential(id: &str, user_id: &str) -> PasskeyCredential {
        // Create a minimal PasskeyCredential with just the fields we need
        // This avoids using private types that aren't re-exported
        let now = chrono::Utc::now();
        PasskeyCredential {
            credential_id: id.to_string(),
            user_id: user_id.to_string(),
            public_key: String::new(),
            aaguid: String::new(),
            counter: 0,
            // We don't need to access the user field in our tests
            // so we can use a simpler approach
            user: serde_json::from_str(
                "{\"user_handle\":\"test\",\"name\":\"test\",\"displayName\":\"Test\"}",
            )
            .unwrap(),
            created_at: now.clone(),
            updated_at: now.clone(),
            last_used_at: now,
        }
    }

    // Helper function to create a test OAuth2 account
    fn create_test_oauth2_account(
        id: &str,
        user_id: &str,
        provider: &str,
        provider_user_id: &str,
    ) -> crate::OAuth2Account {
        crate::OAuth2Account {
            id: id.to_string(),
            user_id: user_id.to_string(),
            provider: provider.to_string(),
            provider_user_id: provider_user_id.to_string(),
            name: "Test User".to_string(),
            email: "test@example.com".to_string(),
            picture: None,
            metadata: serde_json::json!({}),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    // Helper function to set up an in-memory SQLite database for testing
    async fn setup_test_db() -> Result<(), Box<dyn std::error::Error>> {
        // Set environment variables for in-memory SQLite
        // These must be set BEFORE GENERIC_DATA_STORE is first accessed.
        // serial_test ensures this function runs before others in a test.
        // Modifying environment variables is unsafe as it's a global state change.
        unsafe {
            env::set_var("GENERIC_DATA_STORE_TYPE", "sqlite");
            env::set_var("GENERIC_DATA_STORE_URL", "sqlite::memory:");
            // Optionally, ensure a consistent prefix or no prefix for tests
            env::set_var("DB_TABLE_PREFIX", "test_o2p_");
        }

        // Initialize stores - this will create tables in the in-memory DB
        // The GENERIC_DATA_STORE will be initialized with the env vars above
        // when these init() functions first access it.
        UserStore::init()
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        PasskeyStore::init()
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        OAuth2Store::init()
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        Ok(())
    }

    #[serial]
    #[tokio::test]
    async fn test_update_user_account_success() {
        setup_test_db().await.expect("Failed to set up test DB");

        // 1. Create initial user directly in the DB
        let initial_user = create_test_user("test-user", "old-account", "Old Label");
        UserStore::upsert_user(initial_user.clone())
            .await
            .expect("Failed to insert initial user");

        // 2. Call the actual function from the parent module
        let result = super::update_user_account(
            "test-user",
            Some("new-account".to_string()),
            Some("New Label".to_string()),
        )
        .await;

        // 3. Verify the result from the function call
        assert!(
            result.is_ok(),
            "update_user_account failed: {:?}",
            result.err()
        );
        let updated_user_from_func = result.unwrap();
        assert_eq!(updated_user_from_func.id, "test-user");
        assert_eq!(updated_user_from_func.account, "new-account");
        assert_eq!(updated_user_from_func.label, "New Label");

        // 4. Verify directly from DB for extra confidence
        let user_from_db = UserStore::get_user("test-user")
            .await
            .expect("DB error getting user")
            .expect("User not found in DB after update");
        assert_eq!(user_from_db.account, "new-account");
        assert_eq!(user_from_db.label, "New Label");
    }

    #[serial]
    #[tokio::test]
    async fn test_update_user_account_not_found() {
        setup_test_db().await.expect("Failed to set up test DB");

        // Call the actual function with a non-existent user
        let result = super::update_user_account(
            "nonexistent-user",
            Some("new-account".to_string()),
            Some("New Label".to_string()),
        )
        .await;

        // Verify the result
        assert!(result.is_err());
        match result {
            Err(CoordinationError::ResourceNotFound {
                resource_type,
                resource_id,
            }) => {
                assert_eq!(resource_type, "User");
                assert_eq!(resource_id, "nonexistent-user");
            }
            _ => panic!("Expected ResourceNotFound error, got {:?}", result),
        }
    }

    #[serial]
    #[tokio::test]
    async fn test_delete_user_account_success() {
        setup_test_db().await.expect("Failed to set up test DB");

        let user_id_to_delete = "user-to-delete";

        // 1. Create user
        let test_user = create_test_user(user_id_to_delete, "test-account", "Test User");
        UserStore::upsert_user(test_user.clone())
            .await
            .expect("Failed to insert user");

        // 2. Create passkey credentials
        let cred1 = create_test_credential("credential-1", user_id_to_delete);
        let cred2 = create_test_credential("credential-2", user_id_to_delete);
        PasskeyStore::store_credential(cred1.credential_id.clone(), cred1.clone())
            .await
            .expect("Failed to store cred1");
        PasskeyStore::store_credential(cred2.credential_id.clone(), cred2.clone())
            .await
            .expect("Failed to store cred2");

        // 3. Create OAuth2 accounts
        let oauth_acc1 =
            create_test_oauth2_account("oauth-acc-1", user_id_to_delete, "google", "google-id-1");
        let oauth_acc2 =
            create_test_oauth2_account("oauth-acc-2", user_id_to_delete, "github", "github-id-1");
        OAuth2Store::upsert_oauth2_account(oauth_acc1)
            .await
            .expect("Failed to upsert oauth_acc1");
        OAuth2Store::upsert_oauth2_account(oauth_acc2)
            .await
            .expect("Failed to upsert oauth_acc2");

        // 4. Call the actual function
        let result = super::delete_user_account(user_id_to_delete).await;

        // 5. Verify returned credential IDs
        assert!(
            result.is_ok(),
            "delete_user_account failed: {:?}",
            result.err()
        );
        let mut returned_credential_ids = result.unwrap();
        returned_credential_ids.sort(); // Sort for consistent comparison
        assert_eq!(
            returned_credential_ids,
            vec!["credential-1", "credential-2"]
        );

        // 6. Verify user is deleted
        let user_from_db = UserStore::get_user(user_id_to_delete)
            .await
            .expect("DB error getting user");
        assert!(user_from_db.is_none(), "User was not deleted from DB");

        // 7. Verify passkeys are deleted
        let passkeys_from_db = PasskeyStore::get_credentials_by(CredentialSearchField::UserId(
            user_id_to_delete.to_string(),
        ))
        .await
        .expect("DB error getting passkeys");
        assert!(passkeys_from_db.is_empty(), "Passkeys were not deleted");

        // 8. Verify OAuth2 accounts are deleted
        let oauth_accounts_from_db = OAuth2Store::get_oauth2_accounts_by(
            AccountSearchField::UserId(user_id_to_delete.to_string()),
        )
        .await
        .expect("DB error getting oauth accounts");
        assert!(
            oauth_accounts_from_db.is_empty(),
            "OAuth2 accounts were not deleted"
        );
    }

    #[serial]
    #[tokio::test]
    async fn test_delete_user_account_not_found() {
        setup_test_db().await.expect("Failed to set up test DB");

        let result = super::delete_user_account("nonexistent-user").await;

        assert!(result.is_err());
        match result {
            Err(CoordinationError::ResourceNotFound {
                resource_type,
                resource_id,
            }) => {
                assert_eq!(resource_type, "User");
                assert_eq!(resource_id, "nonexistent-user");
            }
            _ => panic!("Expected ResourceNotFound error, got {:?}", result),
        }
    }

    #[serial]
    #[tokio::test]
    async fn test_gen_new_user_id_success() {
        setup_test_db().await.expect("Failed to set up test DB");

        let result = super::gen_new_user_id().await;
        assert!(result.is_ok(), "gen_new_user_id failed: {:?}", result.err());
        let generated_id = result.unwrap();
        assert!(!generated_id.is_empty(), "Generated ID is empty");

        // Verify the ID is indeed not in the DB (gen_new_user_id should ensure this)
        let user_from_db = UserStore::get_user(&generated_id)
            .await
            .expect("DB error checking generated ID");
        assert!(
            user_from_db.is_none(),
            "Generated ID was found in DB, but should be unique"
        );
    }

    #[serial]
    #[tokio::test]
    async fn test_get_all_users() {
        // Set up the test database
        setup_test_db()
            .await
            .expect("Failed to set up test database");

        // First, get all existing users and delete them to ensure a clean state
        let existing_users = UserStore::get_all_users()
            .await
            .expect("Failed to get existing users");
        for user in existing_users {
            // Delete any related OAuth2 accounts first
            OAuth2Store::delete_oauth2_accounts_by(AccountSearchField::UserId(user.id.clone()))
                .await
                .expect("Failed to delete OAuth2 accounts");

            // Delete any related Passkey credentials
            PasskeyStore::delete_credential_by(CredentialSearchField::UserId(user.id.clone()))
                .await
                .expect("Failed to delete Passkey credentials");

            // Now delete the user
            UserStore::delete_user(&user.id)
                .await
                .expect("Failed to delete existing user");
        }

        // Verify the database is empty
        let empty_check = UserStore::get_all_users()
            .await
            .expect("Failed to check for empty database");
        assert_eq!(empty_check.len(), 0, "Database should be empty before test");

        // Create multiple test users
        let user1 = create_test_user("test-user-1", "user1@example.com", "User One");
        let user2 = create_test_user("test-user-2", "user2@example.com", "User Two");
        let user3 = create_test_user("test-user-3", "user3@example.com", "User Three");

        // Insert the users into the database
        UserStore::upsert_user(user1.clone())
            .await
            .expect("Failed to insert user1");
        UserStore::upsert_user(user2.clone())
            .await
            .expect("Failed to insert user2");
        UserStore::upsert_user(user3.clone())
            .await
            .expect("Failed to insert user3");

        // Call get_all_users
        let all_users = UserStore::get_all_users()
            .await
            .expect("Failed to get all users");

        // Verify that all users are returned
        assert_eq!(all_users.len(), 3, "Expected 3 users to be returned");

        // Verify that each user is in the returned list
        let user_ids: Vec<String> = all_users.iter().map(|u| u.id.clone()).collect();
        assert!(user_ids.contains(&"test-user-1".to_string()));
        assert!(user_ids.contains(&"test-user-2".to_string()));
        assert!(user_ids.contains(&"test-user-3".to_string()));
    }

    #[serial]
    #[tokio::test]
    async fn test_get_user() {
        // Set up the test database
        setup_test_db()
            .await
            .expect("Failed to set up test database");

        // Create and insert a test user
        let test_user = create_test_user("test-user-id", "user@example.com", "Test User");
        UserStore::upsert_user(test_user.clone())
            .await
            .expect("Failed to insert test user");

        // Test getting an existing user
        let result = UserStore::get_user("test-user-id")
            .await
            .expect("Failed to get user");
        assert!(result.is_some(), "Expected to find the user");

        let retrieved_user = result.unwrap();
        assert_eq!(retrieved_user.id, "test-user-id");
        assert_eq!(retrieved_user.account, "user@example.com");
        assert_eq!(retrieved_user.label, "Test User");

        // Test getting a non-existent user
        let non_existent_result = UserStore::get_user("non-existent-id")
            .await
            .expect("Failed to query non-existent user");
        assert!(
            non_existent_result.is_none(),
            "Expected not to find a non-existent user"
        );
    }

    #[serial]
    #[tokio::test]
    async fn test_upsert_user() {
        // Set up the test database
        setup_test_db()
            .await
            .expect("Failed to set up test database");

        // Test creating a new user
        let new_user = create_test_user("new-user-id", "new@example.com", "New User");
        let created_user = UserStore::upsert_user(new_user.clone())
            .await
            .expect("Failed to create new user");

        // Verify the created user matches what we provided
        assert_eq!(created_user.id, "new-user-id");
        assert_eq!(created_user.account, "new@example.com");
        assert_eq!(created_user.label, "New User");

        // Verify the user was actually stored in the database
        let stored_user = UserStore::get_user("new-user-id")
            .await
            .expect("Failed to get user")
            .expect("User not found in database");

        assert_eq!(stored_user.id, "new-user-id");
        assert_eq!(stored_user.account, "new@example.com");
        assert_eq!(stored_user.label, "New User");

        // Test updating an existing user
        let mut updated_user = stored_user;
        updated_user.account = "updated@example.com".to_string();
        updated_user.label = "Updated User".to_string();

        let result = UserStore::upsert_user(updated_user)
            .await
            .expect("Failed to update user");

        // Verify the update was returned correctly
        assert_eq!(result.id, "new-user-id");
        assert_eq!(result.account, "updated@example.com");
        assert_eq!(result.label, "Updated User");

        // Verify the update was stored in the database
        let stored_updated_user = UserStore::get_user("new-user-id")
            .await
            .expect("Failed to get updated user")
            .expect("Updated user not found in database");

        assert_eq!(stored_updated_user.id, "new-user-id");
        assert_eq!(stored_updated_user.account, "updated@example.com");
        assert_eq!(stored_updated_user.label, "Updated User");
    }

    #[serial]
    #[tokio::test]
    async fn test_delete_user() {
        // Set up the test database
        setup_test_db()
            .await
            .expect("Failed to set up test database");

        // Create a test user
        let test_user = create_test_user("delete-user-id", "delete@example.com", "Delete User");
        UserStore::upsert_user(test_user.clone())
            .await
            .expect("Failed to insert test user");

        // Verify the user exists before deletion
        let user_before_delete = UserStore::get_user("delete-user-id")
            .await
            .expect("Failed to get user")
            .expect("User not found before deletion");

        assert_eq!(user_before_delete.id, "delete-user-id");

        // Delete the user
        UserStore::delete_user("delete-user-id")
            .await
            .expect("Failed to delete user");

        // Verify the user no longer exists
        let user_after_delete = UserStore::get_user("delete-user-id")
            .await
            .expect("Failed to query deleted user");

        assert!(
            user_after_delete.is_none(),
            "User still exists after deletion"
        );

        // Test deleting a non-existent user (should not error)
        let result = UserStore::delete_user("non-existent-id").await;
        assert!(
            result.is_ok(),
            "Deleting a non-existent user should not error"
        );
    }

    #[serial]
    #[tokio::test]
    async fn test_gen_new_user_id_max_retries() {
        // Set up the test database
        setup_test_db()
            .await
            .expect("Failed to set up test database");

        // Create test users with known IDs that will collide
        let test_user1 = create_test_user("fixed-uuid-1", "user1@example.com", "Test User 1");
        let test_user2 = create_test_user("fixed-uuid-2", "user2@example.com", "Test User 2");
        let test_user3 = create_test_user("fixed-uuid-3", "user3@example.com", "Test User 3");

        UserStore::upsert_user(test_user1)
            .await
            .expect("Failed to insert test user 1");
        UserStore::upsert_user(test_user2)
            .await
            .expect("Failed to insert test user 2");
        UserStore::upsert_user(test_user3)
            .await
            .expect("Failed to insert test user 3");

        // Test the failure case (all 3 UUIDs exist)
        {
            // Mock implementation with 3 colliding IDs
            let result =
                gen_new_user_id_with_mock(&["fixed-uuid-1", "fixed-uuid-2", "fixed-uuid-3"]).await;

            // Verify it fails with the expected error
            assert!(result.is_err());
            if let Err(CoordinationError::Coordination(msg)) = result {
                assert_eq!(
                    msg,
                    "Failed to generate a unique user ID after multiple attempts"
                );
            } else {
                panic!("Expected CoordinationError::Coordination, got {:?}", result);
            }
        }

        // Test the success case (third UUID is unique)
        {
            // Mock implementation where the third ID is unique
            let result =
                gen_new_user_id_with_mock(&["fixed-uuid-1", "fixed-uuid-2", "fixed-uuid-4"]).await;

            // Verify it succeeds with the expected ID
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), "fixed-uuid-4");
        }
    }

    // Helper function to mock UUID generation with fixed values
    async fn gen_new_user_id_with_mock(uuids: &[&str]) -> Result<String, CoordinationError> {
        let mut uuid_index = 0;

        // Try up to 3 times to generate a unique ID
        for _ in 0..3 {
            if uuid_index >= uuids.len() {
                return Err(CoordinationError::Coordination(
                    "Mock UUID list exhausted".to_string(),
                ));
            }

            let id = uuids[uuid_index].to_string();
            uuid_index += 1;

            // Check if a user with this ID already exists
            match UserStore::get_user(&id).await {
                Ok(None) => return Ok(id), // ID is unique, return it
                Ok(Some(_)) => continue,   // ID exists, try again
                Err(e) => {
                    return Err(CoordinationError::Database(format!(
                        "Failed to check user ID: {}",
                        e
                    ))
                    .log());
                }
            }
        }

        // If we get here, we failed to generate a unique ID after multiple attempts
        Err(CoordinationError::Coordination(
            "Failed to generate a unique user ID after multiple attempts".to_string(),
        )
        .log())
    }
}
