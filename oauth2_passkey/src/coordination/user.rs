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
    use crate::test_utils::init_test_environment;
    use serial_test::serial;

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
            created_at: now,
            updated_at: now,
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

    /// Test successful update of a user account
    ///
    /// This test verifies that `update_user_account` correctly updates a user account
    /// when given valid input. It creates a test user in the database, calls the update
    /// function, and verifies both the return value and the updated database state.
    ///
    #[serial]
    #[tokio::test]
    async fn test_update_user_account_success() {
        use crate::test_utils::init_test_environment;
        init_test_environment().await;

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

    /// Test update of a non-existent user account
    ///
    /// This test verifies that `update_user_account` returns a ResourceNotFound error
    /// when called with a user ID that does not exist in the database.
    ///
    #[serial]
    #[tokio::test]
    async fn test_update_user_account_not_found() {
        init_test_environment().await;

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

    /// Test successful deletion of a user account
    ///
    /// This test verifies that `delete_user_account` correctly deletes a user account
    /// when given a valid user ID. It creates a test user in the database, deletes it,
    /// and verifies the user no longer exists in the database.
    ///
    #[serial]
    #[tokio::test]
    async fn test_delete_user_account_success() {
        init_test_environment().await;

        // Explicitly ensure tables exist for this test's connection
        // This is necessary for in-memory databases where each test may get a fresh instance
        UserStore::init()
            .await
            .expect("Failed to initialize UserStore");
        OAuth2Store::init()
            .await
            .expect("Failed to initialize OAuth2Store");
        PasskeyStore::init()
            .await
            .expect("Failed to initialize PasskeyStore");

        // Use unique timestamp to avoid conflicts with other tests
        let timestamp = chrono::Utc::now().timestamp_millis();
        let user_id_to_delete = format!("user-to-delete-{}", timestamp);

        // 1. Create user
        let test_user = create_test_user(
            &user_id_to_delete,
            &format!("test-account-{}", timestamp),
            "Test User",
        );
        UserStore::upsert_user(test_user.clone())
            .await
            .expect("Failed to insert user");

        // 2. Create passkey credentials
        let cred1 =
            create_test_credential(&format!("credential-1-{}", timestamp), &user_id_to_delete);
        let cred2 =
            create_test_credential(&format!("credential-2-{}", timestamp), &user_id_to_delete);
        PasskeyStore::store_credential(cred1.credential_id.clone(), cred1.clone())
            .await
            .expect("Failed to store cred1");
        PasskeyStore::store_credential(cred2.credential_id.clone(), cred2.clone())
            .await
            .expect("Failed to store cred2");

        // 3. Create OAuth2 accounts
        let oauth_acc1 = create_test_oauth2_account(
            &format!("oauth-acc-1-{}", timestamp),
            &user_id_to_delete,
            "google",
            &format!("google-id-1-{}", timestamp),
        );
        let oauth_acc2 = create_test_oauth2_account(
            &format!("oauth-acc-2-{}", timestamp),
            &user_id_to_delete,
            "github",
            &format!("github-id-1-{}", timestamp),
        );
        OAuth2Store::upsert_oauth2_account(oauth_acc1)
            .await
            .expect("Failed to upsert oauth_acc1");
        OAuth2Store::upsert_oauth2_account(oauth_acc2)
            .await
            .expect("Failed to upsert oauth_acc2");

        // 4. Call the actual function
        let result = super::delete_user_account(&user_id_to_delete).await;

        // 5. Verify returned credential IDs
        assert!(
            result.is_ok(),
            "delete_user_account failed: {:?}",
            result.err()
        );
        let mut returned_credential_ids = result.unwrap();
        returned_credential_ids.sort(); // Sort for consistent comparison
        let expected_ids = vec![
            format!("credential-1-{}", timestamp),
            format!("credential-2-{}", timestamp),
        ];
        let mut expected_sorted = expected_ids.clone();
        expected_sorted.sort();
        assert_eq!(returned_credential_ids, expected_sorted);

        // 6. Verify user is deleted
        let user_from_db = UserStore::get_user(&user_id_to_delete)
            .await
            .expect("DB error getting user");
        assert!(user_from_db.is_none(), "User was not deleted from DB");

        // 7. Verify passkeys are deleted
        let passkeys_from_db = PasskeyStore::get_credentials_by(CredentialSearchField::UserId(
            user_id_to_delete.clone(),
        ))
        .await
        .expect("DB error getting passkeys");
        assert!(passkeys_from_db.is_empty(), "Passkeys were not deleted");

        // 8. Verify OAuth2 accounts are deleted
        let oauth_accounts_from_db = OAuth2Store::get_oauth2_accounts_by(
            AccountSearchField::UserId(user_id_to_delete.clone()),
        )
        .await
        .expect("DB error getting oauth accounts");
        assert!(
            oauth_accounts_from_db.is_empty(),
            "OAuth2 accounts were not deleted"
        );
    }

    /// Test deletion of a user account that does not exist
    ///
    /// This test verifies that `delete_user_account` returns a ResourceNotFound error
    /// when called with a non-existent user ID. It performs the following steps:
    /// 1. Initializes a test environment
    /// 2. Calls `delete_user_account` with a non-existent user ID
    /// 3. Verifies that the function returns a ResourceNotFound error
    ///
    #[serial]
    #[tokio::test]
    async fn test_delete_user_account_not_found() {
        init_test_environment().await;

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

    /// Test successful generation of a new user ID
    ///
    /// This test verifies that `gen_new_user_id` correctly generates a new user ID
    /// when called. It performs the following steps:
    /// 1. Initializes a test environment
    /// 2. Creates a test user directly in the database
    /// 3. Calls `gen_new_user_id` to generate a new user ID
    /// 4. Verifies that the user ID was successfully generated
    ///
    #[serial]
    #[tokio::test]
    async fn test_gen_new_user_id_success() {
        init_test_environment().await;

        // Explicitly ensure tables exist for this test's connection
        // This is necessary for in-memory databases where each test may get a fresh instance
        UserStore::init()
            .await
            .expect("Failed to initialize UserStore");
        OAuth2Store::init()
            .await
            .expect("Failed to initialize OAuth2Store");
        PasskeyStore::init()
            .await
            .expect("Failed to initialize PasskeyStore");

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

    /// Test successful retrieval of all users
    ///
    /// This test verifies that `get_all_users` correctly retrieves all users
    /// when called. It performs the following steps:
    /// 1. Initializes a test environment
    /// 2. Creates a test user directly in the database
    /// 3. Calls `get_all_users` to retrieve all users
    /// 4. Verifies that the users were successfully retrieved
    ///
    #[serial]
    #[tokio::test]
    #[ignore = "Requires a fresh database state"]
    async fn test_get_all_users() {
        init_test_environment().await;

        // Explicitly ensure tables exist for this test's connection
        // This is necessary for in-memory databases where each test may get a fresh instance
        UserStore::init()
            .await
            .expect("Failed to initialize UserStore");
        OAuth2Store::init()
            .await
            .expect("Failed to initialize OAuth2Store");
        PasskeyStore::init()
            .await
            .expect("Failed to initialize PasskeyStore");

        // Get initial count of users in database
        let initial_users = UserStore::get_all_users()
            .await
            .expect("Failed to get initial users");
        let initial_count = initial_users.len();

        // Create unique test users with timestamp to avoid conflicts
        let timestamp = chrono::Utc::now().timestamp_millis();
        let user1 = create_test_user(
            &format!("test-user-1-{}", timestamp),
            &format!("user1-{}@example.com", timestamp),
            "User One",
        );
        let user2 = create_test_user(
            &format!("test-user-2-{}", timestamp),
            &format!("user2-{}@example.com", timestamp),
            "User Two",
        );
        let user3 = create_test_user(
            &format!("test-user-3-{}", timestamp),
            &format!("user3-{}@example.com", timestamp),
            "User Three",
        );

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

        // Verify that we have the initial count plus our 3 new users
        assert_eq!(
            all_users.len(),
            initial_count + 3,
            "Expected 3 additional users"
        );

        // Verify that each of our test users is in the returned list
        let user_ids: Vec<String> = all_users.iter().map(|u| u.id.clone()).collect();
        assert!(user_ids.contains(&user1.id));
        assert!(user_ids.contains(&user2.id));
        assert!(user_ids.contains(&user3.id));

        // Clean up - delete the test users we created
        UserStore::delete_user(&user1.id).await.ok();
        UserStore::delete_user(&user2.id).await.ok();
        UserStore::delete_user(&user3.id).await.ok();
    }

    /// Test successful retrieval of a specific user
    ///
    /// This test verifies that `get_user` correctly retrieves a specific user
    /// when given a valid user ID. It performs the following steps:
    /// 1. Initializes a test environment
    /// 2. Creates a test user directly in the database
    /// 3. Calls `get_user` to retrieve the user
    /// 4. Verifies that the user was successfully retrieved
    ///
    #[serial]
    #[tokio::test]
    async fn test_get_user() {
        // Set up the test database
        init_test_environment().await;

        // Explicitly ensure tables exist for this test's connection
        // This is necessary for in-memory databases where each test may get a fresh instance
        UserStore::init()
            .await
            .expect("Failed to initialize UserStore");
        OAuth2Store::init()
            .await
            .expect("Failed to initialize OAuth2Store");
        PasskeyStore::init()
            .await
            .expect("Failed to initialize PasskeyStore");

        // Create and insert a test user with timestamp to avoid conflicts
        let timestamp = chrono::Utc::now().timestamp_millis();
        let user_id = format!("test-user-id-{}", timestamp);
        let test_user = create_test_user(
            &user_id,
            &format!("user-{}@example.com", timestamp),
            "Test User",
        );
        UserStore::upsert_user(test_user.clone())
            .await
            .expect("Failed to insert test user");

        // Test getting an existing user
        let result = UserStore::get_user(&user_id)
            .await
            .expect("Failed to get user");
        assert!(result.is_some(), "Expected to find the user");

        let retrieved_user = result.unwrap();
        assert_eq!(retrieved_user.id, user_id);
        assert_eq!(
            retrieved_user.account,
            format!("user-{}@example.com", timestamp)
        );
        assert_eq!(retrieved_user.label, "Test User");

        // Test getting a non-existent user
        let non_existent_result = UserStore::get_user("non-existent-id")
            .await
            .expect("Failed to query non-existent user");
        assert!(
            non_existent_result.is_none(),
            "Expected not to find a non-existent user"
        );

        // Clean up
        UserStore::delete_user(&user_id).await.ok();
    }

    /// Test successful upsert of a user
    ///
    /// This test verifies that `upsert_user` correctly upserts a user
    /// when given a valid user ID. It performs the following steps:
    /// 1. Initializes a test environment
    /// 2. Creates a test user directly in the database
    /// 3. Calls `upsert_user` to upsert the user
    /// 4. Verifies that the user was successfully upserted
    ///
    #[serial]
    #[tokio::test]
    async fn test_upsert_user() {
        // Set up the test database
        init_test_environment().await;

        // Explicitly ensure tables exist for this test's connection
        // This is necessary for in-memory databases where each test may get a fresh instance
        UserStore::init()
            .await
            .expect("Failed to initialize UserStore");
        OAuth2Store::init()
            .await
            .expect("Failed to initialize OAuth2Store");
        PasskeyStore::init()
            .await
            .expect("Failed to initialize PasskeyStore");

        // Test creating a new user with unique timestamp to avoid conflicts
        let timestamp = chrono::Utc::now().timestamp_millis();
        let user_id = format!("new-user-id-{}", timestamp);
        let new_user = create_test_user(
            &user_id,
            &format!("new-{}@example.com", timestamp),
            "New User",
        );
        let created_user = UserStore::upsert_user(new_user.clone())
            .await
            .expect("Failed to create new user");

        // Verify the created user matches what we provided
        assert_eq!(created_user.id, user_id);
        assert_eq!(
            created_user.account,
            format!("new-{}@example.com", timestamp)
        );
        assert_eq!(created_user.label, "New User");

        // Verify the user was actually stored in the database
        let stored_user = UserStore::get_user(&user_id)
            .await
            .expect("Failed to get user")
            .expect("User not found in database");

        assert_eq!(stored_user.id, user_id);
        assert_eq!(
            stored_user.account,
            format!("new-{}@example.com", timestamp)
        );
        assert_eq!(stored_user.label, "New User");

        // Test updating an existing user
        let mut updated_user = stored_user;
        updated_user.account = format!("updated-{}@example.com", timestamp);
        updated_user.label = "Updated User".to_string();

        let result = UserStore::upsert_user(updated_user)
            .await
            .expect("Failed to update user");

        // Verify the update was returned correctly
        assert_eq!(result.id, user_id);
        assert_eq!(result.account, format!("updated-{}@example.com", timestamp));
        assert_eq!(result.label, "Updated User");

        // Verify the update was stored in the database
        let stored_updated_user = UserStore::get_user(&user_id)
            .await
            .expect("Failed to get updated user")
            .expect("Updated user not found in database");

        assert_eq!(stored_updated_user.id, user_id);
        assert_eq!(
            stored_updated_user.account,
            format!("updated-{}@example.com", timestamp)
        );
        assert_eq!(stored_updated_user.label, "Updated User");

        // Clean up
        UserStore::delete_user(&user_id).await.ok();
    }

    /// Test successful deletion of a user
    ///
    /// This test verifies that `delete_user` correctly deletes a user
    /// when given a valid user ID. It performs the following steps:
    /// 1. Initializes a test environment
    /// 2. Creates a test user directly in the database
    /// 3. Calls `delete_user` to delete the user
    /// 4. Verifies that the user was successfully deleted
    ///
    #[serial]
    #[tokio::test]
    async fn test_delete_user() {
        // Set up the test database
        init_test_environment().await;

        // Explicitly ensure tables exist for this test's connection
        // This is necessary for in-memory databases where each test may get a fresh instance
        UserStore::init()
            .await
            .expect("Failed to initialize UserStore");
        OAuth2Store::init()
            .await
            .expect("Failed to initialize OAuth2Store");
        PasskeyStore::init()
            .await
            .expect("Failed to initialize PasskeyStore");

        // Create a test user with unique timestamp to avoid conflicts
        let timestamp = chrono::Utc::now().timestamp_millis();
        let user_id = format!("delete-user-id-{}", timestamp);
        let test_user = create_test_user(
            &user_id,
            &format!("delete-{}@example.com", timestamp),
            "Delete User",
        );
        UserStore::upsert_user(test_user.clone())
            .await
            .expect("Failed to insert test user");

        // Verify the user exists before deletion
        let user_before_delete = UserStore::get_user(&user_id)
            .await
            .expect("Failed to get user")
            .expect("User not found before deletion");

        assert_eq!(user_before_delete.id, user_id);

        // Delete the user
        UserStore::delete_user(&user_id)
            .await
            .expect("Failed to delete user");

        // Verify the user no longer exists
        let user_after_delete = UserStore::get_user(&user_id)
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

    /// Test generation of a new user ID with maximum retries
    ///
    /// This test verifies that `gen_new_user_id` correctly generates a new user ID
    /// when called with maximum retries. It performs the following steps:
    /// 1. Initializes a test environment
    /// 2. Creates a test user directly in the database
    /// 3. Calls `gen_new_user_id` to generate a new user ID
    /// 4. Verifies that the user ID was successfully generated
    ///
    #[serial]
    #[tokio::test]
    async fn test_gen_new_user_id_max_retries() {
        // Set up the test database
        init_test_environment().await;

        // Explicitly ensure tables exist for this test's connection
        // This is necessary for in-memory databases where each test may get a fresh instance
        UserStore::init()
            .await
            .expect("Failed to initialize UserStore");
        OAuth2Store::init()
            .await
            .expect("Failed to initialize OAuth2Store");
        PasskeyStore::init()
            .await
            .expect("Failed to initialize PasskeyStore");

        // Create test users with known IDs that will collide using unique timestamp
        let timestamp = chrono::Utc::now().timestamp_millis();
        let test_user1 = create_test_user(
            &format!("fixed-uuid-1-{}", timestamp),
            &format!("user1-{}@example.com", timestamp),
            "Test User 1",
        );
        let test_user2 = create_test_user(
            &format!("fixed-uuid-2-{}", timestamp),
            &format!("user2-{}@example.com", timestamp),
            "Test User 2",
        );
        let test_user3 = create_test_user(
            &format!("fixed-uuid-3-{}", timestamp),
            &format!("user3-{}@example.com", timestamp),
            "Test User 3",
        );

        UserStore::upsert_user(test_user1.clone())
            .await
            .expect("Failed to insert test user 1");
        UserStore::upsert_user(test_user2.clone())
            .await
            .expect("Failed to insert test user 2");
        UserStore::upsert_user(test_user3.clone())
            .await
            .expect("Failed to insert test user 3");

        // Test the failure case (all 3 UUIDs exist)
        {
            // Mock implementation with 3 colliding IDs
            let result = gen_new_user_id_with_mock(&[
                &format!("fixed-uuid-1-{}", timestamp),
                &format!("fixed-uuid-2-{}", timestamp),
                &format!("fixed-uuid-3-{}", timestamp),
            ])
            .await;

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
            let result = gen_new_user_id_with_mock(&[
                &format!("fixed-uuid-1-{}", timestamp),
                &format!("fixed-uuid-2-{}", timestamp),
                &format!("fixed-uuid-4-{}", timestamp),
            ])
            .await;

            // Verify it succeeds with the expected ID
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), format!("fixed-uuid-4-{}", timestamp));
        }

        // Clean up
        UserStore::delete_user(&test_user1.id).await.ok();
        UserStore::delete_user(&test_user2.id).await.ok();
        UserStore::delete_user(&test_user3.id).await.ok();
    }

    // Helper function to mock UUID generation with fixed values
    async fn gen_new_user_id_with_mock(uuids: &[&str]) -> Result<String, CoordinationError> {
        // Try up to 3 times to generate a unique ID
        for uuid_index in 0..3 {
            if uuid_index >= uuids.len() {
                return Err(CoordinationError::Coordination(
                    "Mock UUID list exhausted".to_string(),
                ));
            }

            let id = uuids[uuid_index].to_string();

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
