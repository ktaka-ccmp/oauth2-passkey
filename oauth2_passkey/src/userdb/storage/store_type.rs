use crate::storage::GENERIC_DATA_STORE;
use crate::userdb::{
    errors::UserError,
    types::{User, UserSearchField},
};

use super::postgres::*;
use super::sqlite::*;

pub(crate) struct UserStore;

impl UserStore {
    /// Initialize the user database tables
    pub(crate) async fn init() -> Result<(), UserError> {
        let store = GENERIC_DATA_STORE.lock().await;

        match (store.as_sqlite(), store.as_postgres()) {
            (Some(pool), _) => {
                create_tables_sqlite(pool).await?;
                validate_user_tables_sqlite(pool).await?;
                Ok(())
            }
            (_, Some(pool)) => {
                create_tables_postgres(pool).await?;
                validate_user_tables_postgres(pool).await?;
                Ok(())
            }
            _ => Err(UserError::Storage("Unsupported database type".to_string())),
        }
    }

    pub(crate) async fn get_all_users() -> Result<Vec<User>, UserError> {
        let store = GENERIC_DATA_STORE.lock().await;

        if let Some(pool) = store.as_sqlite() {
            get_all_users_sqlite(pool).await
        } else if let Some(pool) = store.as_postgres() {
            get_all_users_postgres(pool).await
        } else {
            Err(UserError::Storage("Unsupported database type".to_string()))
        }
    }

    /// Get a user by their ID
    #[tracing::instrument(fields(user_id = %id))]
    pub(crate) async fn get_user(id: &str) -> Result<Option<User>, UserError> {
        Self::get_user_by(UserSearchField::Id(id.to_string())).await
    }

    #[tracing::instrument(fields(user_field = %field))]
    pub(crate) async fn get_user_by(field: UserSearchField) -> Result<Option<User>, UserError> {
        let store = GENERIC_DATA_STORE.lock().await;

        let result = if let Some(pool) = store.as_sqlite() {
            get_user_by_field_sqlite(pool, &field).await
        } else if let Some(pool) = store.as_postgres() {
            get_user_by_field_postgres(pool, &field).await
        } else {
            Err(UserError::Storage("Unsupported database type".to_string()))
        };

        match &result {
            Ok(Some(_)) => {
                tracing::info!(found = true, "User lookup completed");
            }
            Ok(None) => {
                tracing::info!(found = false, "User lookup completed - not found");
            }
            Err(e) => {
                tracing::error!(error = %e, "User lookup failed");
            }
        }

        result
    }

    /// Create or update a user
    #[tracing::instrument(skip(user), fields(user_id = %user.id))]
    pub(crate) async fn upsert_user(user: User) -> Result<User, UserError> {
        tracing::debug!(user_account = %user.account, "Upserting user");
        let store = GENERIC_DATA_STORE.lock().await;

        // Perform the upsert operation
        let result = if let Some(pool) = store.as_sqlite() {
            upsert_user_sqlite(pool, user).await
        } else if let Some(pool) = store.as_postgres() {
            upsert_user_postgres(pool, user).await
        } else {
            return Err(UserError::Storage("Unsupported database type".to_string()));
        }?;

        // Check if this is the first user (sequence_number = 1)
        // If so, make them an admin if they aren't already
        let final_result = if result.sequence_number == Some(1) && !result.is_admin {
            let mut admin_user = result.clone();
            admin_user.is_admin = true;

            // Update the user to make them an admin
            if let Some(pool) = store.as_sqlite() {
                upsert_user_sqlite(pool, admin_user).await
            } else if let Some(pool) = store.as_postgres() {
                upsert_user_postgres(pool, admin_user).await
            } else {
                return Err(UserError::Storage("Unsupported database type".to_string()));
            }
        } else {
            Ok(result)
        };

        match &final_result {
            Ok(user) => {
                tracing::info!(
                    user_id = %user.id,
                    is_admin = user.is_admin,
                    sequence_number = user.sequence_number,
                    "User upsert completed successfully"
                );
            }
            Err(e) => {
                tracing::error!(error = %e, "User upsert failed");
            }
        }

        final_result
    }

    pub(crate) async fn delete_user(id: &str) -> Result<(), UserError> {
        let store = GENERIC_DATA_STORE.lock().await;

        if let Some(pool) = store.as_sqlite() {
            delete_user_sqlite(pool, id).await
        } else if let Some(pool) = store.as_postgres() {
            delete_user_postgres(pool, id).await
        } else {
            Err(UserError::Storage("Unsupported database type".to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::init_test_environment;
    use chrono::Utc;
    use serial_test::serial;

    /// Helper function to create a test user with unique timestamp-based ID
    fn create_test_user(suffix: &str) -> User {
        let timestamp = Utc::now().timestamp_millis();
        User::new(
            format!("test-user-{suffix}-{timestamp}"),
            format!("user-{suffix}-{timestamp}@example.com"),
            format!("Test User {suffix}"),
        )
    }

    /// Test UserStore initialization
    ///
    /// Verifies that UserStore can be initialized successfully and that
    /// initialization is idempotent (can be called multiple times safely).
    #[tokio::test]
    #[serial]
    async fn test_userstore_init() {
        init_test_environment().await;

        // Test that UserStore can be initialized successfully
        let result = UserStore::init().await;
        assert!(result.is_ok(), "UserStore initialization should succeed");

        // Should be idempotent - calling init again should work
        let result2 = UserStore::init().await;
        assert!(
            result2.is_ok(),
            "UserStore re-initialization should succeed"
        );
    }

    /// Test UserStore upsert_user functionality
    ///
    /// This test covers both creating a new user and updating an existing user.
    #[tokio::test]
    #[serial]
    async fn test_userstore_upsert_user_create() {
        init_test_environment().await;
        UserStore::init()
            .await
            .expect("Failed to initialize UserStore");

        let test_user = create_test_user("create");

        // Test creating a new user
        let result = UserStore::upsert_user(test_user.clone()).await;
        assert!(result.is_ok(), "Creating new user should succeed");

        let created_user = result.expect("User creation should succeed");
        assert_eq!(created_user.id, test_user.id);
        assert_eq!(created_user.account, test_user.account);
        assert_eq!(created_user.label, test_user.label);
        assert_eq!(created_user.is_admin, test_user.is_admin);
        assert!(
            created_user.sequence_number.is_some(),
            "Sequence number should be assigned"
        );

        // Clean up
        let _ = UserStore::delete_user(&created_user.id).await;
    }

    /// Test that the first user created by init_test_environment is an admin
    ///
    /// This test ensures that the first user created during the test environment
    /// initialization has admin privileges, which is a key requirement for the system.
    /// It checks that the user has the expected ID, account, label, and sequence number.
    #[tokio::test]
    #[serial]
    async fn test_first_user_created_by_init_environment_is_admin() {
        init_test_environment().await;
        UserStore::init()
            .await
            .expect("Failed to initialize UserStore");

        // Verify that the "first-user" created by init_test_environment exists and is admin
        let first_user = UserStore::get_user_by(UserSearchField::SequenceNumber(1))
            .await
            .expect("Failed to get user with sequence number 1")
            .expect("User not found");

        println!("First user: {first_user:?}");

        assert!(first_user.is_admin, "First user should be admin");
        assert!(
            first_user.has_admin_privileges(),
            "First user should have admin privileges"
        );
    }

    /// Test UserStore upsert_user for updating an existing user
    ///
    /// This test creates a user, updates it, and verifies that the update is successful.
    /// It checks that the updated user retains the same ID and sequence number,
    /// but has the new label and is_admin status.
    #[tokio::test]
    #[serial]
    async fn test_userstore_upsert_user_update() {
        init_test_environment().await;
        UserStore::init()
            .await
            .expect("Failed to initialize UserStore");

        let test_user = create_test_user("update");

        // Create the user first
        let created_user = UserStore::upsert_user(test_user.clone())
            .await
            .expect("Failed to create user");

        // Update the user
        let mut updated_user = created_user.clone();
        updated_user.label = "Updated Label".to_string();
        updated_user.is_admin = true;

        let result = UserStore::upsert_user(updated_user.clone()).await;
        assert!(result.is_ok(), "Updating user should succeed");

        let final_user = result.expect("User update should succeed");
        assert_eq!(final_user.id, created_user.id);
        assert_eq!(final_user.label, "Updated Label");
        assert!(final_user.is_admin);
        assert_eq!(final_user.sequence_number, created_user.sequence_number);

        // Clean up
        let _ = UserStore::delete_user(&final_user.id).await;
    }

    /// Test UserStore get_user functionality
    ///
    /// This test verifies that we can retrieve a user by their ID,
    /// both for an existing user and a non-existent user.
    /// It checks that the retrieved user matches the expected values
    /// and that querying a non-existent user returns None.
    #[tokio::test]
    #[serial]
    async fn test_userstore_get_user() {
        init_test_environment().await;
        UserStore::init()
            .await
            .expect("Failed to initialize UserStore");

        let test_user = create_test_user("get");

        // Create a user first
        let created_user = UserStore::upsert_user(test_user.clone())
            .await
            .expect("Failed to create user");

        // Test getting an existing user
        let result = UserStore::get_user(&created_user.id).await;
        assert!(result.is_ok(), "Getting existing user should succeed");

        let retrieved_user = result.expect("Getting user should succeed");
        assert!(retrieved_user.is_some(), "User should be found");

        let user = retrieved_user.expect("User should exist");
        assert_eq!(user.id, created_user.id);
        assert_eq!(user.account, created_user.account);
        assert_eq!(user.label, created_user.label);

        // Test getting a non-existent user
        let result = UserStore::get_user("non-existent-user-id").await;
        assert!(result.is_ok(), "Query for non-existent user should succeed");
        assert!(
            result
                .expect("Query for non-existent user should succeed")
                .is_none(),
            "Non-existent user should return None"
        );

        // Clean up
        let _ = UserStore::delete_user(&created_user.id).await;
    }

    /// Test UserStore get_all_users functionality
    ///
    /// This test verifies that we can retrieve all users from the database,
    /// and that the count of users matches the expected number after creating
    /// several test users. It checks that the created users are included in the results.
    /// It also ensures that the initial count of users is respected.
    /// Finally, it cleans up by deleting the test users created during the test.
    #[tokio::test]
    #[serial]
    async fn test_userstore_get_all_users() {
        init_test_environment().await;
        UserStore::init()
            .await
            .expect("Failed to initialize UserStore");

        // Get initial count
        let initial_users = UserStore::get_all_users().await.unwrap_or_default();
        let initial_count = initial_users.len();

        // Create test users
        let user1 = create_test_user("all1");
        let user2 = create_test_user("all2");
        let user3 = create_test_user("all3");

        let created1 = UserStore::upsert_user(user1)
            .await
            .expect("Failed to create user1");
        let created2 = UserStore::upsert_user(user2)
            .await
            .expect("Failed to create user2");
        let created3 = UserStore::upsert_user(user3)
            .await
            .expect("Failed to create user3");

        // Test getting all users
        let result = UserStore::get_all_users().await;
        assert!(result.is_ok(), "Getting all users should succeed");

        let all_users = result.expect("Getting all users should succeed");
        assert_eq!(
            all_users.len(),
            initial_count + 3,
            "Should have 3 additional users"
        );

        // Verify our test users are in the results
        let user_ids: Vec<String> = all_users.iter().map(|u| u.id.clone()).collect();
        assert!(
            user_ids.contains(&created1.id),
            "User 1 should be in results"
        );
        assert!(
            user_ids.contains(&created2.id),
            "User 2 should be in results"
        );
        assert!(
            user_ids.contains(&created3.id),
            "User 3 should be in results"
        );

        // Clean up
        let _ = UserStore::delete_user(&created1.id).await;
        let _ = UserStore::delete_user(&created2.id).await;
        let _ = UserStore::delete_user(&created3.id).await;
    }

    /// Test UserStore delete_user functionality
    ///
    /// This test verifies that we can delete a user by their ID,
    /// and that the user no longer exists after deletion.
    /// It also checks that deleting a non-existent user does not result in an error.
    /// It ensures that the user is successfully removed from the database.
    #[tokio::test]
    #[serial]
    async fn test_userstore_delete_user() {
        init_test_environment().await;
        UserStore::init()
            .await
            .expect("Failed to initialize UserStore");

        let test_user = create_test_user("delete");

        // Create a user first
        let created_user = UserStore::upsert_user(test_user.clone())
            .await
            .expect("Failed to create user");

        // Verify user exists
        let user_before = UserStore::get_user(&created_user.id)
            .await
            .expect("Failed to get user");
        assert!(user_before.is_some(), "User should exist before deletion");

        // Delete the user
        let result = UserStore::delete_user(&created_user.id).await;
        assert!(result.is_ok(), "Deleting user should succeed");

        // Verify user no longer exists
        let user_after = UserStore::get_user(&created_user.id)
            .await
            .expect("Failed to get user after deletion");
        assert!(user_after.is_none(), "User should not exist after deletion");

        // Deleting a non-existent user should not error
        let result = UserStore::delete_user("non-existent-user-id").await;
        assert!(result.is_ok(), "Deleting non-existent user should succeed");
    }

    /// Test UserStore edge cases
    ///
    /// This test covers edge cases such as querying with an empty string ID,
    /// using a very long ID, and special characters in the ID.
    /// It ensures that these cases do not panic and handle gracefully,
    /// returning None for non-existent users.
    #[tokio::test]
    #[serial]
    async fn test_userstore_edge_cases() {
        init_test_environment().await;
        UserStore::init()
            .await
            .expect("Failed to initialize UserStore");

        // Test with empty string ID (should handle gracefully)
        let result = UserStore::get_user("").await;
        assert!(result.is_ok(), "Empty ID query should not panic");
        assert!(
            result.expect("Empty ID query should succeed").is_none(),
            "Empty ID should return None"
        );

        // Test with very long ID
        let long_id = "a".repeat(1000);
        let result = UserStore::get_user(&long_id).await;
        assert!(result.is_ok(), "Long ID query should not panic");

        // Test with special characters in ID
        let special_id = "user@#$%^&*()_+-=[]{}|;':\",./<>?";
        let result = UserStore::get_user(special_id).await;
        assert!(
            result.is_ok(),
            "Special character ID query should not panic"
        );
    }

    /// Test UserStore concurrent operations
    ///
    /// This test verifies that multiple user creation operations can be performed concurrently
    /// without issues. It checks that both users are created successfully and have unique sequence numbers.
    #[tokio::test]
    #[serial]
    async fn test_userstore_concurrent_operations() {
        init_test_environment().await;
        UserStore::init()
            .await
            .expect("Failed to initialize UserStore");

        // Test concurrent user creation
        let timestamp = Utc::now().timestamp_millis();
        let user1 = User::new(
            format!("concurrent-1-{timestamp}"),
            format!("user1-{timestamp}@example.com"),
            "Concurrent User 1".to_string(),
        );
        let user2 = User::new(
            format!("concurrent-2-{timestamp}"),
            format!("user2-{timestamp}@example.com"),
            "Concurrent User 2".to_string(),
        );

        // Create users concurrently
        let result1 = UserStore::upsert_user(user1.clone());
        let result2 = UserStore::upsert_user(user2.clone());
        let (result1, result2) = tokio::join!(result1, result2);

        assert!(result1.is_ok(), "Concurrent user 1 creation should succeed");
        assert!(result2.is_ok(), "Concurrent user 2 creation should succeed");

        let created1 = result1.expect("Concurrent user 1 creation should succeed");
        let created2 = result2.expect("Concurrent user 2 creation should succeed");

        // Verify both users were created
        assert_ne!(
            created1.sequence_number, created2.sequence_number,
            "Users should have different sequence numbers"
        );

        // Clean up
        let _ = UserStore::delete_user(&created1.id).await;
        let _ = UserStore::delete_user(&created2.id).await;
    }

    /// Test UserStore error handling for non-existent users
    ///
    /// This test verifies that attempting to get or delete a non-existent user
    /// does not result in an error, but rather returns Ok(None) for get_user
    /// and Ok(()) for delete_user. It ensures that the implementation handles
    /// non-existent users gracefully without panicking or returning unexpected errors.
    #[tokio::test]
    #[serial]
    async fn test_userstore_error_handling_not_found() {
        init_test_environment().await;
        UserStore::init()
            .await
            .expect("Failed to initialize UserStore");

        // Test getting a non-existent user
        let nonexistent_id = format!("nonexistent-{}", Utc::now().timestamp_millis());
        let result = UserStore::get_user(&nonexistent_id).await;

        // Should return Ok(None), not an error
        assert!(result.is_ok(), "Getting non-existent user should not error");
        assert!(
            result
                .expect("Getting non-existent user should succeed")
                .is_none(),
            "Non-existent user should return None"
        );

        // Note: The current implementation of delete_user doesn't check if the user exists
        // before attempting to delete, so it doesn't return NotFound for non-existent users.
        // This is a potential improvement for the implementation.
        let result = UserStore::delete_user(&nonexistent_id).await;
        assert!(
            result.is_ok(),
            "Current implementation doesn't check existence before deletion"
        );
    }

    /// Test UserStore transaction behavior
    ///
    /// This test verifies that creating and updating a user preserves the sequence number,
    /// created_at, and updated_at fields correctly. It checks that the sequence number
    /// remains the same during updates, and that created_at is preserved while updated_at
    /// is updated to the current time. It also ensures that the user can be created and updated
    /// successfully within a transaction-like behavior.
    #[tokio::test]
    #[serial]
    async fn test_userstore_transaction_behavior() {
        init_test_environment().await;
        UserStore::init()
            .await
            .expect("Failed to initialize UserStore");

        // Create a test user
        let test_user = create_test_user("transaction");
        let created_user = UserStore::upsert_user(test_user.clone())
            .await
            .expect("Failed to create user");

        // Verify user was created with correct sequence number
        assert!(
            created_user.sequence_number.is_some(),
            "User should have a sequence number"
        );

        // Update the user
        let mut updated_user = created_user.clone();
        updated_user.label = "Updated Label".to_string();

        let result = UserStore::upsert_user(updated_user.clone()).await;
        assert!(result.is_ok(), "Updating user should succeed");

        let updated = result.expect("User update should succeed");
        assert_eq!(updated.label, "Updated Label");

        // Sequence number should be preserved during update
        assert_eq!(updated.sequence_number, created_user.sequence_number);

        // created_at should be preserved but updated_at should change
        assert_eq!(updated.created_at, created_user.created_at);
        assert!(
            updated.updated_at > created_user.updated_at,
            "updated_at should be newer"
        );

        // Clean up
        let _ = UserStore::delete_user(&created_user.id).await;
    }

    /// Test UserStore admin user operations
    ///
    /// This test verifies that the first user created has admin privileges,
    /// and that subsequent users can be created with or without admin privileges.
    #[tokio::test]
    #[serial]
    async fn test_userstore_admin_user_operations() {
        // First, clear any existing users to ensure we're starting fresh
        init_test_environment().await;
        UserStore::init()
            .await
            .expect("Failed to initialize UserStore");

        // Now create a first user - this should automatically get admin privileges via sequence_number = 1
        let first_user = create_test_user("first");
        let created_first = UserStore::upsert_user(first_user)
            .await
            .expect("Failed to create first user");

        // The first user we create might not have sequence_number = 1 if there are residual users
        // from other tests, but it should have a valid sequence number
        println!(
            "First user sequence_number: {:?}",
            created_first.sequence_number
        );
        println!("First user is_admin: {}", created_first.is_admin);
        assert!(
            created_first.sequence_number.is_some(),
            "First user should have a sequence number"
        );

        // Verify admin privileges are correctly determined
        // (First user should have admin privileges regardless of is_admin flag)
        if created_first.sequence_number == Some(1) {
            assert!(
                created_first.has_admin_privileges(),
                "First user should have admin privileges"
            );
        }

        // Create a second user with is_admin = true
        let mut admin_user = create_test_user("admin");
        admin_user.is_admin = true;

        let created_admin = UserStore::upsert_user(admin_user)
            .await
            .expect("Failed to create admin user");

        // Verify the second user has admin privileges due to is_admin = true
        println!(
            "Admin user sequence_number: {:?}",
            created_admin.sequence_number
        );
        println!("Admin user is_admin: {}", created_admin.is_admin);
        assert!(
            created_admin.sequence_number != Some(1),
            "Admin user should not have sequence_number = 1"
        );
        assert!(
            created_admin.is_admin,
            "Admin user should have is_admin = true"
        );
        assert!(
            created_admin.has_admin_privileges(),
            "Admin user should have admin privileges"
        );

        // Create a regular user with no special privileges
        let regular_user = create_test_user("regular");
        let created_regular = UserStore::upsert_user(regular_user)
            .await
            .expect("Failed to create regular user");

        // Verify the regular user doesn't have admin privileges
        println!(
            "Regular user sequence_number: {:?}",
            created_regular.sequence_number
        );
        println!("Regular user is_admin: {}", created_regular.is_admin);
        assert!(
            created_regular.sequence_number != Some(1),
            "Regular user should not have sequence_number = 1"
        );
        assert!(
            !created_regular.is_admin,
            "Regular user should have is_admin = false"
        );
        assert!(
            !created_regular.has_admin_privileges(),
            "Regular user should not have admin privileges"
        );

        // Clean up
        let _ = UserStore::delete_user(&created_first.id).await;
        let _ = UserStore::delete_user(&created_admin.id).await;
        let _ = UserStore::delete_user(&created_regular.id).await;
    }
}
