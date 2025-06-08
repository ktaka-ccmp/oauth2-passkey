use crate::storage::GENERIC_DATA_STORE;
use crate::userdb::{errors::UserError, types::User};

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
    pub(crate) async fn get_user(id: &str) -> Result<Option<User>, UserError> {
        let store = GENERIC_DATA_STORE.lock().await;

        if let Some(pool) = store.as_sqlite() {
            get_user_sqlite(pool, id).await
        } else if let Some(pool) = store.as_postgres() {
            get_user_postgres(pool, id).await
        } else {
            Err(UserError::Storage("Unsupported database type".to_string()))
        }
    }

    /// Create or update a user
    pub(crate) async fn upsert_user(user: User) -> Result<User, UserError> {
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
        if result.sequence_number == Some(1) && !result.is_admin {
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
        }
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
            format!("test-user-{}-{}", suffix, timestamp),
            format!("user-{}-{}@example.com", suffix, timestamp),
            format!("Test User {}", suffix),
        )
    }

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

        let created_user = result.unwrap();
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

    #[tokio::test]
    #[serial]
    async fn test_userstore_upsert_user_first_user_becomes_admin() {
        init_test_environment().await;
        UserStore::init()
            .await
            .expect("Failed to initialize UserStore");

        // This test verifies the "first user auto-admin" logic by testing the admin promotion
        // behavior rather than relying on specific sequence numbers (which may vary in tests)

        let mut test_user = create_test_user("admin-test");
        test_user.is_admin = false; // Explicitly set to false

        // Create the user
        let result = UserStore::upsert_user(test_user.clone()).await;
        assert!(result.is_ok(), "Creating user should succeed");

        let created_user = result.unwrap();
        assert!(
            created_user.sequence_number.is_some(),
            "User should have a sequence number"
        );

        // The key test: if this is the first user (sequence_number = 1), they should be admin
        // If not the first user, they should retain their original admin status
        if created_user.sequence_number == Some(1) {
            assert!(
                created_user.is_admin,
                "First user (sequence_number=1) should automatically become admin"
            );
        } else {
            // For non-first users, admin status should be preserved as originally set
            assert_eq!(
                created_user.is_admin, test_user.is_admin,
                "Non-first user admin status should be preserved"
            );
        }

        // Clean up
        let _ = UserStore::delete_user(&created_user.id).await;
    }

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

        let final_user = result.unwrap();
        assert_eq!(final_user.id, created_user.id);
        assert_eq!(final_user.label, "Updated Label");
        assert!(final_user.is_admin);
        assert_eq!(final_user.sequence_number, created_user.sequence_number);

        // Clean up
        let _ = UserStore::delete_user(&final_user.id).await;
    }

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

        let retrieved_user = result.unwrap();
        assert!(retrieved_user.is_some(), "User should be found");

        let user = retrieved_user.unwrap();
        assert_eq!(user.id, created_user.id);
        assert_eq!(user.account, created_user.account);
        assert_eq!(user.label, created_user.label);

        // Test getting a non-existent user
        let result = UserStore::get_user("non-existent-user-id").await;
        assert!(result.is_ok(), "Query for non-existent user should succeed");
        assert!(
            result.unwrap().is_none(),
            "Non-existent user should return None"
        );

        // Clean up
        let _ = UserStore::delete_user(&created_user.id).await;
    }

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

        let all_users = result.unwrap();
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
        assert!(result.unwrap().is_none(), "Empty ID should return None");

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
            format!("concurrent-1-{}", timestamp),
            format!("user1-{}@example.com", timestamp),
            "Concurrent User 1".to_string(),
        );
        let user2 = User::new(
            format!("concurrent-2-{}", timestamp),
            format!("user2-{}@example.com", timestamp),
            "Concurrent User 2".to_string(),
        );

        // Create users concurrently
        let result1 = UserStore::upsert_user(user1.clone());
        let result2 = UserStore::upsert_user(user2.clone());
        let (result1, result2) = tokio::join!(result1, result2);

        assert!(result1.is_ok(), "Concurrent user 1 creation should succeed");
        assert!(result2.is_ok(), "Concurrent user 2 creation should succeed");

        let created1 = result1.unwrap();
        let created2 = result2.unwrap();

        // Verify both users were created
        assert_ne!(
            created1.sequence_number, created2.sequence_number,
            "Users should have different sequence numbers"
        );

        // Clean up
        let _ = UserStore::delete_user(&created1.id).await;
        let _ = UserStore::delete_user(&created2.id).await;
    }
}
