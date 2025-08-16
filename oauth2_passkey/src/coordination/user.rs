use crate::oauth2::{AccountSearchField, OAuth2Store};
use crate::passkey::{CredentialSearchField, PasskeyStore};
use crate::userdb::{User as DbUser, UserStore};

use super::errors::CoordinationError;
use crate::session::{SessionId, UserId, get_user_from_session};

/// Update a user's account and label
///
/// This function allows users to update their own account information.
/// Only the account owner can perform this operation.
///
/// # Arguments
///
/// * `session_id` - The session ID of the user performing the action
/// * `user_id` - The ID of the user whose account will be updated
/// * `account` - The new account name (optional)
/// * `label` - The new label (optional)
///
/// # Returns
///
/// * `Ok(DbUser)` - The updated user account information
/// * `Err(CoordinationError::Unauthorized)` - If the user is not the account owner
/// * `Err(CoordinationError::ResourceNotFound)` - If the target user doesn't exist
/// * `Err(CoordinationError)` - If another error occurs during the update
pub async fn update_user_account(
    session_id: SessionId,
    user_id: UserId,
    account: Option<String>,
    label: Option<String>,
) -> Result<DbUser, CoordinationError> {
    // Get user from session (already does fresh database lookup)
    let session_user = get_user_from_session(session_id.as_str())
        .await
        .map_err(|_| CoordinationError::Unauthorized.log())?;

    // Validate owner session - user can only update their own account
    if session_user.id != user_id.as_str() {
        tracing::debug!(
            session_user_id = %session_user.id,
            target_user_id = %user_id.as_str(),
            "User is not authorized (not resource owner)"
        );
        return Err(CoordinationError::Unauthorized.log());
    }

    // Convert SessionUser to DbUser for database operations
    let user = DbUser::from(session_user);

    // Update the user with the new values
    let updated_user = DbUser {
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
/// This function allows either an administrator (who can delete any user) or the user
/// themselves (who can delete their own account) to perform the deletion.
///
/// # Arguments
///
/// * `session_id` - The session ID of the user performing the action
/// * `user_id` - The ID of the user account to delete
///
/// # Returns
///
/// * `Ok(Vec<String>)` - A list of deleted passkey credential IDs for client-side notification
/// * `Err(CoordinationError::Unauthorized)` - If the user is neither admin nor account owner
/// * `Err(CoordinationError::ResourceNotFound)` - If the target user doesn't exist
/// * `Err(CoordinationError)` - If another error occurs during deletion
///
/// Returns a list of deleted passkey credential IDs for client-side notification
pub async fn delete_user_account(
    session_id: SessionId,
    user_id: UserId,
) -> Result<Vec<String>, CoordinationError> {
    // Get user from session (already does fresh database lookup)
    let session_user = get_user_from_session(session_id.as_str())
        .await
        .map_err(|_| CoordinationError::Unauthorized.log())?;

    // Validate admin or owner session - admin can delete any user, user can delete their own account
    if !session_user.has_admin_privileges() && session_user.id != user_id.as_str() {
        tracing::debug!(
            session_user_id = %session_user.id,
            target_user_id = %user_id.as_str(),
            has_admin_privileges = %session_user.has_admin_privileges(),
            "User is not authorized (neither admin nor resource owner)"
        );
        return Err(CoordinationError::Unauthorized.log());
    }

    // For owner deletion, use session user data (no second DB query needed)
    // For admin deletion of other user, we need to fetch the target user
    let user = if session_user.id == user_id.as_str() {
        // Self-deletion: convert SessionUser to DbUser
        DbUser::from(session_user)
    } else {
        // Admin deleting another user: fetch target user
        UserStore::get_user(user_id.as_str())
            .await?
            .ok_or_else(|| {
                CoordinationError::ResourceNotFound {
                    resource_type: "User".to_string(),
                    resource_id: user_id.as_str().to_string(),
                }
                .log()
            })?
    };

    tracing::debug!("Deleting user account: {:#?}", user);

    // Get all Passkey credentials for this user before deleting them
    let credentials =
        PasskeyStore::get_credentials_by(CredentialSearchField::UserId(user_id.clone())).await?;
    let credential_ids: Vec<String> = credentials
        .iter()
        .map(|c| c.credential_id.clone())
        .collect();

    // Delete all OAuth2 accounts for this user
    OAuth2Store::delete_oauth2_accounts_by(AccountSearchField::UserId(user_id.clone())).await?;

    // Delete all Passkey credentials for this user
    PasskeyStore::delete_credential_by(CredentialSearchField::UserId(user_id.clone())).await?;

    // Finally, delete the user account
    UserStore::delete_user(user_id.as_str()).await?;

    // Returns a list of deleted passkey credential IDs for client-side notification
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
                    CoordinationError::Database(format!("Failed to check user ID: {e}")).log(),
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
    use crate::session::{SessionId, UserId, insert_test_session, insert_test_user};
    use crate::userdb::{User as DbUser, UserStore};

    // Helper function to create a test user
    fn create_test_user(id: &str, account: &str, label: &str) -> DbUser {
        DbUser {
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
    /// when given valid input. It creates a test user in the database with a session,
    /// calls the update function, and verifies both the return value and the updated database state.
    ///
    #[serial]
    #[tokio::test]
    async fn test_update_user_account_success() {
        use crate::test_utils::init_test_environment;
        init_test_environment().await;

        let user_id = "test-user";
        let session_id = "test-session-user";

        // 1. Create user and session using test utilities
        insert_test_user(user_id, "old-account", "Old Label", false)
            .await
            .expect("Failed to create test user");
        insert_test_session(session_id, user_id, "test-csrf", 3600)
            .await
            .expect("Failed to create test session");

        // 2. Call the actual function from the parent module
        let result = super::update_user_account(
            SessionId::new(session_id.to_string()), // session_id with valid session
            UserId::new(user_id.to_string()),       // user_id
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
        assert_eq!(updated_user_from_func.id, user_id);
        assert_eq!(updated_user_from_func.account, "new-account");
        assert_eq!(updated_user_from_func.label, "New Label");

        // 4. Verify directly from DB for extra confidence
        let user_from_db = UserStore::get_user(user_id)
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

        let session_user_id = "session-user";
        let session_id = "test-session";
        let nonexistent_user_id = "nonexistent-user";

        // Create a session user (who will try to update a non-existent user)
        insert_test_user(
            session_user_id,
            "session@example.com",
            "Session User",
            false,
        )
        .await
        .expect("Failed to create session user");
        insert_test_session(session_id, session_user_id, "test-csrf", 3600)
            .await
            .expect("Failed to create session");

        // Call the actual function with a non-existent target user
        let result = super::update_user_account(
            SessionId::new(session_id.to_string()), // session_id (valid session)
            UserId::new(nonexistent_user_id.to_string()), // user_id (non-existent)
            Some("new-account".to_string()),
            Some("New Label".to_string()),
        )
        .await;

        // Verify the result - should fail with Unauthorized because session user != target user
        assert!(result.is_err());
        match result {
            Err(CoordinationError::Unauthorized) => {
                // Expected - session user cannot update other users unless they are the same
            }
            _ => panic!("Expected Unauthorized error, got {result:?}"),
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
        let user_id_to_delete = format!("user-to-delete-{timestamp}");

        // 1. Create user
        let test_user = create_test_user(
            &user_id_to_delete,
            &format!("test-account-{timestamp}"),
            "Test User",
        );
        UserStore::upsert_user(test_user.clone())
            .await
            .expect("Failed to insert user");

        // 2. Create passkey credentials
        let cred1 =
            create_test_credential(&format!("credential-1-{timestamp}"), &user_id_to_delete);
        let cred2 =
            create_test_credential(&format!("credential-2-{timestamp}"), &user_id_to_delete);
        PasskeyStore::store_credential(cred1.credential_id.clone(), cred1.clone())
            .await
            .expect("Failed to store cred1");
        PasskeyStore::store_credential(cred2.credential_id.clone(), cred2.clone())
            .await
            .expect("Failed to store cred2");

        // 3. Create OAuth2 accounts
        let oauth_acc1 = create_test_oauth2_account(
            &format!("oauth-acc-1-{timestamp}"),
            &user_id_to_delete,
            "google",
            &format!("google-id-1-{timestamp}"),
        );
        let oauth_acc2 = create_test_oauth2_account(
            &format!("oauth-acc-2-{timestamp}"),
            &user_id_to_delete,
            "github",
            &format!("github-id-1-{timestamp}"),
        );
        OAuth2Store::upsert_oauth2_account(oauth_acc1)
            .await
            .expect("Failed to upsert oauth_acc1");
        OAuth2Store::upsert_oauth2_account(oauth_acc2)
            .await
            .expect("Failed to upsert oauth_acc2");

        // Create session for the user (user deleting their own account)
        let session_id = format!("test-session-{timestamp}");
        insert_test_session(&session_id, &user_id_to_delete, "test-csrf", 3600)
            .await
            .expect("Failed to create session");

        // 4. Call the actual function
        let result = super::delete_user_account(
            SessionId::new(session_id.clone()),
            UserId::new(user_id_to_delete.clone()),
        )
        .await;

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
            UserId::new(user_id_to_delete.clone()),
        ))
        .await
        .expect("DB error getting passkeys");
        assert!(passkeys_from_db.is_empty(), "Passkeys were not deleted");

        // 8. Verify OAuth2 accounts are deleted
        let oauth_accounts_from_db = OAuth2Store::get_oauth2_accounts_by(
            AccountSearchField::UserId(UserId::new(user_id_to_delete.clone())),
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

        let session_user_id = "session-user";
        let session_id = "test-session";
        let nonexistent_user_id = "nonexistent-user";

        // Create a session user (who will try to delete a non-existent user)
        insert_test_user(
            session_user_id,
            "session@example.com",
            "Session User",
            false,
        )
        .await
        .expect("Failed to create session user");
        insert_test_session(session_id, session_user_id, "test-csrf", 3600)
            .await
            .expect("Failed to create session");

        let result = super::delete_user_account(
            SessionId::new(session_id.to_string()),
            UserId::new(nonexistent_user_id.to_string()),
        )
        .await;

        assert!(result.is_err());
        match result {
            Err(CoordinationError::Unauthorized) => {
                // Expected - session user cannot delete other users unless they are the same or admin
            }
            _ => panic!("Expected Unauthorized error, got {result:?}"),
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
            &format!("fixed-uuid-1-{timestamp}"),
            &format!("user1-{timestamp}@example.com"),
            "Test User 1",
        );
        let test_user2 = create_test_user(
            &format!("fixed-uuid-2-{timestamp}"),
            &format!("user2-{timestamp}@example.com"),
            "Test User 2",
        );
        let test_user3 = create_test_user(
            &format!("fixed-uuid-3-{timestamp}"),
            &format!("user3-{timestamp}@example.com"),
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
                &format!("fixed-uuid-1-{timestamp}"),
                &format!("fixed-uuid-2-{timestamp}"),
                &format!("fixed-uuid-3-{timestamp}"),
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
                panic!("Expected CoordinationError::Coordination, got {result:?}");
            }
        }

        // Test the success case (third UUID is unique)
        {
            // Mock implementation where the third ID is unique
            let result = gen_new_user_id_with_mock(&[
                &format!("fixed-uuid-1-{timestamp}"),
                &format!("fixed-uuid-2-{timestamp}"),
                &format!("fixed-uuid-4-{timestamp}"),
            ])
            .await;

            // Verify it succeeds with the expected ID
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), format!("fixed-uuid-4-{timestamp}"));
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
                        "Failed to check user ID: {e}"
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
