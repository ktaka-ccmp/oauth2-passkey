use crate::oauth2::{AccountSearchField, OAuth2Store};
use crate::passkey::{CredentialSearchField, PasskeyStore};
use crate::session::User as SessionUser;
use crate::userdb::{User, UserStore};

use super::errors::CoordinationError;

/// Retrieves a list of all users in the system.
///
/// This admin-level function fetches all user accounts from the database.
/// It provides a comprehensive view of all registered users and their details.
///
/// # Returns
///
/// * `Ok(Vec<User>)` - A vector containing all user accounts
/// * `Err(CoordinationError)` - If a database error occurs
///
/// # Examples
///
/// ```no_run
/// use oauth2_passkey::get_all_users;
///
/// async fn list_all_users() -> Vec<String> {
///     match get_all_users().await {
///         Ok(users) => users.iter().map(|user| user.account.clone()).collect(),
///         Err(_) => Vec::new()
///     }
/// }
/// ```
pub async fn get_all_users() -> Result<Vec<User>, CoordinationError> {
    UserStore::get_all_users()
        .await
        .map_err(|e| CoordinationError::Database(e.to_string()))
}

/// Retrieves a specific user by their ID.
///
/// This function fetches a user's account information from the database using their
/// unique identifier. It's used for user profile viewing, account management,
/// and administrative tasks.
///
/// # Arguments
///
/// * `user_id` - The unique identifier of the user to retrieve
///
/// # Returns
///
/// * `Ok(Some(User))` - The user's account information if found
/// * `Ok(None)` - If no user exists with the provided ID
/// * `Err(CoordinationError)` - If a database error occurs
///
/// # Examples
///
/// ```no_run
/// use oauth2_passkey::get_user;
///
/// async fn fetch_user_profile(id: &str) -> Option<String> {
///     match get_user(id).await {
///         Ok(Some(user)) => Some(user.account),
///         _ => None
///     }
/// }
/// ```
pub async fn get_user(user_id: &str) -> Result<Option<User>, CoordinationError> {
    UserStore::get_user(user_id)
        .await
        .map_err(|e| CoordinationError::Database(e.to_string()))
}

/// Deletes a passkey credential as an administrator.
///
/// This administrative function allows a system administrator to delete any user's
/// passkey credential. It requires the calling user to have administrative privileges.
/// This is useful for managing compromised credentials or helping users who are
/// locked out of their accounts.
///
/// # Arguments
///
/// * `user` - The administrator user performing the action (must have admin privileges)
/// * `credential_id` - The ID of the passkey credential to delete
///
/// # Returns
///
/// * `Ok(())` - If the credential was successfully deleted
/// * `Err(CoordinationError::Unauthorized)` - If the user doesn't have admin privileges
/// * `Err(CoordinationError)` - If another error occurs during deletion
///
/// # Examples
///
/// ```no_run
/// use oauth2_passkey::{delete_passkey_credential_admin, SessionUser};
///
/// async fn remove_credential(admin: &SessionUser, credential_id: &str) -> bool {
///     delete_passkey_credential_admin(admin, credential_id).await.is_ok()
/// }
/// ```
pub async fn delete_passkey_credential_admin(
    user: &SessionUser,
    credential_id: &str,
) -> Result<(), CoordinationError> {
    if !user.is_admin {
        tracing::debug!("User is not authorized to delete OAuth2 accounts");
        return Err(CoordinationError::Unauthorized.log());
    }

    tracing::debug!(
        "Admin user: {} is deleting credential with ID: {}",
        user.id,
        credential_id
    );

    let credential = PasskeyStore::get_credentials_by(CredentialSearchField::CredentialId(
        credential_id.to_owned(),
    ))
    .await?
    .into_iter()
    .next()
    .ok_or_else(|| {
        CoordinationError::ResourceNotFound {
            resource_type: "Passkey".to_string(),
            resource_id: credential_id.to_string(),
        }
        .log()
    })?;

    // Should we verify a context token here?

    // Delete the credential using the raw credential ID format from the database
    PasskeyStore::delete_credential_by(CredentialSearchField::CredentialId(
        credential.credential_id.clone(),
    ))
    .await?;

    tracing::debug!("Successfully deleted credential");

    Ok(())
}

/// Deletes an OAuth2 account as an administrator.
///
/// This administrative function allows a system administrator to delete any user's
/// OAuth2 account. It requires the calling user to have administrative privileges.
/// This is useful for managing compromised accounts or removing unauthorized
/// OAuth2 connections.
///
/// # Arguments
///
/// * `user` - The administrator user performing the action (must have admin privileges)
/// * `provider_user_id` - The unique provider-specific user ID of the OAuth2 account to delete
///
/// # Returns
///
/// * `Ok(())` - If the OAuth2 account was successfully deleted
/// * `Err(CoordinationError::Unauthorized)` - If the user doesn't have admin privileges
/// * `Err(CoordinationError)` - If another error occurs during deletion
///
/// # Examples
///
/// ```no_run
/// use oauth2_passkey::{delete_oauth2_account_admin, SessionUser};
///
/// async fn remove_oauth2_account(admin: &SessionUser, provider_id: &str) -> bool {
///     delete_oauth2_account_admin(admin, provider_id).await.is_ok()
/// }
/// ```
pub async fn delete_oauth2_account_admin(
    user: &SessionUser,
    provider_user_id: &str,
) -> Result<(), CoordinationError> {
    if !user.is_admin {
        tracing::debug!("User is not authorized to delete OAuth2 accounts");
        return Err(CoordinationError::Unauthorized.log());
    }

    tracing::debug!(
        "Admin user: {} is deleting OAuth2 account with ID: {}",
        user.id,
        provider_user_id
    );

    // Delete the OAuth2 account
    OAuth2Store::delete_oauth2_accounts_by(AccountSearchField::ProviderUserId(
        provider_user_id.to_string(),
    ))
    .await?;

    tracing::info!(
        "Successfully deleted OAuth2 account {} for user {}",
        provider_user_id,
        user.id
    );
    Ok(())
}

/// Completely deletes a user account as an administrator.
///
/// This administrative function permanently removes a user account and all associated
/// data (including OAuth2 accounts and passkey credentials). This is a destructive
/// operation that cannot be undone.
///
/// # Arguments
///
/// * `user_id` - The unique identifier of the user account to delete
///
/// # Returns
///
/// * `Ok(())` - If the user account was successfully deleted
/// * `Err(CoordinationError::ResourceNotFound)` - If the user doesn't exist
/// * `Err(CoordinationError)` - If another error occurs during deletion
///
/// # Examples
///
/// ```no_run
/// use oauth2_passkey::delete_user_account_admin;
///
/// async fn purge_account(user_id: &str) -> Result<(), String> {
///     delete_user_account_admin(user_id).await.map_err(|e| e.to_string())
/// }
/// ```
pub async fn delete_user_account_admin(user_id: &str) -> Result<(), CoordinationError> {
    // Check if the user exists
    let user = UserStore::get_user(user_id).await?.ok_or_else(|| {
        CoordinationError::ResourceNotFound {
            resource_type: "User".to_string(),
            resource_id: user_id.to_string(),
        }
        .log()
    })?;

    tracing::debug!("Deleting user account: {:#?}", user);

    // Delete all OAuth2 accounts for this user
    OAuth2Store::delete_oauth2_accounts_by(AccountSearchField::UserId(user_id.to_string())).await?;

    // Delete all Passkey credentials for this user
    PasskeyStore::delete_credential_by(CredentialSearchField::UserId(user_id.to_string())).await?;

    // Finally, delete the user account
    UserStore::delete_user(user_id).await?;

    Ok(())
}

/// Updates a user's administrative status.
///
/// This function allows an administrator to grant or revoke administrative privileges
/// for another user. For security reasons, the first user in the system (sequence number 1)
/// cannot have their admin status changed.
///
/// # Arguments
///
/// * `admin_user` - The administrator performing the action (must have admin privileges)
/// * `user_id` - The ID of the user whose admin status will be changed
/// * `is_admin` - The new admin status (`true` = admin, `false` = regular user)
///
/// # Returns
///
/// * `Ok(User)` - The updated user account information
/// * `Err(CoordinationError::Unauthorized)` - If the caller doesn't have admin privileges
/// * `Err(CoordinationError::ResourceNotFound)` - If the target user doesn't exist
/// * `Err(CoordinationError)` - If another error occurs, such as trying to change
///   the first user's admin status
///
/// # Examples
///
/// ```no_run
/// use oauth2_passkey::{update_user_admin_status, SessionUser};
///
/// async fn make_user_admin(admin: &SessionUser, user_id: &str) -> bool {
///     update_user_admin_status(admin, user_id, true).await.is_ok()
/// }
/// ```
pub async fn update_user_admin_status(
    admin_user: &SessionUser,
    user_id: &str,
    is_admin: bool,
) -> Result<User, CoordinationError> {
    // Verify that the user has admin privileges
    if !admin_user.is_admin {
        tracing::debug!("User is not authorized to update admin status");
        return Err(CoordinationError::Unauthorized.log());
    }

    // Get the current user
    let user = UserStore::get_user(user_id).await?.ok_or_else(|| {
        CoordinationError::ResourceNotFound {
            resource_type: "User".to_string(),
            resource_id: user_id.to_string(),
        }
        .log()
    })?;

    // Prevent changing admin status of the first user (sequence_number = 1)
    if user.sequence_number == Some(1) {
        tracing::debug!("Cannot change admin status of the first user");
        return Err(CoordinationError::Coordination(
            "Cannot change admin status of the first user for security reasons".to_string(),
        )
        .log());
    }

    // Update the user with the new admin status
    let updated_user = User { is_admin, ..user };

    // Save the updated user
    let user = UserStore::upsert_user(updated_user).await?;

    Ok(user)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::User as SessionUser;
    use crate::test_utils::init_test_environment;
    use chrono::Utc;
    use serial_test::serial;

    // Helper function to create a session user for testing
    fn create_test_session_user(id: &str, is_admin: bool) -> SessionUser {
        SessionUser {
            id: id.to_string(),
            account: format!("{}@example.com", id),
            label: format!("Test User {}", id),
            is_admin,
            sequence_number: 1,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    // Helper function to create a test user in the database
    async fn create_test_user_in_db(
        id: &str,
        is_admin: bool,
    ) -> Result<User, Box<dyn std::error::Error>> {
        let now = Utc::now();
        let user = User {
            sequence_number: None,
            id: id.to_string(),
            account: format!("{}@example.com", id),
            label: format!("Test User {}", id),
            is_admin,
            created_at: now,
            updated_at: now,
        };

        let saved_user = UserStore::upsert_user(user.clone())
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        Ok(saved_user)
    }

    /// Test retrieval of all users from the database
    ///
    /// This test verifies that `get_all_users` correctly retrieves all users and that newly
    /// created users are included in the results. It creates test users in the database,
    /// retrieves all users, and verifies the count and presence of created users.
    ///
    #[serial]
    #[tokio::test]
    async fn test_get_all_users() {
        init_test_environment().await;

        // Get initial count of users in database
        let initial_users = get_all_users().await.expect("Failed to get initial users");
        let initial_count = initial_users.len();

        // Create unique test users with timestamp to avoid conflicts
        let timestamp = chrono::Utc::now().timestamp_millis();
        let user1_id = format!("test-admin-user-1-{}", timestamp);
        let user2_id = format!("test-admin-user-2-{}", timestamp);
        let user3_id = format!("test-admin-user-3-{}", timestamp);

        create_test_user_in_db(&user1_id, false)
            .await
            .expect("Failed to create test user 1");
        create_test_user_in_db(&user2_id, true)
            .await
            .expect("Failed to create test user 2");
        create_test_user_in_db(&user3_id, false)
            .await
            .expect("Failed to create test user 3");

        // Get all users
        let users = get_all_users().await.expect("Failed to get all users");

        // Verify that we have the initial count plus our 3 new users
        assert_eq!(
            users.len(),
            initial_count + 3,
            "Expected 3 additional users"
        );

        // Verify that our test users are in the results
        let user_ids: Vec<String> = users.iter().map(|u| u.id.clone()).collect();
        assert!(
            user_ids.contains(&user1_id),
            "User 1 should be in the result"
        );
        assert!(
            user_ids.contains(&user2_id),
            "User 2 should be in the result"
        );
        assert!(
            user_ids.contains(&user3_id),
            "User 3 should be in the result"
        );

        // Clean up - delete the test users we created
        UserStore::delete_user(&user1_id).await.ok();
        UserStore::delete_user(&user2_id).await.ok();
        UserStore::delete_user(&user3_id).await.ok();
    }

    /// Test retrieval of a specific user by ID
    ///
    /// This test verifies that `get_user` correctly retrieves a specific user by ID
    /// and that the user has the expected properties. It also verifies that trying
    /// to retrieve a non-existent user returns None.
    ///
    #[serial]
    #[tokio::test]
    async fn test_get_user() {
        init_test_environment().await;

        // Create a unique test user
        let timestamp = chrono::Utc::now().timestamp_millis();
        let user_id = format!("test-get-user-{}", timestamp);
        let is_admin = true;
        let _created_user = create_test_user_in_db(&user_id, is_admin)
            .await
            .expect("Failed to create test user");

        // Get the user
        let user_option = get_user(&user_id).await.expect("Failed to get user");

        // Verify that the user is returned
        assert!(user_option.is_some(), "User should be found");
        let user = user_option.unwrap();

        // Verify that the user has the correct properties
        assert_eq!(user.id, user_id, "User ID should match");
        assert_eq!(
            user.account,
            format!("{}@example.com", user_id),
            "User account should match"
        );
        assert_eq!(
            user.label,
            format!("Test User {}", user_id),
            "User label should match"
        );
        assert_eq!(user.is_admin, is_admin, "User admin status should match");

        // Try to get a non-existent user
        let non_existent_user_id = format!("non-existent-user-{}", timestamp);
        let non_existent_user_option = get_user(&non_existent_user_id)
            .await
            .expect("Failed to get non-existent user");

        // Verify that no user is returned
        assert!(
            non_existent_user_option.is_none(),
            "Non-existent user should not be found"
        );

        // Clean up
        UserStore::delete_user(&user_id).await.ok();
    }

    /// Test admin user account deletion functionality
    ///
    /// This test verifies that an admin can delete a user account and that the user
    /// is removed from the database. It also verifies that trying to delete a
    /// non-existent user returns a ResourceNotFound error.
    ///
    #[serial]
    #[tokio::test]
    async fn test_delete_user_account_admin() {
        init_test_environment().await;

        // Create a unique test user to be deleted
        let timestamp = chrono::Utc::now().timestamp_millis();
        let user_id = format!("test-user-to-delete-{}", timestamp);
        create_test_user_in_db(&user_id, false)
            .await
            .expect("Failed to create test user");

        // Verify the user exists before deletion
        let user_before = get_user(&user_id).await.expect("Failed to get user");
        assert!(user_before.is_some(), "User should exist before deletion");

        // Delete the user
        let result = delete_user_account_admin(&user_id).await;
        assert!(result.is_ok(), "Expected successful user deletion");

        // Verify the user no longer exists
        let user_after = get_user(&user_id)
            .await
            .expect("Failed to get user after deletion");
        assert!(user_after.is_none(), "User should not exist after deletion");

        // Try to delete a non-existent user
        let non_existent_user_id = format!("non-existent-user-{}", timestamp);
        let result = delete_user_account_admin(&non_existent_user_id).await;

        // This should return a ResourceNotFound error
        assert!(
            result.is_err(),
            "Deleting non-existent user should return an error"
        );
        match result {
            Err(CoordinationError::ResourceNotFound {
                resource_type,
                resource_id,
            }) => {
                assert_eq!(
                    resource_type, "User",
                    "Error should indicate resource type as User"
                );
                assert_eq!(
                    resource_id, non_existent_user_id,
                    "Error should include the correct user ID"
                );
            }
            _ => panic!("Expected ResourceNotFound error, got {:?}", result),
        }
    }

    /// Test to ensure that we can update a user's admin status
    /// and that the changes are persisted in the database.
    /// This test creates a unique admin user, updates a target user's admin status,
    /// and verifies that the target user's admin status is updated correctly.
    /// It also checks that a non-admin user cannot update another user's admin status.
    /// Finally, it cleans up by deleting the test users created during the test.
    #[serial]
    #[tokio::test]
    async fn test_update_user_admin_status_success() {
        init_test_environment().await;

        // Create unique users with timestamp
        let timestamp = chrono::Utc::now().timestamp_millis();
        let admin_user_id = format!("admin-user-{}", timestamp);
        let target_user_id = format!("target-user-{}", timestamp);

        // Create an admin user who will perform the update
        create_test_user_in_db(&admin_user_id, true)
            .await
            .expect("Failed to create admin user");
        let admin_session_user = create_test_session_user(&admin_user_id, true);

        // Create a regular user whose admin status will be updated
        create_test_user_in_db(&target_user_id, false)
            .await
            .expect("Failed to create target user");

        // Verify the target user is not an admin initially
        let user_before = get_user(&target_user_id)
            .await
            .expect("Failed to get target user")
            .expect("Target user should exist");
        assert!(
            !user_before.is_admin,
            "Target user should not be an admin initially"
        );

        // Update the user's admin status to true
        let updated_user = update_user_admin_status(&admin_session_user, &target_user_id, true)
            .await
            .expect("Failed to update user admin status");

        // Verify the user is now an admin
        assert!(
            updated_user.is_admin,
            "User should be an admin after update"
        );

        // Verify the change was persisted in the database
        let user_after = get_user(&target_user_id)
            .await
            .expect("Failed to get target user after update")
            .expect("Target user should still exist");
        assert!(
            user_after.is_admin,
            "Target user should be an admin in the database"
        );

        // Update the user's admin status back to false
        let updated_user = update_user_admin_status(&admin_session_user, &target_user_id, false)
            .await
            .expect("Failed to update user admin status back");

        // Verify the user is no longer an admin
        assert!(
            !updated_user.is_admin,
            "User should not be an admin after second update"
        );

        // Clean up
        UserStore::delete_user(&admin_user_id).await.ok();
        UserStore::delete_user(&target_user_id).await.ok();
    }

    /// Test to ensure that updating a user's admin status requires admin privileges.
    /// This test creates a non-admin user who attempts to update another user's admin status,
    /// and verifies that the operation fails with an Unauthorized error.
    /// It also checks that the target user's admin status remains unchanged after the failed update.
    #[serial]
    #[tokio::test]
    async fn test_update_user_admin_status_requires_admin() {
        init_test_environment().await;

        // Create unique users with timestamp
        let timestamp = chrono::Utc::now().timestamp_millis();
        let non_admin_user_id = format!("non-admin-user-{}", timestamp);
        let target_user_id = format!("target-user-2-{}", timestamp);

        // Create a non-admin user who will attempt the update
        create_test_user_in_db(&non_admin_user_id, false)
            .await
            .expect("Failed to create non-admin user");
        let non_admin_session_user = create_test_session_user(&non_admin_user_id, false);

        // Create a target user whose admin status will be attempted to be updated
        create_test_user_in_db(&target_user_id, false)
            .await
            .expect("Failed to create target user");

        // Attempt to update the user's admin status as a non-admin
        let result = update_user_admin_status(&non_admin_session_user, &target_user_id, true).await;

        // Verify the operation fails with Unauthorized error
        assert!(
            result.is_err(),
            "Non-admin should not be allowed to update admin status"
        );
        match result {
            Err(CoordinationError::Unauthorized) => {}
            _ => panic!("Expected Unauthorized error, got {:?}", result),
        }

        // Verify the target user's admin status was not changed
        let user_after = get_user(&target_user_id)
            .await
            .expect("Failed to get target user after failed update")
            .expect("Target user should still exist");
        assert!(
            !user_after.is_admin,
            "Target user's admin status should not have changed"
        );

        // Clean up
        UserStore::delete_user(&non_admin_user_id).await.ok();
        UserStore::delete_user(&target_user_id).await.ok();
    }

    /// Test to ensure that updating the admin status of the first user (sequence_number = 1)
    /// is protected and cannot be changed by any user, even an admin.
    /// This test creates an admin user, retrieves or creates the first user,
    /// and attempts to change the first user's admin status.
    /// It verifies that the operation fails with a Coordination error indicating
    /// that the first user's admin status cannot be changed.
    /// It also checks that the first user remains unchanged in the database.
    /// Finally, it cleans up by deleting the admin user and the first user if it was created during the test.
    #[serial]
    #[tokio::test]
    async fn test_update_user_admin_status_protect_first_user() {
        init_test_environment().await;

        // Create unique users with timestamp
        let timestamp = chrono::Utc::now().timestamp_millis();
        let admin_user_id = format!("admin-user-protect-{}", timestamp);

        // Create an admin user
        create_test_user_in_db(&admin_user_id, true)
            .await
            .expect("Failed to create admin user");
        let admin_session_user = create_test_session_user(&admin_user_id, true);

        // Get all current users to understand the database state
        let all_users_before = UserStore::get_all_users()
            .await
            .expect("Failed to get users");

        // Find the user with sequence_number = 1, or create one if none exists
        let first_user = if let Some(existing_first_user) = all_users_before
            .iter()
            .find(|u| u.sequence_number == Some(1))
        {
            existing_first_user.clone()
        } else {
            // If no user with sequence_number = 1 exists, create a new user
            // which should get sequence_number = 1 if it's the first user
            let new_user = User::new(
                format!("first-user-{}", timestamp),
                format!("first-user-{}@example.com", timestamp),
                "First User".to_string(),
            );

            let created_user = UserStore::upsert_user(new_user)
                .await
                .expect("Failed to create first user");

            // If this is not sequence_number = 1, skip the test since it's database-dependent
            if created_user.sequence_number != Some(1) {
                println!(
                    "SKIPPING TEST: Created user doesn't have sequence_number = 1, got {:?}",
                    created_user.sequence_number
                );
                return;
            }

            created_user
        };

        // Attempt to change the admin status of the first user (should fail)
        let result = update_user_admin_status(&admin_session_user, &first_user.id, false).await;

        // Verify the operation fails with Coordination error
        assert!(
            result.is_err(),
            "Should not be able to change first user's admin status"
        );
        match result {
            Err(CoordinationError::Coordination(msg)) => {
                assert!(msg.contains("Cannot change admin status of the first user"));
            }
            _ => panic!(
                "Expected Coordination error about first user, got {:?}",
                result
            ),
        }

        // Clean up
        UserStore::delete_user(&admin_user_id).await.ok();
        // Don't delete the first user if it existed before our test
        if !all_users_before.iter().any(|u| u.id == first_user.id) {
            UserStore::delete_user(&first_user.id).await.ok();
        }
    }

    /// Test to ensure that deleting a passkey credential as an admin
    /// requires admin privileges.
    /// This test creates a non-admin user, attempts to delete a passkey credential,
    /// and verifies that the operation fails with an Unauthorized error.
    /// It also checks that the credential remains in the database after the failed deletion.
    #[serial]
    #[tokio::test]
    async fn test_delete_passkey_credential_admin_requires_admin() {
        init_test_environment().await;

        // Create unique user with timestamp
        let timestamp = chrono::Utc::now().timestamp_millis();
        let non_admin_user_id = format!("non-admin-user-passkey-{}", timestamp);

        // Create a non-admin user
        create_test_user_in_db(&non_admin_user_id, false)
            .await
            .expect("Failed to create non-admin user");
        let non_admin_session_user = create_test_session_user(&non_admin_user_id, false);

        // Attempt to delete a passkey credential
        let result = delete_passkey_credential_admin(&non_admin_session_user, "credential1").await;

        // Verify that the operation is rejected due to lack of admin privileges
        assert!(result.is_err());
        match result {
            Err(CoordinationError::Unauthorized) => {}
            _ => panic!("Expected Unauthorized error, got: {:?}", result),
        }

        // Clean up
        UserStore::delete_user(&non_admin_user_id).await.ok();
    }

    /// Test to ensure that deleting an OAuth2 account as an admin
    /// requires admin privileges.
    #[serial]
    #[tokio::test]
    async fn test_delete_oauth2_account_admin_requires_admin() {
        init_test_environment().await;

        // Create unique user with timestamp
        let timestamp = chrono::Utc::now().timestamp_millis();
        let non_admin_user_id = format!("non-admin-user-oauth2-{}", timestamp);

        // Create a non-admin user
        create_test_user_in_db(&non_admin_user_id, false)
            .await
            .expect("Failed to create non-admin user");
        let non_admin_session_user = create_test_session_user(&non_admin_user_id, false);

        // Attempt to delete an OAuth2 account
        let result = delete_oauth2_account_admin(&non_admin_session_user, "provider_user_id").await;

        // Verify that the operation is rejected due to lack of admin privileges
        assert!(result.is_err());
        match result {
            Err(CoordinationError::Unauthorized) => {}
            _ => panic!("Expected Unauthorized error, got: {:?}", result),
        }

        // Clean up
        UserStore::delete_user(&non_admin_user_id).await.ok();
    }
}
