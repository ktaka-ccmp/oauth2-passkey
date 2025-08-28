use super::*;
use crate::session::{insert_test_session, insert_test_user};
use crate::test_utils::init_test_environment;
use crate::userdb::UserSearchField;
use chrono::Utc;
use serial_test::serial;

// Helper function to create a test admin user with session for testing
async fn create_test_admin_with_session(
    user_id: &str,
    account: &str,
    label: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    // Create admin user in database
    insert_test_user(UserId::new(user_id.to_string()), account, label, true).await?;

    // Create session for the admin user
    let session_id = format!("test-session-{user_id}");
    let csrf_token = "test-csrf-token";
    insert_test_session(
        SessionId::new(session_id.clone()),
        UserId::new(user_id.to_string()),
        csrf_token,
        3600,
    )
    .await?;

    Ok(session_id)
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
        account: format!("{id}@example.com"),
        label: format!("Test User {id}"),
        is_admin,
        created_at: now,
        updated_at: now,
    };

    let saved_user = UserStore::upsert_user(user.clone())
        .await
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

    Ok(saved_user)
}

async fn delete_user_if_exists_and_not_first(user_id: &str) -> Result<(), CoordinationError> {
    // Only proceed if the user exists
    if let Ok(Some(user)) = UserStore::get_user(UserId::new(user_id.to_string())).await {
        // Only delete if sequence_number is not 1
        if user.sequence_number != Some(1) {
            UserStore::delete_user(UserId::new(user_id.to_string())).await?;
        }
    }

    Ok(())
}

/// Test retrieval of all users from the database
///
/// This test verifies that `get_all_users` correctly retrieves all users and that newly
/// created users are included in the results. It creates test users in the database,
/// creates an admin session, retrieves all users, and verifies the count and presence of created users.
///
#[serial]
#[tokio::test]
async fn test_get_all_users() {
    init_test_environment().await;

    // Create unique test users with timestamp to avoid conflicts
    let timestamp = chrono::Utc::now().timestamp_millis();
    let admin_user_id = format!("test-admin-{timestamp}");
    let user1_id = format!("test-user-1-{timestamp}");
    let user2_id = format!("test-user-2-{timestamp}");

    // Create an admin user with session
    let admin_session_id = create_test_admin_with_session(
        &admin_user_id,
        &format!("{admin_user_id}@example.com"),
        "Test Admin",
    )
    .await
    .expect("Failed to create admin session");

    // Create regular test users
    create_test_user_in_db(&user1_id, false)
        .await
        .expect("Failed to create test user 1");
    create_test_user_in_db(&user2_id, false)
        .await
        .expect("Failed to create test user 2");

    // Get all users using admin session
    let users = get_all_users(SessionId::new(admin_session_id.clone()))
        .await
        .expect("Failed to get all users");

    // Verify that our test users are in the results
    let user_ids: Vec<String> = users.iter().map(|u| u.id.clone()).collect();
    assert!(
        user_ids.contains(&admin_user_id),
        "Admin user should be in the result"
    );
    assert!(
        user_ids.contains(&user1_id),
        "User 1 should be in the result"
    );
    assert!(
        user_ids.contains(&user2_id),
        "User 2 should be in the result"
    );

    // Clean up - delete the test users we created
    delete_user_if_exists_and_not_first(&admin_user_id)
        .await
        .ok();
    delete_user_if_exists_and_not_first(&user1_id).await.ok();
    delete_user_if_exists_and_not_first(&user2_id).await.ok();
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

    // Create unique test users with timestamp
    let timestamp = chrono::Utc::now().timestamp_millis();
    let admin_user_id = format!("test-admin-get-{timestamp}");
    let target_user_id = format!("test-get-user-{timestamp}");

    // Create an admin user with session
    let admin_session_id = create_test_admin_with_session(
        &admin_user_id,
        &format!("{admin_user_id}@example.com"),
        "Test Admin",
    )
    .await
    .expect("Failed to create admin session");

    // Create a target user
    let _created_user = create_test_user_in_db(&target_user_id, false)
        .await
        .expect("Failed to create test user");

    // Get the user using admin session
    let user_option = get_user(
        SessionId::new(admin_session_id.clone()),
        UserId::new(target_user_id.clone()),
    )
    .await
    .expect("Failed to get user");

    // Verify that the user is returned
    assert!(user_option.is_some(), "User should be found");
    let user = user_option.unwrap();

    // Verify that the user has the correct properties
    assert_eq!(user.id, target_user_id, "User ID should match");
    assert_eq!(
        user.account,
        format!("{target_user_id}@example.com"),
        "User account should match"
    );
    assert_eq!(
        user.label,
        format!("Test User {target_user_id}"),
        "User label should match"
    );

    // Try to get a non-existent user
    let non_existent_user_id = format!("non-existent-user-{timestamp}");
    let non_existent_user_option = get_user(
        SessionId::new(admin_session_id.clone()),
        UserId::new(non_existent_user_id.clone()),
    )
    .await
    .expect("Failed to get non-existent user");

    // Verify that no user is returned
    assert!(
        non_existent_user_option.is_none(),
        "Non-existent user should not be found"
    );

    // Clean up
    delete_user_if_exists_and_not_first(&admin_user_id)
        .await
        .ok();
    delete_user_if_exists_and_not_first(&target_user_id)
        .await
        .ok();
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

    // Create unique test users with timestamp
    let timestamp = chrono::Utc::now().timestamp_millis();
    let admin_user_id = format!("test-admin-delete-{timestamp}");
    let user_to_delete_id = format!("test-user-to-delete-{timestamp}");

    // Create an admin user with session
    let admin_session_id = create_test_admin_with_session(
        &admin_user_id,
        &format!("{admin_user_id}@example.com"),
        "Test Admin",
    )
    .await
    .expect("Failed to create admin session");

    // Create a user to be deleted
    create_test_user_in_db(&user_to_delete_id, false)
        .await
        .expect("Failed to create test user");

    // Verify the user exists before deletion
    let user_before = get_user(
        SessionId::new(admin_session_id.clone()),
        UserId::new(user_to_delete_id.clone()),
    )
    .await
    .expect("Failed to get user");
    assert!(user_before.is_some(), "User should exist before deletion");

    // Delete the user using admin session
    let result = delete_user_account_admin(
        SessionId::new(admin_session_id.clone()),
        UserId::new(user_to_delete_id.clone()),
    )
    .await;
    assert!(result.is_ok(), "Expected successful user deletion");

    // Verify the user no longer exists
    let user_after = get_user(
        SessionId::new(admin_session_id.clone()),
        UserId::new(user_to_delete_id.clone()),
    )
    .await
    .expect("Failed to get user after deletion");
    assert!(user_after.is_none(), "User should not exist after deletion");

    // Try to delete a non-existent user
    let non_existent_user_id = format!("non-existent-user-{timestamp}");
    let result = delete_user_account_admin(
        SessionId::new(admin_session_id.clone()),
        UserId::new(non_existent_user_id.clone()),
    )
    .await;

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
        _ => panic!("Expected ResourceNotFound error, got {result:?}"),
    }

    // Clean up
    delete_user_if_exists_and_not_first(&admin_user_id)
        .await
        .ok();
}

/// Test to ensure that we can update a user's admin status
/// and that the changes are persisted in the database.
/// This test creates a unique admin user, updates a target user's admin status,
/// and verifies that the target user's admin status is updated correctly.
#[serial]
#[tokio::test]
async fn test_update_user_admin_status_success() {
    init_test_environment().await;

    // Create unique users with timestamp
    let timestamp = chrono::Utc::now().timestamp_millis();
    let admin_user_id = format!("admin-user-{timestamp}");
    let target_user_id = format!("target-user-{timestamp}");

    // Create an admin user with session
    let admin_session_id = create_test_admin_with_session(
        &admin_user_id,
        &format!("{admin_user_id}@example.com"),
        "Test Admin",
    )
    .await
    .expect("Failed to create admin session");

    // Create a regular user whose admin status will be updated
    create_test_user_in_db(&target_user_id, false)
        .await
        .expect("Failed to create target user");

    // Verify the target user is not an admin initially
    let user_before = get_user(
        SessionId::new(admin_session_id.clone()),
        UserId::new(target_user_id.clone()),
    )
    .await
    .expect("Failed to get target user")
    .expect("Target user should exist");
    assert!(
        !user_before.has_admin_privileges(),
        "Target user should not have admin privileges initially"
    );

    // Update the user's admin status to true
    let updated_user = update_user_admin_status(
        SessionId::new(admin_session_id.clone()),
        UserId::new(target_user_id.clone()),
        true,
    )
    .await
    .expect("Failed to update user admin status");

    // Verify the user is now an admin
    assert!(
        updated_user.has_admin_privileges(),
        "User should have admin privileges after update"
    );

    // Verify the change was persisted in the database
    let user_after = get_user(
        SessionId::new(admin_session_id.clone()),
        UserId::new(target_user_id.clone()),
    )
    .await
    .expect("Failed to get target user after update")
    .expect("Target user should still exist");
    assert!(
        user_after.has_admin_privileges(),
        "Target user should have admin privileges in the database"
    );

    // Update the user's admin status back to false
    let updated_user = update_user_admin_status(
        SessionId::new(admin_session_id.clone()),
        UserId::new(target_user_id.clone()),
        false,
    )
    .await
    .expect("Failed to update user admin status back");

    // Verify the user is no longer an admin
    assert!(
        !updated_user.has_admin_privileges(),
        "User should not have admin privileges after second update"
    );

    // Clean up
    delete_user_if_exists_and_not_first(&admin_user_id)
        .await
        .ok();
    delete_user_if_exists_and_not_first(&target_user_id)
        .await
        .ok();
}

/// Test to ensure that updating a user's admin status requires admin privileges.
/// This test creates a non-admin user who attempts to update another user's admin status,
/// and verifies that the operation fails with an Unauthorized error.
/// This validates our fresh database validation security model.
#[serial]
#[tokio::test]
async fn test_update_user_admin_status_requires_admin() {
    init_test_environment().await;

    // Create unique users with timestamp
    let timestamp = chrono::Utc::now().timestamp_millis();
    let non_admin_user_id = format!("non-admin-user-{timestamp}");
    let target_user_id = format!("target-user-2-{timestamp}");

    // Create a non-admin user with session
    insert_test_user(
        UserId::new(non_admin_user_id.clone()),
        &format!("{non_admin_user_id}@example.com"),
        "Non Admin",
        false,
    )
    .await
    .expect("Failed to create non-admin user");

    let non_admin_session_id = format!("test-session-{non_admin_user_id}");
    insert_test_session(
        SessionId::new(non_admin_session_id.clone()),
        UserId::new(non_admin_user_id.clone()),
        "csrf-token",
        3600,
    )
    .await
    .expect("Failed to create non-admin session");

    // Create a target user whose admin status will be attempted to be updated
    create_test_user_in_db(&target_user_id, false)
        .await
        .expect("Failed to create target user");

    // Attempt to update the user's admin status as a non-admin
    let result = update_user_admin_status(
        SessionId::new(non_admin_session_id.clone()),
        UserId::new(target_user_id.clone()),
        true,
    )
    .await;

    // Verify the operation fails with Unauthorized error
    assert!(
        result.is_err(),
        "Non-admin should not be allowed to update admin status"
    );
    match result {
        Err(CoordinationError::Unauthorized) => {}
        _ => panic!("Expected Unauthorized error, got {result:?}"),
    }

    // Create a temporary admin session to verify the target user's status wasn't changed
    let admin_user_id = format!("temp-admin-{timestamp}");
    let admin_session_id = create_test_admin_with_session(
        &admin_user_id,
        &format!("{admin_user_id}@example.com"),
        "Temp Admin",
    )
    .await
    .expect("Failed to create temp admin session");

    // Verify the target user's admin status was not changed
    let user_after = get_user(
        SessionId::new(admin_session_id.clone()),
        UserId::new(target_user_id.clone()),
    )
    .await
    .expect("Failed to get target user after failed update")
    .expect("Target user should still exist");
    assert!(
        !user_after.has_admin_privileges(),
        "Target user's admin privileges should not have changed"
    );

    // Clean up
    delete_user_if_exists_and_not_first(&admin_user_id)
        .await
        .ok();
    delete_user_if_exists_and_not_first(&target_user_id)
        .await
        .ok();
    delete_user_if_exists_and_not_first(&non_admin_user_id)
        .await
        .ok();
}

/// Test to ensure that updating the admin status of the first user (sequence_number = 1)
/// is protected and cannot be changed by any user, even an admin.
/// This test verifies an important business rule that protects the initial admin user.
#[serial]
#[tokio::test]
async fn test_update_user_admin_status_protect_first_user() {
    init_test_environment().await;

    // Create unique admin user with timestamp
    let timestamp = chrono::Utc::now().timestamp_millis();
    let admin_user_id = format!("admin-user-protect-{timestamp}");

    // Create an admin user with session
    let admin_session_id = create_test_admin_with_session(
        &admin_user_id,
        &format!("{admin_user_id}@example.com"),
        "Test Admin",
    )
    .await
    .expect("Failed to create admin session");

    let first_user = UserStore::get_user_by(UserSearchField::SequenceNumber(1))
        .await
        .expect("Failed to get first user")
        .expect("Failed to get first user");

    // Attempt to change the admin status of the first user (should fail)
    let result = update_user_admin_status(
        SessionId::new(admin_session_id.clone()),
        UserId::new(first_user.id.clone()),
        false,
    )
    .await;

    // Verify the operation fails with Coordination error
    assert!(
        result.is_err(),
        "Should not be able to change first user's admin status"
    );
    match result {
        Err(CoordinationError::Coordination(msg)) => {
            assert!(msg.contains("Cannot change admin status of the first user"));
        }
        _ => panic!("Expected Coordination error about first user, got {result:?}"),
    }

    // Clean up
    delete_user_if_exists_and_not_first(&admin_user_id)
        .await
        .ok();
}

/// Test to ensure that deleting a passkey credential as an admin requires admin privileges.
/// This test verifies that our session-based security model correctly prevents
/// unauthorized credential deletion by non-admin users.
#[serial]
#[tokio::test]
async fn test_delete_passkey_credential_admin_requires_admin() {
    init_test_environment().await;

    // Create unique user with timestamp
    let timestamp = chrono::Utc::now().timestamp_millis();
    let non_admin_user_id = format!("non-admin-user-passkey-{timestamp}");

    // Create a non-admin user with session
    insert_test_user(
        UserId::new(non_admin_user_id.clone()),
        &format!("{non_admin_user_id}@example.com"),
        "Non Admin",
        false,
    )
    .await
    .expect("Failed to create non-admin user");

    let non_admin_session_id = format!("test-session-{non_admin_user_id}");
    insert_test_session(
        SessionId::new(non_admin_session_id.clone()),
        UserId::new(non_admin_user_id.clone()),
        "csrf-token",
        3600,
    )
    .await
    .expect("Failed to create non-admin session");

    // Attempt to delete a passkey credential (authorization should fail before credential lookup)
    let result = delete_passkey_credential_admin(
        SessionId::new(non_admin_session_id.clone()),
        CredentialId::new("credential1".to_string()),
    )
    .await;

    // Verify that the operation is rejected due to lack of admin privileges
    assert!(result.is_err());
    match result {
        Err(CoordinationError::Unauthorized) => {}
        _ => panic!("Expected Unauthorized error, got: {result:?}"),
    }

    // Clean up
    delete_user_if_exists_and_not_first(&non_admin_user_id)
        .await
        .ok();
}

/// Test to ensure that deleting an OAuth2 account as an admin requires admin privileges.
/// This test verifies that our session-based security model correctly prevents
/// unauthorized OAuth2 account deletion by non-admin users.
#[serial]
#[tokio::test]
async fn test_delete_oauth2_account_admin_requires_admin() {
    init_test_environment().await;

    // Create unique user with timestamp
    let timestamp = chrono::Utc::now().timestamp_millis();
    let non_admin_user_id = format!("non-admin-user-oauth2-{timestamp}");

    // Create a non-admin user with session
    insert_test_user(
        UserId::new(non_admin_user_id.clone()),
        &format!("{non_admin_user_id}@example.com"),
        "Non Admin",
        false,
    )
    .await
    .expect("Failed to create non-admin user");

    let non_admin_session_id = format!("test-session-{non_admin_user_id}");
    insert_test_session(
        SessionId::new(non_admin_session_id.clone()),
        UserId::new(non_admin_user_id.clone()),
        "csrf-token",
        3600,
    )
    .await
    .expect("Failed to create non-admin session");

    // Attempt to delete an OAuth2 account (authorization should fail before account lookup)
    let result = delete_oauth2_account_admin(
        SessionId::new(non_admin_session_id.clone()),
        ProviderUserId::new("provider_user_id".to_string()),
    )
    .await;

    // Verify that the operation is rejected due to lack of admin privileges
    assert!(result.is_err());
    match result {
        Err(CoordinationError::Unauthorized) => {}
        _ => panic!("Expected Unauthorized error, got: {result:?}"),
    }

    // Clean up
    delete_user_if_exists_and_not_first(&non_admin_user_id)
        .await
        .ok();
}
