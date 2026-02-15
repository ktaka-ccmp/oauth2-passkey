use super::*;
use crate::session::{insert_test_session, insert_test_user};
use crate::test_utils::init_test_environment;
use chrono::Utc;
use serial_test::serial;

// Helper function to create a test admin user with session for testing
async fn create_test_admin_with_session(
    user_id: &str,
    account: &str,
    label: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    // Create admin user in database
    insert_test_user(
        UserId::new(user_id.to_string()).expect("Valid user ID"),
        account,
        label,
        true,
    )
    .await?;

    // Create session for the admin user
    let session_id = format!("test-session-{user_id}");
    let csrf_token = "test-csrf-token";
    insert_test_session(
        SessionId::new(session_id.clone()).expect("Valid session ID"),
        UserId::new(user_id.to_string()).expect("Valid user ID"),
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
    if let Ok(Some(user)) =
        UserStore::get_user(UserId::new(user_id.to_string()).expect("Valid user ID")).await
    {
        // Only delete if sequence_number is not 1
        if user.sequence_number != Some(1) {
            UserStore::delete_user(UserId::new(user_id.to_string()).expect("Valid user ID"))
                .await?;
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
    let users =
        get_all_users(SessionId::new(admin_session_id.clone()).expect("Valid admin session ID"))
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
        SessionId::new(admin_session_id.clone()).expect("Valid admin session ID"),
        UserId::new(target_user_id.clone()).expect("Valid target user ID"),
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
        SessionId::new(admin_session_id.clone()).expect("Valid admin session ID"),
        UserId::new(non_existent_user_id.clone()).expect("Valid non-existent user ID"),
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
        SessionId::new(admin_session_id.clone()).expect("Valid admin session ID"),
        UserId::new(user_to_delete_id.clone()).expect("Valid user to delete ID"),
    )
    .await
    .expect("Failed to get user");
    assert!(user_before.is_some(), "User should exist before deletion");

    // Delete the user using admin session
    let result = delete_user_account_admin(
        SessionId::new(admin_session_id.clone()).expect("Valid admin session ID"),
        UserId::new(user_to_delete_id.clone()).expect("Valid user to delete ID"),
    )
    .await;
    assert!(result.is_ok(), "Expected successful user deletion");

    // Verify the user no longer exists
    let user_after = get_user(
        SessionId::new(admin_session_id.clone()).expect("Valid admin session ID"),
        UserId::new(user_to_delete_id.clone()).expect("Valid user to delete ID"),
    )
    .await
    .expect("Failed to get user after deletion");
    assert!(user_after.is_none(), "User should not exist after deletion");

    // Try to delete a non-existent user
    let non_existent_user_id = format!("non-existent-user-{timestamp}");
    let result = delete_user_account_admin(
        SessionId::new(admin_session_id.clone()).expect("Valid admin session ID"),
        UserId::new(non_existent_user_id.clone()).expect("Valid non-existent user ID"),
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
        SessionId::new(admin_session_id.clone()).expect("Valid admin session ID"),
        UserId::new(target_user_id.clone()).expect("Valid target user ID"),
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
        SessionId::new(admin_session_id.clone()).expect("Valid admin session ID"),
        UserId::new(target_user_id.clone()).expect("Valid target user ID"),
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
        SessionId::new(admin_session_id.clone()).expect("Valid admin session ID"),
        UserId::new(target_user_id.clone()).expect("Valid target user ID"),
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
        SessionId::new(admin_session_id.clone()).expect("Valid admin session ID"),
        UserId::new(target_user_id.clone()).expect("Valid target user ID"),
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
        UserId::new(non_admin_user_id.clone()).expect("Valid non-admin user ID"),
        &format!("{non_admin_user_id}@example.com"),
        "Non Admin",
        false,
    )
    .await
    .expect("Failed to create non-admin user");

    let non_admin_session_id = format!("test-session-{non_admin_user_id}");
    insert_test_session(
        SessionId::new(non_admin_session_id.clone()).expect("Valid non-admin session ID"),
        UserId::new(non_admin_user_id.clone()).expect("Valid non-admin user ID"),
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
        SessionId::new(non_admin_session_id.clone()).expect("Valid non-admin session ID"),
        UserId::new(target_user_id.clone()).expect("Valid target user ID"),
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
        SessionId::new(admin_session_id.clone()).expect("Valid admin session ID"),
        UserId::new(target_user_id.clone()).expect("Valid target user ID"),
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

/// Test to ensure that demoting the first user (sequence_number=1) is unconditionally prevented.
/// The first user has special protection regardless of how many other admins exist.
#[serial]
#[tokio::test]
async fn test_demote_first_user_prevented() {
    init_test_environment().await;

    // Create a session for the first-user (who is the only admin in the test environment)
    let first_user_session_id = "test-session-first-user-demote";
    insert_test_session(
        SessionId::new(first_user_session_id.to_string()).expect("Valid session ID"),
        UserId::new("first-user".to_string()).expect("Valid user ID"),
        "test-csrf-token",
        3600,
    )
    .await
    .expect("Failed to create session for first user");

    // Attempt to demote the first-user -> should fail unconditionally
    let result = update_user_admin_status(
        SessionId::new(first_user_session_id.to_string()).expect("Valid session ID"),
        UserId::new("first-user".to_string()).expect("Valid user ID"),
        false,
    )
    .await;

    // Verify the operation fails with Conflict error
    assert!(
        result.is_err(),
        "Should not be able to demote the first user"
    );
    match result {
        Err(CoordinationError::Conflict(msg)) => {
            assert!(
                msg.contains("Cannot demote the first user"),
                "Error message should mention first user demotion, got: {msg}"
            );
        }
        _ => panic!("Expected Conflict error about first user, got {result:?}"),
    }
}

/// Test to ensure that demoting the first user is prevented even when other admins exist.
/// This verifies that the first-user protection is unconditional (not just a last-admin guard).
#[serial]
#[tokio::test]
async fn test_demote_first_user_prevented_even_with_other_admins() {
    init_test_environment().await;

    let timestamp = chrono::Utc::now().timestamp_millis();
    let other_admin_id = format!("other-admin-demote-first-{timestamp}");

    // Create another admin so first-user is NOT the last admin
    create_test_user_in_db(&other_admin_id, true)
        .await
        .expect("Failed to create other admin");

    // Create a session for the other admin (who will attempt to demote first-user)
    let other_admin_session_id = format!("session-other-admin-{timestamp}");
    insert_test_session(
        SessionId::new(other_admin_session_id.clone()).expect("Valid session ID"),
        UserId::new(other_admin_id.clone()).expect("Valid user ID"),
        "test-csrf-token",
        3600,
    )
    .await
    .expect("Failed to create session for other admin");

    // Attempt to demote the first-user -> should fail even though other admins exist
    let result = update_user_admin_status(
        SessionId::new(other_admin_session_id).expect("Valid session ID"),
        UserId::new("first-user".to_string()).expect("Valid user ID"),
        false,
    )
    .await;

    assert!(
        result.is_err(),
        "Should not be able to demote the first user even when other admins exist"
    );
    match result {
        Err(CoordinationError::Conflict(msg)) => {
            assert!(
                msg.contains("Cannot demote the first user"),
                "Error message should mention first user demotion, got: {msg}"
            );
        }
        _ => panic!("Expected Conflict error about first user, got {result:?}"),
    }

    // Clean up
    delete_user_if_exists_and_not_first(&other_admin_id)
        .await
        .ok();
}

/// Test to ensure that demoting an admin is allowed when other admins exist.
#[serial]
#[tokio::test]
async fn test_demote_admin_allowed_when_others_exist() {
    init_test_environment().await;

    let timestamp = chrono::Utc::now().timestamp_millis();
    let admin1_id = format!("admin1-demote-{timestamp}");
    let admin2_id = format!("admin2-demote-{timestamp}");

    // Create first admin with session
    let admin_session_id =
        create_test_admin_with_session(&admin1_id, &format!("{admin1_id}@example.com"), "Admin 1")
            .await
            .expect("Failed to create admin 1 session");

    // Create second admin
    create_test_user_in_db(&admin2_id, true)
        .await
        .expect("Failed to create admin 2");

    // Demote admin2 (should succeed since admin1 still exists)
    let result = update_user_admin_status(
        SessionId::new(admin_session_id.clone()).expect("Valid admin session ID"),
        UserId::new(admin2_id.clone()).expect("Valid admin2 user ID"),
        false,
    )
    .await;

    assert!(
        result.is_ok(),
        "Should be able to demote admin when other admins exist, got: {result:?}"
    );
    let updated_user = result.unwrap();
    assert!(
        !updated_user.is_admin,
        "Demoted user should no longer be admin"
    );

    // Clean up
    delete_user_if_exists_and_not_first(&admin1_id).await.ok();
    delete_user_if_exists_and_not_first(&admin2_id).await.ok();
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
        UserId::new(non_admin_user_id.clone()).expect("Valid non-admin user ID"),
        &format!("{non_admin_user_id}@example.com"),
        "Non Admin",
        false,
    )
    .await
    .expect("Failed to create non-admin user");

    let non_admin_session_id = format!("test-session-{non_admin_user_id}");
    insert_test_session(
        SessionId::new(non_admin_session_id.clone()).expect("Valid non-admin session ID"),
        UserId::new(non_admin_user_id.clone()).expect("Valid non-admin user ID"),
        "csrf-token",
        3600,
    )
    .await
    .expect("Failed to create non-admin session");

    // Attempt to delete a passkey credential (authorization should fail before credential lookup)
    let result = delete_passkey_credential_admin(
        SessionId::new(non_admin_session_id.clone()).expect("Valid non-admin session ID"),
        CredentialId::new("credential1".to_string()).expect("Valid test credential ID"),
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
        UserId::new(non_admin_user_id.clone()).expect("Valid non-admin user ID"),
        &format!("{non_admin_user_id}@example.com"),
        "Non Admin",
        false,
    )
    .await
    .expect("Failed to create non-admin user");

    let non_admin_session_id = format!("test-session-{non_admin_user_id}");
    insert_test_session(
        SessionId::new(non_admin_session_id.clone()).expect("Valid non-admin session ID"),
        UserId::new(non_admin_user_id.clone()).expect("Valid non-admin user ID"),
        "csrf-token",
        3600,
    )
    .await
    .expect("Failed to create non-admin session");

    // Attempt to delete an OAuth2 account (authorization should fail before account lookup)
    let result = delete_oauth2_account_admin(
        SessionId::new(non_admin_session_id.clone()).expect("Valid non-admin session ID"),
        ProviderUserId::new("provider_user_id".to_string()).expect("Valid test provider user ID"),
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

/// Test to ensure that getting all active sessions requires admin privileges.
/// This test verifies that our session-based security model correctly prevents
/// unauthorized access to session information by non-admin users.
#[serial]
#[tokio::test]
async fn test_get_all_active_sessions_requires_admin() {
    init_test_environment().await;

    // Create unique user with timestamp
    let timestamp = chrono::Utc::now().timestamp_millis();
    let non_admin_user_id = format!("non-admin-all-sessions-{timestamp}");

    // Create a non-admin user with session
    insert_test_user(
        UserId::new(non_admin_user_id.clone()).expect("Valid non-admin user ID"),
        &format!("{non_admin_user_id}@example.com"),
        "Non Admin",
        false,
    )
    .await
    .expect("Failed to create non-admin user");

    let non_admin_session_id = format!("test-session-{non_admin_user_id}");
    insert_test_session(
        SessionId::new(non_admin_session_id.clone()).expect("Valid non-admin session ID"),
        UserId::new(non_admin_user_id.clone()).expect("Valid non-admin user ID"),
        "csrf-token",
        3600,
    )
    .await
    .expect("Failed to create non-admin session");

    // Attempt to get all active sessions as non-admin
    let result = get_all_active_sessions(
        SessionId::new(non_admin_session_id.clone()).expect("Valid non-admin session ID"),
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

/// Test to ensure that force logout requires admin privileges.
/// This test verifies that our session-based security model correctly prevents
/// unauthorized session termination by non-admin users.
#[serial]
#[tokio::test]
async fn test_force_logout_user_requires_admin() {
    init_test_environment().await;

    // Create unique user with timestamp
    let timestamp = chrono::Utc::now().timestamp_millis();
    let non_admin_user_id = format!("non-admin-force-logout-{timestamp}");
    let target_user_id = format!("target-force-logout-{timestamp}");

    // Create a non-admin user with session
    insert_test_user(
        UserId::new(non_admin_user_id.clone()).expect("Valid non-admin user ID"),
        &format!("{non_admin_user_id}@example.com"),
        "Non Admin",
        false,
    )
    .await
    .expect("Failed to create non-admin user");

    let non_admin_session_id = format!("test-session-{non_admin_user_id}");
    insert_test_session(
        SessionId::new(non_admin_session_id.clone()).expect("Valid non-admin session ID"),
        UserId::new(non_admin_user_id.clone()).expect("Valid non-admin user ID"),
        "csrf-token",
        3600,
    )
    .await
    .expect("Failed to create non-admin session");

    // Attempt to force logout as non-admin
    let result = force_logout_user(
        SessionId::new(non_admin_session_id.clone()).expect("Valid non-admin session ID"),
        UserId::new(target_user_id.clone()).expect("Valid target user ID"),
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

/// Test successful retrieval of all active sessions by admin.
/// This test verifies that admins can retrieve session counts for all users.
#[serial]
#[tokio::test]
async fn test_get_all_active_sessions_success() {
    init_test_environment().await;

    // Create unique users with timestamp
    let timestamp = chrono::Utc::now().timestamp_millis();
    let admin_user_id = format!("admin-all-sessions-{timestamp}");

    // Create an admin user with session
    let admin_session_id = create_test_admin_with_session(
        &admin_user_id,
        &format!("{admin_user_id}@example.com"),
        "Test Admin",
    )
    .await
    .expect("Failed to create admin session");

    // Get all active sessions using admin session
    let sessions = get_all_active_sessions(
        SessionId::new(admin_session_id.clone()).expect("Valid admin session ID"),
    )
    .await
    .expect("Failed to get all active sessions");

    // Verify we got a result (a HashMap of user_id -> session_count)
    // At minimum, the admin user should have 1 session
    assert!(
        sessions.contains_key(&admin_user_id),
        "Admin user should have at least one session"
    );
    assert!(
        *sessions.get(&admin_user_id).unwrap_or(&0) >= 1,
        "Admin user should have at least 1 active session"
    );

    // Clean up
    delete_user_if_exists_and_not_first(&admin_user_id)
        .await
        .ok();
}

/// Test successful force logout of a user by admin.
/// This test verifies that admins can terminate all sessions for a target user.
#[serial]
#[tokio::test]
async fn test_force_logout_user_success() {
    init_test_environment().await;

    // Create unique users with timestamp
    let timestamp = chrono::Utc::now().timestamp_millis();
    let admin_user_id = format!("admin-force-logout-success-{timestamp}");
    let target_user_id = format!("target-logout-success-{timestamp}");

    // Create an admin user with session
    let admin_session_id = create_test_admin_with_session(
        &admin_user_id,
        &format!("{admin_user_id}@example.com"),
        "Test Admin",
    )
    .await
    .expect("Failed to create admin session");

    // Create a target user with session
    insert_test_user(
        UserId::new(target_user_id.clone()).expect("Valid target user ID"),
        &format!("{target_user_id}@example.com"),
        "Target User",
        false,
    )
    .await
    .expect("Failed to create target user");

    let target_session_id = format!("test-session-{target_user_id}");
    insert_test_session(
        SessionId::new(target_session_id.clone()).expect("Valid target session ID"),
        UserId::new(target_user_id.clone()).expect("Valid target user ID"),
        "csrf-token-target",
        3600,
    )
    .await
    .expect("Failed to create target session");

    // Force logout the target user
    let terminated_count = force_logout_user(
        SessionId::new(admin_session_id.clone()).expect("Valid admin session ID"),
        UserId::new(target_user_id.clone()).expect("Valid target user ID"),
    )
    .await
    .expect("Failed to force logout user");

    // Verify at least 1 session was terminated
    assert_eq!(
        terminated_count, 1,
        "Exactly 1 session should have been terminated"
    );

    // Verify calling force_logout again returns 0 (no more sessions)
    let terminated_count_again = force_logout_user(
        SessionId::new(admin_session_id.clone()).expect("Valid admin session ID"),
        UserId::new(target_user_id.clone()).expect("Valid target user ID"),
    )
    .await
    .expect("Failed to force logout user again");

    assert_eq!(
        terminated_count_again, 0,
        "No sessions should remain after force logout"
    );

    // Clean up
    delete_user_if_exists_and_not_first(&admin_user_id)
        .await
        .ok();
    delete_user_if_exists_and_not_first(&target_user_id)
        .await
        .ok();
}

/// Test to ensure that deleting the last admin user is prevented.
/// This protects the system from becoming permanently locked out of admin functionality.
/// Uses the first-user (sequence_number=1) as the sole admin to test the guard.
#[serial]
#[tokio::test]
async fn test_delete_last_admin_prevented() {
    init_test_environment().await;

    // Create a session for the first-user (who is the only admin in the test environment)
    let first_user_session_id = "test-session-first-user-delete";
    insert_test_session(
        SessionId::new(first_user_session_id.to_string()).expect("Valid session ID"),
        UserId::new("first-user".to_string()).expect("Valid user ID"),
        "test-csrf-token",
        3600,
    )
    .await
    .expect("Failed to create session for first user");

    // Attempt to delete the first-user (the only admin) -> should fail
    let result = delete_user_account_admin(
        SessionId::new(first_user_session_id.to_string()).expect("Valid session ID"),
        UserId::new("first-user".to_string()).expect("Valid user ID"),
    )
    .await;

    // Verify the operation fails with Conflict error
    assert!(
        result.is_err(),
        "Should not be able to delete the last admin"
    );
    match result {
        Err(CoordinationError::Conflict(msg)) => {
            assert!(
                msg.contains("Cannot delete the last admin user"),
                "Error message should mention last admin deletion, got: {msg}"
            );
        }
        _ => panic!("Expected Conflict error about last admin, got {result:?}"),
    }
}

/// Test to ensure that deleting an admin is allowed when other admins exist.
#[serial]
#[tokio::test]
async fn test_delete_admin_allowed_when_others_exist() {
    init_test_environment().await;

    let timestamp = chrono::Utc::now().timestamp_millis();
    let admin1_id = format!("admin1-delete-ok-{timestamp}");
    let admin2_id = format!("admin2-delete-ok-{timestamp}");

    // Create first admin with session
    let admin_session_id =
        create_test_admin_with_session(&admin1_id, &format!("{admin1_id}@example.com"), "Admin 1")
            .await
            .expect("Failed to create admin 1 session");

    // Create second admin
    create_test_user_in_db(&admin2_id, true)
        .await
        .expect("Failed to create admin 2");

    // Delete admin2 (should succeed since admin1 still exists)
    let result = delete_user_account_admin(
        SessionId::new(admin_session_id.clone()).expect("Valid admin session ID"),
        UserId::new(admin2_id.clone()).expect("Valid admin2 user ID"),
    )
    .await;

    assert!(
        result.is_ok(),
        "Should be able to delete admin when other admins exist, got: {result:?}"
    );

    // Verify admin2 no longer exists
    let deleted_user = UserStore::get_user(UserId::new(admin2_id.clone()).expect("Valid user ID"))
        .await
        .expect("Failed to query user");
    assert!(
        deleted_user.is_none(),
        "Deleted admin user should no longer exist"
    );

    // Clean up
    delete_user_if_exists_and_not_first(&admin1_id).await.ok();
}

/// Test that after the first user is deleted, the remaining last admin is still protected.
///
/// This verifies that the `count_admin_users` SQL query (`WHERE is_admin = true OR sequence_number = 1`)
/// works correctly when sequence_number=1 no longer exists in the database: the `OR sequence_number = 1`
/// clause becomes a no-op and only `is_admin = true` is effective, correctly counting the remaining admin.
///
/// Note: The actual deletion may encounter FK constraint errors when parallel non-serial
/// tests re-create child records via `init_test_environment()` between the child record
/// deletion and user deletion. In that case, `delete_user_atomically()` is used as a
/// fallback to complete the deletion while holding the GENERIC_DATA_STORE lock.
#[serial]
#[tokio::test]
async fn test_last_admin_protected_after_first_user_deleted() {
    use crate::test_utils::{delete_user_atomically, restore_first_user_after_deletion};

    init_test_environment().await;

    let timestamp = chrono::Utc::now().timestamp_millis();
    let admin2_id = format!("admin2-post-first-delete-{timestamp}");

    // Create another admin with session
    let admin2_session_id =
        create_test_admin_with_session(&admin2_id, &format!("{admin2_id}@example.com"), "Admin 2")
            .await
            .expect("Failed to create admin 2 session");

    // Delete the first-user via admin path (should succeed since admin2 also exists)
    let delete_result = delete_user_account_admin(
        SessionId::new(admin2_session_id.clone()).expect("Valid session ID"),
        UserId::new("first-user".to_string()).expect("Valid user ID"),
    )
    .await;

    // The guard should allow this deletion (not Conflict).
    // In the full test suite, parallel tests may re-create child records between
    // the child delete and user delete, causing an FK constraint error.
    match &delete_result {
        Ok(_) => {
            // Guard passed and deletion succeeded
        }
        Err(CoordinationError::Conflict(_)) => {
            panic!(
                "Should be able to delete first-user when other admin exists (guard blocked), got: {delete_result:?}"
            );
        }
        Err(_) => {
            // FK constraint error or other DB error -- guard passed but parallel test interference
            // Complete the deletion atomically
            delete_user_atomically("first-user").await;
        }
    }

    // Verify first-user no longer exists
    let first_user =
        UserStore::get_user(UserId::new("first-user".to_string()).expect("Valid user ID"))
            .await
            .expect("Failed to query user");
    assert!(first_user.is_none(), "First user should be deleted");

    // Now admin2 is the sole admin. Try to delete admin2 -> should fail (last admin)
    let delete_last_result = delete_user_account_admin(
        SessionId::new(admin2_session_id.clone()).expect("Valid session ID"),
        UserId::new(admin2_id.clone()).expect("Valid user ID"),
    )
    .await;

    assert!(
        delete_last_result.is_err(),
        "Should not be able to delete the last admin after first-user is gone"
    );
    match delete_last_result {
        Err(CoordinationError::Conflict(msg)) => {
            assert!(
                msg.contains("Cannot delete the last admin user"),
                "Expected last admin deletion error, got: {msg}"
            );
        }
        _ => panic!("Expected Conflict error about last admin, got {delete_last_result:?}"),
    }

    // Try to demote admin2 -> should also fail (last admin)
    let demote_result = update_user_admin_status(
        SessionId::new(admin2_session_id.clone()).expect("Valid session ID"),
        UserId::new(admin2_id.clone()).expect("Valid user ID"),
        false,
    )
    .await;

    assert!(
        demote_result.is_err(),
        "Should not be able to demote the last admin after first-user is gone"
    );
    match demote_result {
        Err(CoordinationError::Conflict(msg)) => {
            assert!(
                msg.contains("Cannot demote the last admin user"),
                "Expected last admin demotion error, got: {msg}"
            );
        }
        _ => panic!("Expected Conflict error about last admin demotion, got {demote_result:?}"),
    }

    // Cleanup: restore first-user with sequence_number=1 and associated credentials
    restore_first_user_after_deletion().await;

    // Cleanup: delete admin2
    delete_user_if_exists_and_not_first(&admin2_id).await.ok();
}
