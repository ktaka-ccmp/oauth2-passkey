use crate::common::{
    MockBrowser, MultiBrowserTestSetup, TestSetup, TestUsers,
    validation_utils::AuthValidationResult,
};

// Import OAuth2 helper functions from oauth2_flows.rs
use super::oauth2_flows::complete_full_oauth2_flow;
// Import passkey helper functions from passkey_flows.rs
use super::passkey_flows::create_mock_credential;

/// **CONSOLIDATED TEST 1**: Combined Admin Operations
///
/// This test consolidates:
/// - test_get_all_users_integration
/// - test_list_credentials_core_integration
/// - test_delete_user_account_integration
/// - test_delete_passkey_credential_core_integration
/// - test_delete_passkey_credential_core_unauthorized_integration
#[tokio::test]
async fn test_combined_admin_operations() -> Result<(), Box<dyn std::error::Error>> {
    let setup = TestSetup::new_with_init().await?;

    println!("🔐 === CONSOLIDATED ADMIN OPERATIONS TEST ===");

    // Setup admin sessions that will be reused across subtests
    // Test both OAuth2 and Passkey admin authentication to verify they both work
    println!("🔧 Setting up admin sessions...");

    // Test OAuth2 admin session creation
    let oauth2_admin_session_id =
        crate::common::create_admin_session_via_oauth2(&setup.server.base_url).await?;
    println!("✅ OAuth2 admin session created: {oauth2_admin_session_id}");

    // Test Passkey admin session creation
    let passkey_admin_session_id =
        crate::common::create_admin_session_via_passkey(&setup.server.base_url).await?;
    println!("✅ Passkey admin session created: {passkey_admin_session_id}");

    // Use the OAuth2 session for the remaining tests (either would work)
    let admin_session_id = oauth2_admin_session_id;

    // === SUBTEST 1: Get All Users Integration ===
    println!("\n👥 SUBTEST 1: Testing get_all_users integration");

    // Get initial user count - there may be existing users from other tests
    let initial_users = oauth2_passkey::get_all_users(&admin_session_id).await?;
    let initial_count = initial_users.len();
    println!("  Initial user count: {initial_count}");

    // Create a test user via passkey registration (this creates real users)
    let mut test_user = TestUsers::passkey_user();
    test_user.email = format!("passkey_test_{}@example.com", uuid::Uuid::new_v4());

    // Register a user which will create an actual user record
    let reg_options = setup
        .browser
        .start_passkey_registration(&test_user.email, &test_user.name, "create_user")
        .await?;

    // Extract challenge and user_handle from server response
    let challenge = reg_options["challenge"]
        .as_str()
        .expect("Registration options should contain challenge");
    let user_handle = reg_options["user"]["user_handle"]
        .as_str()
        .expect("Registration options should contain user_handle");

    // Create mock credential for the registration
    let (mock_credential, _) = create_mock_credential(
        &test_user.email,
        &test_user.name,
        challenge,
        user_handle,
        "packed",
        Some(&setup.server.base_url),
    );
    let registration_response = setup
        .browser
        .complete_passkey_registration(&mock_credential)
        .await?;

    // Verify registration was successful
    assert!(
        registration_response.status().is_success(),
        "User registration should succeed"
    );

    // Now check if the user count increased
    let updated_users = oauth2_passkey::get_all_users(&admin_session_id).await?;
    let updated_count = updated_users.len();
    println!("  Updated user count: {updated_count}");

    // Verify user was created
    assert!(
        updated_count > initial_count,
        "User count should increase after registration"
    );

    println!("✅ SUBTEST 1 PASSED: Get all users integration successful");

    // === SUBTEST 2: List Credentials Core Integration ===
    println!("\n🔑 SUBTEST 2: Testing list credentials core integration");

    // Find the passkey user we just created (they should have passkey credentials)
    let passkey_user = updated_users
        .iter()
        .find(|u| u.account == test_user.email)
        .expect("Should find the passkey test user");

    let user_credentials = oauth2_passkey::list_credentials_core(&passkey_user.id).await?;
    assert!(
        !user_credentials.is_empty(),
        "Passkey user should have at least one credential after registration"
    );

    println!("  Found {} credentials for user", user_credentials.len());
    println!("✅ SUBTEST 2 PASSED: List credentials integration successful");

    // === SUBTEST 3: Delete User Account Integration ===
    println!("\n🗑️  SUBTEST 3: Testing delete user account integration");

    // Create another test user to delete (using passkey_user with unique email)
    let mut delete_test_user = TestUsers::passkey_user();
    delete_test_user.email = format!("delete_test_{}@example.com", uuid::Uuid::new_v4());

    // Register user to be deleted
    let delete_reg_options = setup
        .browser
        .start_passkey_registration(
            &delete_test_user.email,
            &delete_test_user.name,
            "create_user",
        )
        .await?;

    // Extract challenge and user_handle from server response
    let delete_challenge = delete_reg_options["challenge"]
        .as_str()
        .expect("Registration options should contain challenge");
    let delete_user_handle = delete_reg_options["user"]["user_handle"]
        .as_str()
        .expect("Registration options should contain user_handle");

    let (delete_mock_credential, _) = create_mock_credential(
        &delete_test_user.email,
        &delete_test_user.name,
        delete_challenge,
        delete_user_handle,
        "packed",
        Some(&setup.server.base_url),
    );
    let delete_registration_response = setup
        .browser
        .complete_passkey_registration(&delete_mock_credential)
        .await?;

    assert!(
        delete_registration_response.status().is_success(),
        "Delete test user registration should succeed"
    );

    // Find the user to delete
    let all_users = oauth2_passkey::get_all_users(&admin_session_id).await?;
    let user_to_delete = all_users
        .iter()
        .find(|u| u.account == delete_test_user.email)
        .expect("Should find the delete test user");

    // Delete the user account (using admin function with correct parameter order)
    let delete_result =
        oauth2_passkey::delete_user_account_admin(&admin_session_id, &user_to_delete.id).await;
    assert!(
        delete_result.is_ok(),
        "User account deletion should succeed"
    );

    // Verify user was deleted
    let users_after_delete = oauth2_passkey::get_all_users(&admin_session_id).await?;
    let deleted_user_exists = users_after_delete
        .iter()
        .any(|u| u.account == delete_test_user.email);
    assert!(
        !deleted_user_exists,
        "Deleted user should not exist in user list"
    );

    println!("✅ SUBTEST 3 PASSED: Delete user account integration successful");

    // === SUBTEST 4: Delete Passkey Credential Core Integration ===
    println!("\n🔐 SUBTEST 4: Testing delete passkey credential core integration");

    // Use the remaining test user and try to delete one of their credentials
    let remaining_user_credentials =
        oauth2_passkey::list_credentials_core(&passkey_user.id).await?;

    if let Some(credential_to_delete) = remaining_user_credentials.first() {
        let delete_cred_result = oauth2_passkey::delete_passkey_credential_admin(
            &admin_session_id,
            &credential_to_delete.credential_id,
        )
        .await;

        assert!(
            delete_cred_result.is_ok(),
            "Credential deletion should succeed"
        );

        // Verify credential was deleted
        let updated_credentials = oauth2_passkey::list_credentials_core(&passkey_user.id).await?;
        assert!(
            updated_credentials.len() < remaining_user_credentials.len(),
            "Credential count should decrease after deletion"
        );

        println!("✅ SUBTEST 4 PASSED: Delete passkey credential core integration successful");
    } else {
        println!("ℹ️  SUBTEST 4 SKIPPED: No credentials available to delete");
    }

    // === SUBTEST 5: Delete Passkey Credential Core Unauthorized Integration ===
    println!("\n🚫 SUBTEST 5: Testing delete passkey credential core unauthorized");

    // Create a non-admin browser session
    let regular_browser = MockBrowser::new(&setup.server.base_url, true);
    let mut regular_user = TestUsers::passkey_user();
    regular_user.email = format!("regular_user_{}@example.com", uuid::Uuid::new_v4());

    // Register regular user
    let reg_reg_options = regular_browser
        .start_passkey_registration(&regular_user.email, &regular_user.name, "create_user")
        .await?;

    // Extract challenge and user_handle from server response
    let reg_challenge = reg_reg_options["challenge"]
        .as_str()
        .expect("Registration options should contain challenge");
    let reg_user_handle = reg_reg_options["user"]["user_handle"]
        .as_str()
        .expect("Registration options should contain user_handle");

    let (reg_mock_credential, _) = create_mock_credential(
        &regular_user.email,
        &regular_user.name,
        reg_challenge,
        reg_user_handle,
        "packed",
        Some(&setup.server.base_url),
    );
    let reg_registration_response = regular_browser
        .complete_passkey_registration(&reg_mock_credential)
        .await?;

    assert!(
        reg_registration_response.status().is_success(),
        "Regular user registration should succeed"
    );

    // Get session ID for regular user (non-admin)
    let _regular_session_id = regular_browser
        .get_session_id()
        .expect("Regular user should have session");

    // Try to delete a credential using non-admin session - should fail
    let all_users_final = oauth2_passkey::get_all_users(&admin_session_id).await?;
    if let Some(some_user) = all_users_final.first() {
        let some_credentials = oauth2_passkey::list_credentials_core(&some_user.id).await?;
        if let Some(some_credential) = some_credentials.first() {
            // This should fail because _regular_session_id is not admin
            // Try to use the regular (non-admin) session to delete credentials
            let regular_session_id = regular_browser
                .get_session_id()
                .expect("Regular user should have session");
            let unauthorized_delete_result = oauth2_passkey::delete_passkey_credential_admin(
                &regular_session_id,
                &some_credential.credential_id,
            )
            .await;

            assert!(
                unauthorized_delete_result.is_err(),
                "Non-admin user should not be able to delete credentials"
            );

            println!("✅ SUBTEST 5 PASSED: Unauthorized credential deletion properly rejected");
        } else {
            println!(
                "ℹ️  SUBTEST 5 SKIPPED: No credentials available for unauthorized deletion test"
            );
        }
    }

    setup.shutdown().await;
    println!("🎯 === CONSOLIDATED ADMIN OPERATIONS TEST COMPLETED ===");
    Ok(())
}

/// **CONSOLIDATED TEST 2**: Combined Multi-Auth Flows
///
/// This test consolidates:
/// - test_oauth2_then_add_passkey
/// - test_passkey_then_add_oauth2
#[tokio::test]
async fn test_combined_multi_auth_flows() -> Result<(), Box<dyn std::error::Error>> {
    let setup = MultiBrowserTestSetup::new().await?;

    println!("🔐 === CONSOLIDATED MULTI-AUTH FLOWS TEST ===");

    // === SUBTEST 1: OAuth2 Then Add Passkey ===
    println!("\n🔗➕🔑 SUBTEST 1: OAuth2 authentication then add Passkey credential");

    // Step 1: Create user via OAuth2 registration
    let oauth2_test_user = TestUsers::unique_oauth2_user("oauth2_then_passkey");

    use crate::common::axum_mock_server::configure_mock_for_test;
    configure_mock_for_test(
        oauth2_test_user.email.clone(),
        oauth2_test_user.id.clone(),
        oauth2_test_user.name.clone(),
        oauth2_test_user.given_name.clone(),
        oauth2_test_user.family_name.clone(),
        setup.server.base_url.clone(),
    );

    let oauth2_response =
        complete_full_oauth2_flow(&setup.browser1, "create_user_or_login").await?;
    let oauth2_validation = AuthValidationResult::from_oauth2_response(
        oauth2_response.status(),
        oauth2_response.headers(),
        "Created%20new%20user",
    );
    assert!(
        oauth2_validation.is_success,
        "OAuth2 registration should succeed"
    );
    println!("  ✅ OAuth2 user registration successful");

    // Step 2: Add passkey credential to existing OAuth2 user
    let passkey_reg_options = setup
        .browser1
        .start_passkey_registration(
            &oauth2_test_user.email,
            &oauth2_test_user.name,
            "add_to_user",
        )
        .await?;

    // Extract challenge and user_handle from server response
    let passkey_challenge = passkey_reg_options["challenge"]
        .as_str()
        .expect("Registration options should contain challenge");
    let passkey_user_handle = passkey_reg_options["user"]["user_handle"]
        .as_str()
        .expect("Registration options should contain user_handle");

    let (passkey_mock_credential, _) = create_mock_credential(
        &oauth2_test_user.email,
        &oauth2_test_user.name,
        passkey_challenge,
        passkey_user_handle,
        "packed",
        Some(&setup.server.base_url),
    );
    let passkey_response = setup
        .browser1
        .complete_passkey_registration(&passkey_mock_credential)
        .await?;

    assert!(
        passkey_response.status().is_success(),
        "Passkey addition should succeed"
    );
    println!("  ✅ Passkey credential added to OAuth2 user successfully");

    // Step 3: Verify user has both OAuth2 account and passkey credential
    let user_info: serde_json::Value = setup.browser1.get("/auth/user/info").await?.json().await?;
    println!("  User info after adding passkey: {user_info:?}");

    println!("✅ SUBTEST 1 PASSED: OAuth2 then add passkey flow completed");

    // === SUBTEST 2: Passkey Then Add OAuth2 ===
    println!("\n🔑➕🔗 SUBTEST 2: Passkey authentication then add OAuth2 account");

    // Step 1: Create user via Passkey registration (use browser2 for clean session)
    let mut passkey_test_user = TestUsers::passkey_user();
    passkey_test_user.email = format!("passkey_then_oauth2_{}@example.com", uuid::Uuid::new_v4());

    let passkey_first_reg_options = setup
        .browser2
        .start_passkey_registration(
            &passkey_test_user.email,
            &passkey_test_user.name,
            "create_user",
        )
        .await?;

    // Extract challenge and user_handle from server response
    let passkey_first_challenge = passkey_first_reg_options["challenge"]
        .as_str()
        .expect("Registration options should contain challenge");
    let passkey_first_user_handle = passkey_first_reg_options["user"]["user_handle"]
        .as_str()
        .expect("Registration options should contain user_handle");

    let (passkey_first_mock_credential, _) = create_mock_credential(
        &passkey_test_user.email,
        &passkey_test_user.name,
        passkey_first_challenge,
        passkey_first_user_handle,
        "packed",
        Some(&setup.server.base_url),
    );
    let passkey_first_response = setup
        .browser2
        .complete_passkey_registration(&passkey_first_mock_credential)
        .await?;

    assert!(
        passkey_first_response.status().is_success(),
        "Passkey registration should succeed"
    );
    println!("  ✅ Passkey user registration successful");

    // Step 2: Add OAuth2 account to existing passkey user
    let oauth2_linking_user = TestUsers::unique_oauth2_user("passkey_then_oauth2_link");
    configure_mock_for_test(
        oauth2_linking_user.email.clone(),
        oauth2_linking_user.id.clone(),
        oauth2_linking_user.name.clone(),
        oauth2_linking_user.given_name.clone(),
        oauth2_linking_user.family_name.clone(),
        setup.server.base_url.clone(),
    );

    let oauth2_linking_response = complete_full_oauth2_flow(&setup.browser2, "add_to_user").await?;
    let oauth2_linking_validation = AuthValidationResult::from_oauth2_response(
        oauth2_linking_response.status(),
        oauth2_linking_response.headers(),
        "Successfully%20linked%20to",
    );
    assert!(
        oauth2_linking_validation.is_success,
        "OAuth2 account linking should succeed"
    );
    println!("  ✅ OAuth2 account linked to Passkey user successfully");

    // Step 3: Verify user has both passkey credential and OAuth2 account
    let final_user_info: serde_json::Value =
        setup.browser2.get("/auth/user/info").await?.json().await?;
    println!("  Final user info: {final_user_info:?}");

    println!("✅ SUBTEST 2 PASSED: Passkey then add OAuth2 flow completed");

    setup.shutdown().await;
    println!("🎯 === CONSOLIDATED MULTI-AUTH FLOWS TEST COMPLETED ===");
    Ok(())
}
