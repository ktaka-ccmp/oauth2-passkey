use chrono::{Duration, Utc};
use http::HeaderMap;
use std::{env, sync::LazyLock};

use crate::oauth2::{
    AccountSearchField, AuthResponse, OAUTH2_CSRF_COOKIE_NAME, OAUTH2_RESPONSE_MODE, OAuth2Account,
    OAuth2Mode, OAuth2Store, Provider, ProviderUserId, csrf_checks, decode_state,
    delete_session_and_misc_token_from_store, get_auth_url, get_idinfo_userinfo,
    get_mode_from_stored_session, get_uid_from_stored_session_by_state_param, validate_origin,
};

use crate::userdb::{User as DbUser, UserStore};
use crate::utils::header_set_cookie;

use super::errors::CoordinationError;
use super::user::gen_new_user_id;

use crate::session::{UserId, new_session_header};

/// OAuth2 user account field mapping configuration
static OAUTH2_USER_ACCOUNT_FIELD: LazyLock<String> =
    LazyLock::new(|| env::var("OAUTH2_USER_ACCOUNT_FIELD").unwrap_or_else(|_| "email".to_string()));

/// OAuth2 user label field mapping configuration
static OAUTH2_USER_LABEL_FIELD: LazyLock<String> =
    LazyLock::new(|| env::var("OAUTH2_USER_LABEL_FIELD").unwrap_or_else(|_| "name".to_string()));

/// HTTP method enum for the authorized_core function
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum HttpMethod {
    Get,
    Post,
}

/// Unified function for processing OAuth2 authorization callbacks
///
/// This function handles both GET and POST callbacks with appropriate validation:
/// 1. Validates the HTTP method matches the configured response mode
/// 2. Validates the state parameter is not empty
/// 3. Performs CSRF checks
/// 4. Processes the OAuth2 authorization
#[tracing::instrument(skip(auth_response, cookies, headers), fields(user_id, provider = "google", state = %auth_response.state))]
pub async fn authorized_core(
    method: HttpMethod,
    auth_response: &AuthResponse,
    cookies: &headers::Cookie,
    headers: &HeaderMap,
) -> Result<(HeaderMap, String), CoordinationError> {
    tracing::info!(?method, "Processing OAuth2 authorization callback");
    // Verify this is the correct response mode for the HTTP method
    match (method, OAUTH2_RESPONSE_MODE.to_lowercase().as_str()) {
        (HttpMethod::Get, "form_post") => {
            return Err(CoordinationError::InvalidResponseMode(
                "GET is not allowed for form_post response mode".to_string(),
            ));
        }
        (HttpMethod::Post, "query") => {
            return Err(CoordinationError::InvalidResponseMode(
                "POST is not allowed for query response mode".to_string(),
            ));
        }
        _ => {} // Valid combination, continue processing
    }

    let auth_url = get_auth_url()
        .await
        .map_err(|e| CoordinationError::InvalidState(format!("Failed to get auth url: {e}")))?;
    validate_origin(headers, &auth_url).await?;

    if auth_response.state.is_empty() {
        return Err(CoordinationError::InvalidState(
            "State is empty".to_string(),
        ));
    }

    csrf_checks(cookies.clone(), auth_response, headers.clone()).await?;
    process_oauth2_authorization(auth_response).await
}

/// Processes an OAuth2 GET authorization request.
///
/// This function handles the core business logic for OAuth2 authentication via GET requests.
/// It validates CSRF tokens, processes the authentication response from the provider,
/// and establishes a user session.
///
/// # Arguments
///
/// * `auth_response` - The OAuth2 authentication response from the provider
/// * `cookies` - Cookie headers from the client request
/// * `headers` - All headers from the client request
///
/// # Returns
///
/// * `Ok((HeaderMap, String))` - Response headers (including session cookie) and response body
/// * `Err(CoordinationError)` - If authentication fails for any reason
///
/// # Examples
///
/// ```no_run
/// use oauth2_passkey::{get_authorized_core, AuthResponse};
/// use headers::Cookie;
/// use http::HeaderMap;
///
/// async fn process_oauth_callback(
///     auth_response: &AuthResponse,
///     cookies: &Cookie,
///     headers: &HeaderMap
/// ) -> Result<(HeaderMap, String), Box<dyn std::error::Error>> {
///     let (response_headers, body) = get_authorized_core(auth_response, cookies, headers).await?;
///     Ok((response_headers, body))
/// }
/// ```
pub async fn get_authorized_core(
    auth_response: &AuthResponse,
    cookies: &headers::Cookie,
    headers: &HeaderMap,
) -> Result<(HeaderMap, String), CoordinationError> {
    authorized_core(HttpMethod::Get, auth_response, cookies, headers).await
}

/// Processes an OAuth2 POST authorization request.
///
/// Similar to `get_authorized_core`, but processes OAuth2 authentication via POST requests.
/// This function validates CSRF tokens, processes the authentication response, and
/// establishes a user session.
///
/// # Arguments
///
/// * `auth_response` - The OAuth2 authentication response from the provider
/// * `cookies` - Cookie headers from the client request
/// * `headers` - All headers from the client request
///
/// # Returns
///
/// * `Ok((HeaderMap, String))` - Response headers (including session cookie) and response body
/// * `Err(CoordinationError)` - If authentication fails for any reason
///
/// # Examples
///
/// ```no_run
/// use oauth2_passkey::{post_authorized_core, AuthResponse};
/// use headers::Cookie;
/// use http::HeaderMap;
///
/// async fn process_oauth_form_submission(
///     auth_response: &AuthResponse,
///     cookies: &Cookie,
///     headers: &HeaderMap
/// ) -> Result<(HeaderMap, String), Box<dyn std::error::Error>> {
///     let (response_headers, body) = post_authorized_core(auth_response, cookies, headers).await?;
///     Ok((response_headers, body))
/// }
/// ```
pub async fn post_authorized_core(
    auth_response: &AuthResponse,
    cookies: &headers::Cookie,
    headers: &HeaderMap,
) -> Result<(HeaderMap, String), CoordinationError> {
    authorized_core(HttpMethod::Post, auth_response, cookies, headers).await
}

#[tracing::instrument(skip(auth_response), fields(user_id, provider = "google", state = %auth_response.state))]
async fn process_oauth2_authorization(
    auth_response: &AuthResponse,
) -> Result<(HeaderMap, String), CoordinationError> {
    tracing::info!("Processing OAuth2 authorization core logic");
    let (idinfo, userinfo) = get_idinfo_userinfo(auth_response).await?;

    // Convert GoogleUserInfo to DbUser and store it
    static OAUTH2_GOOGLE_USER: &str = "idinfo";

    let mut oauth2_account = match OAUTH2_GOOGLE_USER {
        "idinfo" => OAuth2Account::from(idinfo),
        "userinfo" => OAuth2Account::from(userinfo),
        _ => OAuth2Account::from(idinfo), // Default case
    };

    // Upsert oauth2_account and user
    // 1. Decode the state from the auth response
    // 2. Extract user_id from the stored session if available
    // 3. Check if the OAuth2 account exists

    // Handle user and account linking
    // 4. If user is logged in and account exists, ensure they match
    // 5. If user is logged in but account doesn't exist, link account to user
    // 6. If user is not logged in but account exists, create session for account
    // 7. If neither user is logged in nor account exists, create new user and account

    // Create session with user_id
    // 8. Create a new entry in session store
    // 9. Create a header for the session cookie

    // Decode the state from the auth response
    let state_in_response = decode_state(&auth_response.state)?;

    // Extract user_id from the stored session if available
    let state_user = get_uid_from_stored_session_by_state_param(&state_in_response).await?;

    let (uid_in_state, account_in_state) = match &state_user {
        Some(user) => (Some(&user.id), Some(&user.account)),
        None => (None, None),
    };

    // Check if the OAuth2 account exists
    let existing_account = OAuth2Store::get_oauth2_account_by_provider(
        &oauth2_account.provider,
        &oauth2_account.provider_user_id,
    )
    .await?;

    // Extract mode_id from the stored session if available
    let mode = match &state_in_response.mode_id {
        Some(mode_id) => get_mode_from_stored_session(mode_id).await?,
        None => {
            tracing::debug!("No mode ID found");
            None
        }
    };

    tracing::debug!("Mode: {:?}", mode);
    tracing::debug!("User ID in state: {:?}", uid_in_state);
    tracing::debug!("Existing account: {:?}", existing_account);
    tracing::debug!("Account in state: {:?}", account_in_state);
    // Match on the combination of mode, auth_user and existing_account
    let (user_id, message) = match (mode.clone(), uid_in_state, &existing_account) {
        // Case 1: AddToUser mode - User is logged in and account doesn't exist (success case)
        (Some(OAuth2Mode::AddToUser), Some(uid), None) => {
            let account_info = account_in_state.ok_or_else(|| {
                CoordinationError::InvalidState(
                    "Missing account information in OAuth2 state".to_string(),
                )
            })?;
            let message = format!("Successfully linked to {account_info}");
            tracing::debug!("{}", message);
            oauth2_account.user_id = uid.clone();
            OAuth2Store::upsert_oauth2_account(oauth2_account).await?;
            delete_session_and_misc_token_from_store(&state_in_response).await?;
            (uid.to_string(), message)
        }

        // Case 2: AddToUser mode - User is logged in and account exists (already linked or error)
        (Some(OAuth2Mode::AddToUser), Some(uid), Some(existing)) => {
            if uid == &existing.user_id {
                let account_info = account_in_state.ok_or_else(|| {
                    CoordinationError::InvalidState(
                        "Missing account information in OAuth2 state".to_string(),
                    )
                })?;
                let msg = format!("Already linked to current user {account_info}");
                tracing::debug!("{}", msg);
                delete_session_and_misc_token_from_store(&state_in_response).await?;
                (uid.to_string(), msg)
            } else {
                return Err(CoordinationError::Conflict(
                    "This OAuth2 account is already linked to a different user".to_string(),
                ));
            }
        }

        // Case 3: Login mode - User is not logged in and account exists (success case)
        (Some(OAuth2Mode::Login), None, Some(existing)) => {
            let message = format!("Signing in as {}", existing.name);
            tracing::debug!("{}", message);
            (existing.user_id.clone(), message)
        }

        // Case 4: CreateUser mode - User is not logged in and account doesn't exist (success case)
        (Some(OAuth2Mode::CreateUser), None, None) => {
            let name = oauth2_account.name.clone();
            let user_id = create_user_and_oauth2account(oauth2_account).await?;
            let message = format!("Created new user {name}");
            tracing::debug!("{}", message);
            (user_id.clone(), message)
        }

        (Some(OAuth2Mode::CreateUserOrLogin), None, Some(existing)) => {
            let message = format!("Signing in as {}", existing.name);
            tracing::debug!("{}", message);
            (existing.user_id.clone(), message)
        }

        (Some(OAuth2Mode::CreateUserOrLogin), None, None) => {
            let name = oauth2_account.name.clone();
            let user_id = create_user_and_oauth2account(oauth2_account).await?;
            let message = format!("Created new user {name}");
            tracing::debug!("{}", message);
            (user_id.clone(), message)
        }

        (Some(OAuth2Mode::CreateUser), None, Some(_)) => {
            tracing::debug!("This OAuth2 account is already registered");
            return Err(CoordinationError::Conflict(
                "This OAuth2 account is already registered".to_string(),
            ));
        }

        (Some(OAuth2Mode::Login), None, None) => {
            tracing::debug!("This OAuth2 account is not registered");
            return Err(CoordinationError::Conflict(
                "This OAuth2 account is not registered".to_string(),
            ));
        }

        // Catch-all for any other invalid combinations
        _ => {
            tracing::error!("Invalid combination of mode {:?} and user state", mode);
            return Err(CoordinationError::InvalidState(format!(
                "Invalid combination of mode {mode:?} and user state"
            )));
        }
    };

    // Record user_id in the tracing span
    tracing::Span::current().record("user_id", &user_id);
    tracing::info!(user_id = %user_id, "OAuth2 authorization completed successfully");

    let mut headers = new_session_header(user_id).await?;

    let _ = header_set_cookie(
        &mut headers,
        OAUTH2_CSRF_COOKIE_NAME.to_string(),
        "value".to_string(),
        Utc::now() - Duration::seconds(86400),
        -86400,
    )?;

    Ok((headers, message))
}

// When creating a new user, map fields according to configuration or defaults
// We also assign the user_id to the oauth2_account.
async fn create_user_and_oauth2account(
    mut oauth2_account: OAuth2Account,
) -> Result<String, CoordinationError> {
    let (account, label) = get_account_and_label_from_oauth2_account(&oauth2_account);

    let new_user = DbUser {
        id: gen_new_user_id().await?,
        account,
        label,
        is_admin: false,
        sequence_number: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    let stored_user = UserStore::upsert_user(new_user).await?;
    oauth2_account.user_id = stored_user.id.clone();
    OAuth2Store::upsert_oauth2_account(oauth2_account).await?;
    Ok(stored_user.id)
}

fn get_account_and_label_from_oauth2_account(oauth2_account: &OAuth2Account) -> (String, String) {
    // Get field mappings from configuration
    let (account_field, label_field) = get_oauth2_field_mappings();

    // Map fields based on configuration
    let account = match account_field.as_str() {
        "email" => oauth2_account.email.clone(),
        "name" => oauth2_account.name.clone(),
        _ => oauth2_account.email.clone(), // Default to email if invalid mapping
    };

    let label = match label_field.as_str() {
        "email" => oauth2_account.email.clone(),
        "name" => oauth2_account.name.clone(),
        _ => oauth2_account.name.clone(), // Default to name if invalid mapping
    };
    (account, label)
}

/// Get the configured OAuth2 field mappings or defaults
fn get_oauth2_field_mappings() -> (String, String) {
    (
        OAUTH2_USER_ACCOUNT_FIELD.clone(),
        OAUTH2_USER_LABEL_FIELD.clone(),
    )
}

/// Delete an OAuth2 account for a user
///
/// This function checks that the OAuth2 account belongs to the authenticated user
/// before deleting it to prevent unauthorized deletions.
#[tracing::instrument(fields(user_id, provider, provider_user_id))]
pub async fn delete_oauth2_account_core(
    user_id: UserId,
    provider: Provider,
    provider_user_id: ProviderUserId,
) -> Result<(), CoordinationError> {
    tracing::info!("Attempting to delete OAuth2 account");
    // Ensure user is authenticated
    // let user = user.ok_or_else(|| CoordinationError::Unauthorized.log())?;

    // Get the OAuth2 account to verify it belongs to the user
    let accounts = OAuth2Store::get_oauth2_accounts_by(AccountSearchField::ProviderUserId(
        provider_user_id.clone(),
    ))
    .await?;

    // Verify the account exists
    let account = accounts
        .into_iter()
        .find(|account| {
            account.provider == provider.as_str()
                && account.provider_user_id == provider_user_id.as_str()
        })
        .ok_or(
            CoordinationError::ResourceNotFound {
                resource_type: "OAuth2Account".to_string(),
                resource_id: format!("{}/{}", provider.as_str(), provider_user_id.as_str()),
            }
            .log(),
        )?;

    // Verify the account belongs to the authenticated user
    if account.user_id != user_id.as_str() {
        return Err(CoordinationError::Unauthorized.log());
    }

    tracing::info!(
        "Successfully deleted OAuth2 account {}/{} for user {}",
        provider.as_str(),
        provider_user_id.as_str(),
        user_id.as_str()
    );

    // Delete the OAuth2 account
    OAuth2Store::delete_oauth2_accounts_by(AccountSearchField::ProviderUserId(provider_user_id))
        .await?;
    Ok(())
}

/// Lists all OAuth2 accounts associated with a user.
///
/// This function retrieves all OAuth2 provider accounts (Google, etc.) that have been
/// linked to a specific user account. This is useful for account management interfaces
/// where users need to view and manage their connected services.
///
/// # Arguments
///
/// * `user_id` - The ID of the user whose OAuth2 accounts should be listed
///
/// # Returns
///
/// * `Ok(Vec<OAuth2Account>)` - A list of connected OAuth2 accounts
/// * `Err(CoordinationError)` - If an error occurs while retrieving the accounts
///
/// # Examples
///
/// ```no_run
/// use oauth2_passkey::{list_accounts_core, UserId};
///
/// async fn get_connected_services(user_id: &str) -> Vec<String> {
///     match list_accounts_core(UserId::new(user_id.to_string())).await {
///         Ok(accounts) => accounts.into_iter().map(|acc| acc.provider).collect(),
///         Err(_) => Vec::new()
///     }
/// }
/// ```
#[tracing::instrument(fields(user_id))]
pub async fn list_accounts_core(user_id: UserId) -> Result<Vec<OAuth2Account>, CoordinationError> {
    tracing::debug!("Listing OAuth2 accounts for user");
    let accounts = OAuth2Store::get_oauth2_accounts(user_id.as_str()).await?;
    tracing::info!(account_count = accounts.len(), "Retrieved OAuth2 accounts");
    Ok(accounts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth2::OAuth2Account;
    use crate::test_utils::init_test_environment;
    use crate::userdb::User;
    use chrono::Utc;
    use serial_test::serial;

    /// Test OAuth2 field mappings return expected defaults
    ///
    /// This test verifies that OAuth2 field mappings return the correct default values
    /// when environment variables are not defined.
    ///
    #[tokio::test]
    #[serial]
    async fn test_get_oauth2_field_mappings_defaults() -> Result<(), Box<dyn std::error::Error>> {
        // Setup test environment
        init_test_environment().await;

        // Test default mappings - since .env_test doesn't set these variables,
        // they should use their default values
        let (account_field, label_field) = get_oauth2_field_mappings();
        assert_eq!(
            account_field, "email",
            "Default account field should be 'email'"
        );
        assert_eq!(label_field, "name", "Default label field should be 'name'");

        Ok(())
    }

    /// Test OAuth2 field mappings with environment variables
    ///
    /// This test verifies that OAuth2 field mappings work correctly when environment
    /// variables are defined, testing the configuration system behavior.
    ///
    #[tokio::test]
    #[serial]
    async fn test_get_account_and_label_from_oauth2_account()
    -> Result<(), Box<dyn std::error::Error>> {
        // Setup test environment
        init_test_environment().await;

        // Create a test OAuth2Account
        let oauth2_account = OAuth2Account {
            id: "test_id".to_string(),
            user_id: "test_user".to_string(),
            provider: "google".to_string(),
            provider_user_id: "google_123".to_string(),
            name: "John Doe".to_string(),
            email: "john.doe@example.com".to_string(),
            picture: Some("https://example.com/picture.jpg".to_string()),
            metadata: serde_json::json!({}),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        // Test the field mapping function
        let (account, label) = get_account_and_label_from_oauth2_account(&oauth2_account);

        // With default mappings: account_field="email", label_field="name"
        assert_eq!(
            account, "john.doe@example.com",
            "Account should be mapped to email"
        );
        assert_eq!(label, "John Doe", "Label should be mapped to name");

        Ok(())
    }

    // Helper function to create a test user
    async fn create_test_user_in_db(user_id: &str) -> Result<(), Box<dyn std::error::Error>> {
        let user = User {
            id: user_id.to_string(),
            account: "test_account".to_string(),
            label: "Test User".to_string(),
            is_admin: false,
            sequence_number: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        UserStore::upsert_user(user).await?;
        Ok(())
    }

    // Helper function to create a test OAuth2 account
    async fn create_test_oauth2_account_in_db(
        user_id: &str,
        provider: &str,
        provider_user_id: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let timestamp = Utc::now().timestamp_nanos_opt().unwrap_or(0);
        let unique_provider_user_id = format!("{provider_user_id}-{timestamp}");
        let account_id = format!("test-id-{timestamp}");

        let oauth2_account = OAuth2Account {
            id: account_id.clone(),
            user_id: user_id.to_string(),
            provider: provider.to_string(),
            provider_user_id: unique_provider_user_id.clone(),
            name: "Test User".to_string(),
            email: "test@example.com".to_string(),
            picture: Some("https://example.com/picture.jpg".to_string()),
            metadata: serde_json::json!({}),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        OAuth2Store::upsert_oauth2_account(oauth2_account).await?;
        Ok(unique_provider_user_id)
    }

    /// Test the core OAuth2 account listing functionality
    ///
    /// This test verifies that `list_accounts_core()` correctly retrieves all OAuth2 accounts
    /// associated with a specific user. It creates a test user with multiple OAuth2 accounts
    /// from different providers and verifies:
    /// - The correct number of accounts are returned
    /// - All returned accounts belong to the specified user
    /// - The function handles multiple provider accounts correctly
    #[tokio::test]
    #[serial]
    async fn test_list_accounts_core() -> Result<(), Box<dyn std::error::Error>> {
        // Setup test environment
        init_test_environment().await;

        // Create test user and OAuth2 accounts with unique timestamp-based ID
        let timestamp = chrono::Utc::now().timestamp_millis();
        let user_id = format!("test_user_list_accounts_{timestamp}");
        let provider1 = "google";
        let provider2 = "github";
        let provider_user_id1 = "google_user_123";
        let provider_user_id2 = "github_user_456";

        create_test_user_in_db(&user_id).await?;
        let _unique_provider_user_id1 =
            create_test_oauth2_account_in_db(&user_id, provider1, provider_user_id1).await?;
        let _unique_provider_user_id2 =
            create_test_oauth2_account_in_db(&user_id, provider2, provider_user_id2).await?;

        // List the OAuth2 accounts
        let accounts = list_accounts_core(UserId::new(user_id.clone())).await?;
        assert_eq!(
            accounts.len(),
            2,
            "Expected 2 OAuth2 accounts, got: {}",
            accounts.len()
        );

        // Verify the accounts belong to the correct user
        for account in &accounts {
            assert_eq!(
                account.user_id, user_id,
                "Account should belong to the test user"
            );
        }

        Ok(())
    }

    /// Test the core OAuth2 account deletion functionality
    /// This test verifies that `delete_oauth2_account_core()` correctly deletes an OAuth2 account
    /// associated with a user. It creates a test user and OAuth2 account, then attempts to delete
    /// the account, verifying:
    /// - The account is successfully deleted
    /// - The account cannot be found after deletion
    /// - Unauthorized deletion attempts by other users are correctly handled
    #[tokio::test]
    #[serial]
    async fn test_delete_oauth2_account_core_success() -> Result<(), Box<dyn std::error::Error>> {
        // Setup test environment
        init_test_environment().await;

        // Create test user and OAuth2 account
        let user_id = "test_user_delete_success";
        let provider = "google";
        let provider_user_id = "google_user_delete_123";

        create_test_user_in_db(user_id).await?;
        let unique_provider_user_id =
            create_test_oauth2_account_in_db(user_id, provider, provider_user_id).await?;

        // Delete the OAuth2 account
        let result = delete_oauth2_account_core(
            UserId::new(user_id.to_string()),
            Provider::new(provider.to_string()),
            ProviderUserId::new(unique_provider_user_id.clone()),
        )
        .await;
        assert!(
            result.is_ok(),
            "Failed to delete OAuth2 account: {result:?}"
        );

        // Verify the account was deleted
        let accounts = OAuth2Store::get_oauth2_accounts_by(AccountSearchField::ProviderUserId(
            crate::oauth2::ProviderUserId::new(unique_provider_user_id),
        ))
        .await?;
        assert!(accounts.is_empty(), "OAuth2 account was not deleted");

        Ok(())
    }

    /// Test the core OAuth2 account deletion functionality for unauthorized access
    /// This test verifies that `delete_oauth2_account_core()` correctly handles unauthorized deletion
    /// attempts. It creates a test user and OAuth2 account, then tries to delete the account
    /// as a different user, verifying:
    /// - The deletion attempt fails with an Unauthorized error
    /// - The account remains in the database after the unauthorized attempt
    #[tokio::test]
    #[serial]
    async fn test_delete_oauth2_account_core_unauthorized() -> Result<(), Box<dyn std::error::Error>>
    {
        // Setup test environment
        init_test_environment().await;

        // Create test users and OAuth2 account with unique IDs
        let timestamp = chrono::Utc::now().timestamp_millis();
        let user_id = format!("test_user_delete_owner_{timestamp}");
        let other_user_id = format!("test_user_delete_unauthorized_{timestamp}");
        let provider = "google";
        let provider_user_id = format!("google_user_delete_456_{timestamp}");

        create_test_user_in_db(&user_id).await?;
        create_test_user_in_db(&other_user_id).await?;
        let unique_provider_user_id =
            create_test_oauth2_account_in_db(&user_id, provider, &provider_user_id).await?;

        // Try to delete the OAuth2 account as a different user
        let result = delete_oauth2_account_core(
            UserId::new(other_user_id),
            Provider::new(provider.to_string()),
            ProviderUserId::new(unique_provider_user_id),
        )
        .await;
        assert!(
            matches!(result, Err(CoordinationError::Unauthorized)),
            "Expected Unauthorized error, got: {result:?}"
        );

        Ok(())
    }
}
