use chrono::{Duration, Utc};
use http::HeaderMap;
use std::env;

use crate::oauth2::{
    AccountSearchField, AuthResponse, OAUTH2_AUTH_URL, OAUTH2_CSRF_COOKIE_NAME, OAuth2Account,
    OAuth2Mode, OAuth2Store, csrf_checks, decode_state, delete_session_and_misc_token_from_store,
    get_idinfo_userinfo, get_mode_from_stored_session, get_uid_from_stored_session_by_state_param,
    validate_origin,
};

use crate::userdb::{User as DbUser, UserStore};
use crate::utils::header_set_cookie;

use super::errors::CoordinationError;
use super::user::gen_new_user_id;

use crate::session::new_session_header;

pub async fn get_authorized_core(
    auth_response: &AuthResponse,
    cookies: &headers::Cookie,
    headers: &HeaderMap,
) -> Result<(HeaderMap, String), CoordinationError> {
    validate_origin(headers, OAUTH2_AUTH_URL.as_str()).await?;

    csrf_checks(cookies.clone(), auth_response, headers.clone()).await?;

    process_oauth2_authorization(auth_response, headers).await
}

pub async fn post_authorized_core(
    auth_response: &AuthResponse,
    headers: &HeaderMap,
) -> Result<(HeaderMap, String), CoordinationError> {
    validate_origin(headers, OAUTH2_AUTH_URL.as_str()).await?;

    if auth_response.state.is_empty() {
        return Err(CoordinationError::InvalidState(
            "State is empty".to_string(),
        ));
    }

    process_oauth2_authorization(auth_response, headers).await
}

async fn process_oauth2_authorization(
    auth_response: &AuthResponse,
    headers: &HeaderMap,
) -> Result<(HeaderMap, String), CoordinationError> {
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
            let message = format!("Successfully linked to {}", account_in_state.unwrap());
            tracing::debug!("{}", message);
            oauth2_account.user_id = uid.clone();
            OAuth2Store::upsert_oauth2_account(oauth2_account).await?;
            delete_session_and_misc_token_from_store(&state_in_response).await?;
            (uid.to_string(), message)
        }

        // Case 2: AddToUser mode - User is logged in and account exists (already linked or error)
        (Some(OAuth2Mode::AddToUser), Some(uid), Some(existing)) => {
            if uid == &existing.user_id {
                let msg = format!(
                    "Already linked to current user {}",
                    account_in_state.unwrap()
                );
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
            let message = format!("Created new user {}", name);
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
            let message = format!("Created new user {}", name);
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
                "Invalid combination of mode {:?} and user state",
                mode
            )));
        }
    };

    let mut headers = new_session_header(user_id, headers.clone()).await?;

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
        env::var("OAUTH2_USER_ACCOUNT_FIELD").unwrap_or_else(|_| "email".to_string()),
        env::var("OAUTH2_USER_LABEL_FIELD").unwrap_or_else(|_| "name".to_string()),
    )
}

/// Delete an OAuth2 account for a user
///
/// This function checks that the OAuth2 account belongs to the authenticated user
/// before deleting it to prevent unauthorized deletions.
pub async fn delete_oauth2_account_core(
    user_id: &str,
    provider: &str,
    provider_user_id: &str,
) -> Result<(), CoordinationError> {
    // Ensure user is authenticated
    // let user = user.ok_or_else(|| CoordinationError::Unauthorized.log())?;

    // Get the OAuth2 account to verify it belongs to the user
    let accounts = OAuth2Store::get_oauth2_accounts_by(AccountSearchField::ProviderUserId(
        provider_user_id.to_string(),
    ))
    .await?;

    // Verify the account exists
    let account = accounts
        .into_iter()
        .find(|account| {
            account.provider == provider && account.provider_user_id == provider_user_id
        })
        .ok_or(
            CoordinationError::ResourceNotFound {
                resource_type: "OAuth2Account".to_string(),
                resource_id: format!("{}/{}", provider, provider_user_id),
            }
            .log(),
        )?;

    // Verify the account belongs to the authenticated user
    if account.user_id != user_id {
        return Err(CoordinationError::Unauthorized.log());
    }

    // Delete the OAuth2 account
    OAuth2Store::delete_oauth2_accounts_by(AccountSearchField::ProviderUserId(
        provider_user_id.to_string(),
    ))
    .await?;

    tracing::info!(
        "Successfully deleted OAuth2 account {}/{} for user {}",
        provider,
        provider_user_id,
        user_id
    );
    Ok(())
}

/// Get all OAuth2 accounts for a user
async fn get_oauth2_accounts(user_id: &str) -> Result<Vec<OAuth2Account>, CoordinationError> {
    let accounts = OAuth2Store::get_oauth2_accounts(user_id).await?;
    Ok(accounts)
}

pub async fn list_accounts_core(user_id: &str) -> Result<Vec<OAuth2Account>, CoordinationError> {
    get_oauth2_accounts(user_id).await
}
