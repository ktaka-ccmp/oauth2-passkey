use chrono::{Duration, Utc};
use http::HeaderMap;
use std::{env, sync::LazyLock};

use crate::audit::{AuthMethod, AuthMethodDetails, LoginContext};
use crate::oauth2::provider::{ProviderConfig, ProviderKind, provider_for};
use crate::oauth2::{
    AccountSearchField, AuthResponse, FedCMCallbackRequest, OAUTH2_CSRF_COOKIE_NAME, OAuth2Account,
    OAuth2Mode, OAuth2Store, Provider, ProviderUserId, StateParams, csrf_checks, decode_state,
    delete_session_and_misc_token_from_store, get_idinfo_userinfo, get_mode_from_stored_session,
    get_uid_from_stored_session_by_state_param, oauth2_account_from_idinfo,
    oauth2_account_from_userinfo, validate_fedcm_token, validate_origin,
};

use crate::userdb::{User as DbUser, UserStore};
use crate::utils::header_set_cookie;

use super::errors::CoordinationError;
use super::login_history::{record_login_failure, record_login_success};
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
enum HttpMethod {
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
///
/// # Arguments
///
/// * `ctx` - The resolved provider configuration
/// * `method` - The HTTP method used for the callback (GET or POST)
/// * `auth_response` - The OAuth2 authentication response from the provider
/// * `cookies` - Cookie headers from the client request
/// * `headers` - All headers from the client request
#[tracing::instrument(skip(ctx, auth_response, cookies, headers), fields(user_id, provider, state = %auth_response.state))]
async fn authorized_core(
    ctx: &ProviderConfig,
    method: HttpMethod,
    auth_response: &AuthResponse,
    cookies: &headers::Cookie,
    headers: &HeaderMap,
) -> Result<(HeaderMap, String), CoordinationError> {
    tracing::Span::current().record("provider", ctx.kind.as_str());
    tracing::info!(?method, "Processing OAuth2 authorization callback");
    // Verify this is the correct response mode for the HTTP method
    match (method, ctx.response_mode.to_lowercase().as_str()) {
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

    let auth_url = ctx
        .auth_url()
        .await
        .map_err(|e| CoordinationError::InvalidState(format!("Failed to get auth url: {e}")))?;
    // Origin validation is skipped only for plain-HTTP localhost callbacks.
    // This is a protocol-level concession, not provider-specific: browsers
    // handle `Origin` inconsistently on cross-site `form_post` redirects to
    // insecure origins during local development, and there is no HTTPS to
    // anchor to. Production callbacks always use HTTPS, so this branch is
    // never taken outside dev/test setups. If a future provider uses a
    // different dev-only scheme, narrow further at that point.
    if ctx.redirect_uri.starts_with("http://localhost")
        || ctx.redirect_uri.starts_with("http://127.0.0.1")
    {
        tracing::warn!(
            redirect_uri = %ctx.redirect_uri,
            "Skipping origin check for HTTP localhost callback"
        );
    } else {
        validate_origin(headers, &auth_url).await?;
    }

    if auth_response.state.is_empty() {
        return Err(CoordinationError::InvalidState(
            "State is empty".to_string(),
        ));
    }

    // Extract login context from headers for history recording
    let login_context = LoginContext::from_headers(headers);

    // CSRF check with security event logging on failure
    match csrf_checks(cookies.clone(), auth_response, headers.clone()).await {
        Err(e) => {
            let failure_reason = format!("oauth2_csrf_failure: {}", e);
            let _ = record_login_failure(
                None,
                AuthMethod::OAuth2,
                login_context,
                None,
                failure_reason,
            )
            .await;
            Err(e.into())
        }
        Ok(()) => process_oauth2_authorization(ctx, auth_response, login_context).await,
    }
}

/// Processes an OAuth2 GET authorization request.
///
/// This function handles the core business logic for OAuth2 authentication via GET requests.
/// It validates CSRF tokens, processes the authentication response from the provider,
/// and establishes a user session.
///
/// # Arguments
///
/// * `provider` - The OAuth2 provider identifier from the URL path (e.g. "google")
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
///     let (response_headers, body) = get_authorized_core("google", auth_response, cookies, headers).await?;
///     Ok((response_headers, body))
/// }
/// ```
pub async fn get_authorized_core(
    provider: &str,
    auth_response: &AuthResponse,
    cookies: &headers::Cookie,
    headers: &HeaderMap,
) -> Result<(HeaderMap, String), CoordinationError> {
    let kind = ProviderKind::from_path_segment(provider).ok_or_else(|| {
        CoordinationError::InvalidState(format!("Unknown OAuth2 provider: {provider}"))
    })?;
    let ctx = provider_for(kind).ok_or_else(|| {
        CoordinationError::InvalidState(format!("OAuth2 provider not enabled: {provider}"))
    })?;
    authorized_core(ctx, HttpMethod::Get, auth_response, cookies, headers).await
}

/// Processes an OAuth2 POST authorization request.
///
/// Similar to `get_authorized_core`, but processes OAuth2 authentication via POST requests.
/// This function validates CSRF tokens, processes the authentication response, and
/// establishes a user session.
///
/// # Arguments
///
/// * `provider` - The OAuth2 provider identifier from the URL path (e.g. "google")
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
///     let (response_headers, body) = post_authorized_core("google", auth_response, cookies, headers).await?;
///     Ok((response_headers, body))
/// }
/// ```
pub async fn post_authorized_core(
    provider: &str,
    auth_response: &AuthResponse,
    cookies: &headers::Cookie,
    headers: &HeaderMap,
) -> Result<(HeaderMap, String), CoordinationError> {
    let kind = ProviderKind::from_path_segment(provider).ok_or_else(|| {
        CoordinationError::InvalidState(format!("Unknown OAuth2 provider: {provider}"))
    })?;
    let ctx = provider_for(kind).ok_or_else(|| {
        CoordinationError::InvalidState(format!("OAuth2 provider not enabled: {provider}"))
    })?;
    authorized_core(ctx, HttpMethod::Post, auth_response, cookies, headers).await
}

#[tracing::instrument(skip(ctx, auth_response, login_context), fields(user_id, provider, state = %auth_response.state))]
async fn process_oauth2_authorization(
    ctx: &ProviderConfig,
    auth_response: &AuthResponse,
    login_context: LoginContext,
) -> Result<(HeaderMap, String), CoordinationError> {
    let provider_name = ctx.kind.as_str();
    tracing::Span::current().record("provider", provider_name);
    tracing::info!("Processing OAuth2 authorization core logic");

    // Decode the state from the auth response first so we can cross-check the provider
    // before doing any expensive token exchange.
    let oauth2_state = crate::OAuth2State::new(auth_response.state.clone())?;
    let state_in_response = decode_state(&oauth2_state)?;

    // Defense-in-depth: the URL path provider is the authoritative dispatch signal.
    // The `provider` field in `StateParams` is a cross-check to detect URL/state
    // mismatches (e.g. an attacker submitting a Google state to an Auth0 callback).
    // Reject on mismatch so the flow never reaches the token exchange.
    if state_in_response.provider != provider_name {
        tracing::error!(
            security_event = "provider_mismatch",
            state_provider = %state_in_response.provider,
            url_path_provider = %provider_name,
            "Provider mismatch: state.provider does not match URL path provider"
        );
        return Err(CoordinationError::InvalidState(format!(
            "Provider mismatch: state contains '{}' but URL path is '{}'",
            state_in_response.provider, provider_name
        )));
    }

    let (idinfo, userinfo) = get_idinfo_userinfo(ctx, auth_response).await?;

    // Convert IdInfo or UserInfo to OAuth2Account using the active provider name
    static OAUTH2_GOOGLE_USER: &str = "idinfo";

    let oauth2_account = match OAUTH2_GOOGLE_USER {
        "idinfo" => oauth2_account_from_idinfo(&idinfo, provider_name),
        "userinfo" => oauth2_account_from_userinfo(&userinfo, provider_name),
        _ => oauth2_account_from_idinfo(&idinfo, provider_name), // Default case
    };

    // Extract user_id from the stored session if available
    let state_user = get_uid_from_stored_session_by_state_param(&state_in_response).await?;
    let (uid_in_state, account_in_state) = match &state_user {
        Some(user) => (Some(user.id.as_str()), Some(user.account.as_str())),
        None => (None, None),
    };

    // Extract mode_id from the stored session if available
    let mode = match &state_in_response.mode_id {
        Some(mode_id) => get_mode_from_stored_session(mode_id).await?,
        None => {
            tracing::debug!("No mode ID found");
            None
        }
    };

    let (mut headers, message) = process_authenticated_oauth2_user(
        oauth2_account,
        mode,
        AuthMethod::OAuth2,
        login_context,
        uid_in_state,
        account_in_state,
        Some(&state_in_response),
    )
    .await?;

    // Clear CSRF cookie (OAuth2-specific cleanup)
    let _ = header_set_cookie(
        &mut headers,
        OAUTH2_CSRF_COOKIE_NAME.to_string(),
        "value".to_string(),
        Utc::now() - Duration::seconds(86400),
        -86400,
        None, // CSRF cookie doesn't need domain attribute
    )?;

    Ok((headers, message))
}

/// Shared logic for processing an authenticated OAuth2/FedCM user.
///
/// Called after the caller has obtained the user identity (via code exchange
/// or JWT validation), resolved the OAuth2 mode, and extracted any logged-in
/// user context from state.
async fn process_authenticated_oauth2_user(
    mut oauth2_account: OAuth2Account,
    mode: Option<OAuth2Mode>,
    auth_method: AuthMethod,
    login_context: LoginContext,
    uid_in_state: Option<&str>,
    account_in_state: Option<&str>,
    state_params: Option<&StateParams>,
) -> Result<(HeaderMap, String), CoordinationError> {
    // 1. Check if the OAuth2 account exists
    //
    // Handle user and account linking
    // 2. If user is logged in and account exists, ensure they match
    // 3. If user is logged in but account doesn't exist, link account to user
    // 4. If user is not logged in but account exists, create session for account
    // 5. If neither user is logged in nor account exists, create new user and account
    //
    // Create session with user_id
    // 6. Create a new entry in session store
    // 7. Create a header for the session cookie

    // Check if the OAuth2 account exists
    let provider = Provider::new(oauth2_account.provider.clone())
        .map_err(|e| CoordinationError::Validation(format!("Invalid provider: {e}")))?;
    let provider_user_id = ProviderUserId::new(oauth2_account.provider_user_id.clone())
        .map_err(|e| CoordinationError::Validation(format!("Invalid provider user ID: {e}")))?;
    let existing_account =
        OAuth2Store::get_oauth2_account_by_provider(provider, provider_user_id).await?;

    // Capture provider info for login history before oauth2_account is potentially moved
    let provider_for_history = oauth2_account.provider.clone();
    let provider_user_id_for_history = oauth2_account.provider_user_id.clone();
    let email_for_history = oauth2_account.email.clone();

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
            let state_params = state_params.ok_or_else(|| {
                CoordinationError::InvalidState("AddToUser requires state parameters".to_string())
            })?;
            let message = format!("Successfully linked to {account_info}");
            tracing::debug!("{}", message);
            oauth2_account.user_id = uid.to_string();
            OAuth2Store::upsert_oauth2_account(oauth2_account).await?;
            delete_session_and_misc_token_from_store(state_params).await?;
            (uid.to_string(), message)
        }

        // Case 2: AddToUser mode - User is logged in and account exists (already linked or error)
        (Some(OAuth2Mode::AddToUser), Some(uid), Some(existing)) => {
            if uid == existing.user_id {
                let account_info = account_in_state.ok_or_else(|| {
                    CoordinationError::InvalidState(
                        "Missing account information in OAuth2 state".to_string(),
                    )
                })?;
                let state_params = state_params.ok_or_else(|| {
                    CoordinationError::InvalidState(
                        "AddToUser requires state parameters".to_string(),
                    )
                })?;
                let msg = format!("Already linked to current user {account_info}");
                tracing::debug!("{}", msg);
                delete_session_and_misc_token_from_store(state_params).await?;
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

    let user_id_validated = UserId::new(user_id)
        .map_err(|e| CoordinationError::Validation(format!("Invalid user ID: {e}")))?;
    let headers = new_session_header(user_id_validated.clone()).await?;

    // Record login history (fire-and-forget: errors are logged but don't fail the login)
    let _ = record_login_success(
        user_id_validated,
        auth_method,
        login_context,
        AuthMethodDetails {
            provider: Some(provider_for_history),
            provider_user_id: Some(provider_user_id_for_history),
            email: Some(email_for_history),
            ..Default::default()
        },
    )
    .await;

    Ok((headers, message))
}

/// Processes a FedCM authorization callback.
///
/// This function validates a JWT ID token received via FedCM's
/// `navigator.credentials.get()`, verifies the nonce, and establishes
/// a user session.
///
/// FedCM does not support `add_to_user` mode -- this mode always uses
/// the traditional OAuth2 popup flow.
#[tracing::instrument(skip(request, headers), fields(user_id, provider = "google"))]
pub async fn fedcm_authorized_core(
    request: &FedCMCallbackRequest,
    headers: &HeaderMap,
) -> Result<(HeaderMap, String), CoordinationError> {
    tracing::info!("Processing FedCM authorization callback");

    // FedCM is currently Google-only.
    let ctx = provider_for(ProviderKind::Google).ok_or_else(|| {
        CoordinationError::InvalidState("Google provider not available".to_string())
    })?;

    // 1. Validate ID token and verify nonce (single-use)
    let idinfo = validate_fedcm_token(ctx, &request.credential, &request.nonce_id).await?;

    // 2. Build OAuth2Account from the verified ID token
    let oauth2_account = oauth2_account_from_idinfo(&idinfo, ctx.kind.as_str());

    // 3. Parse mode directly from request (no cache round-trip needed for FedCM)
    let mode = match &request.mode {
        Some(mode_str) => {
            let parsed: OAuth2Mode = mode_str.parse().map_err(|_| {
                CoordinationError::InvalidState(format!("Invalid FedCM mode: {mode_str}"))
            })?;
            Some(parsed)
        }
        None => None,
    };

    // 4. Reject AddToUser mode (not supported by FedCM)
    if matches!(mode, Some(OAuth2Mode::AddToUser)) {
        return Err(CoordinationError::InvalidState(
            "FedCM does not support add_to_user mode".to_string(),
        ));
    }

    // 5. Extract login context from headers for history recording
    let login_context = LoginContext::from_headers(headers);

    // 6. Process authenticated user (no state user or state params for FedCM)
    let result = process_authenticated_oauth2_user(
        oauth2_account,
        mode,
        AuthMethod::FedCM,
        login_context,
        None,
        None,
        None,
    )
    .await?;

    Ok(result)
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
        is_admin: *crate::config::O2P_DEMO_MODE,
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
///     let user_id = UserId::new(user_id.to_string()).expect("Valid user ID");
///     match list_accounts_core(user_id).await {
///         Ok(accounts) => accounts.into_iter().map(|acc| acc.provider).collect(),
///         Err(_) => Vec::new()
///     }
/// }
/// ```
#[tracing::instrument(fields(user_id))]
pub async fn list_accounts_core(user_id: UserId) -> Result<Vec<OAuth2Account>, CoordinationError> {
    tracing::debug!("Listing OAuth2 accounts for user");
    let accounts = OAuth2Store::get_oauth2_accounts(user_id).await?;
    tracing::info!(account_count = accounts.len(), "Retrieved OAuth2 accounts");
    Ok(accounts)
}

#[cfg(test)]
mod tests;
