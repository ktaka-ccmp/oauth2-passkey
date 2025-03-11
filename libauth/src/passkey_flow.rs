use chrono::Utc;
use http::{HeaderMap, StatusCode};
use serde_json::Value;
use uuid::Uuid;

use libuserdb::{User, UserStore};
use libpasskey::{
    AuthenticationOptions, AuthenticatorResponse, CredentialSearchField, PasskeyStore,
    RegisterCredential, RegistrationOptions, StoredCredential, finish_authentication,
    finish_registration, finish_registration_with_auth_user, start_authentication, start_registration,
};
use libsession::{User as SessionUser, create_session_with_uid};
use liboauth2::OAuth2Store;



/// Core function that handles the business logic of starting registration with OAuth2 account info
///
/// This function takes an optional reference to a SessionUser and returns registration options
/// based on the user's OAuth2 account information.
pub async fn handle_start_registration_get_core(
    user: Option<&SessionUser>,
) -> Result<RegistrationOptions, (StatusCode, String)> {
    match user {
        None => Err((StatusCode::BAD_REQUEST, "Not logged in!".to_string())),
        Some(user) => {
            tracing::debug!("User: {:#?}", user);

            // Get the user's OAuth2 accounts
            let oauth2_accounts = OAuth2Store::get_oauth2_accounts(&user.id)
                .await
                .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?
                .first()
                .cloned()
                .ok_or_else(|| {
                    (
                        StatusCode::BAD_REQUEST,
                        "No OAuth2 accounts found".to_string(),
                    )
                })?;

            // Extract username and displayname from the OAuth2 account
            let username = oauth2_accounts.email.clone();
            let displayname = oauth2_accounts.name.clone();

            // Start registration with the extracted information
            start_registration(Some(user.clone()), username, displayname)
                .await
                .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))
        }
    }
}

/// Core function that handles the business logic of starting registration with provided user info
///
/// This function takes an optional reference to a SessionUser, extracts username and displayname
/// from the request body, and returns registration options.
pub async fn handle_start_registration_post_core(
    auth_user: Option<&SessionUser>,
    body: &Value,
) -> Result<RegistrationOptions, (StatusCode, String)> {
    // Extract username from the request body
    let username = body
        .get("username")
        .and_then(|v| v.as_str())
        .map(String::from)
        .ok_or((StatusCode::BAD_REQUEST, "Missing username".to_string()))?;

    // Extract displayname from the request body, defaulting to username if not provided
    let displayname = body
        .get("displayname")
        .and_then(|v| v.as_str())
        .map(String::from)
        .unwrap_or(username.clone());

    // Call the start_registration function with the extracted data
    start_registration(auth_user.cloned(), username, displayname)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))
}

/// Core function that handles the business logic of finishing registration
///
/// This function takes an optional reference to a SessionUser and registration data,
/// and either registers a new credential for an existing user or creates a new user
/// with the credential.
pub async fn handle_finish_registration_core(
    auth_user: Option<&SessionUser>,
    reg_data: RegisterCredential,
) -> Result<(HeaderMap, String), (StatusCode, String)> {
    match auth_user {
        Some(session_user) => {
            tracing::debug!("User: {:#?}", session_user);

            // Handle authenticated user registration
            let message = finish_registration_with_auth_user(session_user.clone(), reg_data)
                .await
                .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

            Ok((HeaderMap::new(), message))
        }
        None => {
            // Create a new user for unauthenticated registration
            let new_user = User {
                id: Uuid::new_v4().to_string(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            };

            // Store the user
            let stored_user = UserStore::upsert_user(new_user)
                .await
                .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

            // Finish registration
            let result = finish_registration(&stored_user.id, &reg_data)
                .await
                .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()));

            match result {
                Ok(message) => {
                    // Create session with the user_id
                    let headers = create_session_with_uid(&stored_user.id)
                        .await
                        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

                    Ok((headers, message))
                }
                Err(err) => Err(err),
            }
        }
    }
}

/// Core function that handles the business logic of starting authentication
///
/// This function extracts the username from the request body and starts the
/// authentication process.
pub async fn handle_start_authentication_core(
    body: &Value,
) -> Result<AuthenticationOptions, (StatusCode, String)> {
    // Extract username from the request body
    let username = if body.is_object() {
        body.get("username")
            .and_then(|v| v.as_str())
            .map(String::from)
    } else if body.is_string() {
        Some(body.as_str().unwrap().to_string()) // Directly use the string
    } else {
        None
    };

    // Start the authentication process
    start_authentication(username).await.map_err(|e| {
        tracing::debug!("Error: {:#?}", e);
        (StatusCode::BAD_REQUEST, e.to_string())
    })
}

/// Core function that handles the business logic of finishing authentication
///
/// This function verifies the authentication response, creates a session for the
/// authenticated user, and returns the user ID, name, and session headers.
pub async fn handle_finish_authentication_core(
    auth_response: AuthenticatorResponse,
) -> Result<(String, String, HeaderMap), (StatusCode, String)> {
    tracing::debug!("Auth response: {:#?}", auth_response);

    // Verify the authentication and get the user ID and name
    let (uid, name) = finish_authentication(auth_response)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    tracing::debug!("User ID: {:#?}", uid);

    // Create a session for the authenticated user
    let headers = create_session_with_uid(&uid)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    Ok((uid, name, headers))
}

/// Core function that handles the business logic of listing passkey credentials
///
/// This function takes an optional reference to a SessionUser and returns the list of stored credentials
/// associated with that user, or an error if the user is not logged in.
pub async fn list_credentials_core(
    user: Option<&SessionUser>,
) -> Result<Vec<StoredCredential>, (StatusCode, String)> {
    match user {
        Some(user) => {
            tracing::debug!("User: {:#?}", user);
            PasskeyStore::get_credentials_by(CredentialSearchField::UserId(user.id.to_owned()))
                .await
                .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))
        }
        None => Err((StatusCode::BAD_REQUEST, "Not logged in!".to_string())),
    }
}
