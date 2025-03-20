//! oauth2_passkey - Authentication coordination library for axum-oauth2-passkey
//!
//! This crate provides coordination between different authentication mechanisms
//! including OAuth2, Passkey, and user database operations.

mod coordinate;
mod oauth2;
mod passkey;
mod session;
mod storage;
mod userdb;

// Re-export the main coordination components
pub use coordinate::AuthError;
pub use coordinate::{
    RegistrationStartRequest, delete_passkey_credential_core, handle_finish_authentication_core,
    handle_finish_registration_core, handle_start_authentication_core,
    handle_start_registration_core, list_credentials_core,
};
pub use coordinate::{
    USER_CONTEXT_TOKEN_COOKIE, extract_context_token_from_cookies, generate_user_context_token,
    obfuscate_user_id, verify_context_token_and_page, verify_user_context_token,
};
pub use coordinate::{
    delete_oauth2_account_core, get_authorized_core, get_oauth2_accounts, list_accounts_core,
    post_authorized_core, process_oauth2_authorization,
};
pub use coordinate::{delete_user_account, update_user_account};

pub use oauth2::{
    AuthResponse, OAUTH2_AUTH_URL, OAUTH2_CSRF_COOKIE_NAME, OAUTH2_ROUTE_PREFIX, OAuth2Account,
    OAuth2Store, csrf_checks, prepare_oauth2_auth_request, validate_origin,
};

pub use passkey::{
    AuthenticationOptions, AuthenticatorResponse, PASSKEY_ROUTE_PREFIX, PasskeyStore,
    PublicKeyCredentialUserEntity, RegisterCredential, RegistrationOptions, StoredCredential,
    finish_authentication, finish_registration, gen_random_string, get_related_origin_json,
    start_authentication, start_registration, verify_session_then_finish_registration,
};

pub use session::{
    SESSION_COOKIE_NAME, SessionError, User as SessionUser, create_session_with_uid,
    get_user_from_session, prepare_logout_response,
};

pub use storage::GENERIC_DATA_STORE;

/// Initialize the authentication coordination layer
pub async fn init() -> Result<(), AuthError> {
    // Initialize the underlying stores
    userdb::init().await.map_err(AuthError::User)?;
    oauth2::init().await.map_err(AuthError::OAuth2)?;
    passkey::init().await.map_err(AuthError::Passkey)?;

    Ok(())
}
