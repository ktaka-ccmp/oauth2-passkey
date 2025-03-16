//! libauth - Authentication coordination library for axum-oauth2-passkey
//!
//! This crate provides coordination between different authentication mechanisms
//! including OAuth2, Passkey, and user database operations.

mod errors;
mod oauth2_flow;
mod passkey_flow;
mod user_flow;

// Re-export the main coordination components
pub use errors::AuthError;
pub use oauth2_flow::{
    delete_oauth2_account_core, get_authorized_core, get_oauth2_accounts, list_accounts_core,
    post_authorized_core, process_oauth2_authorization,
};
pub use passkey_flow::{
    delete_passkey_credential_core, handle_finish_authentication_core,
    handle_finish_registration_core, handle_start_authentication_core,
    handle_start_registration_post_core, list_credentials_core,
};
pub use user_flow::{delete_user_account, update_user_account};

pub use liboauth2::{
    AuthResponse, OAUTH2_AUTH_URL, OAUTH2_CSRF_COOKIE_NAME, OAUTH2_ROUTE_PREFIX, OAuth2Account,
    OAuth2Store, csrf_checks, prepare_oauth2_auth_request, validate_origin,
};

pub use libpasskey::{
    AuthenticationOptions, AuthenticatorResponse, PasskeyStore, PublicKeyCredentialUserEntity,
    RegisterCredential, RegistrationOptions, finish_authentication, finish_registration,
    gen_random_string, start_authentication, start_registration,
    verify_session_then_finish_registration,
};

pub use libsession::prepare_logout_response;

/// Initialize the authentication coordination layer
pub async fn init() -> Result<(), AuthError> {
    // Initialize the underlying stores
    libuserdb::init().await.map_err(AuthError::User)?;
    liboauth2::init().await.map_err(AuthError::OAuth2)?;
    libpasskey::init().await.map_err(AuthError::Passkey)?;

    Ok(())
}
