mod config;
mod errors;
mod main;
mod storage;
mod types;

pub use main::prepare_oauth2_auth_request;
pub use types::{AuthResponse, OAuth2Account, OAuth2Mode};

pub(crate) use config::{OAUTH2_AUTH_URL, OAUTH2_CSRF_COOKIE_NAME};
pub(crate) use errors::OAuth2Error;
pub(crate) use types::{StateParams, StoredToken};

pub(crate) use main::{
    csrf_checks, decode_state, delete_session_and_misc_token_from_store, get_idinfo_userinfo,
    get_mode_from_stored_session, get_uid_from_stored_session_by_state_param, validate_origin,
};

pub(crate) use storage::OAuth2Store;
pub(crate) use types::AccountSearchField;

pub(crate) async fn init() -> Result<(), errors::OAuth2Error> {
    // Validate required environment variables early
    let _ = *config::OAUTH2_REDIRECT_URI; // This will validate ORIGIN
    let _ = *config::OAUTH2_GOOGLE_CLIENT_ID;
    let _ = *config::OAUTH2_GOOGLE_CLIENT_SECRET;

    // Initialize the storage layer
    crate::storage::init()
        .await
        .map_err(|e| errors::OAuth2Error::Storage(e.to_string()))?;

    // Initialize the OAuth2 database tables
    OAuth2Store::init().await?;

    Ok(())
}
