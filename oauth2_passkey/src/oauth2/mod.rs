//! OAuth2 authentication module
//!
//! This module provides OAuth2 authentication functionality, specifically supporting
//! Google OAuth2/OpenID Connect. It handles the authentication flow, token validation,
//! and user profile retrieval.
//!
//! The module includes:
//! - OAuth2 authentication flow coordination
//! - Token handling and validation
//! - User profile information retrieval
//! - OAuth2 account management

mod config;
mod discovery;
mod errors;
mod main;
mod storage;
mod types;

pub use main::prepare_oauth2_auth_request;
pub use types::{AuthResponse, OAuth2Account, OAuth2Mode, Provider, ProviderUserId};

use crate::storage::CacheErrorConversion;
pub(crate) use config::{OAUTH2_CSRF_COOKIE_NAME, OAUTH2_RESPONSE_MODE, get_auth_url};
pub(crate) use errors::OAuth2Error;
pub(crate) use types::{StateParams, StoredToken};

pub(crate) use main::{
    csrf_checks, decode_state, delete_session_and_misc_token_from_store, get_idinfo_userinfo,
    get_mode_from_stored_session, get_uid_from_stored_session_by_state_param, validate_origin,
};

// Internal utilities needed by test setup
pub(crate) use storage::OAuth2Store;
pub(crate) use types::{AccountId, AccountSearchField};

pub(crate) async fn init() -> Result<(), errors::OAuth2Error> {
    // Validate required environment variables early
    let _ = *config::OAUTH2_REDIRECT_URI; // This will validate ORIGIN
    let _ = *config::OAUTH2_GOOGLE_CLIENT_ID;
    let _ = *config::OAUTH2_GOOGLE_CLIENT_SECRET;

    // Initialize the storage layer
    crate::storage::init()
        .await
        .map_err(errors::OAuth2Error::convert_storage_error)?;

    // Initialize the OAuth2 database tables
    OAuth2Store::init().await?;

    Ok(())
}
