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
pub(crate) mod provider;
mod storage;
mod types;

pub use config::{enabled_providers, get_google_client_id, is_provider_enabled, provider_info};
pub use main::{prepare_fedcm_nonce, prepare_oauth2_auth_request};
pub use provider::{ProviderInfo, ProviderName};
pub use types::{
    AuthResponse, FedCMCallbackRequest, FedCMNonceResponse, OAuth2Account, OAuth2Mode, OAuth2State,
    Provider, ProviderUserId, TokenType,
};

use crate::storage::CacheErrorConversion;
pub(crate) use config::OAUTH2_CSRF_COOKIE_NAME;
pub(crate) use errors::OAuth2Error;
pub(crate) use types::{StateParams, StoredToken};
pub(crate) use types::{oauth2_account_from_idinfo, oauth2_account_from_idinfo_and_userinfo};

#[cfg(test)]
pub(crate) use main::prepare_oauth2_auth_request_inner;
pub(crate) use main::{
    csrf_checks, decode_state, delete_session_and_misc_token_from_store, get_idinfo_userinfo,
    get_mode_from_stored_session, get_uid_from_stored_session_by_state_param, validate_fedcm_token,
    validate_origin,
};

// Internal utilities needed by test setup
pub(crate) use storage::OAuth2Store;
pub(crate) use types::{AccountId, AccountSearchField};

/// Validates that `required` vars are all set whenever `trigger` var is present.
/// Returns `Err(OAuth2Error::Validation)` naming the first missing var.
fn require_env_if_trigger_set(trigger: &str, required: &[&str]) -> Result<(), errors::OAuth2Error> {
    if std::env::var(trigger).is_ok() {
        for var in required {
            if std::env::var(var).is_err() {
                return Err(errors::OAuth2Error::Validation(format!(
                    "{trigger} is set but {var} is missing"
                )));
            }
        }
    }
    Ok(())
}

pub(crate) async fn init() -> Result<(), errors::OAuth2Error> {
    // Validate required env vars at startup (fail fast before serving requests).
    // We do NOT force-initialize GOOGLE_PROVIDER here so that tests can override
    // env vars (e.g. OAUTH2_ISSUER_URL) before the first provider access.
    if std::env::var("OAUTH2_GOOGLE_CLIENT_ID").is_err() {
        return Err(errors::OAuth2Error::Validation(
            "OAUTH2_GOOGLE_CLIENT_ID must be set".to_string(),
        ));
    }
    if std::env::var("OAUTH2_GOOGLE_CLIENT_SECRET").is_err() {
        return Err(errors::OAuth2Error::Validation(
            "OAUTH2_GOOGLE_CLIENT_SECRET must be set".to_string(),
        ));
    }
    if std::env::var("ORIGIN").is_err() {
        return Err(errors::OAuth2Error::Validation(
            "ORIGIN must be set".to_string(),
        ));
    }

    // Optional providers — each declares its own env-var contract in provider.rs.
    // Adding a provider automatically picks up this check.
    for kind in provider::ProviderKind::ALL {
        if let Some((trigger, required)) = kind.optional_env_contract() {
            require_env_if_trigger_set(trigger, required)?;
        }
    }

    // Value-level validation for generic OIDC slots (provider_name shape and
    // collision checks). Env-presence is already covered by the loop above.
    provider::validate_custom_slots().map_err(errors::OAuth2Error::Validation)?;

    // Value-level validation for named-provider STRICT_DISPLAY_CLAIMS. Custom
    // slots already get this via validate_custom_slots' LazyLock force-init;
    // named providers are lazy (see comment above) so we must validate env
    // values directly to avoid a request-time panic.
    provider::validate_named_provider_strict_display_claims()
        .map_err(errors::OAuth2Error::Validation)?;

    let _ = *config::OAUTH2_CSRF_COOKIE_NAME;
    let _ = *config::OAUTH2_CSRF_COOKIE_MAX_AGE;

    // Initialize the storage layer
    crate::storage::init()
        .await
        .map_err(errors::OAuth2Error::convert_storage_error)?;

    // Initialize the OAuth2 database tables
    OAuth2Store::init().await?;

    Ok(())
}
