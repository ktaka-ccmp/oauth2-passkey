mod config;
mod errors;
mod main;
mod storage;
mod types;

pub use errors::PasskeyError;

pub use main::{
    AuthenticationOptions, AuthenticatorResponse, RegisterCredential, RegistrationOptions,
    finish_authentication, finish_registration, get_related_origin_json, start_authentication,
    start_registration, verify_session_then_finish_registration,
};

pub use storage::PasskeyStore;
pub use types::{CredentialSearchField, PasskeyCredential};

pub async fn init() -> Result<(), PasskeyError> {
    // Validate required environment variables early
    let _ = *config::PASSKEY_RP_ID;

    crate::storage::init()
        .await
        .map_err(|e| PasskeyError::Storage(e.to_string()))?;

    PasskeyStore::init().await?;

    Ok(())
}
