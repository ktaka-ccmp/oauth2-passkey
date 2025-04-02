mod config;
mod errors;
mod main;
mod storage;
mod types;

pub use errors::PasskeyError;

pub use main::{
    AuthenticationOptions, AuthenticatorResponse, RegisterCredential, RegistrationOptions,
    get_related_origin_json,
};

pub use types::PasskeyCredential;

pub(crate) use main::{
    finish_authentication, finish_registration, start_authentication, start_registration,
    verify_session_then_finish_registration,
};

pub(crate) use storage::PasskeyStore;
pub(crate) use types::CredentialSearchField;

pub(crate) async fn init() -> Result<(), PasskeyError> {
    // Validate required environment variables early
    let _ = *config::PASSKEY_RP_ID;

    crate::storage::init()
        .await
        .map_err(|e| PasskeyError::Storage(e.to_string()))?;

    PasskeyStore::init().await?;

    Ok(())
}
