/// WebAuthn/Passkey authentication implementation for creating, managing, and authenticating
/// with passkey credentials.
///
/// This module provides WebAuthn (Web Authentication) capabilities, letting users create and use
/// passkeys for authentication. It implements the WebAuthn protocol for creating and verifying
/// cryptographic credentials using authenticators like hardware security keys, platform authenticators
/// (Windows Hello, Apple Touch ID, Android fingerprint), or cross-device passkeys.
///
/// ## Key components:
///
/// - Registration flow: Start/finish registration of new passkey credentials
/// - Authentication flow: Start/finish authentication using existing passkeys
/// - Authenticator information: Details about passkey authenticator devices
/// - Credential management: Updating and storing passkey credentials
///
/// ## Standards compliance:
///
/// The implementation follows the W3C WebAuthn Level 3 specification and FIDO2 standards
/// for secure authentication.
mod config;
mod errors;
mod main;
mod storage;
mod types;

pub use errors::PasskeyError;

pub use main::{
    AuthenticationOptions, AuthenticatorInfo, AuthenticatorResponse, RegisterCredential,
    RegistrationOptions, get_authenticator_info, get_authenticator_info_batch,
    get_related_origin_json,
};

pub use types::{CredentialId, PasskeyCredential};

pub(crate) use main::{
    commit_registration, finish_authentication, prepare_registration_storage, start_authentication,
    start_registration, validate_registration_challenge, verify_session_then_finish_registration,
};

pub(crate) use storage::PasskeyStore;
pub(crate) use types::CredentialSearchField;

pub(crate) async fn init() -> Result<(), PasskeyError> {
    // Validate required environment variables early
    let _ = *config::PASSKEY_RP_ID;
    self::main::store_aaguids().await?;

    crate::storage::init()
        .await
        .map_err(|e| PasskeyError::Storage(e.to_string()))?;

    PasskeyStore::init().await?;

    Ok(())
}
