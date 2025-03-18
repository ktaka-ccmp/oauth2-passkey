//! Error types for the libauth crate

use thiserror::Error;

/// Errors that can occur during authentication coordination
#[derive(Error, Debug)]
pub enum AuthError {
    /// Error from the user database operations
    #[error("User error: {0}")]
    User(#[from] libuserdb::UserError),

    /// Error from OAuth2 operations
    #[error("OAuth2 error: {0}")]
    OAuth2(#[from] liboauth2::OAuth2Error),

    /// Error from Passkey operations
    #[error("Passkey error: {0}")]
    Passkey(#[from] libpasskey::PasskeyError),

    /// General coordination error
    #[error("Coordination error: {0}")]
    Coordination(String),

    /// Database error
    #[error("Database error: {0}")]
    Database(String),
}

/// Errors that can occur during user account operations
#[derive(Error, Debug)]
pub enum UserFlowError {
    #[error("User not found: {0}")]
    UserNotFound(String),
    #[error("Database error: {0}")]
    Database(String),
    #[error("Credential not found: {0}")]
    CredentialNotFound(String),
    #[error("OAuth2 account not found: {0}")]
    OAuth2AccountNotFound(String),
}
