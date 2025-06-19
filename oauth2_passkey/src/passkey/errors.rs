use thiserror::Error;

use crate::utils::UtilError;

/// Errors that can occur during WebAuthn/Passkey operations.
///
/// This enum represents all possible error conditions when handling passkey
/// registration, authentication, verification, and storage operations.
#[derive(Debug, Error)]
pub enum PasskeyError {
    /// Error related to passkey configuration (e.g., invalid RP ID, origin, or settings)
    #[error("Configuration error: {0}")]
    Config(String),

    /// Error with the cryptographic challenge used in the WebAuthn protocol
    #[error("Invalid challenge: {0}")]
    Challenge(String),

    /// Error during the authentication process (e.g., invalid signature)
    #[error("Authentication error: {0}")]
    Authentication(String),

    /// Error during the registration process (e.g., duplicate credential)
    #[error("Registration error: {0}")]
    Registration(String),

    /// Error accessing or modifying stored passkey data
    #[error("Storage error: {0}")]
    Storage(String),

    /// Error converting between data formats using Serde
    #[error("Json conversion(Serde) error: {0}")]
    Serde(String),

    /// Error validating the client data JSON from the browser
    #[error("Invalid client data: {0}")]
    ClientData(String),

    /// Error parsing or validating the authenticator data structure
    #[error("Invalid authenticator data: {0}")]
    AuthenticatorData(String),

    /// Error during cryptographic verification of WebAuthn assertions
    #[error("Verification error: {0}")]
    Verification(String),

    /// Error when a requested resource (e.g., credential) is not found
    #[error("Not found error: {0}")]
    NotFound(String),

    /// Error in cryptographic operations (e.g., signature verification)
    #[error("Crypto error: {0}")]
    Crypto(String),

    /// Error with improperly formatted data
    #[error("Invalid format: {0}")]
    Format(String),

    /// Error when an operation is not authorized
    #[error("Unauthorized error: {0}")]
    Unauthorized(String),

    /// General error not covered by other categories
    #[error("{0}")]
    Other(String),

    /// Error from utility operations
    #[error("Utils error: {0}")]
    Utils(#[from] UtilError),

    /// Error from Redis cache operations
    #[error("Redis error: {0}")]
    Redis(#[from] redis::RedisError),

    /// Error from JSON serialization/deserialization
    #[error("Serde error: {0}")]
    SerdeJson(#[from] serde_json::Error),
}
