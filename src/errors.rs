use thiserror::Error;

#[derive(Debug, Error, Clone)]
pub enum PasskeyError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Invalid challenge: {0}")]
    Challenge(String),

    #[error("Authentication error: {0}")]
    Authentication(String),

    #[error("Registration error: {0}")]
    Registration(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Invalid client data: {0}")]
    ClientData(String),

    #[error("Invalid authenticator data: {0}")]
    AuthenticatorData(String),

    #[error("Verification error: {0}")]
    Verification(String),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Invalid format: {0}")]
    Format(String),

    #[error("{0}")]
    Other(String),
}

// pub type Result<T> = std::result::Result<T, PasskeyError>;

// Implement From for common error types
impl From<base64::DecodeError> for PasskeyError {
    fn from(err: base64::DecodeError) -> Self {
        PasskeyError::Format(format!("Base64 decode error: {}", err))
    }
}

impl From<serde_json::Error> for PasskeyError {
    fn from(err: serde_json::Error) -> Self {
        PasskeyError::Format(format!("JSON error: {}", err))
    }
}

impl From<anyhow::Error> for PasskeyError {
    fn from(err: anyhow::Error) -> Self {
        PasskeyError::Other(err.to_string())
    }
}

// impl From<std::env::VarError> for PasskeyError {
//     fn from(err: std::env::VarError) -> Self {
//         PasskeyError::Config(format!("Environment variable error: {}", err))
//     }
// }

#[derive(Debug, Error)]
pub enum WebAuthnError {
    #[error("Invalid client data: {0}")]
    InvalidClientData(String),

    #[error("Invalid challenge: {0}")]
    InvalidChallenge(String),

    #[error("Invalid authenticator: {0}")]
    InvalidAuthenticator(String),

    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    #[error("Storage error: {0}")]
    StorageError(String),

    #[error("Other error: {0}")]
    Other(String),
}

impl From<WebAuthnError> for (u16, String) {
    fn from(err: WebAuthnError) -> Self {
        (400, err.to_string())
    }
}
