use crate::session::SessionError;
use crate::utils::UtilError;
use thiserror::Error;

#[derive(Debug, Error, Clone)]
pub enum OAuth2Error {
    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Encoding error: {0}")]
    Encoding(String),

    #[error("Cookie error: {0}")]
    Cookie(String),

    #[error("Id mismatch")]
    IdMismatch,

    #[error("Serde error: {0}")]
    Serde(String),

    #[error("Security token not found: {0}")]
    SecurityTokenNotFound(String),

    #[error("Nonce expired")]
    NonceExpired,

    #[error("Nonce mismatch")]
    NonceMismatch,

    #[error("Csrf token mismatch")]
    CsrfTokenMismatch,

    #[error("Csrf token expired")]
    CsrfTokenExpired,

    #[error("User agent mismatch")]
    UserAgentMismatch,

    #[error("Id token error: {0}")]
    IdToken(String),

    #[error("Invalid origin: {0}")]
    InvalidOrigin(String),

    #[error("Decode state error: {0}")]
    DecodeState(String),

    #[error("Fetch user info error: {0}")]
    FetchUserInfo(String),

    #[error("Token exchange error: {0}")]
    TokenExchange(String),

    #[error("Database error: {0}")]
    Database(String),

    #[error("Internal error: {0}")]
    Internal(String),

    /// Error from utils operations
    #[error("Utils error: {0}")]
    Utils(#[from] UtilError),

    /// Error from session operations
    #[error("Session error: {0}")]
    Session(#[from] SessionError),

    #[error("Invalid mode: {0}")]
    InvalidMode(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::SessionError;
    use crate::utils::UtilError;
    use std::error::Error;

    /// Test error source chain preservation in From trait conversions
    ///
    /// This test verifies that when converting from UtilError and SessionError to OAuth2Error
    /// using the From trait, the error source chain is properly preserved. It creates errors
    /// in memory and tests that the original error can be accessed via the source() method.
    ///
    #[test]
    fn test_error_source_chaining() {
        // Test that From conversions preserve error sources
        let util_err = UtilError::Format("format error".to_string());
        let oauth2_err: OAuth2Error = util_err.into();

        // The source should be the original UtilError
        match oauth2_err.source() {
            Some(source) => {
                assert_eq!(source.to_string(), "Invalid format: format error");
            }
            None => panic!("Expected error to have a source"),
        }

        let session_err = SessionError::Storage("session error".to_string());
        let oauth2_err: OAuth2Error = session_err.into();

        // The source should be the original SessionError
        match oauth2_err.source() {
            Some(source) => {
                assert_eq!(source.to_string(), "Storage error: session error");
            }
            None => panic!("Expected error to have a source"),
        }
    }
}
