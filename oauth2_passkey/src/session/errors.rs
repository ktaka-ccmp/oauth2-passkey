use thiserror::Error;

use crate::userdb::UserError;
use crate::utils::UtilError;

#[derive(Debug, Error, Clone)]
pub enum SessionError {
    #[error("Session error")]
    SessionError,

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Cookie error: {0}")]
    Cookie(String),

    #[error("Page session token error: {0}")]
    PageSessionToken(String),

    #[error("CSRF token error: {0}")]
    CsrfToken(String),

    #[error("Session expired error")]
    SessionExpiredError,

    /// Error from utils operations
    #[error("Utils error: {0}")]
    Utils(#[from] UtilError),

    #[error("Header error: {0}")]
    HeaderError(String),

    /// Error from user database operations
    #[error("User error: {0}")]
    User(#[from] UserError),
}
