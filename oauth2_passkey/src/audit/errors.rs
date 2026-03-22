//! Error types for login history module

use thiserror::Error;

/// Errors that can occur during login history operations
#[derive(Clone, Error, Debug)]
pub enum LoginHistoryError {
    /// Database storage error
    #[error("Storage error: {0}")]
    Storage(String),

    /// Invalid or malformed data
    #[error("Invalid data: {0}")]
    InvalidData(String),
}

impl From<serde_json::Error> for LoginHistoryError {
    fn from(err: serde_json::Error) -> Self {
        LoginHistoryError::InvalidData(err.to_string())
    }
}

impl From<sqlx::Error> for LoginHistoryError {
    fn from(err: sqlx::Error) -> Self {
        LoginHistoryError::Storage(err.to_string())
    }
}
