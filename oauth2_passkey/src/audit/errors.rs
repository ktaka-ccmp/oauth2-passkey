//! Error types for login history module

use thiserror::Error;

#[derive(Clone, Error, Debug)]
pub(crate) enum LoginHistoryError {
    #[error("Storage error: {0}")]
    Storage(String),

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
