use thiserror::Error;

#[derive(Error, Debug)]
pub enum UserError {
    #[error("User not found")]
    NotFound,

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Invalid data: {0}")]
    InvalidData(String),
}

impl From<serde_json::Error> for UserError {
    fn from(err: serde_json::Error) -> Self {
        UserError::InvalidData(err.to_string())
    }
}

impl From<redis::RedisError> for UserError {
    fn from(err: redis::RedisError) -> Self {
        UserError::Storage(err.to_string())
    }
}
