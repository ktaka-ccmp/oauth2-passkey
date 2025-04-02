use thiserror::Error;

#[derive(Debug, Error, Clone)]
pub(crate) enum StorageError {
    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Json conversion(Serde) error: {0}")]
    Serde(String),
}

impl From<redis::RedisError> for StorageError {
    fn from(err: redis::RedisError) -> Self {
        Self::Storage(err.to_string()) // Adjust this based on how you want to represent the error
    }
}

impl From<serde_json::Error> for StorageError {
    fn from(err: serde_json::Error) -> Self {
        Self::Serde(err.to_string())
    }
}
