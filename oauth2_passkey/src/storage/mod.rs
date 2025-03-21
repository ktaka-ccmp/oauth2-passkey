mod cache_store;
mod config;
mod data_store;
mod errors;
mod types;

pub async fn init() -> Result<(), errors::StorageError> {
    let _ = *cache_store::GENERIC_CACHE_STORE;
    let _ = *data_store::GENERIC_DATA_STORE;

    Ok(())
}

pub use cache_store::GENERIC_CACHE_STORE;
pub use config::{DB_TABLE_OAUTH2_ACCOUNTS, DB_TABLE_PASSKEY_CREDENTIALS, DB_TABLE_USERS};
pub use types::CacheData;

pub use data_store::GENERIC_DATA_STORE;
