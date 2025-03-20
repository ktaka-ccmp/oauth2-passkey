mod cache;
mod config;
mod data;
mod errors;
mod types;

pub async fn init() -> Result<(), errors::StorageError> {
    let _ = *cache::GENERIC_CACHE_STORE;
    let _ = *data::GENERIC_DATA_STORE;

    Ok(())
}

pub use cache::GENERIC_CACHE_STORE;
pub use config::{DB_TABLE_OAUTH2_ACCOUNTS, DB_TABLE_PASSKEY_CREDENTIALS, DB_TABLE_USERS};
pub use types::CacheData;

pub use data::GENERIC_DATA_STORE;
