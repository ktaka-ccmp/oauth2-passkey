mod cache;
mod data;
mod errors;
mod types;

pub async fn init() -> Result<(), errors::StorageError> {
    // Validate required environment variables early

    cache::init_cache_store().await?;
    Ok(())
}

pub use cache::GENERIC_CACHE_STORE;
pub use cache::init_cache_store;
pub use types::CacheData;

pub use data::{DataStore, GENERIC_DATA_STORE, GENERIC_DATA_STORE_TYPE, GENERIC_DATA_STORE_URL};
