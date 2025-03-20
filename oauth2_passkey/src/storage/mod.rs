mod cache;
mod data;
mod errors;
mod types;

pub async fn init() -> Result<(), errors::StorageError> {
    let _ = *cache::GENERIC_CACHE_STORE;
    let _ = *data::GENERIC_DATA_STORE;

    Ok(())
}

pub use cache::GENERIC_CACHE_STORE;
pub use types::CacheData;

pub use data::GENERIC_DATA_STORE;
