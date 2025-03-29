mod cache_store;
mod data_store;
mod errors;
mod schema_validation;
mod types;

pub async fn init() -> Result<(), errors::StorageError> {
    let _ = *cache_store::GENERIC_CACHE_STORE;
    let _ = *data_store::GENERIC_DATA_STORE;

    Ok(())
}

pub use cache_store::GENERIC_CACHE_STORE;
pub use types::CacheData;

pub(crate) use data_store::{DB_TABLE_PREFIX, GENERIC_DATA_STORE};

// Re-export schema validation function for internal use
pub(crate) use schema_validation::{validate_postgres_table_schema, validate_sqlite_table_schema};
