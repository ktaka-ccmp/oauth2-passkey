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

pub use data_store::{
    DB_TABLE_OAUTH2_ACCOUNTS, DB_TABLE_PASSKEY_CREDENTIALS, DB_TABLE_USERS, GENERIC_DATA_STORE,
};

// Re-export schema validation function for internal use
pub use schema_validation::validate_postgres_table_schema;
