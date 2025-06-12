mod cache_store;
#[cfg(test)]
pub mod data_store;
#[cfg(not(test))]
mod data_store;
mod errors;
mod schema_validation;
mod types;

pub(crate) async fn init() -> Result<(), errors::StorageError> {
    let _ = *cache_store::GENERIC_CACHE_STORE;
    let _ = *data_store::GENERIC_DATA_STORE;

    Ok(())
}

pub(crate) use cache_store::GENERIC_CACHE_STORE;
pub(crate) use types::CacheData;

pub(crate) use data_store::{DB_TABLE_PREFIX, GENERIC_DATA_STORE};

// Re-export schema validation function for internal use
pub(crate) use schema_validation::{validate_postgres_table_schema, validate_sqlite_table_schema};

// Re-export DataStore for test utilities
#[cfg(test)]
pub use data_store::DataStore;

/// Set a custom data store for testing purposes
///
/// This function allows tests to use an isolated database connection
/// to prevent state leakage between tests.
///
/// # Arguments
/// * `store` - The custom data store to use for testing
///
/// # Note
/// This function is intended for testing only and should not be used in production code.
#[cfg(test)]
pub(crate) async fn set_data_store_for_test(store: Box<dyn DataStore>) {
    // Replace the global data store with the test-specific one
    let mut global_store = data_store::GENERIC_DATA_STORE.lock().await;
    *global_store = store;
}
