//! Storage module for persistent and cache data storage.
//!
//! This module provides flexible storage backends for both persistent data (user accounts,
//! credentials) and ephemeral cache data (sessions, challenges). It abstracts the underlying
//! storage implementations, allowing the library to work with various database systems.
//!
//! ## Key components:
//!
//! - Cache store: Fast access to short-lived data like session tokens and challenges
//! - Data store: Persistent storage for user accounts, OAuth2 accounts, and passkey credentials
//! - Schema validation: Database schema verification for supported backends
//! - Adapters for SQLite, PostgreSQL, and Redis

mod cache_operations;
mod cache_store;
mod data_store;
mod errors;
#[cfg(test)]
mod injection_security_tests;
mod schema_validation;
mod types;

pub(crate) async fn init() -> Result<(), errors::StorageError> {
    let _ = *cache_store::GENERIC_CACHE_STORE;
    let _ = *data_store::GENERIC_DATA_STORE;

    Ok(())
}

pub(crate) use cache_operations::{
    CacheErrorConversion, get_data, get_data_by_category, remove_data, remove_data_by_category,
    store_data_with_category, store_data_with_manual_expiration,
};
pub(crate) use cache_store::GENERIC_CACHE_STORE;
pub(crate) use errors::StorageError;
pub(crate) use types::{CacheData, CacheKey, CachePrefix, create_cache_keys};

pub(crate) use data_store::{DB_TABLE_PREFIX, GENERIC_DATA_STORE};

// Re-export schema validation function for internal use
pub(crate) use schema_validation::{validate_postgres_table_schema, validate_sqlite_table_schema};
