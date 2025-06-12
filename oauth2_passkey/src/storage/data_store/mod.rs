mod config;
#[cfg(test)]
pub mod types;
#[cfg(not(test))]
mod types;

pub(crate) use config::{DB_TABLE_PREFIX, GENERIC_DATA_STORE};

// Re-export DataStore trait and implementations for testing
#[cfg(test)]
pub use types::{DataStore, PostgresDataStore, SqliteDataStore};
