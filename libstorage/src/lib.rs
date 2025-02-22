mod config;
mod error;
mod store;
mod types;

pub use config::{StorageConfig, CACHE_STORE, PERMANENT_STORE};
pub use error::StorageError;
pub use store::{CacheStore, PermanentStore, Store};
pub use types::{CacheDataKind, PermanentDataKind, QueryField, QueryRelation, StorageKind, StorageType};
