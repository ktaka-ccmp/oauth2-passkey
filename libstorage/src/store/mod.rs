mod memory;
mod postgres;
pub mod redis;
mod sqlite;
pub mod traits;

use crate::types::{StorageError, StorageType};
pub use memory::MemoryStore;
pub use postgres::PostgresStore;
pub use redis::RedisStore;
pub use sqlite::SqliteStore;
pub use traits::Store;

pub async fn init_store(
    storage_type: StorageType,
    url: &str,
) -> Result<Box<dyn Store>, StorageError> {
    let store: Box<dyn Store> = match storage_type {
        StorageType::Memory => Box::new(MemoryStore::new()),
        StorageType::Redis(_) => Box::new(RedisStore::new(url)?),
        StorageType::Postgres(_) => Box::new(PostgresStore::connect(url).await?),
        StorageType::Sqlite(_) => Box::new(SqliteStore::connect(url).await?),
    };

    store.init().await?;
    Ok(store)
}

pub async fn init_storage<T>(storage_type: StorageType, url: &str) -> Result<T, StorageError>
where
    T: From<MemoryStore> + From<RedisStore> + From<PostgresStore> + From<SqliteStore>,
{
    let store = match storage_type {
        StorageType::Memory => T::from(MemoryStore::new()),
        StorageType::Redis(_) => T::from(RedisStore::new(url)?),
        StorageType::Postgres(_) => T::from(PostgresStore::connect(url).await?),
        StorageType::Sqlite(_) => T::from(SqliteStore::connect(url).await?),
    };

    Ok(store)
}
