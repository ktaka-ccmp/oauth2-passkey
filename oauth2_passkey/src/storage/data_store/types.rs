use sqlx::{Pool, Postgres, Sqlite};

// Types
#[derive(Clone, Debug)]
pub(super) struct SqliteDataStore {
    pub(super) pool: sqlx::SqlitePool,
}

#[derive(Clone, Debug)]
pub(super) struct PostgresDataStore {
    pub(super) pool: sqlx::PgPool,
}

// Trait
pub(crate) trait DataStore: Send + Sync {
    fn as_sqlite(&self) -> Option<&Pool<Sqlite>>;
    fn as_postgres(&self) -> Option<&Pool<Postgres>>;
}

// Store implementations
impl DataStore for SqliteDataStore {
    fn as_sqlite(&self) -> Option<&Pool<Sqlite>> {
        Some(&self.pool)
    }

    fn as_postgres(&self) -> Option<&Pool<Postgres>> {
        None
    }
}

impl DataStore for PostgresDataStore {
    fn as_sqlite(&self) -> Option<&Pool<Sqlite>> {
        None
    }

    fn as_postgres(&self) -> Option<&Pool<Postgres>> {
        Some(&self.pool)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[tokio::test]
    async fn test_sqlite_data_store_as_sqlite() {
        // Given a SqliteDataStore instance
        let opts = sqlx::sqlite::SqliteConnectOptions::from_str("sqlite::memory:")
            .expect("Failed to parse SQLite connection string")
            .create_if_missing(true);

        let store = SqliteDataStore {
            pool: sqlx::sqlite::SqlitePool::connect_lazy_with(opts),
        };

        // When calling as_sqlite
        let sqlite_pool = store.as_sqlite();

        // Then it should return Some with the pool
        assert!(sqlite_pool.is_some());
    }

    #[tokio::test]
    async fn test_sqlite_data_store_as_postgres() {
        // Given a SqliteDataStore instance
        let opts = sqlx::sqlite::SqliteConnectOptions::from_str("sqlite::memory:")
            .expect("Failed to parse SQLite connection string")
            .create_if_missing(true);

        let store = SqliteDataStore {
            pool: sqlx::sqlite::SqlitePool::connect_lazy_with(opts),
        };

        // When calling as_postgres
        let postgres_pool = store.as_postgres();

        // Then it should return None
        assert!(postgres_pool.is_none());
    }

    #[tokio::test]
    async fn test_sqlite_data_store_debug() {
        // Given a SqliteDataStore instance
        let opts = sqlx::sqlite::SqliteConnectOptions::from_str("sqlite::memory:")
            .expect("Failed to parse SQLite connection string")
            .create_if_missing(true);

        let store = SqliteDataStore {
            pool: sqlx::sqlite::SqlitePool::connect_lazy_with(opts),
        };

        // When formatting with Debug
        let debug_string = format!("{:?}", store);

        // Then it should include the type name
        assert!(debug_string.contains("SqliteDataStore"));
    }

    #[test]
    fn test_data_store_trait_bounds() {
        // This test verifies that the trait bounds are correctly enforced
        fn assert_send_sync<T: Send + Sync>() {}

        // SqliteDataStore should be Send + Sync
        assert_send_sync::<SqliteDataStore>();

        // PostgresDataStore should be Send + Sync
        assert_send_sync::<PostgresDataStore>();

        // Box<dyn DataStore> should be Send + Sync
        assert_send_sync::<Box<dyn DataStore>>();
    }
}
