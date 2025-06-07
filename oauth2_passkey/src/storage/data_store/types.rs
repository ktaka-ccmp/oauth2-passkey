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

    #[test]
    fn test_data_store_trait_bounds() {
        // Verify that the trait bounds are correctly enforced for Send + Sync
        fn assert_send_sync<T: Send + Sync>() {}

        assert_send_sync::<SqliteDataStore>();
        assert_send_sync::<PostgresDataStore>();
        assert_send_sync::<Box<dyn DataStore>>();
    }
}
