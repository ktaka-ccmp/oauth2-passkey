use sqlx::{Pool, Postgres, Sqlite};

// Types
#[derive(Clone, Debug)]
pub(crate) struct SqliteDataStore {
    pub(super) pool: sqlx::SqlitePool,
}

#[derive(Clone, Debug)]
pub(crate) struct PostgresDataStore {
    pub(super) pool: sqlx::PgPool,
}

// Trait
pub trait DataStore: Send + Sync {
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
