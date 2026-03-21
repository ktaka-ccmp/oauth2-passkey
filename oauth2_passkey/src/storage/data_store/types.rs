use sqlx::{MySql, Pool, Postgres, Sqlite};

// Types
#[derive(Clone, Debug)]
pub(super) struct SqliteDataStore {
    pub(super) pool: sqlx::SqlitePool,
}

#[derive(Clone, Debug)]
pub(super) struct PostgresDataStore {
    pub(super) pool: sqlx::PgPool,
}

#[derive(Clone, Debug)]
pub(super) struct MySqlDataStore {
    pub(super) pool: sqlx::MySqlPool,
}

// Trait
pub(crate) trait DataStore: Send + Sync {
    fn as_sqlite(&self) -> Option<&Pool<Sqlite>>;
    fn as_postgres(&self) -> Option<&Pool<Postgres>>;
    fn as_mysql(&self) -> Option<&Pool<MySql>>;
}

// Store implementations
impl DataStore for SqliteDataStore {
    fn as_sqlite(&self) -> Option<&Pool<Sqlite>> {
        Some(&self.pool)
    }

    fn as_postgres(&self) -> Option<&Pool<Postgres>> {
        None
    }

    fn as_mysql(&self) -> Option<&Pool<MySql>> {
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

    fn as_mysql(&self) -> Option<&Pool<MySql>> {
        None
    }
}

impl DataStore for MySqlDataStore {
    fn as_sqlite(&self) -> Option<&Pool<Sqlite>> {
        None
    }

    fn as_postgres(&self) -> Option<&Pool<Postgres>> {
        None
    }

    fn as_mysql(&self) -> Option<&Pool<MySql>> {
        Some(&self.pool)
    }
}

#[cfg(test)]
mod tests;
