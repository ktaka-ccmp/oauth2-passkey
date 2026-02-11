//! Database table configuration

use std::{env, str::FromStr, sync::LazyLock};
use tokio::sync::Mutex;

use super::types::{DataStore, PostgresDataStore, SqliteDataStore};

// Configuration
static GENERIC_DATA_STORE_TYPE: LazyLock<String> = LazyLock::new(|| {
    env::var("GENERIC_DATA_STORE_TYPE").expect("GENERIC_DATA_STORE_TYPE must be set")
});

static GENERIC_DATA_STORE_URL: LazyLock<String> = LazyLock::new(|| {
    env::var("GENERIC_DATA_STORE_URL").expect("GENERIC_DATA_STORE_URL must be set")
});

pub(crate) static GENERIC_DATA_STORE: LazyLock<Mutex<Box<dyn DataStore>>> = LazyLock::new(|| {
    let store_type = GENERIC_DATA_STORE_TYPE.as_str();
    let store_url = GENERIC_DATA_STORE_URL.as_str();

    tracing::info!(
        "Initializing data store with type: {}, url: {}",
        store_type,
        store_url
    );

    let store = match store_type {
        "sqlite" => {
            tracing::debug!("Creating SQLite connection with URL: {}", store_url);
            tracing::debug!(
                "Environment GENERIC_DATA_STORE_URL: {:?}",
                std::env::var("GENERIC_DATA_STORE_URL")
            );
            let is_in_memory = store_url.contains(":memory:") || store_url.contains("mode=memory");

            let mut opts = sqlx::sqlite::SqliteConnectOptions::from_str(store_url)
                .expect("Failed to parse SQLite connection string")
                .create_if_missing(true)
                .busy_timeout(std::time::Duration::from_secs(30));

            if is_in_memory {
                // In-memory SQLite: enable shared cache so all pool connections
                // share the same database; WAL and mmap are not supported.
                opts = opts.shared_cache(true);
                tracing::info!("Using in-memory SQLite with shared cache");
            } else {
                // File-based SQLite: use WAL for concurrent reads and mmap for performance.
                opts = opts
                    .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
                    .synchronous(sqlx::sqlite::SqliteSynchronous::Normal)
                    .pragma("temp_store", "memory")
                    .pragma("mmap_size", "268435456"); // 256MB
            }

            tracing::debug!("Creating lazy SQLite pool");
            let pool = if is_in_memory {
                // Keep at least one connection alive so the shared in-memory
                // database is never destroyed by idle connection eviction.
                sqlx::sqlite::SqlitePoolOptions::new()
                    .min_connections(1)
                    .connect_lazy_with(opts)
            } else {
                sqlx::sqlite::SqlitePool::connect_lazy_with(opts)
            };
            Box::new(SqliteDataStore { pool }) as Box<dyn DataStore>
        }
        "postgres" => Box::new(PostgresDataStore {
            pool: sqlx::PgPool::connect_lazy(store_url).expect("Failed to create Postgres pool"),
        }) as Box<dyn DataStore>,
        t => panic!("Unsupported store type: {t}. Supported types are 'sqlite' and 'postgres'"),
    };

    tracing::info!(
        "Connected to database: type={}, url={}",
        store_type,
        store_url
    );

    Mutex::new(store)
});

/// Table prefix from environment variable
pub(crate) static DB_TABLE_PREFIX: LazyLock<String> =
    LazyLock::new(|| env::var("DB_TABLE_PREFIX").unwrap_or_else(|_| "o2p_".to_string()));
