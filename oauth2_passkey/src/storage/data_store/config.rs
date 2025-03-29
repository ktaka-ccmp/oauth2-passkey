//! Database table configuration

use std::{env, str::FromStr, sync::LazyLock};
use tokio::sync::Mutex;

use super::types::{DataStore, PostgresDataStore, SqliteDataStore};

// Configuration
pub static GENERIC_DATA_STORE_TYPE: LazyLock<String> = LazyLock::new(|| {
    env::var("GENERIC_DATA_STORE_TYPE").expect("GENERIC_DATA_STORE_TYPE must be set")
});

pub static GENERIC_DATA_STORE_URL: LazyLock<String> = LazyLock::new(|| {
    env::var("GENERIC_DATA_STORE_URL").expect("GENERIC_DATA_STORE_URL must be set")
});

pub static GENERIC_DATA_STORE: LazyLock<Mutex<Box<dyn DataStore>>> = LazyLock::new(|| {
    let store_type = GENERIC_DATA_STORE_TYPE.as_str();
    let store_url = GENERIC_DATA_STORE_URL.as_str();

    tracing::info!(
        "Initializing data store with type: {}, url: {}",
        store_type,
        store_url
    );

    let store = match store_type {
        "sqlite-test" => {
            let file_path = match (
                store_url.strip_prefix("sqlite:///"),
                store_url.strip_prefix("sqlite:"),
            ) {
                (Some(path), _) => format!("/{}", path),
                (None, Some(path)) => path.to_string(),
                (None, None) => store_url.to_string(),
            };

            tracing::info!("Using SQLite file: {}", file_path);

            let opts = sqlx::sqlite::SqliteConnectOptions::new()
                .filename(file_path)
                .create_if_missing(true);

            Box::new(SqliteDataStore {
                pool: sqlx::SqlitePool::connect_lazy_with(opts), // .expect("Failed to create SQLite pool"),
            }) as Box<dyn DataStore>
        }
        "sqlite" => {
            let opts = sqlx::sqlite::SqliteConnectOptions::from_str(store_url)
                .expect("Failed to parse SQLite connection string")
                .create_if_missing(true);

            let pool = sqlx::sqlite::SqlitePool::connect_lazy_with(opts);

            Box::new(SqliteDataStore { pool }) as Box<dyn DataStore>
        }
        "postgres" => Box::new(PostgresDataStore {
            pool: sqlx::PgPool::connect_lazy(store_url).expect("Failed to create Postgres pool"),
        }) as Box<dyn DataStore>,
        t => panic!(
            "Unsupported store type: {}. Supported types are 'sqlite' and 'postgres'",
            t
        ),
    };

    tracing::info!(
        "Connected to database: type={}, url={}",
        store_type,
        store_url
    );

    Mutex::new(store)
});

/// Table prefix from environment variable
pub static TABLE_PREFIX: LazyLock<String> =
    LazyLock::new(|| env::var("DB_TABLE_PREFIX").unwrap_or_else(|_| "o2p_".to_string()));

/// Users table name
pub static DB_TABLE_USERS: LazyLock<String> = LazyLock::new(|| {
    env::var("DB_TABLE_USERS").unwrap_or_else(|_| format!("{}{}", *TABLE_PREFIX, "users"))
});

/// Passkey credentials table name
pub static DB_TABLE_PASSKEY_CREDENTIALS: LazyLock<String> = LazyLock::new(|| {
    env::var("DB_TABLE_PASSKEY_CREDENTIALS")
        .unwrap_or_else(|_| format!("{}{}", *TABLE_PREFIX, "passkey_credentials"))
});

/// OAuth2 accounts table name
pub static DB_TABLE_OAUTH2_ACCOUNTS: LazyLock<String> = LazyLock::new(|| {
    env::var("DB_TABLE_OAUTH2_ACCOUNTS")
        .unwrap_or_else(|_| format!("{}{}", *TABLE_PREFIX, "oauth2_accounts"))
});
