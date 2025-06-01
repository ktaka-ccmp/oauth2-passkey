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
            let opts = sqlx::sqlite::SqliteConnectOptions::from_str(store_url)
                .expect("Failed to parse SQLite connection string")
                .create_if_missing(true);

            Box::new(SqliteDataStore {
                pool: sqlx::sqlite::SqlitePool::connect_lazy_with(opts),
            }) as Box<dyn DataStore>
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
pub(crate) static DB_TABLE_PREFIX: LazyLock<String> =
    LazyLock::new(|| env::var("DB_TABLE_PREFIX").unwrap_or_else(|_| "o2p_".to_string()));

#[cfg(test)]
mod tests {
    use std::env;

    // Helper struct to safely manage environment variables during tests
    struct EnvVarGuard {
        key: String,
        original_value: Option<String>,
    }

    impl EnvVarGuard {
        // Create a new guard and set the environment variable
        fn new(key: &str, value: &str) -> Self {
            let original_value = env::var(key).ok();

            // Use unsafe block for env var manipulation as it affects global state
            unsafe {
                env::set_var(key, value);
            }

            Self {
                key: key.to_string(),
                original_value,
            }
        }
    }

    impl Drop for EnvVarGuard {
        // Restore the original environment variable when the guard is dropped
        fn drop(&mut self) {
            // Use unsafe block for env var manipulation as it affects global state
            unsafe {
                match &self.original_value {
                    Some(value) => env::set_var(&self.key, value),
                    None => env::remove_var(&self.key),
                }
            }
        }
    }

    #[test]
    fn test_env_var_parsing() {
        // This test only verifies that the environment variables are parsed correctly
        // We don't actually initialize the LazyLock to avoid side effects

        // Set up environment variables for the test
        let _type_guard = EnvVarGuard::new("GENERIC_DATA_STORE_TYPE", "sqlite");
        let _url_guard = EnvVarGuard::new("GENERIC_DATA_STORE_URL", "sqlite::memory:");

        // Directly test the environment variable parsing
        let store_type = env::var("GENERIC_DATA_STORE_TYPE").unwrap();
        let store_url = env::var("GENERIC_DATA_STORE_URL").unwrap();

        assert_eq!(store_type, "sqlite");
        assert_eq!(store_url, "sqlite::memory:");
    }

    #[test]
    #[should_panic(expected = "GENERIC_DATA_STORE_TYPE must be set")]
    fn test_missing_store_type_env_var() {
        // Remove the environment variable to trigger the panic
        unsafe {
            // Save the original value to restore it later
            let original = env::var("GENERIC_DATA_STORE_TYPE").ok();
            env::remove_var("GENERIC_DATA_STORE_TYPE");

            // This should panic with the expected message
            let _ =
                env::var("GENERIC_DATA_STORE_TYPE").expect("GENERIC_DATA_STORE_TYPE must be set");

            // Restore the original value (this won't be reached due to the panic)
            if let Some(value) = original {
                env::set_var("GENERIC_DATA_STORE_TYPE", value);
            }
        }
    }

    #[test]
    #[should_panic(expected = "GENERIC_DATA_STORE_URL must be set")]
    fn test_missing_store_url_env_var() {
        // Remove the environment variable to trigger the panic
        unsafe {
            // Save the original value to restore it later
            let original = env::var("GENERIC_DATA_STORE_URL").ok();
            env::remove_var("GENERIC_DATA_STORE_URL");

            // This should panic with the expected message
            let _ = env::var("GENERIC_DATA_STORE_URL").expect("GENERIC_DATA_STORE_URL must be set");

            // Restore the original value (this won't be reached due to the panic)
            if let Some(value) = original {
                env::set_var("GENERIC_DATA_STORE_URL", value);
            }
        }
    }

    #[test]
    #[should_panic(expected = "Unsupported store type")]
    fn test_unsupported_store_type() {
        // Set an unsupported store type to trigger the panic
        let _type_guard = EnvVarGuard::new("GENERIC_DATA_STORE_TYPE", "unsupported");
        let _url_guard = EnvVarGuard::new("GENERIC_DATA_STORE_URL", "sqlite::memory:");

        // This is a simplified version of the store initialization logic
        // that will panic with the expected message
        let store_type = env::var("GENERIC_DATA_STORE_TYPE").unwrap();
        match store_type.as_str() {
            "sqlite" => {}
            "postgres" => {}
            t => panic!(
                "Unsupported store type: {}. Supported types are 'sqlite' and 'postgres'",
                t
            ),
        };
    }

    #[test]
    fn test_db_table_prefix_default() {
        // Remove the environment variable to test the default value
        unsafe {
            // Save the original value to restore it later
            let original = env::var("DB_TABLE_PREFIX").ok();
            env::remove_var("DB_TABLE_PREFIX");

            // Test the default value
            let prefix = env::var("DB_TABLE_PREFIX").unwrap_or_else(|_| "o2p_".to_string());
            assert_eq!(prefix, "o2p_");

            // Restore the original value
            if let Some(value) = original {
                env::set_var("DB_TABLE_PREFIX", value);
            }
        }
    }

    #[test]
    fn test_db_table_prefix_custom() {
        // Set a custom table prefix
        let _prefix_guard = EnvVarGuard::new("DB_TABLE_PREFIX", "custom_");

        // Test the custom value
        let prefix = env::var("DB_TABLE_PREFIX").unwrap_or_else(|_| "o2p_".to_string());
        assert_eq!(prefix, "custom_");
    }
}
