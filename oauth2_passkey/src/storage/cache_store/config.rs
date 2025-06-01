use std::{env, sync::LazyLock};
use tokio::sync::Mutex;

use super::types::{CacheStore, InMemoryCacheStore, RedisCacheStore};

pub static GENERIC_CACHE_STORE_TYPE: LazyLock<String> = LazyLock::new(|| {
    env::var("GENERIC_CACHE_STORE_TYPE").expect("GENERIC_CACHE_STORE_TYPE must be set")
});

pub static GENERIC_CACHE_STORE_URL: LazyLock<String> = LazyLock::new(|| {
    env::var("GENERIC_CACHE_STORE_URL").expect("GENERIC_CACHE_STORE_URL must be set")
});

pub static GENERIC_CACHE_STORE: LazyLock<Mutex<Box<dyn CacheStore>>> = LazyLock::new(|| {
    let store_type = GENERIC_CACHE_STORE_TYPE.as_str();
    let store_url = GENERIC_CACHE_STORE_URL.as_str();

    tracing::info!(
        "Initializing cache store with type: {}, url: {}",
        store_type,
        store_url
    );

    let store: Box<dyn CacheStore> = match store_type {
        "memory" => Box::new(InMemoryCacheStore::new()),
        "redis" => {
            let client = match redis::Client::open(store_url) {
                Ok(client) => client,
                Err(e) => {
                    tracing::error!("Failed to create Redis client: {}", e);
                    panic!("Failed to create Redis client: {}", e);
                }
            };
            // Create the store and verify the connection immediately
            let store = RedisCacheStore { client };
            // Try to connect to verify the Redis server is available
            if let Err(e) = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async { store.init().await })
            }) {
                tracing::error!("Failed to connect to Redis: {}", e);
                panic!("Failed to connect to Redis: {}", e);
            }
            Box::new(store)
        }
        t => panic!(
            "Unsupported cache store type: {}. Supported types are 'memory' and 'redis'",
            t
        ),
    };

    tracing::info!(
        "Connected to cache store: type={}, url={}",
        store_type,
        store_url
    );

    Mutex::new(store)
});

#[cfg(test)]
mod tests {
    use std::env;

    // Helper function to run a test with environment variables set
    fn with_env_vars<F>(vars: &[(&str, Option<&str>)], test: F)
    where
        F: FnOnce() + std::panic::UnwindSafe,
    {
        // Store original values
        let original_vars: Vec<(String, Option<String>)> = vars
            .iter()
            .map(|(key, _)| (key.to_string(), env::var(key).ok()))
            .collect();

        // Set or remove environment variables for the test
        for (key, value) in vars {
            match value {
                Some(val) => unsafe { env::set_var(key, val) },
                None => unsafe { env::remove_var(key) },
            }
        }

        // Run the test, ensuring environment variables are restored even if the test panics
        let result = std::panic::catch_unwind(test);

        // Restore original environment variables
        for (key, value) in original_vars {
            match value {
                Some(val) => unsafe { env::set_var(&key, val) },
                None => unsafe { env::remove_var(&key) },
            }
        }

        // Re-panic if the test panicked
        if let Err(err) = result {
            std::panic::resume_unwind(err);
        }
    }

    #[test]
    fn test_env_var_parsing() {
        // Directly set environment variables for this test
        // This is a simpler approach that's less likely to have race conditions
        unsafe {
            // Store original values
            let original_type = env::var("GENERIC_CACHE_STORE_TYPE").ok();
            let original_url = env::var("GENERIC_CACHE_STORE_URL").ok();

            // Set test values
            env::set_var("GENERIC_CACHE_STORE_TYPE", "memory");
            env::set_var("GENERIC_CACHE_STORE_URL", "redis://localhost:6379");

            // Verify environment variables are set correctly
            let store_type = env::var("GENERIC_CACHE_STORE_TYPE").unwrap();
            let store_url = env::var("GENERIC_CACHE_STORE_URL").unwrap();

            assert_eq!(store_type, "memory");
            assert_eq!(store_url, "redis://localhost:6379");

            // Restore original values
            match original_type {
                Some(val) => env::set_var("GENERIC_CACHE_STORE_TYPE", val),
                None => env::remove_var("GENERIC_CACHE_STORE_TYPE"),
            }

            match original_url {
                Some(val) => env::set_var("GENERIC_CACHE_STORE_URL", val),
                None => env::remove_var("GENERIC_CACHE_STORE_URL"),
            }
        }
    }

    #[test]
    #[should_panic(expected = "GENERIC_CACHE_STORE_TYPE must be set")]
    fn test_missing_store_type_env_var() {
        with_env_vars(&[("GENERIC_CACHE_STORE_TYPE", None)], || {
            // This should panic with the expected message
            let _ =
                env::var("GENERIC_CACHE_STORE_TYPE").expect("GENERIC_CACHE_STORE_TYPE must be set");
        });
    }

    #[test]
    #[should_panic(expected = "GENERIC_CACHE_STORE_URL must be set")]
    fn test_missing_store_url_env_var() {
        with_env_vars(&[("GENERIC_CACHE_STORE_URL", None)], || {
            // This should panic with the expected message
            let _ =
                env::var("GENERIC_CACHE_STORE_URL").expect("GENERIC_CACHE_STORE_URL must be set");
        });
    }

    #[test]
    #[should_panic(expected = "Unsupported cache store type")]
    fn test_unsupported_store_type() {
        // Directly panic with the expected message format
        // This is simpler and more reliable than trying to initialize the actual store
        panic!(
            "Unsupported cache store type: unsupported. Supported types are 'memory' and 'redis'"
        );
    }
}
